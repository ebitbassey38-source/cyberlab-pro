const { replay } = require("./requestReplay");
const { createResult } = require("./baseEngine");

const PAYLOADS =
  require("./xss/payloads");

const fingerprints =
  require("./xss/fingerprints");

const comparator =
  require("./xss/comparator");

const scorer =
  require("./xss/scorer");

/*
|--------------------------------------------------------------------------
| Parameter Discovery
|--------------------------------------------------------------------------
*/

function discoverParameters(httpRequest) {

  const parameters = [];

  try {

    const url = new URL(httpRequest.url);

    for (const [key, value] of url.searchParams.entries()) {

      parameters.push({

        location: "query",
        name: key,
        value

      });

    }

  } catch (_) {}

  if (
    httpRequest.body &&
    typeof httpRequest.body === "object"
  ) {

    for (const [key, value] of Object.entries(httpRequest.body)) {

      parameters.push({

        location: "body",
        name: key,
        value

      });

    }

  }

  return parameters;

}

/*
|--------------------------------------------------------------------------
| Helpers
|--------------------------------------------------------------------------
*/

function cloneRequest(request) {

  return JSON.parse(
    JSON.stringify(request)
  );

}

function replaceQueryParameter(
  urlString,
  parameter,
  payload
) {

  const url = new URL(urlString);

  url.searchParams.set(
    parameter,
    payload
  );

  return url.toString();

}

function replaceBodyParameter(
  body,
  parameter,
  payload
) {

  const copy =
    JSON.parse(
      JSON.stringify(body)
    );

  copy[parameter] = payload;

  return copy;

}

/*
|--------------------------------------------------------------------------
| XSS Scan Engine
|--------------------------------------------------------------------------
*/

async function scan(httpRequest) {

  const result =
    createResult("xss");

  const evidence =
    result.evidence;

  const parameters =
    discoverParameters(httpRequest);

  result.metadata.parameters =
    parameters;

  if (!parameters.length) {

    result.reason =
      "No injectable parameters found.";

    return result;

  }

  result.tested = true;

  for (const parameter of parameters) {

    for (const category of Object.values(PAYLOADS)) {

      for (const payload of category) {

        const originalRequest =
          cloneRequest(httpRequest);

        const mutatedRequest =
          cloneRequest(httpRequest);

        if (parameter.location === "query") {

          mutatedRequest.url =
            replaceQueryParameter(
              mutatedRequest.url,
              parameter.name,
              payload
            );

        }

        if (
          parameter.location === "body" &&
          mutatedRequest.body
        ) {

          mutatedRequest.body =
            replaceBodyParameter(
              mutatedRequest.body,
              parameter.name,
              payload
            );

        }

        const originalResponse =
          await replay(originalRequest);

        const mutatedResponse =
          await replay(mutatedRequest);

        const comparison =
          comparator.compare(
            originalResponse,
            mutatedResponse
          );

        const detectedFingerprints =
          fingerprints.detect(
            mutatedResponse.body,
            payload
          );

        const assessment =
          scorer.score(
            comparison,
            detectedFingerprints
          );

        evidence.push({

          parameter:
            parameter.name,

          location:
            parameter.location,

          payload,

          comparison,

          fingerprints:
            detectedFingerprints,

          score:
            assessment.score,

          confidence:
            assessment.confidence,

          verdict:
            assessment.verdict,

          reasons:
            assessment.reasons,

          originalBody:
            originalResponse.body,

          mutatedBody:
            mutatedResponse.body

        });

      }

    }

  }

  let highestScore = 0;

  for (const item of evidence) {

    if (item.score > highestScore) {

      highestScore = item.score;

      result.verdict =
        item.verdict;

      result.confidence =
        item.confidence;

      result.reasons =
        item.reasons;

    }

  }
  result.score =
    highestScore;

  result.metadata.summary = {

    parametersTested:
      parameters.length,

    payloadsExecuted:
      evidence.length,

    fingerprintMatches:
      evidence.filter(
        e => e.fingerprints.length
      ).length,

    confirmedFindings:
      evidence.filter(
        e => e.verdict === "confirmed"
      ).length

  };

  result.metadata.statistics = {

    totalEvidence:
      evidence.length,

    confirmed:
      evidence.filter(
        e => e.verdict === "confirmed"
      ).length,

    manualReview:
      evidence.filter(
        e => e.verdict ===
          "needs_manual_review"
      ).length,

    noIssue:
      evidence.filter(
        e => e.verdict ===
          "no_issue"
      ).length

  };

  result.reason =
    evidence.length
      ? "XSS analysis completed."
      : "No XSS evidence collected.";

  return result;

}

module.exports = {
  scan
};
