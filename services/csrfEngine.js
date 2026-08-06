const { replay } = require("./requestReplay");
const { createResult } = require("./baseEngine");

const PAYLOADS =
  require("./csrf/payloads");

const fingerprints =
  require("./csrf/fingerprints");

const comparator =
  require("./csrf/comparator");

const scorer =
  require("./csrf/scorer");
const {
  discoverParameters,
  cloneRequest
} = require("./common/requestHelpers");
/*
|--------------------------------------------------------------------------
| Parameter Discovery
|--------------------------------------------------------------------------
*/

/*
|--------------------------------------------------------------------------
| Helpers
|--------------------------------------------------------------------------
*/

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
| CSRF Scan Engine
|--------------------------------------------------------------------------
*/

async function scan(httpRequest) {

  const result =
    createResult("csrf");

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

    for (const method of PAYLOADS.methods) {

      for (const headerSet of PAYLOADS.headers) {

        const originalRequest =
          cloneRequest(httpRequest);

        const mutatedRequest =
          cloneRequest(httpRequest);
        mutatedRequest.method =
          method;

        mutatedRequest.headers = {

          ...(mutatedRequest.headers || {}),

          ...headerSet

        };

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
            mutatedResponse.headers,
            mutatedResponse.body
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

          method,

          headers:
            headerSet,

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

    protectionDetected:
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
      ? "CSRF analysis completed."
      : "No CSRF evidence collected.";

  return result;

}

module.exports = {
  scan
};
