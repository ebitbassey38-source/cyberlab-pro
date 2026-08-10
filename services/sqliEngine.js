const { replay } = require("./requestReplay");
const { createResult } = require("./baseEngine");
const PAYLOADS =
  require("./sqli/payloads");
const fingerprints =
  require("./sqli/fingerprints");

const comparator =
  require("./sqli/comparator");

const scorer =
  require("./sqli/scorer");
const {
  discoverParameters,
  cloneRequest,
  injectParameter
} = require("./common/requestHelpers");

/*
|--------------------------------------------------------------------------
| SQL Injection Payload Library
|--------------------------------------------------------------------------
*/



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


/*
|--------------------------------------------------------------------------
| SQL Injection Scan Engine
|--------------------------------------------------------------------------
*/

async function scan(httpRequest) {

  const result = createResult("sqli");

  const evidence = result.evidence;

  const parameters = discoverParameters(httpRequest);

  result.metadata.parameters = parameters;

  if (!parameters.length) {

    result.reason = "No injectable parameters found.";

    return result;

  }

  result.tested = true;

  for (const parameter of parameters) {

    for (const category of Object.values(PAYLOADS)) {

      for (const payload of category) {

        const originalRequest =
          cloneRequest(httpRequest);

        const mutatedRequest =
          injectParameter(
            httpRequest,
            parameter,
            payload
          );

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

result.reason =
  evidence.length
    ? "SQL Injection analysis completed."
    : "No SQL Injection evidence collected.";
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
result.findings = evidence
  .filter(e => e.verdict === "confirmed")
  .map(e => ({
    type: "SQL Injection",
    severity: "High",
    confidence: e.confidence,
    parameter: e.parameter,
    location: e.location,
    payload: e.payload,
    score: e.score,
    fingerprints: e.fingerprints,
    reasons: e.reasons
  }));

return result;

}

module.exports = {
  scan
};
