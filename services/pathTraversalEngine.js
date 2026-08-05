const { replay } = require("./requestReplay");
const { createResult } = require("./baseEngine");

const PAYLOADS =
  Object.values(
    require("./pathTraversal/payloads")
  ).flat();

const fingerprints =
  require("./pathTraversal/fingerprints");

const comparator =
  require("./pathTraversal/comparator");

const scorer =
  require("./pathTraversal/scorer");
const {
  discoverParameters,
  cloneRequest,
  injectParameter
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


/*
|--------------------------------------------------------------------------
| Scan Engine
|--------------------------------------------------------------------------
*/

async function scanPathTraversal(httpRequest) {

  const result =
    createResult("path_traversal");

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

    for (const payload of PAYLOADS) {

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
  result.metadata.statistics = {

    tested:
      evidence.length,

    confirmed:
      evidence.filter(
        finding =>
          finding.verdict === "confirmed"
      ).length,

    review:
      evidence.filter(
        finding =>
          finding.verdict === "needs_manual_review"
      ).length

  };

  if (!evidence.length) {

    result.reason =
      "No findings generated.";

  }

  return result;

}

module.exports = {

  scan:
    scanPathTraversal

};
