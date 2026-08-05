const { replay } = require("./requestReplay");
const { createResult } = require("./baseEngine");

const PAYLOADS =
  require("./pathTraversal/payloads");

const fingerprints =
  require("./pathTraversal/fingerprints");

const comparator =
  require("./pathTraversal/comparator");

const scorer =
  require("./pathTraversal/scorer");

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

function cloneRequest(httpRequest) {

  return {

    ...httpRequest,

    headers: {
      ...(httpRequest.headers || {})
    },

    body:
      httpRequest.body &&
      typeof httpRequest.body === "object"
        ? { ...httpRequest.body }
        : httpRequest.body

  };

}


function injectParameter(request, parameter, payload) {

  const modified = cloneRequest(request);

  if (parameter.location === "query") {

    const url = new URL(modified.url);

    url.searchParams.set(
      parameter.name,
      payload
    );

    modified.url = url.toString();

  }


  if (parameter.location === "body") {

    modified.body = {

      ...(modified.body || {}),

      [parameter.name]: payload

    };

  }


  return modified;

}


function collectFingerprintMatches(responseBody) {

  const matches = [];

  for (const fingerprint of fingerprints) {

    if (
      responseBody &&
      responseBody.includes(fingerprint)
    ) {

      matches.push(fingerprint);

    }

  }

  return matches;

}
/*
|--------------------------------------------------------------------------
| Scan Engine
|--------------------------------------------------------------------------
*/

async function scanPathTraversal(httpRequest) {

  const parameters = discoverParameters(httpRequest);

  const findings = [];

  let tested = 0;


  for (const parameter of parameters) {

    for (const payload of PAYLOADS) {

      tested++;

      const modifiedRequest =
        injectParameter(
          httpRequest,
          parameter,
          payload
        );


      let response;

      try {

        response = await replay(modifiedRequest);

      } catch (_) {

        continue;

      }


      const body =
        response.body ||
        "";


      const matches =
        collectFingerprintMatches(body);


      const comparison =
        comparator.compare(
          httpRequest,
          response
        );


      const score =
        scorer.score({

          matches,
          comparison

        });


      if (score > 0) {

        findings.push({

          parameter,
          payload,

          evidence: {

            fingerprints: matches,

            status:
              response.status,

            score

          }

        });

      }

    }

  }


  return createResult({

    vulnerability:
      "Path Traversal",

    tested,

    findings,

    summary: {

      parameters:
        parameters.length,

      payloads:
        PAYLOADS.length,

      findings:
        findings.length

    },

    statistics: {

      requests:
        tested,

      confirmed:
        findings.length

    }

  });

}
/*
|--------------------------------------------------------------------------
| Export
|--------------------------------------------------------------------------
*/

module.exports = {

  scan: scanPathTraversal,

  scanPathTraversal,

  discoverParameters

};
