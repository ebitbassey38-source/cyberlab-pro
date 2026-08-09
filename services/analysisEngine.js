const idorEngine = require('./idorEngine');
const authorizationEngine = require('./authorizationEngine');
const analyzeEndpoints = async (apiRecon, requests) => {
  const results = [];

  for (const endpoint of apiRecon.endpoints) {
    const analysis = {
      endpoint,
      modules: {
        idor: {
          candidate: false,
          evidence: null
        },
        auth: {
          candidate: false,
          evidence: null
        },
        sqli: {
          candidate: false,
          evidence: null
        },
        xss: {
          candidate: false,
          evidence: null
        }
      }
    };

    // Simple heuristics (placeholder for real scanners)

    if (endpoint.url.match(/\/\d+($|\/)/)) {
      analysis.modules.idor.candidate = true;
      analysis.modules.idor.evidence =
        "Endpoint contains a numeric object identifier.";
    }

    if (
  endpoint.authentication &&
  endpoint.authentication !== "none"
) {
  analysis.modules.auth.candidate = true;
  analysis.modules.auth.evidence =
    "Authenticated endpoint detected.";
}

    if (
      endpoint.url.includes("?") ||
      endpoint.method === "POST" ||
      endpoint.method === "PUT"
    ) {
      analysis.modules.sqli.candidate = true;
      analysis.modules.sqli.evidence =
        "Endpoint accepts user-controlled input.";
    }

    if (
  endpoint.url.includes("?") ||
  endpoint.method === "POST" ||
  endpoint.method === "PUT"
) {
  analysis.modules.xss.candidate = true;
  analysis.modules.xss.evidence =
    "Endpoint may reflect user input.";
}
const request = requests.find(
  r =>
    r.url === endpoint.url &&
    r.method === endpoint.method
);

if (request) {

}
    results.push(analysis);
  }

  return results;
};

module.exports = {
  analyzeEndpoints
};
