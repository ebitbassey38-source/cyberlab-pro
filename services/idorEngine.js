const axios = require('axios');
const { createResult } =
  require('./baseEngine');

async function scan(httpRequest) {
  const result = createResult("idor");

  const evidence = result.evidence;

  const ids =
    new URL(httpRequest.url)
      .pathname
      .match(/\d+/g) || [];

  if (ids.length === 0) {
    return {
      tested: false,
      reason: "No numeric object identifier found.",
      evidence
    };
  }

  const originalUrl = httpRequest.url;

  const originalResponse = await axios({
    method: httpRequest.method,
    url: originalUrl,
    headers: httpRequest.headers || {},
    data: httpRequest.body || {},
    validateStatus: () => true,
    timeout: 8000
  });

  for (let newId = 2; newId <= 4; newId++) {

      const mutatedUrl =
        new URL(originalUrl.replace(
          /(\d+)(?!.*\d)/,
          String(newId)
        )).toString();

    const mutatedResponse = await axios({
      method: httpRequest.method,
      url: mutatedUrl,
      headers: httpRequest.headers || {},
      data: httpRequest.body || {},
      validateStatus: () => true,
      timeout: 8000
    });

    evidence.push({
  original: originalUrl,
  mutated: mutatedUrl,

  originalStatus: originalResponse.status,
  mutatedStatus: mutatedResponse.status,

  originalLength: JSON.stringify(originalResponse.data).length,
  mutatedLength: JSON.stringify(mutatedResponse.data).length,

  originalBody: originalResponse.data,
  mutatedBody: mutatedResponse.data,

  sameStatus:
    originalResponse.status === mutatedResponse.status,

  sameLength:
    JSON.stringify(originalResponse.data).length ===
    JSON.stringify(mutatedResponse.data).length,

  bodyChanged:
    JSON.stringify(originalResponse.data) !==
    JSON.stringify(mutatedResponse.data)
});
  }

    const confirmedEvidence = evidence.filter(
    e =>
      !e.sameStatus ||
      !e.sameLength ||
      e.bodyChanged
  );

  result.findings = confirmedEvidence.length
    ? [{
        title: "Possible Insecure Direct Object Reference (IDOR)",
        type: "idor",
        severity: "high",
        description:
          "Changing a numeric object identifier produced a different response, indicating a possible IDOR vulnerability.",
        evidence: confirmedEvidence,
        recommendation:
          "Enforce server-side authorization checks for every object access and verify that the authenticated user is permitted to access the requested resource."
      }]
    : [];

  return {
    ...result,
    tested: true,
    evidence
  };
}

module.exports = {
  scan
};
