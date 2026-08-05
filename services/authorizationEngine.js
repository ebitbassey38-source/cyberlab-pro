const AuthorizationContext =
  require('../models/AuthorizationContext');
async function verify(scanResult, scanJobId) {
  const evidence = scanResult.evidence || [];
const contexts =
  await AuthorizationContext.find({
    scanJob: scanJobId
  });
  if (!evidence.length) {
    return {
  verdict: "no_issue",
  confidence: "high",
  score: 0,
  reasons: [
    "No replay evidence available."
  ]
};
  }

  const suspicious = evidence.some(e => {
  return (
    e.sameStatus &&
    e.bodyChanged &&
    !e.sameLength
  );
});

  if (!suspicious) {
    return {
  verdict: "no_issue",
  confidence: "high",
  score: 0,
  reasons: [
    "No authorization differences detected."
  ]
};
  }

  return {
  verdict: "needs_manual_review",
  confidence: "medium",
  score: 45,
  reasons: [
    "Response body changed.",
    "HTTP status remained successful.",
    "Ownership could not be verified automatically."
  ]
};
}

module.exports = {
  verify
};
