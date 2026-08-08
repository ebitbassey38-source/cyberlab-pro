const AuthorizationContext =
  require('../models/AuthorizationContext');
async function verify(scanResult, scanJobId, httpRequestId) {
  const evidence = scanResult.evidence || [];
const contexts = await AuthorizationContext.find({
  scanJob: scanJobId
}).lean();

const contextByRequest = new Map(
  contexts.map(context => [
    context.httpRequest.toString(),
    context
  ])
);

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

  const context = contextByRequest.get(httpRequestId.toString());

if (!context) {
  return {
    verdict: "needs_manual_review",
    confidence: "low",
    score: 20,
    reasons: [
      "No authorization context found for this HTTP request."
    ]
  };
}

const suspicious = evidence.some(e => {
  const expectedOwner = e.originalBody?.owner;
  const mutatedOwner = e.mutatedBody?.owner;

  return (
    e.sameStatus &&
    e.bodyChanged &&
    expectedOwner &&
    mutatedOwner &&
    mutatedOwner !== expectedOwner
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
    "Mutated object owner differs from the expected owner.",
    "Object-level authorization requires analyst confirmation."
  ]
};
}

module.exports = {
  verify
};
