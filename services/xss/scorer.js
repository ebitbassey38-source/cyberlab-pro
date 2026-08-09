/*
|--------------------------------------------------------------------------
| XSS Confidence Scorer
|--------------------------------------------------------------------------
*/

function score(comparison, fingerprints) {
  let score = 0;
  const reasons = [];

  const sqlErrorReflection =
    fingerprints.some(
      f =>
        f.type === "payload_reflected" &&
        comparison.isHtmlResponse &&
        comparison.statusChanged
    );

  /*
  |--------------------------------------------------------------------------
  | Reject likely SQL-error reflections
  |--------------------------------------------------------------------------
  */

  if (sqlErrorReflection) {
    return {
      score: 0,
      confidence: 0,
      verdict: "no_issue",
      reasons: [
        "Payload reflection occurred in an error response; not sufficient evidence of executable XSS."
      ]
    };
  }

  /*
  |--------------------------------------------------------------------------
  | XSS requires an HTML response
  |--------------------------------------------------------------------------
  */

  if (!comparison.isHtmlResponse) {
    return {
      score: 0,
      confidence: 0,
      verdict: "no_issue",
      reasons: [
        "Response is not HTML; reflected input is not sufficient evidence of XSS."
      ]
    };
  }

  if (comparison.bodyChanged) {
    score += 20;
    reasons.push(
      "Response body changed."
    );
  }

  if (!comparison.sameStatus) {
    score += 10;
    reasons.push(
      "HTTP status changed."
    );
  }

  if (fingerprints.length) {
    score += fingerprints.length * 20;
    reasons.push(
      "XSS fingerprints detected."
    );
  }

  let verdict = "no_issue";

  if (score >= 70) {
    verdict = "confirmed";
  } else if (score >= 40) {
    verdict = "needs_manual_review";
  }

  return {
    score,
    confidence: Math.min(score, 100),
    verdict,
    reasons
  };
}

module.exports = {
  score
};
