/*
|--------------------------------------------------------------------------
| SQLi Confidence Scorer
|--------------------------------------------------------------------------
*/

function score(comparison, fingerprints) {

  let score = 0;

  const reasons = [];

  if (!comparison.sameStatus) {
    score += 20;
    reasons.push("HTTP status changed");
  }

  if (comparison.bodyChanged) {
    score += 25;
    reasons.push("Response body changed");
  }

  if (!comparison.sameLength) {
    score += 15;
    reasons.push("Response length changed");
  }

  if (comparison.headerChanged) {
    score += 10;
    reasons.push("Response headers changed");
  }

  if (fingerprints.length) {

    score += 40;

    reasons.push(
      "SQL error fingerprint detected"
    );

  }

  let verdict = "no_issue";

  if (score >= 70) {
    verdict = "confirmed";
  }
  else if (score >= 40) {
    verdict = "needs_manual_review";
  }

  return {

    score,

    confidence:
      score >= 70
        ? "high"
        : score >= 40
        ? "medium"
        : "low",

    verdict,

    reasons

  };

}

module.exports = {
  score
};
