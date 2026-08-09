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

  /*
   * A fingerprint by itself is not enough to confirm SQLi.
   * Require an HTTP status change as corroborating evidence.
   */
  const strongErrorEvidence =
    fingerprints.length > 0 &&
    !comparison.sameStatus;

  if (strongErrorEvidence && score >= 70) {
    verdict = "confirmed";
  }
  else if (fingerprints.length || score >= 40) {
    verdict = "needs_manual_review";
  }

  return {
    score,

    confidence:
      verdict === "confirmed"
        ? "high"
        : verdict === "needs_manual_review"
        ? "medium"
        : "low",

    verdict,

    reasons
  };
}

module.exports = {
  score
};
