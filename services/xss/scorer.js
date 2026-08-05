/*
|--------------------------------------------------------------------------
| XSS Confidence Scorer
|--------------------------------------------------------------------------
*/

function score(comparison, fingerprints) {

  let score = 0;

  const reasons = [];

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

    score +=
      fingerprints.length * 20;

    reasons.push(
      "XSS fingerprints detected."
    );

  }

  let verdict = "no_issue";

  if (score >= 70) {

    verdict = "confirmed";

  } else if (score >= 40) {

    verdict =
      "needs_manual_review";

  }

  return {

    score,

    confidence:
      Math.min(score, 100),

    verdict,

    reasons

  };

}

module.exports = {
  score
};
