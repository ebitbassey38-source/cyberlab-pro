const Finding = require("../models/Finding");

const FINDING_CONFIG = {
  idor: {
    title: "Possible Insecure Direct Object Reference (IDOR)",
    type: "idor",
    severity: "medium",
    description:
      "Automated replay testing detected authorization differences requiring analyst review.",
    recommendation:
      "Verify object ownership and enforce object-level authorization.",
    authorizationVerdict: "needs_manual_review"
  },

  sqli: {
    title: "Possible SQL Injection",
    type: "sqli",
    severity: "high",
    description:
      "Replay analysis and SQL injection fingerprint detection identified a possible SQL Injection vulnerability.",
    recommendation:
      "Use parameterized queries, prepared statements, and validate all user input.",
    scanVerdict: "confirmed"
  },

  xss: {
    title: "Possible Cross-Site Scripting (XSS)",
    type: "xss",
    severity: "high",
    description:
      "Replay analysis detected possible reflected Cross-Site Scripting.",
    recommendation:
      "Properly encode output, sanitize input, and enforce a Content Security Policy.",
    scanVerdict: "confirmed"
  }
};

async function saveConfirmedFindings(scanResult) {

  const created = [];

  const {
    asset,
    dynamicResults
  } = scanResult;

  for (const result of dynamicResults) {

    const config =
      FINDING_CONFIG[result.module];

    if (!config) {
      continue;
    }

    if (config.authorizationVerdict) {

      if (
        result.authorization.verdict !==
        config.authorizationVerdict
      ) {
        continue;
      }

    } else {

      if (
        result.scanResult.verdict !==
        config.scanVerdict
      ) {
        continue;
      }

    }

    const finding =
      await Finding.create({

        title: config.title,

        type: config.type,

        severity: config.severity,

        description:
          config.description,

        evidence:
          JSON.stringify(
            result.scanResult.evidence
          ),

        recommendation:
          config.recommendation,

        asset: asset._id,
        project: asset.project,
        owner: asset.owner

      });

    created.push(finding);

  }

  return created;

}

module.exports = {
  saveConfirmedFindings
};
