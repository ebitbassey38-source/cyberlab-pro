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
  },
  cmdi: {
    title: "Possible Command Injection",
    type: "cmdi",
    severity: "critical",
    description:
      "Replay analysis detected behavior consistent with operating-system command injection.",
    recommendation:
      "Avoid shell execution with user-controlled input and use strict allowlists and safe process APIs.",
    scanVerdict: "confirmed"
  },

  csrf: {
    title: "Possible Cross-Site Request Forgery (CSRF)",
    type: "csrf",
    severity: "high",
    description:
      "Replay analysis detected a request that may be executable without adequate CSRF protection.",
    recommendation:
      "Use CSRF tokens, SameSite cookies, origin validation, and appropriate request authentication.",
    scanVerdict: "confirmed"
  },

  ssrf: {
    title: "Possible Server-Side Request Forgery (SSRF)",
    type: "ssrf",
    severity: "high",
    description:
      "Replay analysis detected behavior consistent with server-side request forgery.",
    recommendation:
      "Restrict outbound destinations, validate URLs against an allowlist, and block access to internal and metadata networks.",
    scanVerdict: "confirmed"
  },

  path_traversal: {
    title: "Possible Path Traversal",
    type: "path_traversal",
    severity: "high",
    description:
      "Replay analysis detected behavior consistent with path traversal.",
    recommendation:
      "Canonicalize paths, restrict file access to approved directories, and reject traversal sequences.",
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

      const confirmed =
        (result.scanResult.evidence || [])
          .filter(
            e => e.verdict === config.scanVerdict
          ).length;

      if (!confirmed) {
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
  JSON.stringify({
    replayEvidence: result.scanResult.evidence,
    authorization: result.authorization
  }),

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
