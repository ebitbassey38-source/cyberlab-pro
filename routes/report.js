const express = require('express');
const router = express.Router();
const { askClaude } = require('../services/claude');

router.post('/generate', async (req, res) => {
  const { target, findings, scanType } = req.body;
  if (!target || !findings || findings.length === 0) {
    return res.status(400).json({ error: 'Target and findings are required' });
  }

  const confirmedFindings = findings.filter(f =>
    ['critical', 'high', 'medium', 'low'].includes(String(f.severity).toLowerCase()) &&
    !String(f.type).toLowerCase().includes('manual review') &&
    !String(f.type).toLowerCase().includes('test points') &&
    !String(f.type).toLowerCase().includes('recommendation')
  );

  if (confirmedFindings.length === 0) {
    return res.status(200).json({
      target,
      report: 'No confirmed vulnerability is present in the supplied scan findings. A HackerOne report should not be generated from manual-review recommendations or informational test points.',
      topFinding: null
    });
  }

  const topFinding = confirmedFindings.sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return (order[String(a.severity).toLowerCase()] || 4) -
           (order[String(b.severity).toLowerCase()] || 4);
  })[0];

  // Deterministic handling for missing HTTP security headers.
  // These findings establish header absence only; they do not establish exploitability.
  if (
    String(topFinding.type).startsWith('Missing ') &&
    String(topFinding.vector).toLowerCase() === 'http header'
  ) {
    const header = String(topFinding.type).replace(/^Missing\s+/i, '');

    const report = `## Title
Missing ${header} HTTP Header

## Severity
${String(topFinding.severity).toUpperCase()}

## Summary
The scan observed that the ${header} HTTP response header is missing from the supplied target response. The supplied evidence establishes header absence only. No exploitation of the associated security issue was confirmed by this scan.

## Steps to Reproduce
1. Request the supplied target.
2. Inspect the HTTP response headers.
3. Observe that the ${header} header is not present.

## Proof of Concept
No confirmed exploitation PoC is available from the supplied scan evidence.

## Impact
The supplied evidence establishes only that the ${header} HTTP header is missing. No specific security impact or exploitability was confirmed by this scan.

## Recommended Fix
Review the server configuration and add an appropriate ${header} policy if required by the application's security requirements.

## References
CyberLab Pro scan finding: ${topFinding.type}
`;

    return res.json({ target, report, topFinding });
  }

  const report = await askClaude(
  `You are a defensive security report writer.

STRICT EVIDENCE RULES:
- Use ONLY evidence explicitly contained in the supplied scan data.
- Never invent filenames, functions, parameters, payloads, URLs, endpoints, request data, browser behavior, or proof-of-concept results.
- Never use example.com unless it is literally the supplied target.
- Never claim a vulnerability is confirmed unless the supplied finding contains confirmation evidence.
- If the evidence is insufficient, state that clearly.
- Do not manufacture reproduction steps.
- Do not manufacture a PoC.
- Keep the severity exactly as supplied by the scanner.
- Distinguish confirmed findings from recommendations.
- A finding named "Reflected Input" means input reflection only, NOT XSS.
- Never rename "Reflected Input" to "Reflected XSS".
- Never describe script execution unless the supplied finding explicitly says script execution was confirmed.
- If execution is not confirmed, describe the issue only as reflected input and state that XSS remains unconfirmed.
- Do not infer exploitability from severity alone.
- A missing security header is evidence of a missing header only.
- Never claim the associated attack is exploitable unless the scan explicitly confirmed it.
- Never generate a PoC, screenshot URL, iframe test, or attack result that was not supplied in the findings.
- For missing X-Frame-Options, describe the observation as a missing clickjacking-protection header unless actual framing was confirmed.
- For missing Referrer-Policy, do not claim sensitive URL leakage unless leakage was actually observed.
- For missing Permissions-Policy, do not claim browser features are exploitable unless that was actually demonstrated.
- For server header disclosure, report only the disclosed server value; do not infer a vulnerability from the software name alone.
- If a finding type starts with "Missing " and its vector is "HTTP Header", classify it as a missing-header observation, not a confirmed vulnerability, unless the supplied finding explicitly contains evidence of exploitation.
- For missing X-Frame-Options, do not write "vulnerable to clickjacking", "allows an attacker", or iframe reproduction steps unless the supplied finding explicitly confirms successful framing.
- For missing Referrer-Policy, do not claim URL leakage unless the supplied finding explicitly confirms leakage.
- For missing Permissions-Policy, do not claim that camera, microphone, geolocation, or other browser features are exploitable.
- For unconfirmed findings, the Impact section must state only what the supplied evidence establishes.
- If script execution or exploitation was not confirmed, say that no specific security impact can be established from the supplied evidence.
- Do not use speculative phrases such as "if exploited", "could allow", or "may lead to" unless that possibility is explicitly supported by the supplied evidence.

The report must accurately represent what CyberLab Pro actually observed.`,
  `Target: ${target}

Scan type: ${scanType || 'unknown'}

TOP FINDING:
${JSON.stringify(topFinding, null, 2)}

ALL SCAN FINDINGS:
${JSON.stringify(findings, null, 2)}

Write a HackerOne-style report using exactly these sections:

## Title
## Severity
## Summary
## Steps to Reproduce
## Proof of Concept
## Impact
## Recommended Fix
## References

If the supplied evidence does not establish exploitability:
- Say so explicitly in Summary.
- In Steps to Reproduce, describe only the testing that was actually performed.
- In Proof of Concept, say that no confirmed PoC is available from the supplied evidence.
- Do not fill missing evidence with guesses.

The final report must contain no facts that are absent from the supplied scan findings.`
);

  res.json({ target, report, topFinding });
});

module.exports = router;
