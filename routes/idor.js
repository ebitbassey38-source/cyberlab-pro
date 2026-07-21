const express = require('express');
const router = express.Router();
const axios = require('axios');
const { askClaude } = require('../services/claude');

router.post('/scan', async (req, res) => {
  const { target, parameter } = req.body;

  if (!target) {
    return res.status(400).json({ error: 'Target URL is required' });
  }

  const baseUrl = target.startsWith('http') ? target : 'https://' + target;
  const param = parameter || 'id';

  const findings = [];

  try {
    const first = await axios.get(`${baseUrl}?${param}=1`, {
      timeout: 8000,
      validateStatus: () => true
    });

    const second = await axios.get(`${baseUrl}?${param}=2`, {
      timeout: 8000,
      validateStatus: () => true
    });

    if (
      first.status === 200 &&
      second.status === 200 &&
      first.data !== second.data
    ) {
      findings.push({
        parameter: param,
        severity: 'medium',
        issue: 'Possible IDOR detected. Different object IDs returned different accessible resources.'
      });
    }
  } catch (e) {
    // Ignore request errors.
  }

const aiAnalysis = await askClaude(
`You are a senior penetration tester.

  Rules:
- Analyze ONLY the IDOR scan results provided.
- Report ONLY confirmed authorization issues supported by evidence.
- Never invent unauthorized access, account takeover, or sensitive data exposure.
- Never claim IDOR exploitation unless the scan confirmed an access control failure.
- Never fabricate severity ratings, CVSS scores, exploit scenarios, or bounty impact.
- Different responses alone do not prove IDOR; require evidence of unauthorized object access.
- If no evidence exists, clearly state that no IDOR vulnerabilities were identified from this scan.
- Recommend only legitimate next manual testing steps.
- Keep the response concise and professional.`,


`IDOR scan results

Target: ${target}

Confirmed findings: ${findings.length}

Results:
${findings.length
  ? findings.map(f => f.issue).join('\n')
  : 'No IDOR vulnerabilities were identified.'}

Provide:
1. Summary
2. Confirmed findings only
3. Risk assessment based only on the evidence
4. Recommended next manual testing steps`
);


  res.json({
    target,
    found: findings.length,
    findings,
    aiAnalysis
  });
});

module.exports = router;
