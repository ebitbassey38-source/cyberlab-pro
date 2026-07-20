const express = require('express');
const router = express.Router();
const axios = require('axios');
const { askClaude } = require('../services/claude');

const DEFAULT_CREDS = [
  { username: 'admin', password: 'admin' },
  { username: 'admin', password: 'password' },
  { username: 'administrator', password: 'administrator' },
  { username: 'test', password: 'test' },
  { username: 'guest', password: 'guest' }
];

router.post('/scan', async (req, res) => {
  const { target, loginPath, credentials } = req.body;

  if (!target) {
    return res.status(400).json({ error: 'Target URL is required' });
  }

  const baseUrl = target.startsWith('http') ? target : 'https://' + target;
  const path = loginPath || '/login';
  const creds = credentials || DEFAULT_CREDS;

  const findings = [];

  for (const cred of creds) {
    try {
      const response = await axios.post(
        baseUrl.replace(/\/$/, '') + path,
        cred,
        {
          timeout: 8000,
          validateStatus: () => true,
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (compatible; CyberLab-Pro/1.0)'
          }
        }
      );

      if (response.status === 200) {
        findings.push({
          username: cred.username,
          password: cred.password,
          severity: 'high',
          issue: 'Possible default or weak credentials accepted'
        });
      }
    } catch (e) {
      // Ignore connection errors and continue testing.
    }
  }

const aiAnalysis = await askClaude(
`You are a senior penetration tester.

Rules:
- Analyze ONLY the authentication scan results provided.
- Never invent, simulate, or assume vulnerabilities.
- Never fabricate severity ratings, exploit scenarios, or bounty payouts.
- If no evidence exists, clearly state that no authentication weaknesses were identified from this scan.
- Recommend only legitimate next manual testing steps.
- Keep the response concise and professional.`,

`Authentication scan results

Target: ${target}

Credential pairs tested: ${creds.length}
Confirmed findings: ${findings.length}

Results:
${findings.length
  ? findings.map(f =>
      `Accepted credentials: ${f.username}/${f.password}`
    ).join('\n')
  : 'No default or weak credentials were accepted.'}

Provide:
1. Summary
2. Confirmed findings only
3. Risk assessment based only on the evidence
4. Recommended next manual testing steps`
);

  res.json({
    target,
    tested: creds.length,
    found: findings.length,
    findings,
    aiAnalysis
  });
});

module.exports = router;
