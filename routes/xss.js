const express = require('express');
const router = express.Router();
const axios = require('axios');
const { askClaude } = require('../services/claude');

const PAYLOADS = [
  '<script>alert(1)</script>',
  '"><script>alert(1)</script>',
  "'><script>alert(1)</script>",
  '<img src=x onerror=alert(1)>',
  '<svg/onload=alert(1)>',
  '<body onload=alert(1)>',
  '<iframe src="javascript:alert(1)"></iframe>',
  '<details open ontoggle=alert(1)>'
];

async function testParameter(baseUrl, param, payload) {
  try {
    const url = `${baseUrl}?${param}=${encodeURIComponent(payload)}`;

    const res = await axios.get(url, {
      timeout: 8000,
      validateStatus: () => true,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; CyberLab-Pro/1.0)'
      }
    });

    const body = (res.data || '').toString();

    if (body.includes(payload)) {
      return {
        param,
        payload,
        type: 'Reflected XSS',
        severity: 'high',
        url
      };
    }

    return null;
  } catch (e) {
    return null;
  }
}

router.post('/scan', async (req, res) => {
  const { target, params } = req.body;

  if (!target) {
    return res.status(400).json({
      error: 'Target URL is required'
    });
  }

  const baseUrl = target.startsWith('http')
    ? target
    : 'https://' + target;

  const testParams = params || [
    'q',
    'search',
    'query',
    'id',
    'page',
    'name',
    'keyword',
    'term'
  ];

  const findings = [];

  for (const param of testParams) {
    for (const payload of PAYLOADS) {
      const result = await testParameter(baseUrl, param, payload);

      if (result) {
        findings.push(result);
        break;
      }
    }
  }

const aiAnalysis = await askClaude(
`You are a senior penetration tester.

Rules:
- Analyze ONLY the Cross-Site Scripting (XSS) scan results provided.
- Report ONLY confirmed XSS findings supported by evidence.
- Never invent, simulate, or assume vulnerabilities.
- Never claim XSS exploitation unless the scan confirmed payload execution.
- Never fabricate severity ratings, exploit scenarios, CVSS scores, or bounty impact.
- Missing security headers (CSP, X-Frame-Options, HSTS, etc.) must not be reported as confirmed XSS vulnerabilities.
- If no evidence exists, clearly state that no XSS vulnerabilities were identified from this scan.
- Recommend only legitimate next manual testing steps.
- Keep the response concise and professional.`,

`Cross-Site Scripting (XSS) scan results

Target: ${target}

);

Parameters tested: ${testParams.join(', ')}
Parameters tested count: ${testParams.length}
Confirmed findings: ${findings.length}

Results:
${findings.length
  ? findings.map(f =>
      `[${f.type}] Parameter: ${f.param} | Payload: ${f.payload}`
    ).join('\n')
  : 'No Cross-Site Scripting vulnerabilities were identified.'}

Provide:
1. Summary
2. Confirmed findings only
3. Risk assessment based only on the evidence
4. Recommended next manual testing steps`
);

  res.json({
    target,
    tested: testParams.length,
    found: findings.length,
    findings,
    aiAnalysis
  });
});

module.exports = router;
