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
  } catch {
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

Analyze ONLY the scan results provided.
Never invent vulnerabilities.
If no confirmed XSS exists, clearly say none were found.
Keep the response concise.`,
`Target: ${target}

Parameters tested: ${testParams.join(', ')}
Confirmed findings: ${findings.length}

${findings.length
? findings.map(f => `[${f.type}] ${f.param} -> ${f.payload}`).join('\n')
: 'No confirmed XSS vulnerabilities identified.'}`
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
