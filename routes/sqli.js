const express = require('express');
const router = express.Router();
const axios = require('axios');
const { askClaude } = require('../services/claude');

const PAYLOADS = [
  "1'", "1''", "1`", "1``",
  "1' OR '1'='1", "1' OR '1'='1'--",
  "1' OR 1=1--", "1 OR 1=1",
  "1' AND '1'='2", "1' AND 1=2--",
  "1; DROP TABLE users--",
  "1' UNION SELECT NULL--",
  "1' UNION SELECT NULL,NULL--",
  "1' UNION SELECT NULL,NULL,NULL--",
  "1 WAITFOR DELAY '0:0:5'--",
  "1' AND SLEEP(5)--",
  "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
];

const ERROR_PATTERNS = [
  'mysql_fetch', 'mysql_num_rows', 'mysql_query',
  'mysqli_fetch', 'pg_query', 'sqlite_query',
  'ORA-01756', 'ORA-00907', 'Microsoft OLE DB',
  'ODBC SQL Server', 'SQLite3::', 'PDOException',
  'syntax error', 'mysql error', 'sql syntax',
  'unclosed quotation', 'quoted string not properly',
  'Warning: mysql', 'Warning: pg_', 'Warning: sqlite',
  'You have an error in your SQL syntax',
  'supplied argument is not a valid MySQL',
];

async function testParameter(baseUrl, param, payload) {
  try {
    const url = `${baseUrl}?${param}=${encodeURIComponent(payload)}`;
    const start = Date.now();
    const res = await axios.get(url, {
      timeout: 8000,
      validateStatus: () => true,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; CyberLab-Pro/1.0)' }
    });
    const elapsed = Date.now() - start;
    const body = (res.data || '').toString().toLowerCase();

    const errorFound = ERROR_PATTERNS.some(p => body.includes(p.toLowerCase()));
    const timeBased = elapsed > 4500 && payload.includes('SLEEP');

    if (errorFound) {
      return { param, payload, type: 'Error-Based SQLi', severity: 'high', elapsed, url };
    }
    if (timeBased) {
      return { param, payload, type: 'Time-Based Blind SQLi', severity: 'high', elapsed, url };
    }
    return null;
  } catch (e) {
    return null;
  }
}

router.post('/scan', async (req, res) => {
  const { target, params } = req.body;
  if (!target) return res.status(400).json({ error: 'Target URL is required' });

  const baseUrl = target.startsWith('http') ? target : 'https://' + target;
  const testParams = params || ['id', 'user', 'page', 'search', 'q', 'cat', 'item', 'product', 'order', 'ref'];

  const findings = [];

  for (const param of testParams) {
    for (const payload of PAYLOADS.slice(0, 8)) {
      const result = await testParameter(baseUrl, param, payload);
      if (result) { findings.push(result); break; }
    }
  }

const aiAnalysis = await askClaude(
`You are a senior penetration tester.

   Rules:
- Analyze ONLY the SQL Injection scan results provided.
- Report ONLY confirmed SQL injection findings supported by evidence.
- Never invent database access, extracted data, authentication bypass, or impact.
- Never claim SQL injection exploitation unless the scan confirmed it.
- Never fabricate severity ratings, CVSS scores, exploit scenarios, or bounty impact.
- Do not report generic database errors as SQL injection without evidence.
- If no evidence exists, clearly state that no SQL injection vulnerabilities were identified from this scan.
- Recommend only legitimate next manual testing steps.
- Keep the response concise and professional.`,

`SQL injection scan results

Target: ${target}

Parameters tested: ${testParams.join(', ')}
Parameters tested count: ${testParams.length}
Confirmed findings: ${findings.length}

Results:
${findings.length
  ? findings.map(f =>
      `[${f.type}] Parameter: ${f.param} | Payload: ${f.payload}`
    ).join('\n')
  : 'No SQL injection vulnerabilities were identified.'}

Provide:
1. Summary
2. Confirmed findings only
3. Risk assessment based only on the evidence
4. Recommended next manual testing steps`
);
  res.json({ target, paramsTestedCount: testParams.length, found: findings.length, findings, aiAnalysis });
});

module.exports = router;
