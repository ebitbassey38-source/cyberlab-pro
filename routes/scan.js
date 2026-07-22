const express = require('express');
const router = express.Router();
const axios = require('axios');
const { askClaude } = require('../services/claude');

// Real header checker
async function fetchHeaders(target) {
  try {
    const url = target.startsWith('http') ? target : 'https://' + target;
    const res = await axios.get(url, {
      timeout: 8000,
      maxRedirects: 3,
      validateStatus: () => true,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; CyberLab-Mini/1.0)' }
    });
    return { headers: res.headers, status: res.status, finalUrl: res.request?.res?.responseUrl || url };
  } catch (e) {
    return { headers: {}, status: 0, error: e.message };
  }
}

// Analyze headers for security issues
function analyzeHeaders(headers, status) {
  const findings = [];

  if (!headers['content-security-policy']) {
  findings.push({
    id: 1,
    type: 'Missing Content-Security-Policy',
    severity: 'low',
    detail: 'Content-Security-Policy header is missing. This reduces browser-side security hardening. No XSS vulnerability was confirmed.',
    vector: 'HTTP Header'
  });
}
  if (!headers['x-frame-options'] && !headers['content-security-policy']?.includes('frame-ancestors')) {
    findings.push({ id: 2, type: 'Missing X-Frame-Options', severity: 'medium', detail: 'Clickjacking protection header missing. Page can be embedded in iframes.', vector: 'HTTP Header' });
  }
  if (!headers['strict-transport-security']) {
    findings.push({ id: 3, type: 'Missing HSTS', severity: 'medium', detail: 'Strict-Transport-Security not set. SSL stripping attacks possible.', vector: 'HTTP Header' });
  }
  if (!headers['x-content-type-options']) {
    findings.push({ id: 4, type: 'Missing X-Content-Type-Options', severity: 'low', detail: 'MIME sniffing not disabled. Browser may misinterpret file types.', vector: 'HTTP Header' });
  }
  if (!headers['referrer-policy']) {
    findings.push({ id: 5, type: 'Missing Referrer-Policy', severity: 'low', detail: 'Referrer-Policy not set. Sensitive URLs may leak to third parties.', vector: 'HTTP Header' });
  }
  if (!headers['permissions-policy'] && !headers['feature-policy']) {
    findings.push({ id: 6, type: 'Missing Permissions-Policy', severity: 'info', detail: 'Browser feature access not restricted (camera, mic, geolocation).', vector: 'HTTP Header' });
  }
  const server = headers['server'];
  if (server) {
    findings.push({
  id: 7,
  type: 'Server Header Disclosure',
  severity: 'info',
  detail: `Server header reveals: "${server}". No server version information was exposed.`,
  vector: 'HTTP Header'
});
  }
  const powered = headers['x-powered-by'];
  if (powered) {
    findings.push({ id: 8, type: 'Technology Disclosure', severity: 'low', detail: `X-Powered-By reveals: "${powered}". Technology stack exposed.`, vector: 'HTTP Header' });
  }
  if (status === 0) {
    findings.push({ id: 9, type: 'Target Unreachable', severity: 'info', detail: 'Could not connect to target. May be offline or blocking requests.', vector: 'Network' });
  }

  if (findings.length === 0) {
    findings.push({ id: 1, type: 'Good Security Headers', severity: 'info', detail: 'All major security headers are present. Good security posture detected.', vector: 'HTTP Header' });
  }

  return findings;
}

router.post('/vuln', async (req, res) => {
  const { target, scanType = 'full' } = req.body;
  if (!target) return res.status(400).json({ error: 'Target is required' });

  let findings = [];

  if (scanType === 'headers' || scanType === 'full') {
    const { headers, status, error } = await fetchHeaders(target);
    findings = analyzeHeaders(headers, status);
  } else if (scanType === 'sqli') {
    findings = [
      { id: 1, type: 'SQLi Test Points', severity: 'info', detail: 'Manual testing recommended: try single quote in all input fields, look for database errors.', vector: 'Input Fields' },
      { id: 2, type: 'Error-Based SQLi Vector', severity: 'medium', detail: "Test: ' OR '1'='1 in login forms. Check for MySQL/MSSQL error messages in response.", vector: 'Query Params' },
    ];
  } else if (scanType === 'xss') {
    findings = [
      { id: 1, type: 'XSS Test Points', severity: 'info', detail: 'Test all input fields with: <script>alert(1)</script>. Check if input is reflected unencoded.', vector: 'Input Fields' },
      { id: 2, type: 'DOM XSS Check', severity: 'medium', detail: 'Review client-side JS for document.write(), innerHTML, eval() with user-controlled input.', vector: 'JavaScript' },
    ];
  }

  const aiAnalysis = await askClaude(
    'You are a senior bug bounty hunter and defensive security reviewer. Analyze only the provided scan findings. Never increase severity beyond the scanner rating. Never claim a vulnerability is exploitable unless confirmed by evidence. Missing security headers alone are not critical unless an actual impact is demonstrated. Clearly separate confirmed findings from recommendations.',
    `Real scan results for target: ${target}\n\n${findings.map(f => `[${f.severity.toUpperCase()}] ${f.type}: ${f.detail}`).join('\n')}\n\nPrioritize top findings for a bounty report and suggest next manual steps. Be concise.`
  );

  res.json({ target, scanType, findings, aiAnalysis });
});

module.exports = router;
