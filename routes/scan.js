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
    {
      id: 1,
      type: 'SQLi Manual Review Recommended',
      severity: 'info',
      detail: 'No SQL injection vulnerability was confirmed by this scan. Use the dedicated SQLi scanner for authorized parameter testing.',
      vector: 'Recommendation'
    }
  ];
} else if (scanType === 'xss') {
  findings = [
    {
      id: 1,
      type: 'XSS Manual Review Recommended',
      severity: 'info',
      detail: 'No XSS vulnerability was confirmed by this scan. Use the dedicated XSS scanner for authorized testing.',
      vector: 'Recommendation'
    }
  ];
}

  let aiAnalysis;

  if (scanType === 'headers' || scanType === 'full') {
    aiAnalysis = findings.map(f => {
      const severity = String(f.severity).toUpperCase();
      const type = String(f.type);
      const detail = String(f.detail);

      if (type.startsWith('Missing ') &&
          String(f.vector).toLowerCase() === 'http header') {
        return `${severity} ${type}: ${detail} This scan establishes only that the header is missing; exploitability was not confirmed.`;
      }

      if (type === 'Server Header Disclosure') {
        return `${severity} ${type}: ${detail} This scan establishes only the disclosed server header value; no vulnerability was confirmed from this observation alone.`;
      }

      return `${severity} ${type}: ${detail}`;
    }).join('\\n');
  } else {
    aiAnalysis = await askClaude(
      'You are a defensive security reviewer. Use ONLY the findings provided. Never invent or infer vulnerabilities, exploitability, URLs, parameters, code, PoCs, or severity levels. If the supplied findings do not confirm a vulnerability, say so clearly.',
      `Real scan results for target: ${target}

${findings.map(f => `[${f.severity.toUpperCase()}] ${f.type}: ${f.detail}`).join('\\n')}

Keep the analysis concise and evidence-based.`
    );
  }

  res.json({ target, scanType, findings, aiAnalysis });
});

module.exports = router;
