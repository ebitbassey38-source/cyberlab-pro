const express = require('express');
const router = express.Router();
const axios = require('axios');
const { askClaude } = require('../services/claude');

const API_PATHS = [
  '/api', '/api/v1', '/api/v2', '/api/v3',
  '/api/users', '/api/admin', '/api/config',
  '/api/debug', '/api/test', '/api/keys',
  '/swagger', '/swagger-ui.html', '/swagger.json',
  '/api-docs', '/openapi.json', '/graphql',
  '/api/v1/users', '/api/v1/admin', '/api/v1/config',
  '/api/v1/keys', '/api/v1/debug', '/api/v1/health',
  '/v1', '/v2', '/v3', '/rest', '/rest/api',
  '/.env', '/config.json', '/api/credentials',
  '/api/token', '/api/auth', '/api/login',
];

async function probeEndpoint(baseUrl, path) {
  const url = baseUrl.replace(/\/$/, '') + path;
  const result = { path, url, status: null, vulnerable: false, issue: null, severity: null };

  try {
    const res = await axios.get(url, {
      timeout: 5000,
      maxRedirects: 2,
      validateStatus: () => true,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; CyberLab-Mini/1.0)',
        'Accept': 'application/json, text/html',
      }
    });

    result.status = res.status;
    const body = JSON.stringify(res.data || '').toLowerCase();
    const contentType = res.headers['content-type'] || '';

    // Check for exposed endpoints
    if (res.status === 200) {
      if (path.includes('swagger') || path.includes('api-docs') || path.includes('openapi')) {
        result.vulnerable = true;
        result.issue = 'API documentation exposed publicly — reveals all endpoints, parameters and auth methods';
        result.severity = 'high';
      } else if (path.includes('graphql')) {
        result.vulnerable = true;
        result.issue = 'GraphQL endpoint exposed — test for introspection query to dump full schema';
        result.severity = 'high';
      } else if (path.includes('.env') || path.includes('config') || path.includes('credential')) {
        result.vulnerable = true;
        result.issue = 'Sensitive configuration file exposed — may contain API keys, DB credentials';
        result.severity = 'critical';
      } else if (path.includes('admin')) {
        result.vulnerable = true;
        result.issue = 'Admin API endpoint accessible without authentication check';
        result.severity = 'high';
      } else if (path.includes('debug') || path.includes('test')) {
        result.vulnerable = true;
        result.issue = 'Debug/test endpoint exposed in production — may leak internal data';
        result.severity = 'medium';
      } else if (contentType.includes('application/json')) {
        result.vulnerable = true;
        result.issue = 'API endpoint returns data without authentication — potential IDOR or data exposure';
        result.severity = 'medium';
      }
    }

    // Check for verbose errors
    if (res.status >= 500) {
      if (body.includes('stack') || body.includes('exception') || body.includes('traceback') || body.includes('error') && body.includes('line')) {
        result.vulnerable = true;
        result.issue = 'Server error reveals stack trace — exposes internal code structure';
        result.severity = 'medium';
      }
    }

    // Check for auth bypass (403 vs 401)
    if (res.status === 403) {
      result.issue = 'Endpoint exists but returns 403 — try auth bypass techniques';
      result.severity = 'info';
    }

    // Check OPTIONS method
    if (res.status === 200 || res.status === 405) {
      try {
        const optRes = await axios.options(url, { timeout: 3000, validateStatus: () => true });
        const allow = optRes.headers['allow'] || optRes.headers['access-control-allow-methods'] || '';
        if (allow.includes('PUT') || allow.includes('DELETE') || allow.includes('PATCH')) {
          result.vulnerable = true;
          result.issue = `Dangerous HTTP methods allowed: ${allow} — test for unauthorized data modification`;
          result.severity = 'medium';
        }
      } catch (e) {}
    }

  } catch (e) {
    result.status = 'timeout';
  }

  return result;
}

router.post('/scan', async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Target URL is required' });

  const baseUrl = target.startsWith('http') ? target : 'https://' + target;

  // Probe all endpoints in parallel (batches of 8)
  const results = [];
  for (let i = 0; i < API_PATHS.length; i += 8) {
    const batch = API_PATHS.slice(i, i + 8);
    const batchResults = await Promise.all(batch.map(path => probeEndpoint(baseUrl, path)));
    results.push(...batchResults);
  }

  const found      = results.filter(r => r.status === 200 || r.status === 403);
  const vulnerable = results.filter(r => r.vulnerable);

  const aiAnalysis = await askClaude(
    'You are a senior bug bounty hunter specializing in API security testing.',
    `API vulnerability scan for: ${target}

Exposed endpoints found (status 200/403):
${found.map(r => `${r.status} ${r.path} ${r.issue ? '— ' + r.issue : ''}`).join('\n') || 'None found'}

Vulnerable endpoints:
${vulnerable.map(r => `[${r.severity?.toUpperCase()}] ${r.path}: ${r.issue}`).join('\n') || 'None found'}

For each vulnerable endpoint:
1. How to exploit it
2. Bounty impact and expected payout
3. Next manual testing steps

If none found, suggest what to test manually. Be specific and concise.`
  );

  res.json({
    target,
    total: results.length,
    found: found.length,
    vulnerable: vulnerable.length,
    results: found,
    aiAnalysis
  });
});

module.exports = router;
