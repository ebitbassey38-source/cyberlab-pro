const express = require('express');
const router = express.Router();
const axios = require('axios');
const { askClaude } = require('../services/claude');

const WORDLIST = [
  '/admin', '/administrator', '/login', '/dashboard', '/panel',
  '/wp-admin', '/wp-login.php', '/wp-config.php', '/wp-content',
  '/.env', '/.git', '/.git/config', '/.gitignore',
  '/backup', '/backup.zip', '/backup.sql', '/db.sql',
  '/config', '/config.php', '/config.json', '/settings.php',
  '/api', '/api/v1', '/api/v2', '/api/users', '/api/admin',
  '/phpinfo.php', '/info.php', '/test.php', '/shell.php',
  '/uploads', '/files', '/images', '/assets', '/static',
  '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
  '/server-status', '/server-info', '/.htaccess',
  '/old', '/new', '/temp', '/tmp', '/cache',
  '/logs', '/log', '/error.log', '/access.log',
  '/readme.txt', '/README.md', '/CHANGELOG.md',
  '/install.php', '/setup.php', '/install',
  '/console', '/debug', '/trace', '/actuator',
  '/swagger', '/swagger-ui.html', '/api-docs',
  '/graphql', '/graphiql', '/playground',
];

async function checkPath(baseUrl, path) {
  const url = baseUrl.replace(/\/$/, '') + path;
  try {
    const res = await axios.get(url, {
      timeout: 2000,
      maxRedirects: 2,
      validateStatus: () => true,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; CyberLab-Pro/1.0)' }
    });

    const interesting = [200, 201, 301, 302, 403, 500];
    if (!interesting.includes(res.status)) return null;

    const body = (res.data || '').toString().substring(0, 500);
    const contentType = res.headers['content-type'] || '';
    const size = res.headers['content-length'] || body.length;

    let severity = 'info';
    let issue = null;

    if (res.status === 200) {
      if (path.includes('.env') || path.includes('config') || path.includes('backup') || path.includes('.sql')) {
        severity = 'critical'; issue = 'Sensitive file exposed publicly';
      } else if (path.includes('.git')) {
        severity = 'high'; issue = 'Git repository exposed — source code leakage';
      } else if (path.includes('admin') || path.includes('panel') || path.includes('dashboard')) {
        severity = 'high'; issue = 'Admin panel accessible without authentication';
      } else if (path.includes('phpinfo') || path.includes('server-status') || path.includes('debug')) {
        severity = 'medium'; issue = 'Server information disclosure';
      } else if (path.includes('swagger') || path.includes('api-docs') || path.includes('graphql')) {
        severity = 'high'; issue = 'API documentation exposed publicly';
      } else {
        severity = 'low'; issue = 'Directory or file accessible';
      }
    } else if (res.status === 403) {
      severity = 'info'; issue = 'Exists but access forbidden — try bypass techniques';
    } else if (res.status === 500) {
      severity = 'medium'; issue = 'Server error — may reveal stack trace or internal info';
    }

    return { path, url, status: res.status, severity, issue, size, contentType: contentType.split(';')[0] };
  } catch (e) {
    return null;
  }
}

router.post('/scan', async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Target URL is required' });

  const baseUrl = target.startsWith('http') ? target : 'https://' + target;
  const results = [];

  for (let i = 0; i < WORDLIST.length; i += 20) {
    const batch = WORDLIST.slice(i, i + 10);
    const batchResults = await Promise.all(batch.map(path => checkPath(baseUrl, path)));
    results.push(...batchResults.filter(r => r !== null));
  }

  const critical = results.filter(r => r.severity === 'critical');
  const high = results.filter(r => r.severity === 'high');
  const found = results.length;

 const aiAnalysis = await askClaude(
`You are a senior penetration tester.

  Rules:
- Analyze ONLY the directory scan results provided.
- Report ONLY confirmed exposed files, directories, or resources supported by evidence.
- Never invent exposed backups, credentials, configuration files, or sensitive data.
- Never claim data exposure unless the scan confirmed the resource is publicly accessible.
- Never fabricate severity ratings, CVSS scores, exploit scenarios, or bounty impact.
- Directory existence alone does not prove a vulnerability; consider the evidence provided.
- If no evidence exists, clearly state that no exposed resources were identified from this scan.
- Recommend only legitimate next manual testing steps.
- Keep the response concise and professional.`,

`Directory scan results

Target: ${target}

Paths tested: ${WORDLIST.length}
Accessible paths found: ${found}
Critical findings: ${critical.length}
High findings: ${high.length}

Results:
${results.length
  ? results.map(r =>
      `[${r.severity.toUpperCase()}] ${r.path} (HTTP ${r.status}) - ${r.issue}`
    ).join('\n')
  : 'No accessible paths were identified.'}

Provide:
1. Summary
2. Confirmed findings only
3. Risk assessment based only on the evidence
4. Recommended next manual testing steps`
);

  res.json({ target, total: WORDLIST.length, found, critical: critical.length, high: high.length, results, aiAnalysis });
});

module.exports = router;
