const express = require('express');
const router = express.Router();
const dns = require('dns').promises;
const axios = require('axios');
const { askClaude } = require('../services/claude');

// Known vulnerable service fingerprints
const FINGERPRINTS = [
  { service: 'GitHub Pages',    pattern: "There isn't a GitHub Pages site here",  severity: 'high' },
  { service: 'Heroku',          pattern: 'No such app',                            severity: 'high' },
  { service: 'Shopify',         pattern: "Sorry, this shop is currently unavailable", severity: 'high' },
  { service: 'AWS S3',          pattern: 'NoSuchBucket',                           severity: 'high' },
  { service: 'Netlify',         pattern: "Not Found - Request ID",                 severity: 'high' },
  { service: 'Surge.sh',        pattern: "project not found",                      severity: 'high' },
  { service: 'Fastly',          pattern: "Fastly error: unknown domain",           severity: 'high' },
  { service: 'Ghost',           pattern: "The thing you were looking for is no longer here", severity: 'medium' },
  { service: 'Pantheon',        pattern: "404 error unknown site",                 severity: 'high' },
  { service: 'WordPress',       pattern: "Do you want to register",                severity: 'medium' },
  { service: 'Tumblr',          pattern: "Whatever you were looking for doesn't live here", severity: 'medium' },
  { service: 'Azure',           pattern: "404 Web Site not found",                 severity: 'high' },
  { service: 'Zendesk',         pattern: "Help Center Closed",                     severity: 'medium' },
  { service: 'Unbounce',        pattern: "The requested URL was not found",        severity: 'medium' },
];

// Common subdomains to check
const COMMON_SUBDOMAINS = [
  'www', 'mail', 'ftp', 'dev', 'staging', 'api', 'app',
  'blog', 'shop', 'store', 'admin', 'portal', 'dashboard',
  'cdn', 'static', 'assets', 'media', 'images', 'help',
  'support', 'docs', 'status', 'beta', 'test', 'demo',
];

async function checkSubdomain(subdomain, domain) {
  const full = `${subdomain}.${domain}`;
  const result = { subdomain: full, status: 'unknown', vulnerable: false, service: null, severity: null, cname: null };

  // Check DNS
  try {
    const cname = await dns.resolveCname(full).catch(() => null);
    const a = await dns.resolve4(full).catch(() => null);

    if (!cname && !a) {
      result.status = 'no-dns';
      return result;
    }

    result.status = 'dns-found';
    if (cname && cname.length > 0) result.cname = cname[0];

    // Try HTTP request
    try {
      const res = await axios.get(`https://${full}`, {
        timeout: 5000,
        maxRedirects: 2,
        validateStatus: () => true,
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; CyberLab-Mini/1.0)' }
      });

      const body = res.data?.toString() || '';
      result.httpStatus = res.status;

      // Check fingerprints
      for (const fp of FINGERPRINTS) {
        if (body.toLowerCase().includes(fp.pattern.toLowerCase())) {
          result.vulnerable = true;
          result.service = fp.service;
          result.severity = fp.severity;
          result.status = 'vulnerable';
          break;
        }
      }

      if (!result.vulnerable) result.status = 'active';

    } catch (e) {
      result.status = 'unreachable';
    }

  } catch (e) {
    result.status = 'no-dns';
  }

  return result;
}

router.post('/check', async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Target domain is required' });

  const domain = target.replace(/^https?:\/\//, '').split('/')[0];

  // Check all subdomains in parallel
  const results = await Promise.all(
    COMMON_SUBDOMAINS.map(sub => checkSubdomain(sub, domain))
  );

  const found      = results.filter(r => r.status !== 'no-dns');
  const vulnerable = results.filter(r => r.vulnerable);
  const active     = results.filter(r => r.status === 'active');

  const aiAnalysis = await askClaude(
`You are a senior defensive security reviewer.

Rules:
- Analyze ONLY confirmed subdomain takeover scan evidence.
- Never provide takeover exploitation steps unless a vulnerable subdomain is confirmed.
- DNS records or CNAME presence alone do not prove takeover.
- Never claim a bounty impact without confirmed vulnerability evidence.
- Clearly separate confirmed findings from recommendations.
- If no vulnerable subdomains are found, state that no subdomain takeover vulnerability was identified.

Provide:
1. Summary
2. Confirmed Findings
3. Risk Assessment
4. Recommended Manual Verification Steps.`,
    `Subdomain takeover scan for: ${domain}

Found subdomains: ${found.map(r => r.subdomain).join(', ') || 'None'}
Vulnerable subdomains: ${vulnerable.map(r => `${r.subdomain} (${r.service} - ${r.severity})`).join(', ') || 'None found'}
Active subdomains: ${active.map(r => r.subdomain).join(', ') || 'None'}

For each vulnerable subdomain explain:
1. How to exploit and claim it
2. What the bounty impact is
3. How to write the report

If none vulnerable, suggest next manual steps. Be concise and specific.`
  );

  res.json({ domain, total: results.length, found: found.length, vulnerable: vulnerable.length, results: found, aiAnalysis });
});

module.exports = router;
