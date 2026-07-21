const express = require('express');
const router = express.Router();
const dns = require('dns').promises;
const axios = require('axios');
const tls = require('tls');
const { askClaude } = require('../services/claude');

// Real SSL checker
function checkSSL(host) {
  return new Promise((resolve) => {
    const port = 443;
    const socket = tls.connect(port, host, { servername: host, timeout: 5000 }, () => {
      const cert = socket.getPeerCertificate();
      const valid = socket.authorized;
      socket.destroy();
      resolve({
        valid: valid,
        issuer: cert.issuer?.O || 'Unknown',
        subject: cert.subject?.CN || host,
        expires: cert.valid_to || 'Unknown',
        protocol: socket.getProtocol() || 'Unknown',
        grade: valid ? 'A' : 'F'
      });
    });
    socket.on('error', () => resolve({ valid: false, issuer: 'N/A', expires: 'N/A', protocol: 'N/A', grade: 'F', error: 'SSL check failed' }));
    socket.on('timeout', () => { socket.destroy(); resolve({ valid: false, issuer: 'N/A', expires: 'N/A', protocol: 'N/A', grade: 'F', error: 'Timeout' }); });
  });
}

// Real header checker
async function fetchSecurityHeaders(host) {
  try {
    const res = await axios.get('https://' + host, {
      timeout: 6000, maxRedirects: 3, validateStatus: () => true,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; CyberLab-Mini/1.0)' }
    });
    const h = res.headers;
    return [
      { name: 'X-Frame-Options',           value: h['x-frame-options'] || 'MISSING',           risk: h['x-frame-options'] ? 'safe' : 'warn' },
      { name: 'Content-Security-Policy',    value: h['content-security-policy'] ? 'Present' : 'MISSING', risk: h['content-security-policy'] ? 'safe' : 'warn' },
      { name: 'Strict-Transport-Security',  value: h['strict-transport-security'] || 'MISSING',  risk: h['strict-transport-security'] ? 'safe' : 'warn' },
      { name: 'X-Content-Type-Options',     value: h['x-content-type-options'] || 'MISSING',     risk: h['x-content-type-options'] ? 'safe' : 'warn' },
      { name: 'Referrer-Policy',            value: h['referrer-policy'] || 'MISSING',            risk: h['referrer-policy'] ? 'safe' : 'warn' },
      { name: 'Server',                     value: h['server'] || 'Hidden',                      risk: h['server'] ? 'warn' : 'safe' },
    ];
  } catch (e) {
    return [{ name: 'Headers', value: 'Could not fetch', risk: 'warn' }];
  }
}

router.post('/analyze', async (req, res) => {
  const { target } = req.body;
  if (!target) return res.status(400).json({ error: 'Target is required' });

  const host = target.replace(/^https?:\/\//, '').split('/')[0];

  // Run all checks in parallel
  const [dnsResults, sslResult, headerResults] = await Promise.all([
    // Real DNS lookup
    Promise.allSettled([
      dns.resolve4(host).then(v => v.map(r => ({ type: 'A', value: r }))),
      dns.resolveMx(host).then(v => v.map(r => ({ type: 'MX', value: `${r.exchange} (priority ${r.priority})` }))),
      dns.resolveTxt(host).then(v => v.map(r => ({ type: 'TXT', value: r.join(' ') }))),
      dns.resolveNs(host).then(v => v.map(r => ({ type: 'NS', value: r }))),
    ]).then(results => results.flatMap(r => r.status === 'fulfilled' ? r.value : [])),
    // Real SSL check
    checkSSL(host),
    // Real header check
    fetchSecurityHeaders(host),
  ]);

  const subdomains = [`www.${host}`, `api.${host}`, `mail.${host}`, `dev.${host}`, `staging.${host}`];
  const ports = [
    { port: 80,   service: 'HTTP',     status: 'open',     note: 'Standard HTTP' },
    { port: 443,  service: 'HTTPS',    status: 'open',     note: sslResult.protocol || 'TLS' },
    { port: 22,   service: 'SSH',      status: 'unknown',  note: 'Requires direct probe' },
    { port: 3306, service: 'MySQL',    status: 'unknown',  note: 'Requires direct probe' },
    { port: 8080, service: 'HTTP-Alt', status: 'unknown',  note: 'Requires direct probe' },
  ];

  const missingHeaders = headerResults.filter(h => h.risk === 'warn').map(h => h.name);
  const aiAnalysis = await askClaude(
    'You are a senior bug bounty hunter specializing in network recon.',
    `Real network analysis for: ${target}\nDNS: ${dnsResults.map(r => `${r.type}:${r.value}`).join(', ')}\nSSL Grade: ${sslResult.grade} | Valid: ${sslResult.valid} | Issuer: ${sslResult.issuer} | Expires: ${sslResult.expires}\nMissing headers: ${missingHeaders.join(', ') || 'None'}\nSubdomains to investigate: ${subdomains.join(', ')}\n\nMap the attack surface and suggest next bounty steps. Be concise.`
  );

  res.json({ host, dnsRecords: dnsResults, ssl: sslResult, headers: headerResults, ports, subdomains, aiAnalysis });
});

module.exports = router;
