const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { askClaude } = require('../services/claude');

router.post('/identify', async (req, res) => {
  const { hash } = req.body;
  if (!hash) return res.status(400).json({ error: 'Hash is required' });

  const patterns = [
    { name: 'MD5',     regex: /^[a-f0-9]{32}$/i,   crackable: true,  notes: 'Weak. Rainbow tables available.' },
    { name: 'SHA-1',   regex: /^[a-f0-9]{40}$/i,   crackable: true,  notes: 'Deprecated. Collision attacks known.' },
    { name: 'SHA-256', regex: /^[a-f0-9]{64}$/i,   crackable: false, notes: 'Strong. Needs wordlist attack.' },
    { name: 'SHA-512', regex: /^[a-f0-9]{128}$/i,  crackable: false, notes: 'Very strong. 512-bit output.' },
    { name: 'bcrypt',  regex: /^\$2[ayb]\$[0-9]{2}\$[./A-Za-z0-9]{53}$/, crackable: false, notes: 'Adaptive. Very slow to crack.' },
    { name: 'NTLM',   regex: /^[a-f0-9]{32}$/i,   crackable: true,  notes: 'Windows hash. Hashcat mode 1000.' }
  ];

  const matches = patterns.filter(p => p.regex.test(hash.trim()));
  const result = matches.length ? matches : [{ name: 'Unknown', crackable: false, notes: 'Does not match known formats.' }];

  const aiAnalysis = await askClaude(
    'You are a CTF player and cryptography expert. Give practical cracking advice.',
    `Hash: ${hash}\nPossible types: ${result.map(m => m.name).join(', ')}\n\nAdvise on: most likely type, cracking approach, hashcat mode, and bounty report impact. Be concise.`
  );

  res.json({ hash, matches: result, aiAnalysis });
});

router.post('/generate', async (req, res) => {
  const { input, algorithm = 'sha256' } = req.body;
  if (!input) return res.status(400).json({ error: 'Input is required' });

  const supported = ['sha1', 'sha256', 'sha512', 'md5'];
  if (!supported.includes(algorithm)) {
    return res.status(400).json({ error: 'Unsupported algorithm' });
  }

  const hash = crypto.createHash(algorithm).update(input).digest('hex');
  res.json({ input, algorithm, hash });
});

router.post('/strength', async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password is required' });

  const checks = [
    { label: 'Length >= 12',       pass: password.length >= 12 },
    { label: 'Uppercase letter',   pass: /[A-Z]/.test(password) },
    { label: 'Lowercase letter',   pass: /[a-z]/.test(password) },
    { label: 'Number',             pass: /[0-9]/.test(password) },
    { label: 'Special character',  pass: /[^A-Za-z0-9]/.test(password) },
    { label: 'Not common pattern', pass: !/^(password|123|qwerty|admin)/i.test(password) },
    { label: 'No repeated chars',  pass: !/(.)(\1{3,})/.test(password) }
  ];

  const score = checks.filter(c => c.pass).length;
  const rating = score <= 2 ? 'Weak' : score <= 4 ? 'Fair' : score <= 6 ? 'Good' : 'Strong';

  const aiAnalysis = await askClaude(
    'You are a security consultant advising on password security.',
    `Password score: ${score}/7 (${rating})\nFailed checks: ${checks.filter(c => !c.pass).map(c => c.label).join(', ') || 'None'}\n\nAdvise on: weaknesses, rockyou.txt survivability, estimated crack time, one improvement. Be concise.`
  );

  res.json({ score, rating, checks, aiAnalysis });
});

module.exports = router;
