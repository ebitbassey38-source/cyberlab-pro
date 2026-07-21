const express = require('express');
const router = express.Router();
const { askClaude } = require('../services/claude');

router.post('/generate', async (req, res) => {
  const { target, findings, scanType } = req.body;
  if (!target || !findings || findings.length === 0) {
    return res.status(400).json({ error: 'Target and findings are required' });
  }

  const topFinding = findings.sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return (order[a.severity] || 4) - (order[b.severity] || 4);
  })[0];

  const report = await askClaude(
    'You are a professional bug bounty report writer. Write clear, structured, convincing vulnerability reports that get accepted and paid. Always use the exact HackerOne report format.',
    `Write a complete HackerOne-ready bug bounty report for this finding:

Target: ${target}
Vulnerability: ${topFinding.type}
Severity: ${topFinding.severity.toUpperCase()}
Detail: ${topFinding.detail}
Vector: ${topFinding.vector}

All findings from scan:
${findings.map(f => `- [${f.severity.toUpperCase()}] ${f.type}: ${f.detail}`).join('\n')}

Write the full report with these exact sections:
## Title
## Severity
## Summary
## Steps to Reproduce
## Proof of Concept
## Impact
## Recommended Fix
## References

Make it professional, specific, and ready to submit. Include realistic PoC steps.`
  );

  res.json({ target, report, topFinding });
});

module.exports = router;
