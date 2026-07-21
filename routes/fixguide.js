const express = require('express');
const router = express.Router();
const { askClaude } = require('../services/claude');

router.post('/generate', async (req, res) => {
  const { vulnerability, platform, target } = req.body;
  if (!vulnerability || !platform) {
    return res.status(400).json({ error: 'Vulnerability and platform are required' });
  }

  const fix = await askClaude(
    'You are a senior web security engineer. Generate exact, copy-paste ready fix instructions. Always include real code examples. Be specific to the platform. No fluff.',
    `Generate a complete fix guide for this vulnerability:

Vulnerability: ${vulnerability.type}
Severity: ${vulnerability.severity}
Detail: ${vulnerability.detail}
Target: ${target || 'unknown'}
Platform: ${platform}

Provide:
## What is this vulnerability?
One paragraph plain English explanation for a non-technical business owner.

## Why it matters
Real-world impact — what can a hacker actually do if this is not fixed.

## How to fix it on ${platform}
Exact step-by-step instructions with copy-paste ready code.

## Verify the fix
How to confirm the fix worked after implementing it.

## Time to fix
Estimated time for a developer to implement this fix.

Make the code examples complete and ready to copy-paste. Be specific to ${platform}.`
  );

  res.json({ vulnerability, platform, fix });
});

module.exports = router;
