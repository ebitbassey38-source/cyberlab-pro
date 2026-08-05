const express = require('express');
const auth = require('../middleware/auth');

const router = express.Router();

// API Recon
router.post('/discover', auth, async (req, res) => {
  try {
    const { target } = req.body;

    if (!target) {
      return res.status(400).json({
        error: 'Target URL is required'
      });
    }

    res.json({
      message: 'API Recon started',
      target,
      discovered: []
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

module.exports = router;
