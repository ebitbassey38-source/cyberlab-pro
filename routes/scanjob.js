const express = require('express');
const ScanJob = require('../models/ScanJob');
const Asset = require('../models/Asset');
const auth = require('../middleware/auth');
const scanEngine = require('../services/scanEngine');
const router = express.Router();

// Create Scan Job
router.post('/create', auth, async (req, res) => {
  try {
    const { name, assetId } = req.body;

    if (!name || !assetId) {
      return res.status(400).json({
        error: 'name and assetId are required'
      });
    }

    const asset = await Asset.findById(assetId);

    if (!asset) {
      return res.status(404).json({
        error: 'Asset not found'
      });
    }

    if (asset.owner.toString() !== req.user.id) {
      return res.status(403).json({
        error: 'Access denied'
      });
    }

    const scanJob = await ScanJob.create({
      name,
      asset: asset._id,
      project: asset.project,
      owner: req.user.id
    });

    res.status(201).json({
      message: 'Scan job created successfully',
      scanJob
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});
// Start Scan Job
router.post('/:id/start', auth, async (req, res) => {
  try {
    const scanJob = await ScanJob.findById(req.params.id);

    if (!scanJob) {
      return res.status(404).json({
        error: 'Scan job not found'
      });
    }

    if (scanJob.owner.toString() !== req.user.id) {
      return res.status(403).json({
        error: 'Access denied'
      });
    }

    const result = await scanEngine.run(scanJob._id);

res.json({
  message: 'Scan completed successfully',
  result
});

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});
module.exports = router;
