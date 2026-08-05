const express = require('express');
const Finding = require('../models/Finding');
const Asset = require('../models/Asset');
const auth = require('../middleware/auth');

const router = express.Router();

// Create Finding
router.post('/create', auth, async (req, res) => {
  try {
    const {
      title,
      type,
      severity,
      description,
      evidence,
      recommendation,
      assetId
    } = req.body;

    if (!title || !type || !assetId) {
      return res.status(400).json({
        error: 'title, type and assetId are required'
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

    const finding = await Finding.create({
      title,
      type,
      severity,
      description,
      evidence,
      recommendation,
      asset: asset._id,
      project: asset.project,
      owner: req.user.id
    });

    res.status(201).json({
      message: 'Finding created successfully',
      finding
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

module.exports = router;
