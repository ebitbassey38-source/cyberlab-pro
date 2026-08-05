const express = require('express');
const HTTPRequest = require('../models/HTTPRequest');
const Asset = require('../models/Asset');
const auth = require('../middleware/auth');

const router = express.Router();

// Import HTTP Request
router.post('/import', auth, async (req, res) => {
  try {
    const {
      method,
      url,
      headers,
      cookies,
      body,
      authentication,
      assetId
    } = req.body;

    if (!method || !url || !assetId) {
      return res.status(400).json({
        error: 'method, url and assetId are required'
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

    const httpRequest = await HTTPRequest.create({
      method,
      url,
      headers,
      cookies,
      body,
      authentication,
      asset: asset._id,
      owner: req.user.id
    });

    res.status(201).json({
      message: 'HTTP request imported successfully',
      httpRequest
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});

module.exports = router;
