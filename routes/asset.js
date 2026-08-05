const express = require('express');
const Asset = require('../models/Asset');
const Project = require('../models/Project');
const auth = require('../middleware/auth');

const router = express.Router();

// Create Asset
router.post('/create', auth, async (req, res) => {
  try {
    const { name, type, value, projectId } = req.body;

    if (!name || !type || !value || !projectId) {
      return res.status(400).json({
        error: 'name, type, value and projectId are required'
      });
    }

    const project = await Project.findById(projectId);

    if (!project) {
      return res.status(404).json({
        error: 'Project not found'
      });
    }

    if (project.owner.toString() !== req.user.id) {
      return res.status(403).json({
        error: 'Access denied'
      });
    }

    const asset = await Asset.create({
      name,
      type,
      value,
      project: projectId,
      owner: req.user.id
    });

    res.status(201).json({
      message: 'Asset created successfully',
      asset
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});
// List My Assets
router.get('/mine', auth, async (req, res) => {
  try {
    const assets = await Asset.find({
      owner: req.user.id
    });

    res.json({
      count: assets.length,
      assets
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});
// Get Asset by ID
router.get('/:id', auth, async (req, res) => {
  try {
    const asset = await Asset.findById(req.params.id);

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

    res.json({
      asset
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});
// Update Asset
router.put('/:id', auth, async (req, res) => {
  try {
    const { name, type, value, status } = req.body;

    const asset = await Asset.findById(req.params.id);

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

    if (name) asset.name = name;
    if (type) asset.type = type;
    if (value) asset.value = value;
    if (status) asset.status = status;

    await asset.save();

    res.json({
      message: 'Asset updated successfully',
      asset
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});
// Delete Asset
router.delete('/:id', auth, async (req, res) => {
  try {
    const asset = await Asset.findById(req.params.id);

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

    await asset.deleteOne();

    res.json({
      message: 'Asset deleted successfully'
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});
module.exports = router;
