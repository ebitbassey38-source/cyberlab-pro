const express = require('express');
const Organization = require('../models/Organization');
const OrganizationMember = require('../models/OrganizationMember');
const auth = require('../middleware/auth');

const router = express.Router();

// Create Organization
router.post('/create', auth, async (req, res) => {
  try {
    const { name } = req.body;

    if (!name) {
      return res.status(400).json({
        error: 'Organization name is required'
      });
    }

    const organization = await Organization.create({
      name,
      owner: req.user.id
    });

await OrganizationMember.create({
  organization: organization._id,
  user: req.user.id,
  role: 'owner'
});
    res.status(201).json({
      message: 'Organization created successfully',
      organization
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});
// Get My Organizations
router.get('/mine', auth, async (req, res) => {
  try {
    const organizations = await Organization.find({
      owner: req.user.id
    });

    res.json({
      count: organizations.length,
      organizations
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});
// Get Organization by ID
router.get('/:id', auth, async (req, res) => {
  try {
    const organization = await Organization.findById(req.params.id);

    if (!organization) {
      return res.status(404).json({
        error: 'Organization not found'
      });
    }

    if (organization.owner.toString() !== req.user.id) {
      return res.status(403).json({
        error: 'Access denied'
      });
    }

    res.json({
      organization
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});
// Update Organization
router.put('/:id', auth, async (req, res) => {
  try {
    const { name } = req.body;

    const organization = await Organization.findById(req.params.id);

    if (!organization) {
      return res.status(404).json({
        error: 'Organization not found'
      });
    }

    if (organization.owner.toString() !== req.user.id) {
      return res.status(403).json({
        error: 'Access denied'
      });
    }

    if (name) {
      organization.name = name;
    }

    await organization.save();

    res.json({
      message: 'Organization updated successfully',
      organization
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});
// Delete Organization
router.delete('/:id', auth, async (req, res) => {
  try {
    const organization = await Organization.findById(req.params.id);

    if (!organization) {
      return res.status(404).json({
        error: 'Organization not found'
      });
    }

    if (organization.owner.toString() !== req.user.id) {
      return res.status(403).json({
        error: 'Access denied'
      });
    }

    await organization.deleteOne();

    res.json({
      message: 'Organization deleted successfully'
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});
// List Organization Members (Temporary Verification)
router.get('/:id/members', auth, async (req, res) => {
  try {
    const OrganizationMember = require('../models/OrganizationMember');

    const members = await OrganizationMember.find({
      organization: req.params.id
    }).populate('user', 'name email');

    res.json({
      count: members.length,
      members
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});
module.exports = router;
