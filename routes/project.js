const express = require('express');
const Project = require('../models/Project');
const Organization = require('../models/Organization');
const auth = require('../middleware/auth');

const router = express.Router();

// Create Project
router.post('/create', auth, async (req, res) => {
  try {
    const { name, description, organizationId } = req.body;

    if (!name || !organizationId) {
      return res.status(400).json({
        error: 'Project name and organizationId are required'
      });
    }

    const organization = await Organization.findById(organizationId);

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

    const project = await Project.create({
      name,
      description,
      organization: organizationId,
      owner: req.user.id
    });

    res.status(201).json({
      message: 'Project created successfully',
      project
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});
// List My Projects
router.get('/mine', auth, async (req, res) => {
  try {
    const projects = await Project.find({
      owner: req.user.id
    });

    res.json({
      count: projects.length,
      projects
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});
// Get Project by ID
router.get('/:id', auth, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);

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

    res.json({
      project
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});
// Update Project
router.put('/:id', auth, async (req, res) => {
  try {
    const { name, description, status } = req.body;

    const project = await Project.findById(req.params.id);

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

    if (name) project.name = name;
    if (description !== undefined) project.description = description;
    if (status) project.status = status;

    await project.save();

    res.json({
      message: 'Project updated successfully',
      project
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});
// Delete Project
router.delete('/:id', auth, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);

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

    await project.deleteOne();

    res.json({
      message: 'Project deleted successfully'
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Internal server error'
    });
  }
});
module.exports = router;
