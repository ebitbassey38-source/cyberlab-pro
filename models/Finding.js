const mongoose = require('mongoose');

const FindingSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },

  type: {
    type: String,
    required: true,
    trim: true
  },

  severity: {
    type: String,
    enum: ['critical', 'high', 'medium', 'low', 'info'],
    default: 'info'
  },

  description: {
    type: String,
    default: ''
  },

  evidence: {
    type: String,
    default: ''
  },

  recommendation: {
    type: String,
    default: ''
  },

  asset: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Asset',
    required: true
  },

  project: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Project',
    required: true
  },

  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },

  status: {
    type: String,
    enum: ['open', 'fixed', 'accepted'],
    default: 'open'
  },

  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Finding', FindingSchema);
