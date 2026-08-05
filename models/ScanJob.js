const mongoose = require('mongoose');

const ScanJobSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
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
    enum: ['pending', 'running', 'completed', 'failed'],
    default: 'pending'
  },

  startedAt: {
    type: Date,
    default: Date.now
  },

  completedAt: {
    type: Date
  }
});

module.exports = mongoose.model('ScanJob', ScanJobSchema);
