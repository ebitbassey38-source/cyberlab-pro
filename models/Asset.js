const mongoose = require('mongoose');

const AssetSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },

  type: {
    type: String,
    enum: ['domain', 'ip', 'website', 'api', 'mobile'],
    required: true
  },

  value: {
    type: String,
    required: true,
    trim: true
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
    enum: ['active', 'inactive'],
    default: 'active'
  },

  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Asset', AssetSchema);
