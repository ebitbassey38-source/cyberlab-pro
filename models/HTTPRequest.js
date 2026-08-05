const mongoose = require('mongoose');

const HTTPRequestSchema = new mongoose.Schema({
  method: {
    type: String,
    required: true
  },

  url: {
    type: String,
    required: true
  },

  headers: {
    type: Object,
    default: {}
  },

  cookies: {
    type: Object,
    default: {}
  },

  body: {
    type: Object,
    default: {}
  },

  authentication: {
    type: String,
    enum: ['none', 'cookie', 'bearer', 'apikey', 'basic'],
    default: 'none'
  },

  asset: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Asset',
    required: true
  },

  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },

  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('HTTPRequest', HTTPRequestSchema);
