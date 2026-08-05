const mongoose = require('mongoose');

const AuthorizationContextSchema = new mongoose.Schema({
  scanJob: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'ScanJob',
    required: true
  },

  httpRequest: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'HTTPRequest',
    required: true
  },

  authenticationType: {
    type: String,
    enum: ['none', 'cookie', 'bearer', 'apikey', 'basic'],
    default: 'none'
  },

  identity: {
    type: String,
    default: null
  },

  expectedOwner: {
    type: String,
    default: null
  },

  notes: {
    type: String,
    default: ''
  },

  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model(
  'AuthorizationContext',
  AuthorizationContextSchema
);
