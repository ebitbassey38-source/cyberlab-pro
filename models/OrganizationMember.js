const mongoose = require('mongoose');

const OrganizationMemberSchema = new mongoose.Schema({
  organization: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    required: true
  },

  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },

  role: {
    type: String,
    enum: ['owner', 'admin', 'analyst', 'viewer'],
    default: 'viewer'
  },

  joinedAt: {
    type: Date,
    default: Date.now
  }
});

OrganizationMemberSchema.index(
  { organization: 1, user: 1 },
  { unique: true }
);

module.exports = mongoose.model(
  'OrganizationMember',
  OrganizationMemberSchema
);
