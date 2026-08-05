const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const auth = require('../middleware/auth');
const authController = require('../controllers/authController');
const router = express.Router();

// Register
router.post('/register', authController.register);

// Login
router.post('/login', authController.login);
// Get current user profile
router.get('/profile', auth, authController.profile);
module.exports = router;
