// routes/authRoutes.js - Defines all API endpoints.

const express = require('express');
const router = express.Router();
const {
    registerHandler,
    loginHandler,
    verifyEmailHandler,
    googleLoginHandler,
    updateProfileHandler,
    changePasswordHandler,
    updateFplTeamIdHandler,
    fetchAllUsersHandler,
    protect,
    adminCheck,
} = require('../services/authService');

// --- Public Routes ---

// POST /api/register
router.post('/register', registerHandler);

// POST /api/login
router.post('/login', loginHandler);

// GET /api/verify?token=...
router.get('/verify', verifyEmailHandler);

// POST /api/auth/google
router.post('/auth/google', googleLoginHandler);

// --- Protected Routes (require JWT) ---

// POST /api/profile/update
router.post('/profile/update', protect, updateProfileHandler);

// POST /api/password/change
router.post('/password/change', protect, changePasswordHandler);

// POST /api/profile/fpl-team-id
router.post('/profile/fpl-team-id', protect, updateFplTeamIdHandler);


// --- Admin Routes (require JWT and admin privilege) ---

// GET /api/admin/users
router.get('/admin/users', protect, adminCheck, fetchAllUsersHandler);


module.exports = router;