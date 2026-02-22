// services/authService.js - Contains all business logic for authentication and user management.

const db = require('../db');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const axios = require('axios');
const crypto = require('crypto');

const JWT_SECRET = process.env.JWT_SECRET;
const VERIFICATION_BASE_URL = process.env.VERIFICATION_BASE_URL;

// --- Email Service Implementation ---
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT, 10),
    secure: process.env.SMTP_SSL === 'true', // true for 465, false for other ports
    auth: {
        user: process.env.SMTP_USERNAME,
        pass: process.env.SMTP_PASSWORD,
    },
});

const sendVerificationEmail = async (recipientEmail, token) => {
    const verificationLink = `${VERIFICATION_BASE_URL}?token=${token}`;

    const mailOptions = {
        from: process.env.SENDER_EMAIL,
        to: recipientEmail,
        subject: 'Verify your Jersey Premier League Account',
        html: `
            <p>Thank you for registering! Please click the link below to verify your email address:</p>
            <p><a href="${verificationLink}">Verify Email Address</a></p>
            <p>If you did not request this, please ignore this email.</p>
        `,
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`Verification email sent to ${recipientEmail}`);
    } catch (error) {
        console.error(`Error sending verification email to ${recipientEmail}:`, error);
        // Do not crash the server on email failure, but log it.
    }
};

// --- Helper Functions ---

const generateToken = (user) => {
    return jwt.sign(
        {
            id: user.id,
            email: user.email,
            verified: user.isEmailVerified,
            is_admin: user.isAdmin, // Include admin status in JWT
        },
        JWT_SECRET,
        { expiresIn: '7d' }
    );
};

const generateRandomString = (length) => {
    return crypto.randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length);
};

// Middleware to protect routes and attach user data
const protect = async (req, res, next) => {
    let token;
    const authHeader = req.headers.authorization;

    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.split(' ')[1];
    }

    if (!token) {
        return res.status(401).json({ error: 'Unauthorized: No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // Attach the JWT payload to the request
        next();
    } catch (error) {
        console.error('JWT Verification Failed:', error.message);
        return res.status(401).json({ error: 'Unauthorized: Invalid token.' });
    }
};

const adminCheck = (req, res, next) => {
    // Requires the `protect` middleware to run first
    if (!req.user || !req.user.is_admin) {
        console.log(`Forbidden access attempt by user ID: ${req.user ? req.user.id : 'N/A'}`);
        return res.status(403).json({ error: 'Forbidden: Administrator privileges required.' });
    }
    next();
};

// --- Handlers ---

const registerHandler = async (req, res) => {
    const { email, name, password } = req.body;

    if (!email || !name || !password) {
        return res.status(400).json({ error: 'Missing required fields: email, name, or password.' });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 10);
        const verificationToken = generateRandomString(40);

        const result = await db.query(
            "INSERT INTO users (name, email, password_hash, verification_token) VALUES ($1, $2, $3, $4) RETURNING id, name, email, fpl_team_id, is_email_verified, is_admin",
            [name, email, passwordHash, verificationToken]
        );

        const newUser = new User(result.rows[0]);
        const token = generateToken(newUser);

        // Send email (non-blocking)
        sendVerificationEmail(newUser.email, verificationToken);

        const userWithToken = newUser.toJson();
        userWithToken.token = token;

        return res.status(201).json(userWithToken);

    } catch (e) {
        if (e.code === '23505') { // PostgreSQL unique violation error code
            return res.status(409).json({ error: 'User with this email already exists.' });
        }
        console.error('PostgreSQL Error during registration:', e);
        return res.status(500).json({ error: 'Database error during registration.' });
    }
};

const loginHandler = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Missing required fields: email or password.' });
    }

    try {
        const result = await db.query(
            "SELECT id, name, email, password_hash, fpl_team_id, is_email_verified, is_admin FROM users WHERE email = $1",
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        const userRow = result.rows[0];
        const storedHash = userRow.password_hash;

        if (!(await bcrypt.compare(password, storedHash))) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        const user = new User(userRow);
        const token = generateToken(user);

        const userWithToken = user.toJson();
        userWithToken.token = token;

        return res.status(200).json(userWithToken);

    } catch (e) {
        console.error('PostgreSQL Error during login:', e);
        return res.status(500).json({ error: 'Database error during login.' });
    }
};

const verifyEmailHandler = async (req, res) => {
    const token = req.query.token;

    if (!token) {
        return res.status(400).json({ error: 'Missing verification token.' });
    }

    try {
        const result = await db.query(
            "UPDATE users SET is_email_verified = TRUE, verification_token = NULL WHERE verification_token = $1 RETURNING id, name, email, fpl_team_id, is_email_verified, is_admin",
            [token]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Invalid or expired verification token.' });
        }

        const user = new User(result.rows[0]);
        const newToken = generateToken(user);

        const userWithToken = user.toJson();
        userWithToken.token = newToken;

        // In production, you might redirect here instead of returning JSON
        return res.status(200).json({
            message: 'Email successfully verified. You can now log in with this token.',
            user: userWithToken,
        });

    } catch (e) {
        console.error('PostgreSQL Error during email verification:', e);
        return res.status(500).json({ error: 'Database error during verification.' });
    }
};

const verifyGoogleToken = async (idToken) => {
    try {
        // Use Google's token verification API
        const response = await axios.get(`https://oauth2.googleapis.com/tokeninfo?id_token=${idToken}`);
        const data = response.data;

        // Basic validation: Check if client ID matches and token is valid
        if (data.aud !== process.env.GOOGLE_CLIENT_ID || data.email_verified !== 'true') {
            return null;
        }

        return data; // Returns object with email, name, etc.
    } catch (error) {
        console.error('Google Token Verification Failed:', error.response ? error.response.data : error.message);
        return null;
    }
};

const googleLoginHandler = async (req, res) => {
    const { idToken } = req.body;

    if (!idToken) {
        return res.status(400).json({ error: 'Missing Google ID token.' });
    }

    const googleUser = await verifyGoogleToken(idToken);
    if (!googleUser) {
        return res.status(401).json({ error: 'Invalid Google ID token.' });
    }

    const email = googleUser.email;
    const name = googleUser.name;

    const client = await db.getClient();
    try {
        await client.query('BEGIN');

        // 1. Check if user exists
        let result = await client.query(
            "SELECT id, name, email, fpl_team_id, is_email_verified, is_admin FROM users WHERE email = $1",
            [email]
        );

        let user;

        if (result.rows.length > 0) {
            // User exists
            user = new User(result.rows[0]);
        } else {
            // User does not exist, create a new one
            const dummyPasswordHash = await bcrypt.hash('google_auth_placeholder', 10);

            result = await client.query(
                "INSERT INTO users (name, email, password_hash, is_email_verified, is_admin) VALUES ($1, $2, $3, TRUE, FALSE) RETURNING id, name, email, fpl_team_id, is_email_verified, is_admin",
                [name || 'Google User', email, dummyPasswordHash]
            );
            user = new User(result.rows[0]);
        }

        await client.query('COMMIT');
        
        const token = generateToken(user);
        const userWithToken = user.toJson();
        userWithToken.token = token;

        return res.status(200).json(userWithToken);

    } catch (e) {
        await client.query('ROLLBACK');
        console.error('PostgreSQL Error during Google Login:', e);
        return res.status(500).json({ error: 'Database error during Google login/registration.' });
    } finally {
        client.release();
    }
};

const updateProfileHandler = async (req, res) => {
    // This handler assumes 'protect' middleware has run and req.user exists.
    const userId = req.user.id;
    const { name, email } = req.body; // Can update name and email (if email change is handled carefully)

    if (!name || !email) {
        return res.status(400).json({ error: 'Missing required fields: name and email.' });
    }

    try {
        const result = await db.query(
            "UPDATE users SET name = $1, email = $2 WHERE id = $3 RETURNING id, name, email, fpl_team_id, is_email_verified, is_admin",
            [name, email, userId]
        );

        if (result.rows.length === 0) {
             // This case is unlikely if the token verification passed, but good for safety.
            return res.status(404).json({ error: 'User not found.' });
        }

        const updatedUser = new User(result.rows[0]);
        // Note: Changing email means the current JWT is still valid for the old email,
        // but a new JWT should be generated if the email is a key part of the claim.
        // For simplicity, we just return the updated user data.
        return res.status(200).json(updatedUser.toJson());
    } catch (e) {
        if (e.code === '23505') { // Unique violation for email
            return res.status(409).json({ error: 'This email is already taken.' });
        }
        console.error('PostgreSQL Error updating profile:', e);
        return res.status(500).json({ error: 'Database error while updating profile.' });
    }
};

const changePasswordHandler = async (req, res) => {
    const userId = req.user.id;
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
        return res.status(400).json({ error: 'Missing required fields: oldPassword or newPassword.' });
    }

    if (oldPassword === newPassword) {
        return res.status(400).json({ error: 'New password must be different from the old password.' });
    }

    const client = await db.getClient();
    try {
        await client.query('BEGIN');

        // 1. Get current hash to verify old password
        let result = await client.query(
            "SELECT password_hash FROM users WHERE id = $1",
            [userId]
        );

        if (result.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'User not found.' });
        }

        const storedHash = result.rows[0].password_hash;

        if (!(await bcrypt.compare(oldPassword, storedHash))) {
            await client.query('ROLLBACK');
            return res.status(401).json({ error: 'Invalid current password.' });
        }

        // 2. Hash and update new password
        const newPasswordHash = await bcrypt.hash(newPassword, 10);
        await client.query(
            "UPDATE users SET password_hash = $1 WHERE id = $2",
            [newPasswordHash, userId]
        );

        await client.query('COMMIT');
        return res.status(200).json({ message: 'Password successfully changed.' });

    } catch (e) {
        await client.query('ROLLBACK');
        console.error('PostgreSQL Error changing password:', e);
        return res.status(500).json({ error: 'Database error while changing password.' });
    } finally {
        client.release();
    }
};

const updateFplTeamIdHandler = async (req, res) => {
    const userId = req.user.id;
    const { fplTeamID } = req.body;

    if (!fplTeamID) {
        return res.status(400).json({ error: 'Missing required field: fplTeamID.' });
    }

    try {
        const result = await db.query(
            "UPDATE users SET fpl_team_id = $1 WHERE id = $2 RETURNING id, name, email, fpl_team_id, is_email_verified, is_admin",
            [fplTeamID, userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        const updatedUser = new User(result.rows[0]);
        return res.status(200).json(updatedUser.toJson());
    } catch (e) {
        console.error('PostgreSQL Error updating FPL ID:', e);
        return res.status(500).json({ error: 'Database error while updating FPL ID.' });
    }
};


// --- Admin Handlers ---

const fetchAllUsersHandler = async (req, res) => {
    // Admin check is done by the adminCheck middleware in the route definition

    try {
        const result = await db.query(
            "SELECT id, name, email, fpl_team_id, is_email_verified, is_admin FROM users ORDER BY created_at DESC"
        );

        // Map database rows to User models and then to JSON
        const users = result.rows.map(row => new User(row).toJson());

        return res.status(200).json({ users });
    } catch (e) {
        console.error('PostgreSQL Error fetching all users:', e);
        return res.status(500).json({ error: 'Database error while fetching users.' });
    }
};

module.exports = {
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
};