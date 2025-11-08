// index.js - Main Express Server Entrypoint

const express = require('express');
const cors = require('cors');
require('dotenv').config(); // Load environment variables
require('./db'); // Initialize database connection pool

const authRoutes = require('./routes/authRoutes');

const app = express();
const PORT = process.env.PORT || 8080;

// --- Middleware Setup (Dart's Pipeline and CORS) ---

// CORS Middleware
app.use(cors({
    origin: '*', // Allows all origins, matching Dart's setup
    methods: 'GET, POST, PUT, DELETE, OPTIONS',
    allowedHeaders: 'Origin, Content-Type, Authorization',
}));

// Body Parser Middleware for JSON requests
app.use(express.json());

// Request logging middleware (simple version of Dart's logRequests)
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

// --- Public Routes (Dart's appRouter.get('/')) ---
app.get('/', (req, res) => {
    res.status(200).send('Jersey Premier League Backend API is running!');
});

// --- API Router Setup (Dart's appRouter) ---
app.use('/api', authRoutes);


// --- Start the Server ---
app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
});