/**
 * Standalone Face ID Login Testing Server - Vercel Deployment Version
 * 
 * This server provides a simple environment for testing Face ID (WebAuthn/FIDO2) authentication
 * without dependencies on the main application.
 */

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { Fido2Lib } = require('fido2-lib');
const crypto = require('crypto');
const base64url = require('base64url');
const bcrypt = require('bcrypt');
const path = require('path');
const morgan = require('morgan');
const helmet = require('helmet');

// Import Vercel KV (Redis alternative for Vercel)
const { kv } = require('@vercel/kv');

// Create Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? [process.env.VERCEL_URL, process.env.ALLOWED_ORIGIN] 
    : ['null', 'file://', 'http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true
}));
app.use(bodyParser.json());
app.use(morgan('dev')); // Logging
app.use(helmet({
  contentSecurityPolicy: false, // Disabled for testing purposes
}));

// In-memory user store for testing (in production, use a database)
const users = {};

// Import the rest of your routes and logic from faceid-test-server.js
// but replace all redis.* calls with kv.* calls

// Example of how to adapt Redis functions to Vercel KV:
// Original: await redis.set(key, value, 'EX', 600);
// Adapted: await kv.set(key, value, { ex: 600 });

// Original: const value = await redis.get(key);
// Adapted: const value = await kv.get(key);

// Export the Express app for Vercel
module.exports = app;

// Only start the server if running locally, not on Vercel
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`Face ID test server running on port ${PORT}`);
  });
} 