/**
 * Standalone Face ID Login Testing Server
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
const Redis = require('ioredis');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');
const morgan = require('morgan');
const helmet = require('helmet');

// Create Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Configure Redis client for storing user data and challenges
const redis = new Redis({
  port: 6379,
  host: '127.0.0.1',
  db: 0,
});

// Middleware
app.use(cors({
  origin: ['null', 'file://', 'http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true
}));
app.use(bodyParser.json());
app.use(morgan('dev')); // Logging
app.use(helmet({
  contentSecurityPolicy: false, // Disabled for testing purposes
}));
app.use(express.static(path.join(__dirname, 'public')));

// In-memory user store for testing (in production, use a database)
const users = {};

// Create public directory if it doesn't exist
const publicDir = path.join(__dirname, 'public');
if (!fs.existsSync(publicDir)) {
  fs.mkdirSync(publicDir);
}

// Helper functions
const generateSalt = async () => {
  return bcrypt.genSalt(10);
};

const hashPassword = async (password) => {
  const salt = await generateSalt();
  return bcrypt.hash(password, salt);
};

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// User registration endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    // Check if user already exists
    const userExists = await redis.exists(`user:${username}`);
    if (userExists) {
      return res.status(409).json({ error: 'User already exists' });
    }
    
    // Hash password
    const hashedPassword = await hashPassword(password);
    
    // Store user in Redis
    await redis.hset(`user:${username}`, {
      username,
      password: hashedPassword,
      fidoCredentials: JSON.stringify([]),
      createdAt: new Date().toISOString()
    });
    
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// User login endpoint (password-based)
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    // Get user from Redis
    const userExists = await redis.exists(`user:${username}`);
    if (!userExists) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const userData = await redis.hgetall(`user:${username}`);
    
    // Verify password
    const isPasswordValid = await bcrypt.compare(password, userData.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate session token
    const sessionToken = crypto.randomBytes(32).toString('hex');
    await redis.setex(`session:${sessionToken}`, 3600, username);
    
    res.status(200).json({ 
      message: 'Login successful',
      token: sessionToken,
      hasFidoCredentials: JSON.parse(userData.fidoCredentials || '[]').length > 0
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// FIDO registration endpoint - Step 1: Get registration options
app.post('/api/fido/register', async (req, res) => {
  try {
    const { username, token, authenticatorType = 'platform' } = req.body;
    
    // Verify session token
    const storedUsername = await redis.get(`session:${token}`);
    if (!storedUsername || storedUsername !== username) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    // Generate challenge
    const challenge = crypto.randomBytes(32);
    const challengeBase64 = base64url.encode(challenge);
    
    // Store challenge in Redis
    await redis.setex(`challenge:${username}`, 300, challengeBase64);
    
    // Create registration options
    const registrationOptions = {
      challenge: challengeBase64,
      rp: {
        name: 'Face ID Test App',
        id: req.hostname
      },
      user: {
        id: base64url.encode(username),
        name: username,
        displayName: username
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },  // ES256
        { type: 'public-key', alg: -257 } // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: authenticatorType, // 'platform' for Face ID, 'cross-platform' for security keys, undefined for any
        userVerification: 'preferred', // Changed from 'required' to 'preferred' for better compatibility
        requireResidentKey: false,
        residentKey: 'preferred' // For Chrome profile fingerprinting
      },
      timeout: 60000,
      attestation: 'none'
    };
    
    // Store the authenticator type for verification
    await redis.setex(`authenticator:${username}`, 300, authenticatorType);
    
    res.status(200).json(registrationOptions);
  } catch (error) {
    console.error('FIDO registration options error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// FIDO registration endpoint - Step 2: Verify registration response
app.post('/api/fido/register/verify', async (req, res) => {
  try {
    const { username, token, attestationResponse } = req.body;
    
    // Verify session token
    const storedUsername = await redis.get(`session:${token}`);
    if (!storedUsername || storedUsername !== username) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    // Get stored challenge
    const expectedChallenge = await redis.get(`challenge:${username}`);
    if (!expectedChallenge) {
      return res.status(400).json({ error: 'Challenge expired or not found' });
    }
    
    // Get stored authenticator type
    const authenticatorType = await redis.get(`authenticator:${username}`) || 'platform';
    
    // Configure Fido2Lib
    const f2l = new Fido2Lib({
      timeout: 60000,
      rpId: req.hostname,
      rpName: 'Face ID Test App',
      challengeSize: 32,
      attestation: 'none',
      cryptoParams: [-7, -257],
      authenticatorAttachment: authenticatorType, // Use the stored authenticator type
      authenticatorRequireResidentKey: false,
      authenticatorUserVerification: 'preferred' // Changed from 'required' to 'preferred'
    });
    
    // Prepare clientData and attestationObject
    const clientDataJSON = base64url.decode(attestationResponse.response.clientDataJSON);
    const attestationObject = base64url.toBuffer(attestationResponse.response.attestationObject);
    const clientData = JSON.parse(clientDataJSON.toString('utf8'));
    
    // Verify the attestation
    const attestationExpectations = {
      challenge: expectedChallenge,
      origin: `https://${req.hostname}`,
      factor: 'either'
    };
    
    const regResult = await f2l.attestationResult(attestationObject, clientData, attestationExpectations);
    
    // Extract credential information
    const credential = {
      id: attestationResponse.id,
      publicKey: regResult.authnrData.get('credentialPublicKeyPem'),
      counter: regResult.authnrData.get('counter'),
      created: new Date().toISOString(),
      authenticatorType: authenticatorType // Store the authenticator type with the credential
    };
    
    // Get user data
    const userData = await redis.hgetall(`user:${username}`);
    
    // Update user's FIDO credentials
    const fidoCredentials = JSON.parse(userData.fidoCredentials || '[]');
    fidoCredentials.push(credential);
    
    await redis.hset(`user:${username}`, 'fidoCredentials', JSON.stringify(fidoCredentials));
    
    // Remove challenge and authenticator type
    await redis.del(`challenge:${username}`);
    await redis.del(`authenticator:${username}`);
    
    res.status(200).json({ 
      message: 'Authentication method registered successfully',
      credential: {
        id: credential.id,
        created: credential.created,
        authenticatorType: credential.authenticatorType
      }
    });
  } catch (error) {
    console.error('FIDO registration verification error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// FIDO authentication endpoint - Step 1: Get authentication options
app.post('/api/fido/authenticate', async (req, res) => {
  try {
    const { username } = req.body;
    
    // Get user data
    const userExists = await redis.exists(`user:${username}`);
    if (!userExists) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const userData = await redis.hgetall(`user:${username}`);
    const fidoCredentials = JSON.parse(userData.fidoCredentials || '[]');
    
    if (fidoCredentials.length === 0) {
      return res.status(400).json({ error: 'No Face ID credentials found for this user' });
    }
    
    // Generate challenge
    const challenge = crypto.randomBytes(32);
    const challengeBase64 = base64url.encode(challenge);
    
    // Store challenge in Redis
    await redis.setex(`challenge:${username}`, 300, challengeBase64);
    
    // Create authentication options
    const authenticationOptions = {
      challenge: challengeBase64,
      rpId: req.hostname,
      allowCredentials: fidoCredentials.map(cred => ({
        id: cred.id,
        type: 'public-key',
      })),
      userVerification: 'required',
      timeout: 60000
    };
    
    res.status(200).json(authenticationOptions);
  } catch (error) {
    console.error('FIDO authentication options error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// FIDO authentication endpoint - Step 2: Verify authentication response
app.post('/api/fido/authenticate/verify', async (req, res) => {
  try {
    const { username, assertionResponse } = req.body;
    
    // Get user data
    const userExists = await redis.exists(`user:${username}`);
    if (!userExists) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const userData = await redis.hgetall(`user:${username}`);
    const fidoCredentials = JSON.parse(userData.fidoCredentials || '[]');
    
    // Find the credential that matches the ID in the assertion
    const credential = fidoCredentials.find(cred => cred.id === assertionResponse.id);
    if (!credential) {
      return res.status(400).json({ error: 'Credential not found' });
    }
    
    // Get stored challenge
    const expectedChallenge = await redis.get(`challenge:${username}`);
    if (!expectedChallenge) {
      return res.status(400).json({ error: 'Challenge expired or not found' });
    }
    
    // Configure Fido2Lib
    const f2l = new Fido2Lib({
      timeout: 60000,
      rpId: req.hostname,
      rpName: 'Face ID Test App',
      challengeSize: 32,
      attestation: 'none',
      cryptoParams: [-7, -257],
      authenticatorAttachment: credential.authenticatorType || 'platform', // Use the stored authenticator type
      authenticatorRequireResidentKey: false,
      authenticatorUserVerification: 'preferred' // Changed from 'required' to 'preferred'
    });
    
    // Prepare clientData and authenticatorData
    const clientDataJSON = base64url.decode(assertionResponse.response.clientDataJSON);
    const authenticatorData = base64url.toBuffer(assertionResponse.response.authenticatorData);
    const signature = base64url.toBuffer(assertionResponse.response.signature);
    const clientData = JSON.parse(clientDataJSON.toString('utf8'));
    
    // Verify the assertion
    const assertionExpectations = {
      challenge: expectedChallenge,
      origin: `https://${req.hostname}`,
      factor: 'either',
      publicKey: credential.publicKey,
      prevCounter: credential.counter,
      userHandle: base64url.encode(username)
    };
    
    const authnResult = await f2l.assertionResult(
      assertionResponse,
      assertionExpectations
    );
    
    // Update credential counter
    const updatedCredentials = fidoCredentials.map(cred => {
      if (cred.id === assertionResponse.id) {
        return {
          ...cred,
          counter: authnResult.authnrData.get('counter')
        };
      }
      return cred;
    });
    
    await redis.hset(`user:${username}`, 'fidoCredentials', JSON.stringify(updatedCredentials));
    
    // Remove challenge
    await redis.del(`challenge:${username}`);
    
    // Generate session token
    const sessionToken = crypto.randomBytes(32).toString('hex');
    await redis.setex(`session:${sessionToken}`, 3600, username);
    
    res.status(200).json({ 
      message: 'Authentication successful',
      token: sessionToken,
      authenticatorType: credential.authenticatorType || 'platform' // Return the authenticator type
    });
  } catch (error) {
    console.error('FIDO authentication verification error:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Face ID test server running on port ${PORT}`);
}); 