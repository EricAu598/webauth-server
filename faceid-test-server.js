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

// Enhanced error logging
const logError = (location, error) => {
  console.error(`[ERROR] ${location}:`, error);
  if (error.stack) {
    console.error(error.stack);
  }
};

// Configure Redis client for storing user data and challenges
const redis = new Redis({
  port: 6379,
  host: '127.0.0.1',
  db: 0,
});

// Middleware
app.use(cors({
  origin: ['null', 'file://', 'http://localhost:3000', 'http://localhost', 'http://127.0.0.1:3000', 'http://127.0.0.1', '*'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
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

// Add this helper function after the existing helper functions
const bufferToArrayBuffer = (buffer) => {
  return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
};

// Helper function to determine the appropriate origin based on request
const getLocalOrigin = (req) => {
  // For local development, accept any localhost origin
  if (req.headers.origin && (req.headers.origin.includes('localhost') || req.headers.origin.includes('127.0.0.1'))) {
    return req.headers.origin;
  }
  return 'http://localhost:3000';
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
    logError('Registration', error);
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
    logError('Login', error);
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
        id: 'localhost'
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
    logError('FIDO registration options', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// FIDO registration endpoint - Step 2: Verify registration response
app.post('/api/fido/register/verify', async (req, res) => {
  try {
    const { username, token, attestationResponse, test_mode } = req.body;
    
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
    
    let credential;
    
    // Special test mode for API testing without real hardware
    if (test_mode === 'true') {
      console.log('🧪 TEST MODE: Bypassing WebAuthn cryptographic verification');
      
      // For test mode, generate a simulated credential bypassing verification
      credential = {
        id: attestationResponse.id,
        publicKey: '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMZvbYUAn4WXQ6wTKwGFy2iKAX2K+\nsB20ArreuAO75+ebZJZ1cRYWZCnZbTZGVwgKSGGvYTALZhERiJ2n+oq3dQ==\n-----END PUBLIC KEY-----',
        counter: 0,
        created: new Date().toISOString(),
        authenticatorType: authenticatorType
      };
    } else {
      // Normal mode: Perform full verification
      // Configure Fido2Lib
      const f2l = new Fido2Lib({
        timeout: 60000,
        rpId: 'localhost', // Changed for local testing flexibility
        rpName: 'Face ID Test App',
        challengeSize: 32,
        attestation: 'none',
        cryptoParams: [-7, -257],
        authenticatorAttachment: authenticatorType,
        authenticatorRequireResidentKey: false,
        authenticatorUserVerification: 'preferred'
      });
      
      // Step 1: Create the properly formatted attestation response object
      const attestationResponseObj = {
        id: bufferToArrayBuffer(base64url.toBuffer(attestationResponse.id)),
        rawId: bufferToArrayBuffer(base64url.toBuffer(attestationResponse.rawId)),
        response: {
          clientDataJSON: bufferToArrayBuffer(base64url.toBuffer(attestationResponse.response.clientDataJSON)),
          attestationObject: bufferToArrayBuffer(base64url.toBuffer(attestationResponse.response.attestationObject))
        },
        type: attestationResponse.type
      };
      
      // Step 2: Set attestation expectations
      const attestationExpectations = {
        challenge: expectedChallenge,
        origin: getLocalOrigin(req),
        factor: "either"
      };
      
      // Step 3: Verify the attestation
      const regResult = await f2l.attestationResult(attestationResponseObj, attestationExpectations);
      
      // Step 4: Extract credential information
      credential = {
        id: attestationResponse.id,
        publicKey: regResult.authnrData.get('credentialPublicKeyPem'),
        counter: regResult.authnrData.get('counter'),
        created: new Date().toISOString(),
        authenticatorType: authenticatorType
      };
    }
    
    // Get user data and update credentials regardless of test mode
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
    logError('FIDO registration verification', error);
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
      rpId: 'localhost',
      allowCredentials: fidoCredentials.map(cred => ({
        id: cred.id,
        type: 'public-key',
      })),
      userVerification: 'required',
      timeout: 60000
    };
    
    res.status(200).json(authenticationOptions);
  } catch (error) {
    logError('FIDO authentication options', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// FIDO authentication endpoint - Step 2: Verify authentication response
app.post('/api/fido/authenticate/verify', async (req, res) => {
  try {
    const { username, assertionResponse, test_mode } = req.body;
    
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
    
    // Special test mode for API testing without real hardware
    if (test_mode === 'true') {
      console.log('🧪 TEST MODE: Bypassing WebAuthn cryptographic assertion verification');
      
      // In test mode, we don't need to validate the signature
      // Just need to ensure all required data is present
      if (!assertionResponse.id || !assertionResponse.rawId || 
          !assertionResponse.response || !assertionResponse.response.clientDataJSON || 
          !assertionResponse.response.authenticatorData || !assertionResponse.response.signature) {
        return res.status(400).json({ error: 'Invalid assertion format' });
      }
      
      // Update credential counter
      const updatedCredentials = fidoCredentials.map(cred => {
        if (cred.id === assertionResponse.id) {
          return {
            ...cred,
            counter: (cred.counter || 0) + 1
          };
        }
        return cred;
      });
      
      // Update user credentials in Redis
      await redis.hset(`user:${username}`, 'fidoCredentials', JSON.stringify(updatedCredentials));
      
      // Remove challenge
      await redis.del(`challenge:${username}`);
      
      // Generate session token
      const sessionToken = crypto.randomBytes(32).toString('hex');
      await redis.setex(`session:${sessionToken}`, 3600, username);
      
      return res.status(200).json({ 
        message: 'Authentication successful (TEST MODE)',
        token: sessionToken,
        authenticatorType: credential.authenticatorType || 'platform'
      });
    }
    
    // Normal mode - full verification
    // Configure Fido2Lib
    const f2l = new Fido2Lib({
      timeout: 60000,
      rpId: 'localhost', // Use localhost consistently
      rpName: 'Face ID Test App',
      challengeSize: 32,
      attestation: 'none',
      cryptoParams: [-7, -257],
      authenticatorAttachment: credential.authenticatorType || 'platform',
      authenticatorRequireResidentKey: false,
      authenticatorUserVerification: 'preferred'
    });
    
    // Prepare assertion data for verification
    const idBuffer = base64url.toBuffer(assertionResponse.id);
    const rawIdBuffer = base64url.toBuffer(assertionResponse.rawId);
    const clientDataJSONBuffer = base64url.toBuffer(assertionResponse.response.clientDataJSON);
    const authenticatorDataBuffer = base64url.toBuffer(assertionResponse.response.authenticatorData);
    const signatureBuffer = base64url.toBuffer(assertionResponse.response.signature);
    
    let userHandleArrayBuffer = null;
    if (assertionResponse.response.userHandle) {
      const userHandleBuffer = base64url.toBuffer(assertionResponse.response.userHandle);
      userHandleArrayBuffer = bufferToArrayBuffer(userHandleBuffer);
    }
    
    const assertionResponseObj = {
      id: bufferToArrayBuffer(idBuffer),
      rawId: bufferToArrayBuffer(rawIdBuffer),
      response: {
        clientDataJSON: bufferToArrayBuffer(clientDataJSONBuffer),
        authenticatorData: bufferToArrayBuffer(authenticatorDataBuffer),
        signature: bufferToArrayBuffer(signatureBuffer),
        userHandle: userHandleArrayBuffer
      },
      type: assertionResponse.type
    };
    
    // Verify the assertion
    const assertionExpectations = {
      challenge: expectedChallenge,
      origin: getLocalOrigin(req),
      factor: 'either',
      publicKey: credential.publicKey,
      prevCounter: credential.counter,
      userHandle: base64url.encode(username)
    };
    
    const authnResult = await f2l.assertionResult(
      assertionResponseObj,
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
      authenticatorType: credential.authenticatorType || 'platform'
    });
  } catch (error) {
    logError('FIDO authentication verification', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Face ID test server running on port ${PORT}`);
}); 