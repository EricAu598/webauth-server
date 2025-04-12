/**
 * API Test Script for Face ID Test Server
 * 
 * This script tests all the API endpoints of the Face ID server to verify they're working correctly.
 * It doesn't test actual WebAuthn operations (which require browser interaction) but ensures
 * endpoints respond properly to valid requests.
 */

const fetch = require('node-fetch');
const crypto = require('crypto');
const base64url = require('base64url');
const cbor = require('cbor');

// Configuration
const API_BASE_URL = 'http://localhost:3000';
const TEST_USER = {
  username: `test-${Date.now()}@example.com`,
  password: 'TestPassword123!'
};

// Test runner
async function runTests() {
  console.log('🧪 Starting API endpoint tests');
  console.log('----------------------------');
  console.log(`Test user: ${TEST_USER.username}`);
  console.log('----------------------------\n');

  let sessionToken;
  let mockCredentialId;
  
  try {
    // Test 1: User registration
    console.log('Test 1: User Registration');
    const registrationResult = await testRegistration(TEST_USER);
    logResult('Registration', registrationResult);
    
    // Test 2: User login
    console.log('\nTest 2: User Login');
    const loginResult = await testLogin(TEST_USER);
    logResult('Login', loginResult);
    
    if (loginResult.success) {
      sessionToken = loginResult.data.token;
      console.log(`Session token obtained: ${sessionToken.slice(0, 10)}...`);
      
      // Test 3: FIDO registration options
      console.log('\nTest 3: FIDO Registration Options');
      const fidoRegOptionsResult = await testFidoRegistrationOptions(TEST_USER.username, sessionToken);
      logResult('FIDO Registration Options', fidoRegOptionsResult);
      
      // Test 3.1: Mock FIDO Registration (API Only)
      if (fidoRegOptionsResult.success) {
        console.log('\nTest 3.1: Mock FIDO Registration (API Only)');
        const fidoRegMockResult = await testMockFidoRegistration(
          TEST_USER.username, 
          sessionToken,
          fidoRegOptionsResult.data.challenge
        );
        logResult('Mock FIDO Registration', fidoRegMockResult);
        
        // Save the credential ID for authentication tests if registration succeeded
        if (fidoRegMockResult.success && fidoRegMockResult.data && fidoRegMockResult.data.credential) {
          mockCredentialId = fidoRegMockResult.data.credential.id;
          console.log(`Mock credential ID created: ${mockCredentialId}`);
        }
      }
      
      // Test 4: FIDO authentication options
      console.log('\nTest 4: FIDO Authentication Options');
      const fidoAuthOptionsResult = await testFidoAuthenticationOptions(TEST_USER.username);
      logResult('FIDO Authentication Options', fidoAuthOptionsResult);
      
      // Test 4.1: Mock FIDO Authentication (API Only)
      if (fidoAuthOptionsResult.success && fidoAuthOptionsResult.data && fidoAuthOptionsResult.data.challenge) {
        console.log('\nTest 4.1: Mock FIDO Authentication (API Only)');
        const fidoAuthMockResult = await testMockFidoAuthentication(
          TEST_USER.username,
          mockCredentialId, // This will likely be undefined unless registration succeeded
          fidoAuthOptionsResult.data.challenge
        );
        logResult('Mock FIDO Authentication', fidoAuthMockResult);
      }
      
      // Note: We can't actually test the complete FIDO flow as it requires browser WebAuthn API
      console.log('\nNote: Full WebAuthn testing requires browser interaction with biometric hardware.');
      console.log('The mock tests attempt to verify API endpoint structure only, not actual WebAuthn verification.');
    }
    
    console.log('\n----------------------------');
    console.log('🎉 API endpoint tests completed');
    process.exit(0);
  } catch (error) {
    console.error('❌ Test failed with error:', error);
    process.exit(1);
  }
}

// Helper function to log test results
function logResult(testName, result) {
  if (result.success) {
    console.log(`✅ ${testName} succeeded`);
    if (result.details) {
      console.log(`   Details: ${result.details}`);
    }
  } else {
    console.log(`❌ ${testName} failed: ${result.error}`);
    if (result.details) {
      console.log(`   Details: ${result.details}`);
    }
  }
}

// Test user registration
async function testRegistration(user) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username: user.username,
        password: user.password
      })
    });
    
    const data = await response.json();
    
    if (response.ok) {
      return {
        success: true,
        data,
        details: 'User created successfully'
      };
    } else {
      return {
        success: false,
        error: data.error || 'Unknown error',
        details: `Status: ${response.status}`
      };
    }
  } catch (error) {
    return {
      success: false,
      error: error.message,
      details: 'Network or server error'
    };
  }
}

// Test user login
async function testLogin(user) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username: user.username,
        password: user.password
      })
    });
    
    const data = await response.json();
    
    if (response.ok) {
      return {
        success: true,
        data,
        details: `User logged in successfully. Has FIDO credentials: ${data.hasFidoCredentials}`
      };
    } else {
      return {
        success: false,
        error: data.error || 'Unknown error',
        details: `Status: ${response.status}`
      };
    }
  } catch (error) {
    return {
      success: false,
      error: error.message,
      details: 'Network or server error'
    };
  }
}

// Test FIDO registration options
async function testFidoRegistrationOptions(username, token) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/fido/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username,
        token,
        authenticatorType: 'platform' // Test with platform (Face ID/Touch ID)
      })
    });
    
    const data = await response.json();
    
    if (response.ok) {
      return {
        success: true,
        data,
        details: `Got registration options with challenge: ${data.challenge.slice(0, 10)}...`
      };
    } else {
      return {
        success: false,
        error: data.error || 'Unknown error',
        details: `Status: ${response.status}`
      };
    }
  } catch (error) {
    return {
      success: false,
      error: error.message,
      details: 'Network or server error'
    };
  }
}

// Test FIDO authentication options
async function testFidoAuthenticationOptions(username) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/fido/authenticate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username
      })
    });
    
    const data = await response.json();
    
    // Note: This will likely fail for a newly created test user as they won't have FIDO credentials yet
    // We're just testing if the endpoint responds correctly
    
    if (response.ok) {
      return {
        success: true,
        data,
        details: `Got authentication options with challenge: ${data.challenge.slice(0, 10)}...`
      };
    } else {
      // For this test, a 400 error about no FIDO credentials is actually expected and OK
      if (response.status === 400 && data.error && data.error.includes('No Face ID credentials found')) {
        return {
          success: true,
          error: data.error,
          details: 'Expected error for new user without FIDO credentials'
        };
      }
      
      return {
        success: false,
        error: data.error || 'Unknown error',
        details: `Status: ${response.status}`
      };
    }
  } catch (error) {
    return {
      success: false,
      error: error.message,
      details: 'Network or server error'
    };
  }
}

// Mock WebAuthn registration (simulates attestation)
async function testMockFidoRegistration(username, token, challenge) {
  try {
    // Create a mock attestation response
    // This won't be valid for actual WebAuthn verification but tests the API endpoint format
    const mockAttestationResponse = createMockAttestationResponse(challenge);
    
    console.log('Sending mock attestation response:', JSON.stringify(mockAttestationResponse, null, 2));
    
    const response = await fetch(`${API_BASE_URL}/api/fido/register/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username,
        token,
        attestationResponse: mockAttestationResponse,
        test_mode: 'true' // Enable test mode to bypass cryptographic verification
      })
    });
    
    const data = await response.json();
    
    console.log('Server response for mock registration:', JSON.stringify(data, null, 2));
    
    return {
      success: !data.error,
      data,
      error: data.error,
      details: data.error ? 
        `Mock registration verification failed: ${data.error}${data.details ? ' - ' + data.details : ''}` : 
        'Note: Mock registration successful (test mode)'
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
      details: 'Network or server error in mock FIDO registration'
    };
  }
}

// Creates a mock attestation response with the required structure
function createMockAttestationResponse(challenge) {
  // Generate random credential ID (16 bytes)
  const rawId = crypto.randomBytes(16);
  const id = base64url.encode(rawId);
  
  // Create mock clientDataJSON with the challenge we received from the server
  const clientData = {
    type: 'webauthn.create',
    challenge: challenge,
    origin: 'http://localhost:3000',
    crossOrigin: false
  };
  
  // Convert clientData to proper base64url JSON string
  const clientDataJSON = base64url.encode(JSON.stringify(clientData));
  
  // Create mock authData (authenticator data) following WebAuthn spec structure
  // https://www.w3.org/TR/webauthn-2/#authenticator-data
  
  // 1. RP ID Hash (32 bytes) - SHA256 hash of "localhost"
  const rpIdHash = crypto.createHash('sha256').update('localhost').digest();
  
  // 2. Flags (1 byte) - bit 0: User Present, bit 6: Attested Credential Data Present
  const flags = Buffer.from([0x41]); // 01000001 in binary
  
  // 3. Counter (4 bytes)
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(1, 0); // Initial counter value of 1
  
  // 4. AAGUID (16 bytes) - all zeros for test
  const aaguid = Buffer.alloc(16);
  
  // 5. Credential ID Length (2 bytes)
  const credIdLen = Buffer.alloc(2);
  credIdLen.writeUInt16BE(rawId.length, 0);
  
  // 6. Credential ID (variable length - 16 bytes in our case)
  
  // 7. Credential Public Key (COSE_Key format) - creating a minimal one
  // COSE_Key for ES256
  const cosePublicKey = Buffer.from([
    0xa5, // Map of 5 items
    0x01, 0x02, // kty: EC2 key type
    0x03, 0x26, // alg: ES256 (-7)
    0x20, 0x01, // crv: P-256
    0x21, 0x58, 0x20, // x-coord, byte string of 32 bytes
    // 32 bytes for X coordinate
    ...crypto.randomBytes(32),
    0x22, 0x58, 0x20, // y-coord, byte string of 32 bytes
    // 32 bytes for Y coordinate
    ...crypto.randomBytes(32)
  ]);
  
  // Combine all the pieces together
  const authData = Buffer.concat([
    rpIdHash,      // 32 bytes
    flags,         // 1 byte
    counter,       // 4 bytes
    aaguid,        // 16 bytes
    credIdLen,     // 2 bytes
    rawId,         // 16 bytes
    cosePublicKey  // variable (71 bytes in our case)
  ]);
  
  // Create attestation object
  const attestationObject = {
    fmt: 'none',
    attStmt: {},
    authData: authData
  };
  
  // Encode attestation object as CBOR
  const attestationObjectBuffer = cbor.encode(attestationObject);
  
  // Create final attestation response
  return {
    id,
    rawId: base64url.encode(rawId),
    response: {
      clientDataJSON,
      attestationObject: base64url.encode(attestationObjectBuffer)
    },
    type: 'public-key'
  };
}

// Create a mock assertion response for testing
function createMockAssertionResponse(challenge, credentialId) {
  // Create mock clientDataJSON
  const clientData = {
    type: 'webauthn.get',
    challenge: challenge,
    origin: 'http://localhost:3000',
    crossOrigin: false
  };
  
  // Convert to base64url JSON string
  const clientDataJSON = base64url.encode(JSON.stringify(clientData));
  
  // Create authenticator data
  // 1. RP ID Hash (32 bytes) - SHA256 hash of "localhost"
  const rpIdHash = crypto.createHash('sha256').update('localhost').digest();
  
  // 2. Flags (1 byte) - bit 0: User Present
  const flags = Buffer.from([0x01]); // 00000001 in binary
  
  // 3. Counter (4 bytes)
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(1, 0); // Counter value of 1
  
  // Combine to create authenticator data
  const authenticatorData = Buffer.concat([rpIdHash, flags, counter]);
  
  // Create mock signature (64 bytes for ES256)
  const signature = crypto.randomBytes(64);
  
  // Credential ID from parameter or generate a new one
  const rawId = credentialId ? 
    Buffer.from(base64url.toBuffer(credentialId)) : 
    crypto.randomBytes(16);
  const id = base64url.encode(rawId);
  
  // Create assertion response
  return {
    id,
    rawId: base64url.encode(rawId),
    response: {
      clientDataJSON,
      authenticatorData: base64url.encode(authenticatorData),
      signature: base64url.encode(signature),
      userHandle: base64url.encode(Buffer.from('test-user-handle'))
    },
    type: 'public-key'
  };
}

// Add new test after the mock FIDO registration test
// This won't pass in most cases as it requires a previously registered credential ID
// But it will test if the endpoint responds correctly to the format
async function testMockFidoAuthentication(username, credentialId, challenge) {
  try {
    // Create a mock assertion response
    const mockAssertionResponse = createMockAssertionResponse(challenge, credentialId);
    
    console.log('Sending mock assertion response:', JSON.stringify(mockAssertionResponse, null, 2));
    
    const response = await fetch(`${API_BASE_URL}/api/fido/authenticate/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        username,
        assertionResponse: mockAssertionResponse,
        test_mode: 'true' // Enable test mode to bypass cryptographic verification
      })
    });
    
    const data = await response.json();
    
    console.log('Server response for mock authentication:', JSON.stringify(data, null, 2));
    
    return {
      success: !data.error,
      data,
      error: data.error,
      details: data.error ? 
        `Mock authentication verification failed: ${data.error}${data.details ? ' - ' + data.details : ''}` : 
        'Note: Mock authentication successful (test mode)'
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
      details: 'Network or server error in mock FIDO authentication'
    };
  }
}

// Run the tests
runTests();
