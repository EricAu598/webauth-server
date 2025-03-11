# Face ID Login Testing Server

A standalone server for testing Face ID (WebAuthn/FIDO2) authentication without dependencies on the main application.

## Features

- User registration and login with password
- Face ID registration for registered users
- Face ID authentication
- Simple web interface for testing
- Redis for data storage

## Prerequisites

- Node.js (v14 or higher)
- Redis server running on localhost:6379
- For Face ID testing: A device with biometric capabilities (e.g., MacBook with Touch ID, iPhone with Face ID)
- HTTPS connection (for production) or localhost (for development)

## Installation

1. Clone this repository:
   ```
   git clone <repository-url>
   cd faceid-test-server
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Make sure Redis is running:
   ```
   redis-server
   ```

4. Start the server:
   ```
   node faceid-test-server.js
   ```

5. Open your browser and navigate to:
   ```
   http://localhost:3000
   ```

## Usage

### 1. Register a New User

- Navigate to the "Register" tab
- Enter your email and password
- Click "Register"

### 2. Login with Password

- Navigate to the "Login" tab
- Enter your email and password
- Click "Login"
- Note: After successful login, you'll receive a session token that will be automatically filled in the Face ID registration form

### 3. Register Face ID

- Navigate to the "Register Face ID" tab
- Your email and session token should be pre-filled if you just logged in
- Click "Register Face ID"
- Follow the Face ID/Touch ID prompt on your device

### 4. Login with Face ID

- Navigate to the "Login with Face ID" tab
- Enter your email
- Click "Login with Face ID"
- Follow the Face ID/Touch ID prompt on your device

## API Endpoints

### User Management

- `POST /api/register` - Register a new user
- `POST /api/login` - Login with username and password

### Face ID Registration

- `POST /api/fido/register` - Get registration options
- `POST /api/fido/register/verify` - Verify registration response

### Face ID Authentication

- `POST /api/fido/authenticate` - Get authentication options
- `POST /api/fido/authenticate/verify` - Verify authentication response

## Security Notes

This server is designed for testing purposes only and includes several simplifications:

1. Uses HTTP instead of HTTPS (WebAuthn typically requires HTTPS except on localhost)
2. Stores data in Redis without encryption
3. Has minimal error handling and logging
4. No rate limiting or other security protections

For production use, you would need to:

1. Use HTTPS
2. Implement proper data encryption
3. Add comprehensive error handling
4. Implement rate limiting and other security measures
5. Use a more robust database solution

## WebAuthn/FIDO2 Compatibility

This implementation uses the `fido2-lib` package and follows the WebAuthn Level 2 specification. It should work with:

- Safari on macOS (Touch ID)
- Safari on iOS (Face ID)
- Chrome on Android (fingerprint)
- Windows Hello on Edge/Chrome (facial recognition, fingerprint)

## Troubleshooting

### Face ID Not Working

1. Make sure you're using a compatible browser and device
2. For development, ensure you're using localhost (not an IP address)
3. Check browser console for errors
4. Verify that your device has biometric capabilities enabled

### Redis Connection Issues

1. Ensure Redis server is running: `redis-server`
2. Check Redis connection settings in the server code

## License

MIT
