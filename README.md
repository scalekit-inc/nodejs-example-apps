# Node.js Example Apps

This repository contains Node.js example applications demonstrating how to integrate with Scalekit services.

## Available Examples

### 1. Embed Admin Portal
This example shows how to embed a Scalekit admin portal in your Node.js application. It demonstrates:
- Authentication flow using OAuth 2.0 client credentials
- Generating portal links
- Serving the portal in an iframe with proper security headers

**Key Files:**
- `embed-admin-portal-sample/index.js` - Main application server
- `embed-admin-portal-sample/libraries/auth.js` - Authentication helper
- `embed-admin-portal-sample/libraries/scalekit.js` - Portal link generation

### 2. Authentication Example
This example demonstrates how to implement authentication using Scalekit's authentication services. It shows:
- OAuth 2.0 token acquisition
- Secure credential management
- Error handling for authentication flows

## Getting Started

### Prerequisites
- Node.js (v16 or higher)
- Scalekit credentials (client ID and secret)
- .env file with required environment variables

### Installation
1. Clone this repository
2. Navigate to the desired example directory
3. Run `npm install` to install dependencies
4. Create a `.env` file with your credentials
5. Run `npm start` to launch the application

## Environment Variables
Each example requires specific environment variables. Refer to the example's README for details.

## Contributing
We welcome contributions! Please follow these guidelines:
1. Fork the repository
2. Create a new branch for your feature
3. Submit a pull request with a clear description of changes

## Support
For assistance, please contact Scalekit support or open an issue in this repository.

## License
This project is licensed under the MIT License - see the LICENSE file for details.
