<p align="center">
  <a href="https://scalekit.com" target="_blank" rel="noopener noreferrer">
    <picture>
      <img src="https://cdn.scalekit.cloud/v1/scalekit-logo-dark.svg" height="64">
    </picture>
  </a>
</p>

<h1 align="center">
  Scalekit Node.js Example Apps
</h1>

<p align="center">
  <strong>Auth stack for AI apps ⚡ Human auth capabilities</strong>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@scalekit-sdk/node"><img src="https://img.shields.io/npm/v/@scalekit-sdk/node.svg" alt="npm version"></a>
  <a href="https://github.com/scalekit-inc/nodejs-example-apps/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://docs.scalekit.com"><img src="https://img.shields.io/badge/docs-scalekit.com-blue" alt="Documentation"></a>
</p>

<p align="center">
  Production-ready Node.js applications showcasing enterprise authentication and admin portal integration
</p>

## 🚀 Available Examples

### 1. Embedded Admin Portal
**Enterprise-grade admin interface integration**

- **OAuth 2.0 Client Credentials**: Secure server-to-server authentication
- **Portal Link Generation**: Dynamic admin portal URLs with proper security
- **iframe Integration**: Seamless embedding with CSP headers and security policies
- **Session Management**: Secure token handling and refresh mechanisms

**Key Implementation Files:**
- `embed-admin-portal-sample/index.js` - Express server with portal integration
- `embed-admin-portal-sample/libraries/auth.js` - OAuth token management
- `embed-admin-portal-sample/libraries/scalekit.js` - Portal URL generation and validation

### 2. Enterprise Authentication
**Server-side authentication patterns**

- **OAuth 2.0 Flows**: Authorization code and client credentials patterns
- **Token Management**: Secure credential storage and rotation
- **Error Handling**: Comprehensive error scenarios and recovery
- **API Integration**: Direct Scalekit API interactions for user management

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

## Key Features

- **Enterprise SSO**: SAML 2.0 and OIDC protocol support
- **Admin Portal**: White-labeled administration interface
- **User Management**: Complete organization user lifecycle
- **Directory Sync**: SCIM 2.0 automated provisioning
- **OAuth Security**: Client credentials and authorization code flows
- **Error Handling**: Production-ready error management and logging

## Additional Resources

- 📚 [Scalekit Documentation](https://docs.scalekit.com)
- 🔧 [API Reference](https://docs.scalekit.com/apis/)
- 🚀 [Full Stack Auth Quickstart](https://docs.scalekit.com/fsa/quickstart/)
- 🔗 [SSO Integration Guide](https://docs.scalekit.com/sso/quickstart/)
- 💬 [Community Examples](https://github.com/orgs/scalekit-developers/repositories)
- ⚡ [Node.js SDK](https://github.com/scalekit-inc/scalekit-sdk-node)

## Support

For assistance, please contact Scalekit support or open an issue in this repository.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

<p align="center">
  Made with ❤️ by <a href="https://scalekit.com">Scalekit</a>
</p>
