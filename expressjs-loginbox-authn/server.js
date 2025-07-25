import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import { Scalekit } from '@scalekit-sdk/node';
import jwt from 'jsonwebtoken';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import axios from 'axios';
import cookieParser from 'cookie-parser';
import { validateEnvironmentVariables } from './utils/utilities.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// JWT secret for token validation (in production, use a strong key from env)
const JWT_SECRET =
  process.env.JWT_SECRET || 'your-jwt-secret-key-change-in-production';

// Environment check
const isProduction = process.env.NODE_ENV === 'production';

// Refresh token storage - in production use Redis or a database
const refreshTokenStore = new Map();

const app = express();

const redirectUri = 'http://localhost:3000/api/callback';

// Initialize Scalekit with error handling
let scalekit;
try {
  scalekit = validateEnvironmentVariables();
} catch (error) {
  console.error('Failed to initialize Scalekit:', error.message);
  process.exit(1);
}

// Global error handler for uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('\n🚨 Uncaught Exception:');
  console.error('Error:', error.message);

  // Handle specific Scalekit SDK errors
  if (error.response && error.response.status === 401) {
    const errorData = error.response.data;
    if (errorData && errorData.error === 'invalid_client') {
      console.error('\n❌ Authentication Error: Invalid Client Credentials');
      console.error('\nThis error occurs when:');
      console.error(
        '1. Your SCALEKIT_CLIENT_ID or SCALEKIT_CLIENT_SECRET is incorrect'
      );
      console.error('2. Your Scalekit application is not properly configured');
      console.error("3. You're using credentials from a different environment");
      console.error('\nTo fix this:');
      console.error('1. Check your .env file has the correct credentials');
      console.error('2. Verify your credentials in the Scalekit dashboard');
      console.error(
        "3. Ensure you're using the right environment (dev/staging/prod)"
      );
      console.error('\nCurrent configuration:');
      console.error(`   Environment: ${process.env.SCALEKIT_ENVIRONMENT_URL}`);
      console.error(`   Client ID: ${process.env.SCALEKIT_CLIENT_ID}`);
      console.error(
        `   Client Secret: ${
          process.env.SCALEKIT_CLIENT_SECRET
            ? '***' + process.env.SCALEKIT_CLIENT_SECRET.slice(-4)
            : 'NOT SET'
        }`
      );
    } else {
      console.error('\n❌ Authentication Error: Unauthorized');
      console.error('Response data:', errorData);
    }
  } else if (error.code === 'ENOTFOUND') {
    console.error('\n❌ Network Error: Could not reach Scalekit service');
    console.error(
      'Please check your internet connection and SCALEKIT_ENVIRONMENT_URL'
    );
  } else if (error.code === 'ECONNREFUSED') {
    console.error('\n❌ Connection Error: Scalekit service is not responding');
    console.error(
      'Please try again later or check if the service is available'
    );
  } else {
    console.error('\n❌ Unexpected Error:');
    console.error('Stack trace:', error.stack);
  }

  console.error('\n💡 For help, visit: https://docs.scalekit.com');
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('\n🚨 Unhandled Promise Rejection:');
  console.error('Promise:', promise);
  console.error('Reason:', reason);

  // Handle Scalekit SDK promise rejections
  if (reason && reason.response && reason.response.status === 401) {
    const errorData = reason.response.data;
    if (errorData && errorData.error === 'invalid_client') {
      console.error('\n❌ Authentication Error: Invalid Client Credentials');
      console.error(
        'Please check your Scalekit configuration in the .env file'
      );
    }
  }

  process.exit(1);
});

// Mock user data (replace with database in production)
const users = [
  {
    id: 1,
    username: 'demo',
    password: '$2a$10$IpwiF1tRx0mXXxnprRZxoeZ6LY6zhRkaw6.1.An78ebUnauCskF/a',
    name: 'Demo User',
    email: process.env.DEMO_USER_EMAIL,
    role: 'User',
  },
];

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(
  session({
    secret: process.env.SESSION_SECRET ?? 'your-secret-key',
    resave: false,
    saveUninitialized: false,
  })
);

// Set cookie parser middleware
app.use(cookieParser());

// Set EJS as templating engine
app.set('view engine', 'ejs');
app.set('views', join(__dirname, 'views'));

// Middleware to check if user is authenticated
const isAuthenticated = (req, res, next) => {
  if (req.session.user) {
    next();
  } else {
    res.redirect('/login');
  }
};

// Add rate limiting for token endpoints - simplified version
const tokenRequestLimiter = (req, res, next) => {
  // In production, use a proper rate limiter like express-rate-limit
  next();
};

// Create middleware to verify JWT token
const verifyToken = async (req, res, next) => {
  // Get token from Authorization header or cookie
  const authHeader = req.headers.authorization;
  const token = authHeader ? authHeader.split(' ')[1] : req.cookies.accessToken;

  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  try {
    // Use Scalekit SDK to validate the token
    const decoded = await scalekit.validateAccessToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token validation error:', error);
    return res.status(401).json({ message: 'Invalid token' });
  }
};

// Routes
app.get('/', (req, res) => {
  // If user is already authenticated, show profile
  if (req.session.user) {
    res.redirect('/profile');
    return;
  }
  // Otherwise, render the home page with the Scalekit button
  res.render('home', { error: null });
});

// Redirect old login route to home
app.get('/login', (req, res) => {
  res.redirect('/');
});

// New route for direct Scalekit login
app.get('/scalekit-login', (req, res) => {
  const options = {
    scopes: ['openid', 'profile', 'email', 'offline_access'],
    prompt: 'create',
  };

  try {
    const authorizationUrl = scalekit.getAuthorizationUrl(redirectUri, options);
    console.log('authorizationUrl', authorizationUrl, options);
    res.redirect(authorizationUrl);
  } catch (error) {
    console.error('Scalekit login error:', error);
    res.render('home', {
      error: 'An error occurred while initiating Scalekit login',
    });
  }
});

app.get('/profile', isAuthenticated, (req, res) => {
  // First try to find user in our users array
  let user = users.find((user) => user.id === req.session.user.id);

  // If user not found in array but we have session data (SSO case)
  if (!user && req.session.user) {
    user = {
      id: req.session.user.id,
      name: req.session.user.name,
      email: req.session.user.email,
      username: req.session.user.username,
    };
  }

  // Get the decoded idToken if it exists
  let decodedToken = null;
  let userProfile = null;
  if (req.session.idToken) {
    try {
      decodedToken = jwt.decode(req.session.idToken);

      // Create a more comprehensive user profile object from token claims
      userProfile = {
        // Basic information
        id: decodedToken.sub,
        name:
          decodedToken.name ||
          `${decodedToken.given_name || ''} ${decodedToken.family_name || ''}`,
        email: decodedToken.email,
        username: decodedToken.preferred_username || decodedToken.email,

        // Additional information from claims if available
        givenName: decodedToken.given_name,
        familyName: decodedToken.family_name,
        middleName: decodedToken.middle_name,
        nickname: decodedToken.nickname,
        picture: decodedToken.picture,
        phoneNumber: decodedToken.phone_number,

        // Identity verification
        emailVerified: decodedToken.email_verified,
        phoneVerified: decodedToken.phone_number_verified,

        // Additional metadata
        locale: decodedToken.locale,
        zoneinfo: decodedToken.zoneinfo,

        // Groups and permissions if present
        groups: decodedToken.groups,
        roles: decodedToken.roles,
        permissions: decodedToken.permissions,

        // Token information
        issuer: decodedToken.iss,
        audience: decodedToken.aud,
        expiration: new Date(decodedToken.exp * 1000).toLocaleString(),
        issuedAt: new Date(decodedToken.iat * 1000).toLocaleString(),
        tokenType: decodedToken.token_type,
      };

      console.log('User profile from token:', userProfile);
    } catch (error) {
      console.error('Error decoding token:', error);
    }
  }

  res.render('profile', {
    user,
    idToken: decodedToken,
    userProfile,
  });
});

app.get('/logout', (req, res) => {
  // Get the refresh token to remove it from storage
  const refreshToken = req.cookies.refreshToken;
  if (refreshToken) {
    refreshTokenStore.delete(refreshToken);
  }

  // Get ID token from session if it exists, but store it in a local variable
  // so it's available even after the session is destroyed
  const idToken = req.session.idToken;

  // Clear session first to remove all session data including the ID token
  req.session.destroy(() => {
    // Clear auth cookies
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');

    // Check if we had an ID token (for SSO logout)
    if (idToken) {
      // Define the URL that Scalekit will redirect back to after logout
      const postLogoutRedirectUri = 'http://localhost:3000/';

      // Create the logout URL
      // const logoutUrl = `${
      //   process.env.SCALEKIT_ENVIRONMENT_URL
      // }/end_session?id_token_hint=${idToken}&post_logout_redirect_uri=${encodeURIComponent(
      //   postLogoutRedirectUri
      // )}`;

      const logoutUrl = scalekit.getLogoutUrl({
        idTokenHint: idToken,
        postLogoutRedirectUri: postLogoutRedirectUri,
      });

      console.log('Redirecting to Scalekit logout URL:', logoutUrl);

      // Redirect to Scalekit logout endpoint
      // This is a one-time redirect with the ID token, after which the token will no longer be valid
      res.redirect(logoutUrl);
    } else {
      // Regular login case - redirect directly to home page
      res.redirect('/');
    }
  });
});

app.get('/api/callback', async (req, res) => {
  const entireQuery = req.query;
  const { error, error_description, code } = entireQuery;

  if (error) {
    console.error('SSO callback error:', error, error_description);
    res.render('home', {
      error: `Login failed: ${error_description || error}`,
    });
    return;
  }

  try {
    console.log('requesting scalekit to exchange oauth code for token', code);
    const response = await scalekit.authenticateWithCode(code, redirectUri);

    // const backupResponse = await exchangeCodeForToken({
    //   env_url: process.env.SCALEKIT_ENVIRONMENT_URL,
    //   code,
    //   redirect_uri: redirectUri,
    //   client_id: process.env.SCALEKIT_CLIENT_ID,
    //   client_secret: process.env.SCALEKIT_CLIENT_SECRET,
    // });

    console.log('user claims by sdk:\n', JSON.stringify(response, null, 2));

    // Get user info from properly verified token
    let decodedToken;
    try {
      decodedToken = jwt.decode(response.idToken);
    } catch (error) {
      console.error('Token verification error:', error);
      res.render('home', {
        error: 'Invalid token received. Please try again.',
      });
      return;
    }

    // Store user info in session with more fields
    req.session.user = {
      id: decodedToken.sub,
      email: decodedToken.email,
      username: decodedToken.preferred_username || decodedToken.email,
      name:
        decodedToken.name ||
        `${decodedToken.given_name || ''} ${decodedToken.family_name || ''}`,
      givenName: decodedToken.given_name,
      familyName: decodedToken.family_name,
      picture: decodedToken.picture,
    };

    // Store idToken separately in session
    req.session.idToken = response.idToken;

    // Store refresh token in server-side storage
    const refreshTokenId = response.refreshToken;
    refreshTokenStore.set(refreshTokenId, {
      userId: decodedToken.sub,
      createdAt: new Date(),
    });

    // Set cookies with tokens for client-side access
    // Access token - accessible to JavaScript
    // const encryptedAccessToken = scalekit.encrypt(response.accessToken, password);
    const encryptedAccessToken = response.accessToken;

    res.cookie('accessToken', encryptedAccessToken, {
      maxAge: (response.expiresIn || 3600) * 1000, // Default to 1 hour if expiresIn is not provided
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      path: '/',
      sameSite: 'strict',
    });

    // Refresh token - httpOnly to prevent JS access
    res.cookie('refreshToken', response.refreshToken, {
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      path: '/',
      sameSite: 'strict',
    });

    res.redirect('/profile');
  } catch (error) {
    console.error('Token exchange error:', error);
    res.render('home', {
      error: 'Failed to complete SSO login. Please try again.',
    });
  }
});

// Add token refresh endpoint - server-side implementation with token rotation
app.post('/api/refresh-token', tokenRequestLimiter, async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(400).json({ message: 'Refresh token is required' });
  }

  try {
    // Use Scalekit SDK to refresh the token
    const response = await scalekit.refreshAccessToken(refreshToken);

    // Store the new refresh token
    const newRefreshTokenId = response.refreshToken;
    refreshTokenStore.set(newRefreshTokenId, {
      userId: req.user?.sub,
      createdAt: new Date(),
    });

    // Update the idToken in the session if a new one is provided
    if (response.idToken) {
      req.session.idToken = response.idToken;
    }

    // Set cookies with updated tokens
    // Access token - httpOnly for security
    res.cookie('accessToken', response.accessToken, {
      maxAge: (response.expiresIn || 3600) * 1000,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      path: '/',
      sameSite: 'strict',
    });

    // Refresh token - httpOnly to prevent JS access
    res.cookie('refreshToken', response.refreshToken, {
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      path: '/',
      sameSite: 'strict',
    });

    // Return just the access token info (not the refresh token)
    return res.json({
      access_token: response.accessToken,
      expires_in: response.expiresIn,
    });
  } catch (error) {
    console.error('Error refreshing token:', error);
    return res.status(401).json({ message: 'Failed to refresh token' });
  }
});

// Add protected API endpoints
app.get('/api/user-info', verifyToken, (req, res) => {
  // Return user info from the token
  return res.json({
    user: req.user,
    message: 'This is protected data',
  });
});

// Add dashboard endpoint
app.get('/dashboard', (req, res) => {
  res.json({ status: 'ok', message: 'Dashboard endpoint is working' });
});

// Test endpoint to verify Scalekit configuration
app.get('/api/test-config', async (req, res) => {
  try {
    // Test basic configuration
    const config = {
      environment: process.env.SCALEKIT_ENVIRONMENT_URL,
      clientId: process.env.SCALEKIT_CLIENT_ID,
      clientSecret: process.env.SCALEKIT_CLIENT_SECRET
        ? '***' + process.env.SCALEKIT_CLIENT_SECRET.slice(-4)
        : 'NOT SET',
      redirectUri: redirectUri,
    };

    // Test if we can create a basic authorization URL (this doesn't make API calls)
    try {
      const authUrl = scalekit.getAuthorizationUrl(redirectUri, {
        scopes: ['openid', 'profile', 'email'],
      });

      res.json({
        status: 'success',
        message: 'Scalekit configuration appears valid',
        config: config,
        authUrl: authUrl,
        note: 'This only tests URL generation, not actual API connectivity',
      });
    } catch (urlError) {
      res.status(400).json({
        status: 'error',
        message: 'Failed to generate authorization URL',
        error: urlError.message,
        config: config,
      });
    }
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Configuration test failed',
      error: error.message,
    });
  }
});

// Example of a protected POST endpoint - removed CSRF protection
app.post('/api/user-action', verifyToken, (req, res) => {
  // This endpoint is protected by JWT only (removed CSRF protection)
  return res.json({
    success: true,
    message: 'Action performed successfully',
  });
});

async function exchangeCodeForToken({
  env_url,
  code,
  redirect_uri,
  client_id,
  client_secret,
}) {
  try {
    const response = await axios.post(
      `${env_url}/oauth/token`,
      null, // No request body needed
      {
        params: {
          code,
          redirect_uri,
          client_id,
          client_secret,
          grant_type: 'authorization_code',
          scopes: ['openid', 'profile', 'email', 'offline_access'],
        },
      }
    );
    return response.data;
  } catch (error) {
    console.error('Error exchanging code for token:', error);
    throw error;
  }
}

async function initiateAuth({ env_url, redirect_uri, scopes }) {
  return `${env_url}/oauth/authorize?response_type=code&client_id=${client_id}&redirect_uri=${redirect_uri}&scope=${scopes.join(
    ' '
  )}`;
}

async function refreshTokenExchange({
  env_url,
  refresh_token,
  client_id,
  client_secret,
}) {
  try {
    console.log(
      'trying to refresh the access token',
      JSON.stringify({
        env_url,
        refresh_token,
        client_id,
        client_secret,
      })
    );
    const response = await axios.post(`${env_url}/oauth/token`, null, {
      params: {
        refresh_token,
        client_id,
        client_secret,
        grant_type: 'refresh_token',
      },
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    return response.data;
  } catch (error) {
    console.error('Error exchanging code for token:', error);
    throw error;
  }
}

const PORT = process.env.PORT ?? 3000;

app.listen(PORT, () => {
  console.log(
    `Server is running in ${
      process.env.NODE_ENV ?? 'development'
    } mode on port ${PORT}`
  );
});
