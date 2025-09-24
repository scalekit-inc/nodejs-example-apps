import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import { Scalekit } from '@scalekit-sdk/node';
import jwt from 'jsonwebtoken';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();

const redirectUri = 'http://localhost:3000/callback';

let scalekit;
try {
  scalekit = new Scalekit(
    process.env.SCALEKIT_ENV_URL,
    process.env.SCALEKIT_CLIENT_ID,
    process.env.SCALEKIT_CLIENT_SECRET
  );
  console.log('ScaleKit initialized successfully');
} catch (error) {
  if (error.code === 'ERR_INVALID_URL') {
    console.error('\n❌ ScaleKit Environment URL is invalid or missing!');
    console.error(
      'Please check your .env file and ensure SCALEKIT_ENV_URL is set correctly.'
    );
    console.error('Example: SCALEKIT_ENV_URL=https://api.scalekit.com\n');
  } else {
    console.error('Failed to initialize Scalekit:', error.message);
  }
  process.exit(1);
}

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

// Routes
app.get('/', (req, res) => {
  res.redirect(req.session.user ? '/profile' : '/login');
});

app.get('/login', (req, res) => {
  if (req.session.user) {
    res.redirect('/profile');
    return;
  }
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = users.find((user) => user.email === email);
    const isValidPassword =
      user && (await bcrypt.compare(password, user.password));

    if (isValidPassword) {
      req.session.user = { id: user.id, email: user.email };
      res.redirect('/profile');
      return;
    }

    res.render('login', { error: 'Invalid email or password' });
  } catch (error) {
    console.error('Login error:', error);
    res.render('login', { error: 'An error occurred during login' });
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
  if (req.session.idToken) {
    try {
      decodedToken = jwt.decode(req.session.idToken);
      console.log('Decoded token:', decodedToken);
    } catch (error) {
      console.error('Error decoding token:', error);
    }
  }

  res.render('profile', {
    user,
    idToken: decodedToken,
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

app.get('/sso-login', (req, res) => {
  res.render('sso-login', { error: null });
});

app.post('/sso-login', (req, res) => {
  const { email } = req.body;
  let [, domain] = email.split('@');
  let options = Object.create({});
  options['loginHint'] = email;

  try {
    const authorizationUrl = scalekit.getAuthorizationUrl(redirectUri, options);
    // Redirect the user to the authorization URL
    res.redirect(authorizationUrl);
  } catch (error) {
    console.error('SSO login error:', error);
    res.render('sso-login', {
      error: 'An error occurred while initiating SSO login',
    });
  }
});

app.get('/callback', async (req, res) => {
  const { code, error, error_description } = req.query;

  if (error) {
    console.error('SSO callback error:', error, error_description);
    res.render('login', {
      error: `SSO login failed: ${error_description || error}`,
    });
    return;
  }

  try {
    // Get tokens from ScaleKit
    const response = await scalekit.authenticateWithCode(code, redirectUri);
    console.log(`response`, response);
    const { user, idToken } = response;
    // Store user info in session
    req.session.user = {
      id: user.id,
      email: user.email,
      username: user.username,
      name: `${user.givenName} ${user.familyName}`,
    };

    // Store idToken separately in session
    req.session.idToken = idToken;

    res.redirect('/profile');
  } catch (error) {
    console.error('Token exchange error:', error);
    res.render('login', {
      error: 'Failed to complete SSO login. Please try again.',
    });
  }
});

const PORT = process.env.PORT ?? 3000;
app.listen(PORT, () => {
  console.log(
    `Server is running in ${
      process.env.NODE_ENV ?? 'development'
    } mode on port ${PORT}`
  );
});
