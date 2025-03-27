# Single Sign On Example App with Scalekit

A simple web application demonstrating Single Sign-On (SSO) authentication using Scalekit, Node.js, Express, and Tailwind CSS. This example shows how to implement secure authentication flows using Scalekit's SSO service.

![App Overview](public/images/login-page.png)

For more screenshots, see the [screenshots folder](public/images).

## Features

- Single Sign-On (SSO) authentication powered by Scalekit
- Secure user authentication and session management
- Profile viewing and management after successful login
- Clean and modern UI using Tailwind CSS
- Server-side rendering with EJS templates
- Example of Scalekit SSO integration

## Setup

You can use either Bun or npm to run this project.

### Using Bun (Recommended)

1. Install dependencies:

```bash
bun install
```

2. Build Tailwind CSS:

```bash
bun run build:css
```

3. Start the server:

```bash
bun run dev
```

### Using npm

1. Install dependencies:

```bash
npm install
```

2. Build Tailwind CSS:

```bash
npm run build:css
```

3. Start the server:

```bash
npm run dev
```

4. Visit http://localhost:3001 in your browser

## Demo Credentials

- Username: demo
- Password: demo123

## Technologies Used

- Scalekit SSO Service
- Bun.js Runtime
- Node.js
- Express.js
- EJS Templates
- Tailwind CSS
- express-session for session management
- bcryptjs for password hashing
