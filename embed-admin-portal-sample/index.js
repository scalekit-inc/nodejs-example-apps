// index.js
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { getPortalLink } from './libraries/scalekit.js';

const app = express();
const PORT = 3001;

// Fix for __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "frame-ancestors 'self' http://localhost:3001"
  );
  next();
});

// Serve the HTML file
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// New endpoint to get portal link data
app.get('/api/portal-link', async (req, res) => {
  try {
    const portalData = await getPortalLink();
    res.json(portalData);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
