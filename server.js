require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const app = express();

// Security middleware
app.use(helmet());
app.use(express.json({ limit: '1mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests, please try again later'
});
app.use('/tools/', limiter);

// JWT verification
const client = jwksClient({
  jwksUri: 'https://www.googleapis.com/oauth2/v3/certs'
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    callback(err, key?.getPublicKey());
  });
}

function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Token required' });
  }
  
  jwt.verify(token, getKey, {
    audience: process.env.GOOGLE_CLIENT_ID,
    issuer: 'https://accounts.google.com'
  }, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token', message: err.message });
    }
    req.user = decoded;
    next();
  });
}

// Public endpoints
app.get('/', (req, res) => {
  res.json({ 
    status: 'healthy',
    service: 'mcp-say-hello',
    timestamp: new Date().toISOString()
  });
});

app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString() 
  });
});

// Protected endpoint
app.post('/tools/call', authenticateToken, (req, res) => {
  const { name, arguments: args } = req.body;
  
  if (name !== 'sayHello') {
    return res.status(404).json({ error: 'Tool not found' });
  }
  
  const greetings = {
    formal: `Good day, ${req.user.name}.`,
    enthusiastic: `HEY ${req.user.name.toUpperCase()}! 🎉`,
    casual: `Hey ${req.user.name}! 👋`
  };
  
  res.json({
    content: [{ 
      type: 'text', 
      text: greetings[args?.greeting_type || 'casual'] 
    }]
  });
});

// Export for Vercel
module.exports = app;

// Local server only
if (require.main === module) {
  const PORT = process.env.PORT || 3001;
  app.listen(PORT, () => {
    console.log(`✅ Server running on :${PORT}`);
  });
}