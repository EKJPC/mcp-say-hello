require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const arcjet = require('@arcjet/node');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const app = express();

// Security middleware
app.use(helmet());
app.use(express.json({ limit: '1mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per window
  message: 'Too many requests, please try again later'
});
app.use('/tools/', limiter);

// Audit logging with Winston
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'audit.log' })
  ]
});

// Arcjet security rules
const aj = arcjet({
  key: process.env.ARCJET_KEY,
  rules: [
    arcjet.detectBot({ mode: "LIVE" }),
    arcjet.shield({ mode: "LIVE" })
  ]
});

// JWT verification (from Week 7)
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
    logger.warn('Unauthorized access attempt', { ip: req.ip, path: req.path });
    return res.status(401).json({ error: 'Token required' });
  }
  
  jwt.verify(token, getKey, {
    audience: process.env.GOOGLE_CLIENT_ID,
    issuer: 'https://accounts.google.com'
  }, (err, decoded) => {
    if (err) {
      logger.error('Token verification failed', { error: err.message, ip: req.ip });
      return res.status(403).json({ error: 'Invalid token' });
    }
    
    req.user = decoded;
    logger.info('Authenticated request', { 
      user: decoded.email, 
      action: req.path,
      timestamp: new Date().toISOString()
    });
    next();
  });
}

// Public endpoint (no auth)
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Protected endpoint
app.post('/tools/call', authenticateToken, async (req, res) => {
  // Arcjet security check
  const decision = await aj.protect(req);
  if (decision.isDenied()) {
    logger.warn('Arcjet blocked request', { reason: decision.reason, ip: req.ip });
    return res.status(403).json({ error: 'Request blocked by security policy' });
  }

  const { name, arguments: args } = req.body;
  
  if (name !== 'sayHello') {
    return res.status(404).json({ error: 'Tool not found' });
  }
  
  const greetings = {
    formal: `Good day, ${req.user.name}.`,
    enthusiastic: `HEY ${req.user.name.toUpperCase()}! 🎉`,
    casual: `Hey ${req.user.name}! 👋`
  };
  
  const greeting = greetings[args?.greeting_type || 'casual'];
  
  logger.info('Tool executed', {
    user: req.user.email,
    tool: name,
    args: args,
    timestamp: new Date().toISOString()
  });
  
  res.json({
    content: [{ type: 'text', text: greeting }]
  });
});

// Token revocation endpoint
const revokedTokens = new Set();

app.post('/auth/revoke', authenticateToken, (req, res) => {
  const token = req.headers.authorization.split(' ')[1];
  revokedTokens.add(token);
  
  logger.warn('Token revoked', { 
    user: req.user.email, 
    reason: req.body.reason || 'user_request',
    timestamp: new Date().toISOString()
  });
  
  res.json({ message: 'Token revoked successfully' });
});

app.listen(3001, () => {
  logger.info('Server started', { port: 3001 });
  console.log('✅ Production server running on :3001');
});