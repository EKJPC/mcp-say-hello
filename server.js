require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const app = express();
app.use(express.json());

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
  if (!token) return res.status(401).json({ error: 'Token required' });
  
  jwt.verify(token, getKey, {
    audience: process.env.GOOGLE_CLIENT_ID,
    issuer: 'https://accounts.google.com'
  }, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
}

app.post('/tools/call', authenticateToken, (req, res) => {
  const { name, arguments: args } = req.body;
  if (name !== 'sayHello') return res.status(404).json({ error: 'Tool not found' });
  
  const greetings = {
    formal: `Good day, ${req.user.name}.`,
    enthusiastic: `HEY ${req.user.name.toUpperCase()}! 🎉`,
    casual: `Hey ${req.user.name}! 👋`
  };
  
  res.json({
    content: [{ type: 'text', text: greetings[args?.greeting_type || 'casual'] }]
  });
});

app.listen(3001, () => console.log('✅ Server running on :3001'));
