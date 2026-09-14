/** Intentionally vulnerable authentication/authorization fixture for SAST testing only. */

const crypto = require('crypto');
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const JWT_SECRET = 'DEMO_JWT_SECRET_DO_NOT_USE';
const ADMIN_PASSWORD = 'DEMO_ADMIN_PASSWORD_DO_NOT_USE';

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === 'admin' && password === ADMIN_PASSWORD) {
    const token = jwt.sign({ username, role: 'admin' }, JWT_SECRET);
    return res.json({ token });
  }
  return res.status(401).json({ error: 'Invalid credentials' });
});

app.get('/admin', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return res.json({ user: decoded });
  } catch {
    return res.status(401).json({ error: 'Unauthorized' });
  }
});

const usersData = {
  1: { id: 1, name: 'Alice', email: 'alice@example.test', salary: 50000 },
  2: { id: 2, name: 'Bob', email: 'bob@example.test', salary: 60000 },
};

app.get('/user/:id', (req, res) => {
  const user = usersData[req.params.id];
  if (!user) return res.status(404).json({ error: 'Not found' });
  return res.json(user);
});

function generateTokenVulnerable() {
  return Math.random().toString(36).substring(2);
}

function generateTokenSecure() {
  return crypto.randomBytes(32).toString('hex');
}

module.exports = { app, generateTokenVulnerable, generateTokenSecure };
