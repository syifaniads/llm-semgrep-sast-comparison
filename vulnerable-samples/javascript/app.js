/** Intentionally vulnerable Node.js fixture for SAST testing only. */

const express = require('express');
const mysql = require('mysql2');
const { exec, execFile } = require('child_process');

const app = express();
app.use(express.json());

const db = mysql.createConnection({
  host: 'localhost',
  user: 'demo',
  password: 'DEMO_PASSWORD_DO_NOT_USE',
  database: 'demo',
});

app.get('/user', (req, res) => {
  const username = req.query.username;
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  db.query(query, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

app.get('/user/secure', (req, res) => {
  db.query('SELECT * FROM users WHERE username = ?', [req.query.username], (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

app.get('/greet', (req, res) => {
  res.send(`<html><body><h1>Hello, ${req.query.name}!</h1></body></html>`);
});

app.get('/ping', (req, res) => {
  exec(`ping -c 4 ${req.query.host}`, (_error, stdout) => res.send(stdout));
});

app.get('/ping/secure', (req, res) => {
  const host = req.query.host;
  if (!/^[a-zA-Z0-9.\-]+$/.test(host)) return res.status(400).send('Invalid hostname');
  execFile('ping', ['-c', '4', host], (_error, stdout) => res.send(stdout));
});

module.exports = app;
