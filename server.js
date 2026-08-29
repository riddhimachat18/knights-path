const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';

// ── Middleware ──
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());

// Serve the static site from /public
app.use(express.static(path.join(__dirname, 'public')));

// ── Database setup ──
const db = new Database(path.join(__dirname, 'progress.db'));
db.pragma('journal_mode = WAL'); // better concurrent read performance

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    passcode_hash TEXT    NOT NULL,
    created_at    TEXT    DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS progress (
    user_id    INTEGER PRIMARY KEY REFERENCES users(id),
    data       TEXT    NOT NULL DEFAULT '{}',
    updated_at TEXT    DEFAULT (datetime('now'))
  );
`);

// ── Auth middleware ──
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ── POST /api/auth/login ──
// Registers on first visit; authenticates on subsequent visits.
app.post('/api/auth/login', (req, res) => {
  const { name, passcode } = req.body;

  if (!name || typeof name !== 'string' || name.trim().length < 2) {
    return res.status(400).json({ error: 'name must be at least 2 characters' });
  }
  if (!passcode || typeof passcode !== 'string' || passcode.length < 4) {
    return res.status(400).json({ error: 'passcode must be at least 4 characters' });
  }

  const cleanName = name.trim();
  let user = db.prepare('SELECT * FROM users WHERE name = ?').get(cleanName);

  if (!user) {
    // First time — register
    const hash = bcrypt.hashSync(passcode, 10);
    const info = db.prepare(
      'INSERT INTO users (name, passcode_hash) VALUES (?, ?)'
    ).run(cleanName, hash);
    user = { id: info.lastInsertRowid, name: cleanName };
  } else {
    // Returning — verify passcode
    if (!bcrypt.compareSync(passcode, user.passcode_hash)) {
      return res.status(401).json({ error: 'Wrong passcode' });
    }
  }

  const token = jwt.sign(
    { id: user.id, name: user.name },
    JWT_SECRET,
    { expiresIn: '90d' }
  );
  res.json({ token, name: user.name });
});

// ── GET /api/progress ──
app.get('/api/progress', requireAuth, (req, res) => {
  const row = db.prepare('SELECT data FROM progress WHERE user_id = ?').get(req.user.id);
  res.json(row ? JSON.parse(row.data) : {});
});

// ── POST /api/progress ──
// Full upsert — client sends the entire state object.
app.post('/api/progress', requireAuth, (req, res) => {
  const data = JSON.stringify(req.body);
  db.prepare(`
    INSERT INTO progress (user_id, data, updated_at) VALUES (?, ?, datetime('now'))
    ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at
  `).run(req.user.id, data);
  res.json({ ok: true });
});

// ── Health check ──
app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));

// ── Catch-all: serve index.html for client-side navigation ──
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Knights-path server running on http://localhost:${PORT}`);
});
