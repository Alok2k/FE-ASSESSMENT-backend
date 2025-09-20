// server.js
const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(express.json());

const USERS_FILE = path.join(__dirname, 'users.json');
const SALT_ROUNDS = 10;


async function loadUsers() {
  try {
    const raw = await fs.readFile(USERS_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) throw new Error('users.json invalid');
    return parsed;
  } catch (err) {
    // Create default users if file missing/invalid
    const seed = [
      { id: 'u1', username: 'alice', email: 'alice@example.com', password: await bcrypt.hash('password', SALT_ROUNDS) },
      { id: 'u2', username: 'bob', email: 'bob@example.com', password: await bcrypt.hash('password', SALT_ROUNDS) },
    ];
    await saveUsers(seed);
    return seed;
  }
}

async function saveUsers(users) {
  await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
}

// Signup endpoint
app.post('/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username and password are required' });

    const users = await loadUsers();
    if (users.find(u => u.username === username || (email && u.email === email))) {
      return res.status(409).json({ error: 'User with same username/email already exists' });
    }

    const hashed = await bcrypt.hash(password, SALT_ROUNDS);
    const newUser = {
      id: `u${Date.now()}`,
      username,
      email: email || null,
      password: hashed,
      createdAt: new Date().toISOString(),
    };

    users.push(newUser);
    await saveUsers(users);

    const safe = { id: newUser.id, username: newUser.username, email: newUser.email, createdAt: newUser.createdAt };
    res.status(201).json({ message: 'User created', user: safe });
  } catch (err) {
    console.error('Signup error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username and password are required' });

    const users = await loadUsers();
    const user = users.find(u => u.username === username || u.email === username);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const safe = { id: user.id, username: user.username, email: user.email, createdAt: user.createdAt };
    res.json({ message: 'Login successful', user: safe });
  } catch (err) {
    console.error('Login error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

const PORT = 6446;
app.listen(PORT, () => console.log(`Auth server listening on http://localhost:${PORT}`));
