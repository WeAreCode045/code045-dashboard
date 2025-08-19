require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
const path = require('path');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));

// Session setup
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// DB setup
let db;
(async () => {
  db = await open({
    filename: path.join(__dirname, 'db/database.sqlite'),
    driver: sqlite3.Database
  });
  // Create tables if not exist
  await db.exec(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    github_id TEXT UNIQUE,
    username TEXT,
    role TEXT DEFAULT 'user',
    active INTEGER DEFAULT 0
  );`);
  await db.exec(`CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    host TEXT,
    username TEXT,
    password TEXT
  );`);
  await db.exec(`CREATE TABLE IF NOT EXISTS server_access (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    server_id INTEGER
  );`);
  await db.exec(`CREATE TABLE IF NOT EXISTS pma_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT,
    user_id INTEGER,
    server_id INTEGER,
    expires_at INTEGER
  );`);
})();

// Passport config
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const user = await db.get('SELECT * FROM users WHERE id = ?', id);
  done(null, user);
});
passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: process.env.GITHUB_CALLBACK_URL
}, async (accessToken, refreshToken, profile, done) => {
  let user = await db.get('SELECT * FROM users WHERE github_id = ?', profile.id);
  if (!user) {
    await db.run('INSERT INTO users (github_id, username) VALUES (?, ?)', profile.id, profile.username);
    user = await db.get('SELECT * FROM users WHERE github_id = ?', profile.id);
  }
  return done(null, user);
}));

// Middleware
function requireAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}
function requireActive(req, res, next) {
  if (req.user && req.user.active) return next();
  res.render('inactive');
}
function requireAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') return next();
  res.status(403).send('Forbidden');
}

// Routes
app.get('/', (req, res) => {
  res.render('home');
});
app.get('/login', (req, res) => {
  res.render('login');
});
app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/');
  });
});

// GitHub OAuth
app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));
app.get('/auth/github/callback', passport.authenticate('github', {
  failureRedirect: '/login'
}), (req, res) => {
  res.redirect('/dashboard');
});

// Dashboard
app.get('/dashboard', requireAuth, requireActive, async (req, res) => {
  let servers;
  if (req.user.role === 'admin') {
    servers = await db.all('SELECT * FROM servers');
  } else {
    servers = await db.all('SELECT s.* FROM servers s JOIN server_access sa ON s.id = sa.server_id WHERE sa.user_id = ?', req.user.id);
  }
  res.render('dashboard', { user: req.user, servers });
});

// Admin: Userbeheer
app.get('/admin/users', requireAuth, requireActive, requireAdmin, async (req, res) => {
  const users = await db.all('SELECT * FROM users');
  res.render('admin_users', { users });
});
app.post('/admin/users/activate', requireAuth, requireActive, requireAdmin, async (req, res) => {
  await db.run('UPDATE users SET active = 1 WHERE id = ?', req.body.id);
  res.redirect('/admin/users');
});
app.post('/admin/users/role', requireAuth, requireActive, requireAdmin, async (req, res) => {
  await db.run('UPDATE users SET role = ? WHERE id = ?', req.body.role, req.body.id);
  res.redirect('/admin/users');
});

// Admin: Serverbeheer
app.get('/admin/servers', requireAuth, requireActive, requireAdmin, async (req, res) => {
  const servers = await db.all('SELECT * FROM servers');
  res.render('admin_servers', { servers });
});
app.post('/admin/servers/add', requireAuth, requireActive, requireAdmin, async (req, res) => {
  await db.run('INSERT INTO servers (name, host, username, password) VALUES (?, ?, ?, ?)', req.body.name, req.body.host, req.body.username, req.body.password);
  res.redirect('/admin/servers');
});
app.post('/admin/servers/delete', requireAuth, requireActive, requireAdmin, async (req, res) => {
  await db.run('DELETE FROM servers WHERE id = ?', req.body.id);
  res.redirect('/admin/servers');
});
app.post('/admin/servers/assign', requireAuth, requireActive, requireAdmin, async (req, res) => {
  await db.run('INSERT INTO server_access (user_id, server_id) VALUES (?, ?)', req.body.user_id, req.body.server_id);
  res.redirect('/admin/servers');
});

// SSO voor phpMyAdmin
app.get('/login-pma', requireAuth, requireActive, async (req, res) => {
  const server_id = req.query.server_id;
  const server = await db.get('SELECT * FROM servers WHERE id = ?', server_id);
  if (!server) return res.status(404).send('Server niet gevonden');
  // Genereer token
  const token = crypto.randomBytes(16).toString('hex');
  const expires_at = Date.now() + 60000; // 60 sec
  await db.run('INSERT INTO pma_sessions (token, user_id, server_id, expires_at) VALUES (?, ?, ?, ?)', token, req.user.id, server_id, expires_at);
  // Redirect naar phpMyAdmin login
  res.redirect(`/phpmyadmin/login.php?token=${token}`);
});

// Inactive page
app.get('/inactive', requireAuth, (req, res) => {
  res.render('inactive');
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
