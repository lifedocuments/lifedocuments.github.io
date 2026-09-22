require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { v4: uuid } = require('uuid');
const nodemailer = require('nodemailer');
const cron = require('node-cron');
const db = require('./db');

const UPLOAD_DIR = process.env.UPLOAD_DIR || './uploads';
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const app = express();
app.use(cors());

/* ---------------- mail ---------------- */
const transporter = process.env.SMTP_HOST ? nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: Number(process.env.SMTP_PORT) === 465,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
}) : null;

function sendMail(to, subject, text) {
  if (!transporter) return Promise.reject(new Error('SMTP not configured on the server (.env)'));
  return transporter.sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER, to, subject, text });
}

app.use(express.json());

/* ---------------- helpers ---------------- */
function daysLeft(expiry) {
  if (!expiry) return null;
  const t = new Date(); t.setHours(0, 0, 0, 0);
  const e = new Date(expiry + 'T00:00:00');
  return Math.round((e - t) / 86400000);
}
function publicUser(u) {
  return { id: u.id, name: u.name, email: u.email, phone: u.phone, plan: u.plan };
}
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.indexOf('Bearer ') === 0 ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not signed in.' });
  try {
    req.userId = jwt.verify(token, process.env.JWT_SECRET).uid;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Session expired. Sign in again.' });
  }
}
function isAdminEmail(email) {
  const admin = (process.env.ADMIN_EMAIL || '').toLowerCase().trim();
  return !!admin && String(email || '').toLowerCase().trim() === admin;
}
// Must run after auth(). Only the account whose email matches ADMIN_EMAIL
// in the server's .env can pass this — not just whoever signed up first.
function requireAdmin(req, res, next) {
  const u = db.prepare('SELECT email FROM users WHERE id=?').get(req.userId);
  if (!u || !isAdminEmail(u.email)) return res.status(403).json({ error: 'Not authorized.' });
  next();
}
app.get('/api/health', (req, res) => res.json({ ok: true }));

/* ---------------- auth ---------------- */
app.post('/api/signup', async (req, res) => {
  const { name, email, phone, password } = req.body || {};
  if (!name || !email || !phone || !password || password.length < 6) {
    return res.status(400).json({ error: 'Fill in your name, email, phone, and a password of at least 6 characters.' });
  }
  const emailNorm = String(email).toLowerCase().trim();
  if (db.prepare('SELECT id FROM users WHERE email=?').get(emailNorm)) {
    return res.status(409).json({ error: 'An account with that email already exists.' });
  }
  const hash = await bcrypt.hash(password, 10);
  const id = uuid();
  db.prepare('INSERT INTO users(id,name,email,phone,password_hash,plan,created_at) VALUES(?,?,?,?,?,?,?)')
    .run(id, name, emailNorm, phone, hash, 'free', Date.now());
  const token = jwt.sign({ uid: id }, process.env.JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: publicUser({ id, name, email: emailNorm, phone, plan: 'free' }) });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(String(email || '').toLowerCase().trim());
  if (!u) return res.status(401).json({ error: 'No account with that email.' });
  const ok = await bcrypt.compare(password || '', u.password_hash);
  if (!ok) return res.status(401).json({ error: 'Wrong password.' });
  const token = jwt.sign({ uid: u.id }, process.env.JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: publicUser(u) });
});

app.post('/api/forgot', async (req, res) => {
  const email = String((req.body && req.body.email) || '').toLowerCase().trim();
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (u) {
    const token = uuid();
    db.prepare('UPDATE users SET reset_token=?, reset_expires=? WHERE id=?').run(token, Date.now() + 3600000, u.id);
    const link = (process.env.FRONTEND_URL || '') + '?reset=' + token;
    try {
      await sendMail(u.email, 'Reset your Life Documents password',
        'Tap this link within 1 hour to set a new password:\n\n' + link + '\n\nIf you did not request this, ignore this email.');
    } catch (e) {
      console.error('Reset email failed:', e.message);
    }
  }
  // Always the same response, so this endpoint can't be used to find out which emails are registered.
  res.json({ ok: true, message: 'If that email is registered, a reset link has been sent.' });
});

app.post('/api/reset', async (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password || password.length < 6) return res.status(400).json({ error: 'Invalid request.' });
  const u = db.prepare('SELECT * FROM users WHERE reset_token=?').get(token);
  if (!u || !u.reset_expires || u.reset_expires < Date.now()) {
    return res.status(400).json({ error: 'That reset link is invalid or has expired. Request a new one.' });
  }
  const hash = await bcrypt.hash(password, 10);
  db.prepare('UPDATE users SET password_hash=?, reset_token=NULL, reset_expires=NULL WHERE id=?').run(hash, u.id);
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.userId);
  if (!u) return res.status(404).json({ error: 'Account not found.' });
  res.json({ user: publicUser(u) });
});

app.put('/api/me', auth, (req, res) => {
  const { name, email, phone } = req.body || {};
  db.prepare('UPDATE users SET name=?, email=?, phone=? WHERE id=?')
    .run(name || '', String(email || '').toLowerCase().trim(), phone || '', req.userId);
  res.json({ ok: true });
});

/* ---------------- admin (owner-only) ---------------- */
// Lets the frontend know whether the signed-in account is the admin,
// without needing to guess by calling an admin-only route and checking the error.
app.get('/api/admin/whoami', auth, (req, res) => {
  const u = db.prepare('SELECT email FROM users WHERE id=?').get(req.userId);
  res.json({ isAdmin: isAdminEmail(u && u.email) });
});

app.get('/api/admin/users', auth, requireAdmin, (req, res) => {
  const users = db.prepare('SELECT id,name,email,phone,created_at FROM users ORDER BY created_at DESC').all();
  const docCounts = db.prepare('SELECT user_id, COUNT(*) c FROM documents GROUP BY user_id').all();
  const byUser = {};
  docCounts.forEach(r => { byUser[r.user_id] = r.c; });
  users.forEach(u => { u.documentCount = byUser[u.id] || 0; });
  res.json({ users });
});

app.get('/api/admin/users/:id', auth, requireAdmin, (req, res) => {
  const u = db.prepare('SELECT id,name,email,phone,created_at FROM users WHERE id=?').get(req.params.id);
  if (!u) return res.status(404).json({ error: 'Not found.' });
  const docs = db.prepare('SELECT * FROM documents WHERE user_id=? ORDER BY created_at').all(u.id);
  const files = db.prepare('SELECT id,document_id,name,mime,size FROM files WHERE user_id=?').all(u.id);
  docs.forEach(d => { d.files = files.filter(f => f.document_id === d.id); });
  res.json({ user: u, docs });
});

// Admin can open any user's file (support/verification), bypassing the
// normal owner-only check in /api/files/:id.
app.get('/api/admin/files/:id', auth, requireAdmin, (req, res) => {
  const f = db.prepare('SELECT * FROM files WHERE id=?').get(req.params.id);
  if (!f) return res.status(404).end();
  res.setHeader('Content-Type', f.mime || 'application/octet-stream');
  res.setHeader('Content-Disposition', 'inline; filename="' + f.name.replace(/"/g, '') + '"');
  res.sendFile(path.resolve(f.path));
});

/* ---------------- documents ---------------- */
app.get('/api/documents', auth, (req, res) => {
  const docs = db.prepare('SELECT * FROM documents WHERE user_id=? ORDER BY created_at').all(req.userId);
  const files = db.prepare('SELECT id,document_id,name,mime,size FROM files WHERE user_id=?').all(req.userId);
  docs.forEach(d => { d.files = files.filter(f => f.document_id === d.id); });
  res.json({ docs });
});

app.post('/api/documents', auth, (req, res) => {
  const b = req.body || {};
  if (!b.title) return res.status(400).json({ error: 'Give the document a name.' });
  const id = uuid();
  db.prepare('INSERT INTO documents(id,user_id,type,title,holder,number,issue,expiry,lead,notes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)')
    .run(id, req.userId, b.type || 'other', b.title, b.holder || '', b.number || '', b.issue || '', b.expiry || '', Number(b.lead) || 30, b.notes || '', Date.now());
  res.json({ id });
});

app.put('/api/documents/:id', auth, (req, res) => {
  const d = db.prepare('SELECT * FROM documents WHERE id=? AND user_id=?').get(req.params.id, req.userId);
  if (!d) return res.status(404).json({ error: 'Not found.' });
  const b = req.body || {};
  if (!b.title) return res.status(400).json({ error: 'Give the document a name.' });
  db.prepare('UPDATE documents SET type=?,title=?,holder=?,number=?,issue=?,expiry=?,lead=?,notes=? WHERE id=?')
    .run(b.type || d.type, b.title, b.holder || '', b.number || '', b.issue || '', b.expiry || '', Number(b.lead) || 30, b.notes || '', d.id);
  res.json({ ok: true });
});

app.delete('/api/documents/:id', auth, (req, res) => {
  const d = db.prepare('SELECT * FROM documents WHERE id=? AND user_id=?').get(req.params.id, req.userId);
  if (!d) return res.status(404).json({ error: 'Not found.' });
  const files = db.prepare('SELECT * FROM files WHERE document_id=?').all(d.id);
  files.forEach(f => { try { fs.unlinkSync(f.path); } catch (e) {} });
  db.prepare('DELETE FROM files WHERE document_id=?').run(d.id);
  db.prepare('DELETE FROM notified WHERE document_id=?').run(d.id);
  db.prepare('DELETE FROM documents WHERE id=?').run(d.id);
  res.json({ ok: true });
});

/* ---------------- files ---------------- */
const upload = multer({ dest: UPLOAD_DIR, limits: { fileSize: 6 * 1024 * 1024 } });

app.post('/api/documents/:id/files', auth, upload.single('file'), (req, res) => {
  const d = db.prepare('SELECT * FROM documents WHERE id=? AND user_id=?').get(req.params.id, req.userId);
  if (!d) {
    if (req.file) try { fs.unlinkSync(req.file.path); } catch (e) {}
    return res.status(404).json({ error: 'Not found.' });
  }
  if (!req.file) return res.status(400).json({ error: 'No file received.' });
  const id = uuid();
  db.prepare('INSERT INTO files(id,document_id,user_id,name,mime,size,path,created_at) VALUES(?,?,?,?,?,?,?,?)')
    .run(id, d.id, req.userId, req.file.originalname, req.file.mimetype, req.file.size, req.file.path, Date.now());
  res.json({ id, name: req.file.originalname, mime: req.file.mimetype, size: req.file.size });
});

app.get('/api/files/:id', auth, (req, res) => {
  const f = db.prepare('SELECT * FROM files WHERE id=? AND user_id=?').get(req.params.id, req.userId);
  if (!f) return res.status(404).end();
  res.setHeader('Content-Type', f.mime || 'application/octet-stream');
  res.setHeader('Content-Disposition', 'inline; filename="' + f.name.replace(/"/g, '') + '"');
  res.sendFile(path.resolve(f.path));
});

app.delete('/api/files/:id', auth, (req, res) => {
  const f = db.prepare('SELECT * FROM files WHERE id=? AND user_id=?').get(req.params.id, req.userId);
  if (!f) return res.status(404).json({ error: 'Not found.' });
  try { fs.unlinkSync(f.path); } catch (e) {}
  db.prepare('DELETE FROM files WHERE id=?').run(f.id);
  res.json({ ok: true });
});

/* ---------------- daily reminder emails (the actual automatic part) ---------------- */
function runReminderSweep() {
  const todayISO = new Date().toISOString().slice(0, 10);
  const rows = db.prepare(`
    SELECT documents.*, users.email AS user_email
    FROM documents JOIN users ON users.id = documents.user_id
    WHERE documents.expiry IS NOT NULL AND documents.expiry <> ''
  `).all();
  rows.forEach(d => {
    const dl = daysLeft(d.expiry);
    if (dl === null || dl > (d.lead || 30)) return;
    const already = db.prepare('SELECT id FROM notified WHERE document_id=? AND sent_date=?').get(d.id, todayISO);
    if (already) return;
    const when = dl < 0 ? ('expired ' + (-dl) + ' day(s) ago') : dl === 0 ? 'expires today' : ('expires in ' + dl + ' day(s)');
    const subject = (dl < 0 ? 'Expired: ' : 'Reminder: ') + d.title;
    const body = d.title + ' ' + when + ' (' + d.expiry + ').' + (d.notes ? ('\n\n' + d.notes) : '');
    sendMail(d.user_email, subject, body)
      .then(() => db.prepare('INSERT INTO notified(id,user_id,document_id,sent_date) VALUES(?,?,?,?)').run(uuid(), d.user_id, d.id, todayISO))
      .catch(e => console.error('Reminder email failed for document', d.id, e.message));
  });
}
// Runs every day at 09:00 server time, plus once shortly after boot so you can see it work.
cron.schedule('0 9 * * *', runReminderSweep);
setTimeout(runReminderSweep, 15000);

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log('Life Documents API listening on :' + PORT));
