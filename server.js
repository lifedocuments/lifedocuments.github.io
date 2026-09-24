require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { v4: uuid } = require('uuid');
const nodemailer = require('nodemailer');
const cron = require('node-cron');
const db = require('./db');

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
async function requireAdmin(req, res, next) {
  try {
    const u = await db.findUserById(req.userId);
    if (!u || !isAdminEmail(u.email)) return res.status(403).json({ error: 'Not authorized.' });
    next();
  } catch (e) { next(e); }
}
// Wraps an async route so a thrown/rejected error becomes a clean 500
// instead of crashing the process.
function wrap(fn) {
  return (req, res, next) => fn(req, res, next).catch(next);
}

app.get('/api/health', (req, res) => res.json({ ok: true }));

/* ---------------- auth ---------------- */
app.post('/api/signup', wrap(async (req, res) => {
  const { name, email, phone, password } = req.body || {};
  if (!name || !email || !phone || !password || password.length < 6) {
    return res.status(400).json({ error: 'Fill in your name, email, phone, and a password of at least 6 characters.' });
  }
  const emailNorm = String(email).toLowerCase().trim();
  if (await db.findUserByEmail(emailNorm)) {
    return res.status(409).json({ error: 'An account with that email already exists.' });
  }
  const hash = await bcrypt.hash(password, 10);
  const id = uuid();
  await db.insertUser({ id, name, email: emailNorm, phone, password_hash: hash, plan: 'free', reset_token: null, reset_expires: null, created_at: Date.now() });
  const token = jwt.sign({ uid: id }, process.env.JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: publicUser({ id, name, email: emailNorm, phone, plan: 'free' }) });

  const appLink = process.env.FRONTEND_URL || '';
  sendMail(emailNorm, 'Welcome to Life Documents',
    'Hi ' + name + ',\n\n' +
    'Your vault is set up. Add your NID, passport, trade licence, insurance, or any document with an expiry date, and you\'ll get an email reminder automatically before it lapses.' +
    (appLink ? ('\n\nOpen your vault: ' + appLink) : '') +
    '\n\n\u2014 Life Documents'
  ).catch(e => console.error('Welcome email failed for', emailNorm, e.message));
}));

app.post('/api/login', wrap(async (req, res) => {
  const { email, password } = req.body || {};
  const u = await db.findUserByEmail(String(email || '').toLowerCase().trim());
  if (!u) return res.status(401).json({ error: 'No account with that email.' });
  const ok = await bcrypt.compare(password || '', u.password_hash);
  if (!ok) return res.status(401).json({ error: 'Wrong password.' });
  const token = jwt.sign({ uid: u.id }, process.env.JWT_SECRET, { expiresIn: '30d' });
  db.touchLastLogin(u.id).catch(e => console.error('Could not record last login for', u.id, e.message));
  res.json({ token, user: publicUser(u) });
}));

app.post('/api/forgot', wrap(async (req, res) => {
  const email = String((req.body && req.body.email) || '').toLowerCase().trim();
  const u = await db.findUserByEmail(email);
  if (u) {
    const token = uuid();
    await db.updateUser(u.id, { reset_token: token, reset_expires: Date.now() + 3600000 });
    const link = (process.env.FRONTEND_URL || '') + '?reset=' + token;
    try {
      await sendMail(u.email, 'Reset your Life Documents password',
        'Tap this link within 1 hour to set a new password:\n\n' + link + '\n\nIf you did not request this, ignore this email.');
    } catch (e) {
      console.error('Reset email failed:', e.message);
    }
  }
  res.json({ ok: true, message: 'If that email is registered, a reset link has been sent.' });
}));

app.post('/api/reset', wrap(async (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password || password.length < 6) return res.status(400).json({ error: 'Invalid request.' });
  const u = await db.findUserByResetToken(token);
  if (!u || !u.reset_expires || Number(u.reset_expires) < Date.now()) {
    return res.status(400).json({ error: 'That reset link is invalid or has expired. Request a new one.' });
  }
  const hash = await bcrypt.hash(password, 10);
  await db.updateUser(u.id, { password_hash: hash, reset_token: null, reset_expires: null });
  res.json({ ok: true });
}));

app.get('/api/me', auth, wrap(async (req, res) => {
  const u = await db.findUserById(req.userId);
  if (!u) return res.status(404).json({ error: 'Account not found.' });
  res.json({ user: publicUser(u) });
}));

app.put('/api/me', auth, wrap(async (req, res) => {
  const { name, email, phone } = req.body || {};
  await db.updateUser(req.userId, { name: name || '', email: String(email || '').toLowerCase().trim(), phone: phone || '' });
  res.json({ ok: true });
}));

/* ---------------- admin (owner-only) ---------------- */
app.get('/api/admin/whoami', auth, wrap(async (req, res) => {
  const u = await db.findUserById(req.userId);
  res.json({ isAdmin: isAdminEmail(u && u.email) });
}));

app.get('/api/admin/stats', auth, requireAdmin, wrap(async (req, res) => {
  res.json(await db.adminStats());
}));

app.get('/api/admin/users', auth, requireAdmin, wrap(async (req, res) => {
  const users = await db.listUsers({ q: req.query.q });
  const byUser = await db.docCountsByUser();
  users.forEach(u => { u.documentCount = byUser[u.id] || 0; });

  const sort = req.query.sort || 'newest';
  if (sort === 'oldest') users.sort((a, b) => a.created_at - b.created_at);
  else if (sort === 'most_docs') users.sort((a, b) => b.documentCount - a.documentCount || b.created_at - a.created_at);
  else if (sort === 'name') users.sort((a, b) => a.name.localeCompare(b.name));
  else users.sort((a, b) => b.created_at - a.created_at); // newest (default)

  res.json({ users });
}));

app.get('/api/admin/users/:id', auth, requireAdmin, wrap(async (req, res) => {
  const full = await db.findUserById(req.params.id);
  if (!full) return res.status(404).json({ error: 'Not found.' });
  const u = { id: full.id, name: full.name, email: full.email, phone: full.phone, created_at: full.created_at };
  const docs = await db.listDocumentsByUser(u.id);
  const files = await db.listFilesByUser(u.id);
  docs.forEach(d => { d.files = files.filter(f => f.document_id === d.id); });
  res.json({ user: u, docs });
}));

app.get('/api/admin/files/:id', auth, requireAdmin, wrap(async (req, res) => {
  const f = await db.findFileById(req.params.id);
  if (!f) return res.status(404).end();
  res.setHeader('Content-Type', f.mime || 'application/octet-stream');
  res.setHeader('Content-Disposition', 'inline; filename="' + f.name.replace(/"/g, '') + '"');
  res.send(f.data);
}));

/* ---------------- documents ---------------- */
app.get('/api/documents', auth, wrap(async (req, res) => {
  const docs = await db.listDocumentsByUser(req.userId);
  const files = await db.listFilesByUser(req.userId);
  docs.forEach(d => { d.files = files.filter(f => f.document_id === d.id); });
  res.json({ docs });
}));

app.post('/api/documents', auth, wrap(async (req, res) => {
  const b = req.body || {};
  if (!b.title) return res.status(400).json({ error: 'Give the document a name.' });
  const id = uuid();
  await db.insertDocument({
    id, user_id: req.userId, type: b.type || 'other', title: b.title, holder: b.holder || '',
    number: b.number || '', issue: b.issue || '', expiry: b.expiry || '', lead: Number(b.lead) || 30,
    notes: b.notes || '', created_at: Date.now()
  });
  res.json({ id });
}));

app.put('/api/documents/:id', auth, wrap(async (req, res) => {
  const d = await db.findDocument(req.params.id, req.userId);
  if (!d) return res.status(404).json({ error: 'Not found.' });
  const b = req.body || {};
  if (!b.title) return res.status(400).json({ error: 'Give the document a name.' });
  await db.updateDocument(d.id, {
    type: b.type || d.type, title: b.title, holder: b.holder || '', number: b.number || '',
    issue: b.issue || '', expiry: b.expiry || '', lead: Number(b.lead) || 30, notes: b.notes || ''
  });
  res.json({ ok: true });
}));

app.delete('/api/documents/:id', auth, wrap(async (req, res) => {
  const d = await db.findDocument(req.params.id, req.userId);
  if (!d) return res.status(404).json({ error: 'Not found.' });
  await db.deleteFilesByDocument(d.id);
  await db.deleteNotifiedByDocument(d.id);
  await db.deleteDocument(d.id);
  res.json({ ok: true });
}));

/* ---------------- files (stored as bytes in the database) ---------------- */
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 6 * 1024 * 1024 } });

app.post('/api/documents/:id/files', auth, upload.single('file'), wrap(async (req, res) => {
  const d = await db.findDocument(req.params.id, req.userId);
  if (!d) return res.status(404).json({ error: 'Not found.' });
  if (!req.file) return res.status(400).json({ error: 'No file received.' });
  const id = uuid();
  await db.insertFile({
    id, document_id: d.id, user_id: req.userId, name: req.file.originalname, mime: req.file.mimetype,
    size: req.file.size, data: req.file.buffer, created_at: Date.now()
  });
  res.json({ id, name: req.file.originalname, mime: req.file.mimetype, size: req.file.size });
}));

app.get('/api/files/:id', auth, wrap(async (req, res) => {
  const f = await db.findFile(req.params.id, req.userId);
  if (!f) return res.status(404).end();
  res.setHeader('Content-Type', f.mime || 'application/octet-stream');
  res.setHeader('Content-Disposition', 'inline; filename="' + f.name.replace(/"/g, '') + '"');
  res.send(f.data);
}));

app.delete('/api/files/:id', auth, wrap(async (req, res) => {
  const f = await db.findFile(req.params.id, req.userId);
  if (!f) return res.status(404).json({ error: 'Not found.' });
  await db.deleteFile(f.id);
  res.json({ ok: true });
}));

/* ---------------- daily reminder emails ---------------- */
async function runReminderSweep() {
  const todayISO = new Date().toISOString().slice(0, 10);
  const rows = await db.allDocumentsWithExpiry();
  for (const d of rows) {
    const dl = daysLeft(d.expiry);
    if (dl === null || dl > (d.lead || 30)) continue;
    if (!d.user_email) continue;
    if (await db.findNotified(d.id, todayISO)) continue;
    const when = dl < 0 ? ('expired ' + (-dl) + ' day(s) ago') : dl === 0 ? 'expires today' : ('expires in ' + dl + ' day(s)');
    const subject = (dl < 0 ? 'Expired: ' : 'Reminder: ') + d.title;
    const body = d.title + ' ' + when + ' (' + d.expiry + ').' + (d.notes ? ('\n\n' + d.notes) : '');
    try {
      await sendMail(d.user_email, subject, body);
      await db.insertNotified({ id: uuid(), user_id: d.user_id, document_id: d.id, sent_date: todayISO });
    } catch (e) {
      console.error('Reminder email failed for document', d.id, e.message);
    }
  }
}
cron.schedule('0 9 * * *', runReminderSweep);

// generic error handler (from wrap())
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Something went wrong on the server.' });
});

const PORT = process.env.PORT || 4000;
db.init()
  .then(() => {
    app.listen(PORT, () => console.log('Life Documents API listening on :' + PORT));
    setTimeout(runReminderSweep, 15000);
  })
  .catch(e => {
    console.error('Could not connect to the database. Check DATABASE_URL in your .env:', e.message);
    process.exit(1);
  });
