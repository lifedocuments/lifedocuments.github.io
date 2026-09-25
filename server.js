require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { v4: uuid } = require('uuid');
const nodemailer = require('nodemailer');
const cron = require('node-cron');
const webpush = require('web-push');
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

/* ---------------- push notifications (admin phone alerts) ---------------- */
// Real phone notifications (even with the app closed), e.g. "a new user just
// signed up" — separate from the email/in-app broadcast system above, and
// off entirely unless VAPID_PUBLIC_KEY/VAPID_PRIVATE_KEY are set in .env.
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || '';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || '';
if (VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(process.env.VAPID_CONTACT || 'mailto:admin@example.com', VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
}
// Sends to every device the admin has enabled notifications on. Never
// throws — a subscription that's gone stale (the browser/OS revoked it) is
// just quietly removed instead of failing the caller.
async function notifyAdminPush(title, body, url) {
  if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) return;
  try {
    const adminEmail = (process.env.ADMIN_EMAIL || '').toLowerCase().trim();
    if (!adminEmail) return;
    const admin = await db.findUserByEmail(adminEmail);
    if (!admin) return;
    const subs = await db.listPushSubscriptionsByUser(admin.id);
    for (const s of subs) {
      try {
        await webpush.sendNotification(
          { endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } },
          JSON.stringify({ title, body, url })
        );
      } catch (e) {
        if (e.statusCode === 404 || e.statusCode === 410) {
          await db.deletePushSubscriptionByEndpoint(s.endpoint).catch(() => {});
        } else {
          console.error('Push send failed:', e.message);
        }
      }
    }
  } catch (e) {
    console.error('notifyAdminPush failed:', e.message);
  }
}

/* ---------------- document photo scanning (Claude vision, optional) ---------------- */
// Off unless ANTHROPIC_API_KEY is set — the "Scan & autofill" button just
// shows a friendly "not set up yet" message otherwise. Uses Node's built-in
// fetch (Node 18+), so no extra dependency for this.
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
const ANTHROPIC_MODEL = process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-5';

app.use(express.json());

/* ---------------- helpers ---------------- */
function daysLeft(expiry) {
  if (!expiry) return null;
  const t = new Date(); t.setHours(0, 0, 0, 0);
  const e = new Date(expiry + 'T00:00:00');
  return Math.round((e - t) / 86400000);
}
// First-login guided tour: bump this when a major new feature ships and the
// tour content is updated, so everyone (including accounts that already saw
// an older tour) gets it once more. Just showing/replaying the tour never
// touches this — only actually finishing/skipping it does.
const CURRENT_TOUR_VERSION = 1;
function publicUser(u) {
  return {
    id: u.id, name: u.name, email: u.email, phone: u.phone, plan: u.plan,
    lastLoginAt: u.last_login_at || null, lastLoginDevice: u.last_login_device || null,
    pinEnabled: !!u.pin_enabled,
    showIntro: (Number(u.intro_seen_version) || 0) < CURRENT_TOUR_VERSION,
  };
}
// Sensible default reminder milestones, only used when a document/subscription
// somehow arrives with none set.
const DEFAULT_DOC_MILESTONES = [180, 90, 30, 7, 1];
const DEFAULT_SUB_MILESTONES = [7, 3, 1, 0];
// Cleans up a client-supplied reminder-days list: whole numbers, 0–3650,
// deduplicated, capped at 10 entries so nobody can wedge an enormous array in.
function cleanMilestones(arr, fallback) {
  if (!Array.isArray(arr)) return fallback.slice();
  const seen = new Set();
  const out = [];
  for (const v of arr) {
    const n = Math.round(Number(v));
    if (!Number.isFinite(n) || n < 0 || n > 3650 || seen.has(n)) continue;
    seen.add(n);
    out.push(n);
    if (out.length >= 10) break;
  }
  return out;
}
// Turns a User-Agent header into a short, friendly label like "Chrome on
// Windows" for the account page's "last signed in" trust line. Best-effort
// only — an unrecognized UA just falls back to generic labels.
function simplifyDevice(ua) {
  if (!ua) return null;
  ua = String(ua);
  var os = 'your device';
  if (/iPhone/i.test(ua)) os = 'iPhone';
  else if (/iPad/i.test(ua)) os = 'iPad';
  else if (/Android/i.test(ua)) os = 'Android';
  else if (/Windows/i.test(ua)) os = 'Windows';
  else if (/Mac OS X/i.test(ua)) os = 'Mac';
  else if (/Linux/i.test(ua)) os = 'Linux';
  var browser = 'a browser';
  if (/Edg\//i.test(ua)) browser = 'Edge';
  else if (/CriOS/i.test(ua) || (/Chrome\//i.test(ua) && !/Chromium/i.test(ua))) browser = 'Chrome';
  else if (/Firefox\//i.test(ua)) browser = 'Firefox';
  else if (/Safari\//i.test(ua) && !/Chrome/i.test(ua)) browser = 'Safari';
  return browser + ' on ' + os;
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
  // Family Vault: everyone starts with a "Me" profile so documents can be
  // tagged right away without a separate setup step.
  await db.insertProfile({ id: uuid(), user_id: id, name, relation: 'self', created_at: Date.now() }).catch(e => console.error('Could not create default profile for', id, e.message));
  const token = jwt.sign({ uid: id }, process.env.JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: publicUser({ id, name, email: emailNorm, phone, plan: 'free' }) });

  const appLink = process.env.FRONTEND_URL || '';
  sendMail(emailNorm, 'Welcome to Life Documents',
    'Hi ' + name + ',\n\n' +
    'Your vault is set up. Add your NID, passport, trade licence, insurance, or any document with an expiry date, and you\'ll get an email reminder automatically before it lapses.' +
    (appLink ? ('\n\nOpen your vault: ' + appLink) : '') +
    '\n\n\u2014 Life Documents'
  ).catch(e => console.error('Welcome email failed for', emailNorm, e.message));
  notifyAdminPush('New signup on Life Documents', name + ' (' + emailNorm + ') just created an account.', appLink);
}));

app.post('/api/login', wrap(async (req, res) => {
  const { email, password } = req.body || {};
  const u = await db.findUserByEmail(String(email || '').toLowerCase().trim());
  if (!u) return res.status(401).json({ error: 'No account with that email.' });
  const ok = await bcrypt.compare(password || '', u.password_hash);
  if (!ok) return res.status(401).json({ error: 'Wrong password.' });
  const token = jwt.sign({ uid: u.id }, process.env.JWT_SECRET, { expiresIn: '30d' });
  await db.touchLastLogin(u.id, simplifyDevice(req.headers['user-agent'])).catch(e => console.error('Could not record last login for', u.id, e.message));
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

/* ---------------- App Lock (PIN) ---------------- */
// A re-entry lock on top of the normal sign-in — for someone who's already
// signed in on a device and wants a quick PIN gate before the vault shows,
// not a replacement for the account password.
app.put('/api/me/pin', auth, wrap(async (req, res) => {
  const { pin, currentPassword } = req.body || {};
  if (!/^\d{4,8}$/.test(String(pin || ''))) return res.status(400).json({ error: 'Use a PIN of 4 to 8 digits.' });
  const u = await db.findUserById(req.userId);
  if (!u) return res.status(404).json({ error: 'Account not found.' });
  const ok = await bcrypt.compare(currentPassword || '', u.password_hash);
  if (!ok) return res.status(401).json({ error: 'Your account password is wrong.' });
  const hash = await bcrypt.hash(String(pin), 10);
  await db.updateUser(u.id, { pin_hash: hash, pin_enabled: true });
  res.json({ ok: true });
}));

app.delete('/api/me/pin', auth, wrap(async (req, res) => {
  const { currentPassword } = req.body || {};
  const u = await db.findUserById(req.userId);
  if (!u) return res.status(404).json({ error: 'Account not found.' });
  const ok = await bcrypt.compare(currentPassword || '', u.password_hash);
  if (!ok) return res.status(401).json({ error: 'Your account password is wrong.' });
  await db.updateUser(u.id, { pin_hash: null, pin_enabled: false });
  res.json({ ok: true });
}));

app.post('/api/me/pin/verify', auth, wrap(async (req, res) => {
  const { pin } = req.body || {};
  const u = await db.findUserById(req.userId);
  if (!u || !u.pin_enabled || !u.pin_hash) return res.json({ ok: true }); // nothing to check
  const ok = await bcrypt.compare(String(pin || ''), u.pin_hash);
  res.json({ ok });
}));

// First-login guided tour: called once the user finishes or skips it, so it
// doesn't show again on this tour version. Replaying it from Account never
// calls this, so replaying never resets the "already seen" state.
app.post('/api/me/intro-seen', auth, wrap(async (req, res) => {
  await db.updateUser(req.userId, { intro_seen_version: CURRENT_TOUR_VERSION });
  res.json({ ok: true });
}));

/* ---------------- profiles (Family Vault) ---------------- */
app.get('/api/profiles', auth, wrap(async (req, res) => {
  let list = await db.listProfilesByUser(req.userId);
  // Self-heal: accounts created before Family Vault shipped never got the
  // automatic "Me" profile signup now creates. Give them one on first load
  // instead of leaving the picker with nothing but "No one in particular".
  if (!list.length) {
    const u = await db.findUserById(req.userId);
    if (u) {
      await db.insertProfile({ id: uuid(), user_id: req.userId, name: u.name, relation: 'self', created_at: Date.now() }).catch(e => console.error('Could not backfill default profile for', req.userId, e.message));
      list = await db.listProfilesByUser(req.userId);
    }
  }
  res.json({ profiles: list });
}));

app.post('/api/profiles', auth, wrap(async (req, res) => {
  const { name, relation } = req.body || {};
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'Give this person a name.' });
  const id = uuid();
  await db.insertProfile({ id, user_id: req.userId, name: String(name).trim(), relation: relation || 'other', created_at: Date.now() });
  res.json({ id });
}));

app.put('/api/profiles/:id', auth, wrap(async (req, res) => {
  const p = await db.findProfile(req.params.id, req.userId);
  if (!p) return res.status(404).json({ error: 'Not found.' });
  const { name, relation } = req.body || {};
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'Give this person a name.' });
  await db.updateProfile(p.id, { name: String(name).trim(), relation: relation || p.relation });
  res.json({ ok: true });
}));

app.delete('/api/profiles/:id', auth, wrap(async (req, res) => {
  const p = await db.findProfile(req.params.id, req.userId);
  if (!p) return res.status(404).json({ error: 'Not found.' });
  await db.deleteProfile(p.id);
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

/* ---------------- admin broadcasts / announcements ---------------- */
// The admin writes one title+message and picks, per broadcast, the channel
// (email, in-app, or both) and the audience (everyone, or one specific
// account) — the recipient doesn't get a separate preference for this;
// whatever the admin picked for that broadcast is what goes out.
function isValidBroadcastChannel(c) { return c === 'email' || c === 'inapp' || c === 'both'; }

app.post('/api/admin/broadcasts', auth, requireAdmin, wrap(async (req, res) => {
  const b = req.body || {};
  const title = String(b.title || '').trim();
  const body = String(b.body || '').trim();
  if (!title || !body) return res.status(400).json({ error: 'Write a title and a message.' });
  const channel = isValidBroadcastChannel(b.channel) ? b.channel : 'both';
  const audience = b.audience === 'user' ? 'user' : 'all';

  let targetUser = null;
  if (audience === 'user') {
    if (!b.targetUserId) return res.status(400).json({ error: 'Pick a user to target.' });
    targetUser = await db.findUserById(b.targetUserId);
    if (!targetUser) return res.status(404).json({ error: 'That user was not found.' });
  }

  const id = uuid();
  await db.insertBroadcast({
    id, title, body, channel, audience,
    target_user_id: targetUser ? targetUser.id : null,
    created_at: Date.now()
  });
  res.json({ id, ok: true });

  // Email is sent after responding (same fire-and-forget pattern as the
  // welcome email on signup) so a large user list can't make the admin's
  // request hang or time out.
  if (channel === 'email' || channel === 'both') {
    (async () => {
      const recipients = audience === 'user' ? [targetUser] : await db.listAllUsersBasic();
      for (const u of recipients) {
        if (!u || !u.email) continue;
        try { await sendMail(u.email, title, body); }
        catch (e) { console.error('Broadcast email failed for', u.email, e.message); }
      }
    })();
  }
}));

app.get('/api/admin/broadcasts', auth, requireAdmin, wrap(async (req, res) => {
  res.json({ broadcasts: await db.listBroadcasts() });
}));

/* ---------------- announcements (recipient side) ---------------- */
app.get('/api/announcements', auth, wrap(async (req, res) => {
  res.json({ announcements: await db.listAnnouncementsForUser(req.userId) });
}));

app.post('/api/announcements/:id/read', auth, wrap(async (req, res) => {
  await db.markBroadcastRead(req.params.id, req.userId);
  res.json({ ok: true });
}));

app.post('/api/announcements/read-all', auth, wrap(async (req, res) => {
  await db.markAllBroadcastsRead(req.userId, Date.now());
  res.json({ ok: true });
}));

/* ---------------- push notification subscription (admin only) ---------------- */
app.get('/api/push/vapid-public-key', auth, requireAdmin, wrap(async (req, res) => {
  res.json({ publicKey: VAPID_PUBLIC_KEY || null });
}));

app.post('/api/admin/push-subscribe', auth, requireAdmin, wrap(async (req, res) => {
  const s = req.body || {};
  if (!s.endpoint || !s.keys || !s.keys.p256dh || !s.keys.auth) {
    return res.status(400).json({ error: 'That subscription looks invalid.' });
  }
  await db.insertPushSubscription({
    id: uuid(), user_id: req.userId, endpoint: s.endpoint,
    p256dh: s.keys.p256dh, auth: s.keys.auth, created_at: Date.now()
  });
  res.json({ ok: true });
}));

/* ---------------- suggestions (user feedback, optional attachment) ---------------- */
const uploadSuggestion = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (/^image\//.test(file.mimetype) || file.mimetype === 'application/pdf') return cb(null, true);
    cb(new Error('Only a photo or PDF can be attached.'));
  }
});

app.post('/api/suggestions', auth, uploadSuggestion.single('file'), wrap(async (req, res) => {
  const message = String((req.body || {}).message || '').trim();
  if (!message) return res.status(400).json({ error: 'Write your suggestion first.' });
  const id = uuid();
  await db.insertSuggestion({
    id, user_id: req.userId, message: message.slice(0, 2000),
    file_name: req.file ? req.file.originalname : null,
    file_mime: req.file ? req.file.mimetype : null,
    file_size: req.file ? req.file.size : null,
    file_data: req.file ? req.file.buffer : null,
    created_at: Date.now()
  });
  res.json({ ok: true });
}));

app.get('/api/admin/suggestions', auth, requireAdmin, wrap(async (req, res) => {
  res.json({ suggestions: await db.listSuggestionsForAdmin() });
}));

app.get('/api/admin/suggestions/:id/file', auth, requireAdmin, wrap(async (req, res) => {
  const f = await db.findSuggestionFile(req.params.id);
  if (!f || !f.file_data) return res.status(404).end();
  res.setHeader('Content-Type', f.file_mime || 'application/octet-stream');
  res.setHeader('Content-Disposition', 'inline; filename="' + (f.file_name || 'attachment').replace(/"/g, '') + '"');
  res.send(f.file_data);
}));

/* ---------------- documents ---------------- */
app.get('/api/documents', auth, wrap(async (req, res) => {
  const docs = await db.listDocumentsByUser(req.userId);
  const files = await db.listFilesByUser(req.userId);
  docs.forEach(d => { d.files = files.filter(f => f.document_id === d.id); });
  res.json({ docs });
}));

// A profile_id must actually belong to this account, or it's dropped —
// otherwise a tampered request could tag a document onto someone else's
// Family Vault profile.
async function cleanProfileId(userId, profileId) {
  if (!profileId) return null;
  const p = await db.findProfile(profileId, userId);
  return p ? p.id : null;
}

app.post('/api/documents', auth, wrap(async (req, res) => {
  const b = req.body || {};
  if (!b.title) return res.status(400).json({ error: 'Give the document a name.' });
  const id = uuid();
  await db.insertDocument({
    id, user_id: req.userId, type: b.type || 'other', title: b.title, holder: b.holder || '',
    number: b.number || '', issue: b.issue || '', expiry: b.expiry || '', lead: Number(b.lead) || 30,
    notes: b.notes || '', category: b.category ? String(b.category).trim().slice(0, 40) : null,
    profile_id: await cleanProfileId(req.userId, b.profileId),
    reminder_days: cleanMilestones(b.reminderDays, DEFAULT_DOC_MILESTONES),
    created_at: Date.now()
  });
  res.json({ id });
}));

app.put('/api/documents/:id', auth, wrap(async (req, res) => {
  const d = await db.findDocument(req.params.id, req.userId);
  if (!d) return res.status(404).json({ error: 'Not found.' });
  const b = req.body || {};
  if (!b.title) return res.status(400).json({ error: 'Give the document a name.' });
  const patch = {
    type: b.type || d.type, title: b.title, holder: b.holder || '', number: b.number || '',
    issue: b.issue || '', expiry: b.expiry || '', lead: Number(b.lead) || 30, notes: b.notes || '',
    category: b.category ? String(b.category).trim().slice(0, 40) : null,
    profile_id: await cleanProfileId(req.userId, b.profileId),
    reminder_days: cleanMilestones(b.reminderDays, Array.isArray(d.reminder_days) ? d.reminder_days : DEFAULT_DOC_MILESTONES)
  };
  // Renewal: the expiry date moved to a new date. Quietly keep the old
  // number/issue/expiry so it's still there for insurance claims, visa
  // applications, etc. that ask about the previous document.
  if (d.expiry && patch.expiry && patch.expiry !== d.expiry) {
    const history = Array.isArray(d.history) ? d.history.slice() : [];
    history.push({ number: d.number || '', issue: d.issue || '', expiry: d.expiry, archivedAt: Date.now() });
    patch.history = JSON.stringify(history);
    // A new expiry starts a new reminder cycle — otherwise a milestone
    // already emailed for the old expiry would silently never fire again.
    await db.deleteNotifiedByDocument(d.id).catch(() => {});
  }
  await db.updateDocument(d.id, patch);
  res.json({ ok: true });
}));

app.delete('/api/documents/:id', auth, wrap(async (req, res) => {
  const d = await db.findDocument(req.params.id, req.userId);
  if (!d) return res.status(404).json({ error: 'Not found.' });
  await db.deleteFilesByDocument(d.id);
  await db.deleteNotifiedByDocument(d.id);
  await db.deleteBundleItemsByDocument(d.id);
  await db.deleteDocument(d.id);
  res.json({ ok: true });
}));

/* ---------------- subscriptions & recurring payments ---------------- */
function isValidRecurrence(r) { return r === 'monthly' || r === 'yearly'; }
// Moves a YYYY-MM-DD date forward by one billing cycle, from the due date
// itself (not from today) so a fixed schedule (e.g. "the 5th of every
// month") stays on the 5th even if it's marked paid a few days late.
function advanceDate(dateStr, recurrence) {
  const d = new Date(dateStr + 'T00:00:00');
  if (recurrence === 'yearly') d.setFullYear(d.getFullYear() + 1);
  else d.setMonth(d.getMonth() + 1);
  return d.toISOString().slice(0, 10);
}

app.get('/api/subscriptions', auth, wrap(async (req, res) => {
  res.json({ subscriptions: await db.listSubscriptionsByUser(req.userId) });
}));

app.post('/api/subscriptions', auth, wrap(async (req, res) => {
  const b = req.body || {};
  if (!b.name || !String(b.name).trim()) return res.status(400).json({ error: 'Give this subscription a name.' });
  const recurrence = isValidRecurrence(b.recurrence) ? b.recurrence : 'monthly';
  const id = uuid();
  await db.insertSubscription({
    id, user_id: req.userId, profile_id: await cleanProfileId(req.userId, b.profileId),
    category: b.category ? String(b.category).trim().slice(0, 40) : 'other',
    name: String(b.name).trim(), amount: b.amount ? String(b.amount).trim().slice(0, 30) : '',
    recurrence, next_due: b.nextDue || '', reminder_days: cleanMilestones(b.reminderDays, DEFAULT_SUB_MILESTONES),
    notes: b.notes || '', created_at: Date.now()
  });
  res.json({ id });
}));

app.put('/api/subscriptions/:id', auth, wrap(async (req, res) => {
  const s = await db.findSubscription(req.params.id, req.userId);
  if (!s) return res.status(404).json({ error: 'Not found.' });
  const b = req.body || {};
  if (!b.name || !String(b.name).trim()) return res.status(400).json({ error: 'Give this subscription a name.' });
  const patch = {
    profile_id: await cleanProfileId(req.userId, b.profileId),
    category: b.category ? String(b.category).trim().slice(0, 40) : 'other',
    name: String(b.name).trim(), amount: b.amount ? String(b.amount).trim().slice(0, 30) : '',
    recurrence: isValidRecurrence(b.recurrence) ? b.recurrence : s.recurrence,
    next_due: b.nextDue || '', notes: b.notes || '',
    reminder_days: cleanMilestones(b.reminderDays, Array.isArray(s.reminder_days) ? s.reminder_days : DEFAULT_SUB_MILESTONES)
  };
  if (s.next_due && patch.next_due && patch.next_due !== s.next_due) {
    await db.deleteSubNotifiedBySubscription(s.id).catch(() => {});
  }
  await db.updateSubscription(s.id, patch);
  res.json({ ok: true });
}));

// "Mark as paid" — rolls the due date forward one billing cycle and resets
// the reminder milestones so the new cycle's warnings can fire again.
app.post('/api/subscriptions/:id/renew', auth, wrap(async (req, res) => {
  const s = await db.findSubscription(req.params.id, req.userId);
  if (!s) return res.status(404).json({ error: 'Not found.' });
  if (!s.next_due) return res.status(400).json({ error: 'This subscription has no due date set yet.' });
  const nextDue = advanceDate(s.next_due, s.recurrence);
  await db.updateSubscription(s.id, { next_due: nextDue, last_paid_at: Date.now() });
  await db.deleteSubNotifiedBySubscription(s.id).catch(() => {});
  res.json({ ok: true, nextDue });
}));

app.delete('/api/subscriptions/:id', auth, wrap(async (req, res) => {
  const s = await db.findSubscription(req.params.id, req.userId);
  if (!s) return res.status(404).json({ error: 'Not found.' });
  await db.deleteSubscription(s.id);
  res.json({ ok: true });
}));

/* ---------------- document bundles (e.g. "Travel Documents") ---------------- */
// View/filter-only grouping for now — no bulk download or public sharing.
// A document can belong to more than one bundle.
app.get('/api/bundles', auth, wrap(async (req, res) => {
  const bundles = await db.listBundlesByUser(req.userId);
  const items = await db.listBundleItemsByUser(req.userId);
  const byBundle = {};
  items.forEach(it => { (byBundle[it.bundle_id] = byBundle[it.bundle_id] || []).push(it.document_id); });
  res.json({ bundles: bundles.map(b => ({ id: b.id, name: b.name, createdAt: b.created_at, documentIds: byBundle[b.id] || [] })) });
}));

app.post('/api/bundles', auth, wrap(async (req, res) => {
  const { name } = req.body || {};
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'Give this bundle a name.' });
  const id = uuid();
  await db.insertBundle({ id, user_id: req.userId, name: String(name).trim().slice(0, 60), created_at: Date.now() });
  res.json({ id });
}));

app.put('/api/bundles/:id', auth, wrap(async (req, res) => {
  const b = await db.findBundle(req.params.id, req.userId);
  if (!b) return res.status(404).json({ error: 'Not found.' });
  const { name } = req.body || {};
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'Give this bundle a name.' });
  await db.updateBundle(b.id, { name: String(name).trim().slice(0, 60) });
  res.json({ ok: true });
}));

app.delete('/api/bundles/:id', auth, wrap(async (req, res) => {
  const b = await db.findBundle(req.params.id, req.userId);
  if (!b) return res.status(404).json({ error: 'Not found.' });
  await db.deleteBundle(b.id);
  res.json({ ok: true });
}));

app.post('/api/bundles/:id/items', auth, wrap(async (req, res) => {
  const b = await db.findBundle(req.params.id, req.userId);
  if (!b) return res.status(404).json({ error: 'Not found.' });
  const d = await db.findDocument((req.body || {}).documentId, req.userId);
  if (!d) return res.status(404).json({ error: 'Document not found.' });
  await db.insertBundleItem({ id: uuid(), bundle_id: b.id, document_id: d.id });
  res.json({ ok: true });
}));

app.delete('/api/bundles/:id/items/:documentId', auth, wrap(async (req, res) => {
  const b = await db.findBundle(req.params.id, req.userId);
  if (!b) return res.status(404).json({ error: 'Not found.' });
  await db.deleteBundleItem(b.id, req.params.documentId);
  res.json({ ok: true });
}));

/* ---------------- Life Admin Alert (documents + subscriptions due soon, combined) ---------------- */
const WEEKLY_ALERT_WINDOW_DAYS = 7;
async function weeklyAlertItemsForUser(userId) {
  const [docs, subs] = await Promise.all([db.listDocumentsByUser(userId), db.listSubscriptionsByUser(userId)]);
  const items = [];
  docs.forEach(d => {
    const dl = daysLeft(d.expiry);
    if (dl !== null && dl <= WEEKLY_ALERT_WINDOW_DAYS) items.push({ kind: 'document', id: d.id, title: d.title, daysLeft: dl });
  });
  subs.forEach(s => {
    const dl = daysLeft(s.next_due);
    if (dl !== null && dl <= WEEKLY_ALERT_WINDOW_DAYS) items.push({ kind: 'subscription', id: s.id, title: s.name, daysLeft: dl });
  });
  items.sort((a, b) => a.daysLeft - b.daysLeft);
  return items;
}
app.get('/api/alerts/weekly', auth, wrap(async (req, res) => {
  const items = await weeklyAlertItemsForUser(req.userId);
  res.json({ count: items.length, items: items.slice(0, 8) });
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

// Reads a photo of a document (NID, passport, trade licence, etc.) and
// pulls out whatever labeled fields it can find — name, father's/mother's
// name, address, document number, dates and so on — so the Add Document
// form can be pre-filled instead of typed by hand. The photo is sent to
// Anthropic's API for this one request only; nothing is stored there.
app.post('/api/documents/scan', auth, upload.single('file'), wrap(async (req, res) => {
  if (!ANTHROPIC_API_KEY) {
    return res.status(400).json({ error: 'Scanning isn’t set up on this server yet (ANTHROPIC_API_KEY is missing).' });
  }
  if (!req.file) return res.status(400).json({ error: 'No photo received.' });
  if (!/^image\//.test(req.file.mimetype)) {
    return res.status(400).json({ error: 'Attach a photo (not a PDF) to scan it.' });
  }

  const prompt =
    'You are reading a photo of a personal identity or official document — it may be a Bangladeshi ' +
    'National ID card, passport, birth certificate, trade licence, or something similar, and any text on it ' +
    'may be in Bangla, English, or both. Identify what kind of document this looks like, and extract every ' +
    'clearly legible labeled field you can actually see, such as name, father’s name, mother’s name, date of ' +
    'birth, address, ID/document number, issue date, and expiry date — whichever of these are present. ' +
    'Respond with ONLY a JSON object and nothing else, in exactly this shape: ' +
    '{"documentType":"<short guess, e.g. \\"National ID\\", \\"Passport\\", \\"Trade licence\\", \\"Birth certificate\\", or \\"Other\\">",' +
    '"fields":{"<field label as seen on the document>":"<value>", ...}}. ' +
    'Only include fields you can actually read — never guess or invent a value.';

  let apiRes;
  try {
    apiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        model: ANTHROPIC_MODEL,
        max_tokens: 1024,
        messages: [{
          role: 'user',
          content: [
            { type: 'image', source: { type: 'base64', media_type: req.file.mimetype, data: req.file.buffer.toString('base64') } },
            { type: 'text', text: prompt }
          ]
        }]
      })
    });
  } catch (e) {
    console.error('Scan request could not reach Anthropic:', e.message);
    return res.status(502).json({ error: 'Could not reach the scanning service. Try again in a moment.' });
  }

  const data = await apiRes.json().catch(() => null);
  if (!apiRes.ok || !data) {
    console.error('Scan request failed:', apiRes.status, data);
    return res.status(502).json({ error: 'Could not reach the scanning service. Try again in a moment.' });
  }

  const text = (data.content && data.content[0] && data.content[0].text) || '';
  let parsed;
  try {
    const match = text.match(/\{[\s\S]*\}/); // tolerates any stray text/code fences around the JSON
    parsed = JSON.parse(match ? match[0] : text);
  } catch (e) {
    console.error('Could not parse scan result:', text);
    return res.status(502).json({ error: 'Could not read the details from that photo clearly. Try a sharper, well-lit photo.' });
  }

  res.json({ documentType: parsed.documentType || null, fields: (parsed.fields && typeof parsed.fields === 'object') ? parsed.fields : {} });
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

/* ---------------- daily reminder emails (Smart Reminder System) ---------------- */
// Each document has its own milestone list (default 180/90/30/7/1 days
// before expiry, customizable per document). A milestone fires exactly
// once — the day the countdown hits that exact number — instead of the old
// behavior of emailing every single day once inside one fixed lead window.
// Missing the exact day once (e.g. the server was down) just means that one
// milestone's email doesn't go out; it does not cause a backlog of emails.
async function runReminderSweep() {
  const todayISO = new Date().toISOString().slice(0, 10);
  const rows = await db.allDocumentsWithExpiry();
  for (const d of rows) {
    const dl = daysLeft(d.expiry);
    if (dl === null || !d.user_email) continue;
    const milestones = Array.isArray(d.reminder_days) && d.reminder_days.length ? d.reminder_days : DEFAULT_DOC_MILESTONES;
    if (milestones.indexOf(dl) === -1) continue;
    if (await db.findNotifiedMilestone(d.id, dl)) continue;
    const when = dl < 0 ? ('expired ' + (-dl) + ' day(s) ago') : dl === 0 ? 'expires today' : ('expires in ' + dl + ' day(s)');
    const subject = (dl < 0 ? 'Expired: ' : 'Reminder: ') + d.title;
    const body = d.title + ' ' + when + ' (' + d.expiry + ').' + (d.notes ? ('\n\n' + d.notes) : '');
    try {
      await sendMail(d.user_email, subject, body);
      await db.insertNotifiedMilestone({ id: uuid(), user_id: d.user_id, document_id: d.id, sent_date: todayISO, milestone: dl });
    } catch (e) {
      console.error('Reminder email failed for document', d.id, e.message);
    }
  }
}
cron.schedule('0 9 * * *', runReminderSweep);

/* ---------------- subscription & payment reminders ---------------- */
async function runSubscriptionReminderSweep() {
  const rows = await db.allSubscriptionsWithDue();
  for (const s of rows) {
    const dl = daysLeft(s.next_due);
    if (dl === null || !s.user_email) continue;
    const milestones = Array.isArray(s.reminder_days) && s.reminder_days.length ? s.reminder_days : DEFAULT_SUB_MILESTONES;
    if (milestones.indexOf(dl) === -1) continue;
    if (await db.findSubNotifiedMilestone(s.id, dl)) continue;
    const when = dl < 0 ? ('was due ' + (-dl) + ' day(s) ago') : dl === 0 ? 'is due today' : ('is due in ' + dl + ' day(s)');
    const subject = (dl < 0 ? 'Overdue: ' : 'Payment reminder: ') + s.name;
    const body = s.name + (s.amount ? (' (' + s.amount + ')') : '') + ' ' + when + ' (' + s.next_due + ').' + (s.notes ? ('\n\n' + s.notes) : '');
    try {
      await sendMail(s.user_email, subject, body);
      await db.insertSubNotifiedMilestone({ id: uuid(), user_id: s.user_id, subscription_id: s.id, milestone: dl });
    } catch (e) {
      console.error('Subscription reminder email failed for', s.id, e.message);
    }
  }
}
cron.schedule('0 9 * * *', runSubscriptionReminderSweep);

/* ---------------- weekly "use your vault" follow-up email ---------------- */
// Retention nudge, separate from the near-expiry reminders above: everyone
// gets one email a week, but what it says depends on their vault —
// empty vault, documents with no expiry date set (so we can't remind them
// automatically), or a general check-in for an otherwise healthy vault.
async function runWeeklyEngagementSweep() {
  const now = Date.now();
  const MIN_GAP_MS = 6.5 * 24 * 60 * 60 * 1000; // guards against double-sending the same week on a restart
  const appLink = process.env.FRONTEND_URL || '';

  const users = await db.weeklyEmailCandidates();
  const withExpiry = await db.allDocumentsWithExpiry();
  const withDue = await db.allSubscriptionsWithDue();
  const nearestByUser = {};
  for (const d of withExpiry) {
    const dl = daysLeft(d.expiry);
    if (dl === null) continue;
    const cur = nearestByUser[d.user_id];
    if (!cur || dl < cur.dl) nearestByUser[d.user_id] = { dl, title: d.title, expiry: d.expiry };
  }
  // Life Admin Alert: documents + subscriptions together, due/expiring
  // within the same week-out window as the in-app banner (see
  // weeklyAlertItemsForUser above), so the email and the banner always
  // agree on what counts as "this week".
  const alertItemsByUser = {};
  function pushAlertItem(userId, title, dl) {
    if (dl > WEEKLY_ALERT_WINDOW_DAYS) return;
    (alertItemsByUser[userId] = alertItemsByUser[userId] || []).push({ title, dl });
  }
  withExpiry.forEach(d => { const dl = daysLeft(d.expiry); if (dl !== null) pushAlertItem(d.user_id, d.title, dl); });
  withDue.forEach(s => { const dl = daysLeft(s.next_due); if (dl !== null) pushAlertItem(s.user_id, s.name, dl); });
  Object.keys(alertItemsByUser).forEach(uid => alertItemsByUser[uid].sort((a, b) => a.dl - b.dl));

  for (const u of users) {
    if (!u.email) continue;
    if (u.last_weekly_email_at && (now - Number(u.last_weekly_email_at)) < MIN_GAP_MS) continue;

    let subject, body;
    if (u.doc_count === 0) {
      subject = 'Your Life Documents vault is still empty';
      body = 'Hi ' + u.name + ',\n\n' +
        'You haven\'t added any documents yet. Add your NID, passport, trade licence, insurance policy, or any document with an expiry date, and you\'ll get an automatic email reminder before it lapses.' +
        (appLink ? ('\n\nOpen your vault: ' + appLink) : '') +
        '\n\n— Life Documents';
    } else if (u.missing_expiry_count > 0) {
      subject = 'Quick check: ' + u.missing_expiry_count + ' of your documents have no expiry date';
      body = 'Hi ' + u.name + ',\n\n' +
        u.missing_expiry_count + ' of your ' + u.doc_count + ' saved document(s) don\'t have an expiry date set, so we can\'t remind you before they lapse. Open your vault and add the missing dates.' +
        (appLink ? ('\n\nOpen your vault: ' + appLink) : '') +
        '\n\n— Life Documents';
    } else if ((alertItemsByUser[u.id] || []).length > 0) {
      const items = alertItemsByUser[u.id];
      subject = 'You have ' + items.length + ' thing' + (items.length === 1 ? '' : 's') + ' to take care of this week';
      const lines = items.slice(0, 8).map(it => {
        const when = it.dl < 0 ? ((-it.dl) + ' day(s) overdue') : it.dl === 0 ? 'due/expires today' : ('in ' + it.dl + ' day(s)');
        return '- ' + it.title + ' — ' + when;
      }).join('\n');
      body = 'Hi ' + u.name + ',\n\n' +
        'Here\'s what needs your attention this week:\n\n' + lines +
        (items.length > 8 ? ('\n\n...and ' + (items.length - 8) + ' more.') : '') +
        (appLink ? ('\n\nOpen your vault: ' + appLink) : '') +
        '\n\n— Life Documents';
    } else {
      const nearest = nearestByUser[u.id];
      subject = 'Weekly check-in: ' + u.doc_count + ' document(s) in your vault';
      body = 'Hi ' + u.name + ',\n\n' +
        'You have ' + u.doc_count + ' document(s) saved. Take a moment to check that everything is still accurate — especially the document number and expiry date on anything you\'ve recently renewed.' +
        (nearest ? ('\n\nComing up: ' + nearest.title + ' ' + (nearest.dl < 0 ? ('expired ' + (-nearest.dl) + ' day(s) ago') : nearest.dl === 0 ? 'expires today' : ('expires in ' + nearest.dl + ' day(s)')) + ' (' + nearest.expiry + ').') : '') +
        (appLink ? ('\n\nOpen your vault: ' + appLink) : '') +
        '\n\n— Life Documents';
    }

    try {
      await sendMail(u.email, subject, body);
      await db.markWeeklyEmailSent(u.id, now);
    } catch (e) {
      console.error('Weekly follow-up email failed for', u.email, e.message);
    }
  }
}
// Monday 10:00 server time (UTC on Render) — mid-afternoon in Bangladesh.
cron.schedule('0 10 * * 1', runWeeklyEngagementSweep);

// generic error handler (from wrap())
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Something went wrong on the server.' });
});

const PORT = process.env.PORT || 4000;
db.init()
  .then(() => {
    app.listen(PORT, () => console.log('Life Documents API listening on :' + PORT));
  })
  .catch(e => {
    console.error('Could not connect to the database. Check DATABASE_URL in your .env:', e.message);
    process.exit(1);
  });
