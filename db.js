// Plain-JSON file store. No native/compiled dependencies, so it can never
// fail to build the way SQLite-based packages sometimes do on free hosts.
// Fine for a personal-scale app; everything loads into memory and is
// rewritten to disk after every change.
const fs = require('fs');
require('dotenv').config();

const FILE = process.env.DB_PATH || './data.json';

function load() {
  try {
    const raw = fs.readFileSync(FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return {
      users: parsed.users || [],
      documents: parsed.documents || [],
      files: parsed.files || [],
      notified: parsed.notified || []
    };
  } catch (e) {
    return { users: [], documents: [], files: [], notified: [] };
  }
}

let data = load();

function save() {
  // Write to a temp file then rename, so a crash mid-write can't corrupt data.json.
  const tmp = FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data));
  fs.renameSync(tmp, FILE);
}

module.exports = {
  // ---- users ----
  insertUser(u) { data.users.push(u); save(); },
  findUserByEmail(email) { return data.users.find(u => u.email === email) || null; },
  findUserById(id) { return data.users.find(u => u.id === id) || null; },
  findUserByResetToken(token) { return data.users.find(u => u.reset_token === token) || null; },
  updateUser(id, patch) {
    const u = data.users.find(x => x.id === id);
    if (u) { Object.assign(u, patch); save(); }
  },
  listUsers() {
    return data.users
      .slice()
      .sort((a, b) => b.created_at - a.created_at)
      .map(u => ({ id: u.id, name: u.name, email: u.email, phone: u.phone, created_at: u.created_at }));
  },
  docCountsByUser() {
    const m = {};
    data.documents.forEach(d => { m[d.user_id] = (m[d.user_id] || 0) + 1; });
    return m;
  },

  // ---- documents ----
  insertDocument(d) { data.documents.push(d); save(); },
  findDocument(id, userId) { return data.documents.find(d => d.id === id && d.user_id === userId) || null; },
  listDocumentsByUser(userId) {
    return data.documents.filter(d => d.user_id === userId).sort((a, b) => a.created_at - b.created_at).map(d => ({ ...d }));
  },
  updateDocument(id, patch) {
    const d = data.documents.find(x => x.id === id);
    if (d) { Object.assign(d, patch); save(); }
  },
  deleteDocument(id) { data.documents = data.documents.filter(d => d.id !== id); save(); },
  allDocumentsWithExpiry() {
    return data.documents
      .filter(d => d.expiry)
      .map(d => {
        const u = data.users.find(x => x.id === d.user_id);
        return Object.assign({}, d, { user_email: u ? u.email : null });
      });
  },

  // ---- files ----
  insertFile(f) { data.files.push(f); save(); },
  findFile(id, userId) { return data.files.find(f => f.id === id && f.user_id === userId) || null; },
  findFileById(id) { return data.files.find(f => f.id === id) || null; },
  listFilesByUser(userId) {
    return data.files.filter(f => f.user_id === userId).map(f => ({ id: f.id, document_id: f.document_id, name: f.name, mime: f.mime, size: f.size }));
  },
  listFilesByDocument(docId) { return data.files.filter(f => f.document_id === docId); },
  deleteFile(id) { data.files = data.files.filter(f => f.id !== id); save(); },
  deleteFilesByDocument(docId) { data.files = data.files.filter(f => f.document_id !== docId); save(); },

  // ---- notified ----
  findNotified(docId, date) { return data.notified.find(n => n.document_id === docId && n.sent_date === date) || null; },
  insertNotified(n) { data.notified.push(n); save(); },
  deleteNotifiedByDocument(docId) { data.notified = data.notified.filter(n => n.document_id !== docId); save(); }
};
