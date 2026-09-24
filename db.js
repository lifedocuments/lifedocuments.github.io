// Postgres-backed store (e.g. a free Supabase project). Replaces the old
// local JSON file, which Render's free tier wipes on every restart/redeploy.
// Uploaded file BYTES also live in this database now (not on local disk),
// for the same reason — local disk isn't persistent on the free tier either.
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('supabase') ? { rejectUnauthorized: false } : undefined
});

async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users(
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT,
      password_hash TEXT NOT NULL,
      plan TEXT NOT NULL DEFAULT 'free',
      reset_token TEXT,
      reset_expires BIGINT,
      created_at BIGINT NOT NULL
    );
    -- Added after the table already existed in production, so a plain
    -- CREATE TABLE IF NOT EXISTS above won't add it to existing databases.
    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at BIGINT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_device TEXT;
    CREATE TABLE IF NOT EXISTS documents(
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      holder TEXT,
      number TEXT,
      issue TEXT,
      expiry TEXT,
      lead INTEGER NOT NULL DEFAULT 30,
      notes TEXT,
      created_at BIGINT NOT NULL
    );
    -- Snapshot of prior expiry/number/issue kept whenever a document is
    -- renewed (its expiry date is changed to a new one), so old versions
    -- stay available for insurance claims, visa applications, etc.
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS history JSONB NOT NULL DEFAULT '[]';
    CREATE TABLE IF NOT EXISTS files(
      id TEXT PRIMARY KEY,
      document_id TEXT NOT NULL REFERENCES documents(id),
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      mime TEXT,
      size INTEGER,
      data BYTEA NOT NULL,
      created_at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS notified(
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      document_id TEXT NOT NULL,
      sent_date TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_documents_user ON documents(user_id);
    CREATE INDEX IF NOT EXISTS idx_files_document ON files(document_id);
    CREATE INDEX IF NOT EXISTS idx_notified_lookup ON notified(document_id, sent_date);
  `);
}

module.exports = {
  init,

  // ---- users ----
  async insertUser(u) {
    await pool.query(
      `INSERT INTO users(id,name,email,phone,password_hash,plan,reset_token,reset_expires,created_at)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [u.id, u.name, u.email, u.phone, u.password_hash, u.plan, u.reset_token, u.reset_expires, u.created_at]
    );
  },
  async findUserByEmail(email) {
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    return r.rows[0] || null;
  },
  async findUserById(id) {
    const r = await pool.query('SELECT * FROM users WHERE id=$1', [id]);
    return r.rows[0] || null;
  },
  async findUserByResetToken(token) {
    const r = await pool.query('SELECT * FROM users WHERE reset_token=$1', [token]);
    return r.rows[0] || null;
  },
  async updateUser(id, patch) {
    const keys = Object.keys(patch);
    if (!keys.length) return;
    const sets = keys.map((k, i) => `${k}=$${i + 2}`).join(', ');
    await pool.query(`UPDATE users SET ${sets} WHERE id=$1`, [id, ...keys.map(k => patch[k])]);
  },
  // `q` filters by name/email/phone (case-insensitive substring); the
  // actual sort (including "most documents", which needs the join in
  // server.js) is applied by the caller after merging in document counts.
  async listUsers({ q } = {}) {
    if (q) {
      const like = `%${String(q).toLowerCase()}%`;
      const r = await pool.query(
        `SELECT id,name,email,phone,created_at,last_login_at FROM users
         WHERE LOWER(name) LIKE $1 OR LOWER(email) LIKE $1 OR LOWER(COALESCE(phone,'')) LIKE $1
         ORDER BY created_at DESC`,
        [like]
      );
      return r.rows;
    }
    const r = await pool.query('SELECT id,name,email,phone,created_at,last_login_at FROM users ORDER BY created_at DESC');
    return r.rows;
  },
  async touchLastLogin(id, device) {
    await pool.query('UPDATE users SET last_login_at=$2, last_login_device=$3 WHERE id=$1', [id, Date.now(), device || null]);
  },
  async docCountsByUser() {
    const r = await pool.query('SELECT user_id, COUNT(*)::int c FROM documents GROUP BY user_id');
    const m = {};
    r.rows.forEach(row => { m[row.user_id] = row.c; });
    return m;
  },
  // Top-line counts for the admin stats bar. "Expiring this week" and
  // "overdue" only look at documents with a well-formed YYYY-MM-DD expiry.
  async adminStats() {
    const users = await pool.query('SELECT COUNT(*)::int c FROM users');
    const docs = await pool.query('SELECT COUNT(*)::int c FROM documents');
    const expiry = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE expiry::date < CURRENT_DATE)::int AS overdue,
        COUNT(*) FILTER (WHERE expiry::date >= CURRENT_DATE AND expiry::date < CURRENT_DATE + INTERVAL '7 days')::int AS expiring_this_week
      FROM documents
      WHERE expiry ~ '^\\d{4}-\\d{2}-\\d{2}$'
    `);
    return {
      totalUsers: users.rows[0].c,
      totalDocuments: docs.rows[0].c,
      expiringThisWeek: expiry.rows[0].expiring_this_week,
      overdue: expiry.rows[0].overdue,
    };
  },

  // ---- documents ----
  async insertDocument(d) {
    await pool.query(
      `INSERT INTO documents(id,user_id,type,title,holder,number,issue,expiry,lead,notes,created_at)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [d.id, d.user_id, d.type, d.title, d.holder, d.number, d.issue, d.expiry, d.lead, d.notes, d.created_at]
    );
  },
  async findDocument(id, userId) {
    const r = await pool.query('SELECT * FROM documents WHERE id=$1 AND user_id=$2', [id, userId]);
    return r.rows[0] || null;
  },
  async listDocumentsByUser(userId) {
    const r = await pool.query('SELECT * FROM documents WHERE user_id=$1 ORDER BY created_at', [userId]);
    return r.rows;
  },
  async updateDocument(id, patch) {
    const keys = Object.keys(patch);
    if (!keys.length) return;
    const sets = keys.map((k, i) => `${k}=$${i + 2}`).join(', ');
    await pool.query(`UPDATE documents SET ${sets} WHERE id=$1`, [id, ...keys.map(k => patch[k])]);
  },
  async deleteDocument(id) {
    await pool.query('DELETE FROM documents WHERE id=$1', [id]);
  },
  async allDocumentsWithExpiry() {
    const r = await pool.query(`
      SELECT documents.*, users.email AS user_email
      FROM documents JOIN users ON users.id = documents.user_id
      WHERE documents.expiry IS NOT NULL AND documents.expiry <> ''
    `);
    return r.rows;
  },

  // ---- files ----
  async insertFile(f) {
    await pool.query(
      `INSERT INTO files(id,document_id,user_id,name,mime,size,data,created_at)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
      [f.id, f.document_id, f.user_id, f.name, f.mime, f.size, f.data, f.created_at]
    );
  },
  async findFile(id, userId) {
    const r = await pool.query('SELECT * FROM files WHERE id=$1 AND user_id=$2', [id, userId]);
    return r.rows[0] || null;
  },
  async findFileById(id) {
    const r = await pool.query('SELECT * FROM files WHERE id=$1', [id]);
    return r.rows[0] || null;
  },
  async listFilesByUser(userId) {
    const r = await pool.query('SELECT id,document_id,name,mime,size FROM files WHERE user_id=$1', [userId]);
    return r.rows;
  },
  async listFilesByDocument(docId) {
    const r = await pool.query('SELECT id,document_id,name,mime,size FROM files WHERE document_id=$1', [docId]);
    return r.rows;
  },
  async deleteFile(id) {
    await pool.query('DELETE FROM files WHERE id=$1', [id]);
  },
  async deleteFilesByDocument(docId) {
    await pool.query('DELETE FROM files WHERE document_id=$1', [docId]);
  },

  // ---- notified ----
  async findNotified(docId, date) {
    const r = await pool.query('SELECT id FROM notified WHERE document_id=$1 AND sent_date=$2', [docId, date]);
    return r.rows[0] || null;
  },
  async insertNotified(n) {
    await pool.query('INSERT INTO notified(id,user_id,document_id,sent_date) VALUES($1,$2,$3,$4)', [n.id, n.user_id, n.document_id, n.sent_date]);
  },
  async deleteNotifiedByDocument(docId) {
    await pool.query('DELETE FROM notified WHERE document_id=$1', [docId]);
  }
};
