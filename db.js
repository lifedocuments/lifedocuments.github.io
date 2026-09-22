const Database = require('better-sqlite3');
require('dotenv').config();

const db = new Database(process.env.DB_PATH || './data.sqlite');
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  phone TEXT,
  password_hash TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'free',
  reset_token TEXT,
  reset_expires INTEGER,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS documents(
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  type TEXT NOT NULL,
  title TEXT NOT NULL,
  holder TEXT,
  number TEXT,
  issue TEXT,
  expiry TEXT,
  lead INTEGER NOT NULL DEFAULT 30,
  notes TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS files(
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  mime TEXT,
  size INTEGER,
  path TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(document_id) REFERENCES documents(id)
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

module.exports = db;
