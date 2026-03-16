const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'oneclickscan.db');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS target (
    target_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    is_delete   INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS katana (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL,
    result_file TEXT NOT NULL,
    flags_json  TEXT,
    scan_at     DATETIME NOT NULL,
    FOREIGN KEY (target_id) REFERENCES target(target_id)
  );
`);

// lightweight migrations for older DBs
const katanaCols = db
  .prepare(`PRAGMA table_info(katana)`)
  .all()
  .map((c) => c.name);
if (!katanaCols.includes('flags_json')) {
  db.exec(`ALTER TABLE katana ADD COLUMN flags_json TEXT;`);
}

const getOrCreateTargetStmt = db.prepare(
  'SELECT * FROM target WHERE target_name = ? AND is_delete = 0'
);

const insertTargetStmt = db.prepare(
  'INSERT INTO target (target_name, is_delete) VALUES (?, 0)'
);

const countKatanaByTargetStmt = db.prepare(
  'SELECT COUNT(*) AS count FROM katana WHERE target_id = ?'
);

const insertKatanaStmt = db.prepare(
  'INSERT INTO katana (target_id, result_file, flags_json, scan_at) VALUES (?, ?, ?, ?)'
);

const listTargetsStmt = db.prepare(
  `SELECT target_id, target_name
   FROM target
   WHERE is_delete = 0 AND target_name LIKE ?
   ORDER BY target_id DESC
   LIMIT ? OFFSET ?`
);

const listKatanaByTargetStmt = db.prepare(
  `SELECT id, target_id, result_file, flags_json, scan_at
   FROM katana
   WHERE target_id = ?
   ORDER BY id DESC`
);

function getOrCreateTarget(targetName) {
  let row = getOrCreateTargetStmt.get(targetName);
  if (!row) {
    const info = insertTargetStmt.run(targetName);
    row = { target_id: info.lastInsertRowid, target_name: targetName, is_delete: 0 };
  }
  return row;
}

function getKatanaScanRound(targetId) {
  const { count } = countKatanaByTargetStmt.get(targetId);
  return count + 1;
}

function insertKatanaScan(targetId, resultFile, flagsJson, scanAt) {
  const info = insertKatanaStmt.run(targetId, resultFile, flagsJson, scanAt);
  return info.lastInsertRowid;
}

function listTargets({ q, limit = 50, offset = 0 }) {
  const query = `%${q || ''}%`;
  return listTargetsStmt.all(query, limit, offset);
}

function listKatanaByTarget(targetId) {
  return listKatanaByTargetStmt.all(targetId);
}

module.exports = {
  db,
  getOrCreateTarget,
  getKatanaScanRound,
  insertKatanaScan,
  listTargets,
  listKatanaByTarget,
};

