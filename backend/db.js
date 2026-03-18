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

  CREATE TABLE IF NOT EXISTS ffuf (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL,
    result_file TEXT NOT NULL,
    wordlist_source TEXT,
    scan_at     DATETIME NOT NULL,
    FOREIGN KEY (target_id) REFERENCES target(target_id)
  );

  CREATE TABLE IF NOT EXISTS payload_recon (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL,
    result_file TEXT NOT NULL,
    scan_at     DATETIME NOT NULL,
    FOREIGN KEY (target_id) REFERENCES target(target_id)
  );

  CREATE TABLE IF NOT EXISTS payload_recon_ai (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    payload_recon_id INTEGER NOT NULL,
    result_file      TEXT NOT NULL,
    model            TEXT,
    error            TEXT,
    scan_at          DATETIME NOT NULL,
    FOREIGN KEY (payload_recon_id) REFERENCES payload_recon(id)
  );

  CREATE TABLE IF NOT EXISTS nuclei (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL,
    result_file TEXT NOT NULL,
    scan_at     DATETIME NOT NULL,
    FOREIGN KEY (target_id) REFERENCES target(target_id)
  );

  CREATE TABLE IF NOT EXISTS whatweb (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL,
    result_file TEXT NOT NULL,
    scan_at     DATETIME NOT NULL,
    FOREIGN KEY (target_id) REFERENCES target(target_id)
  );

  CREATE TABLE IF NOT EXISTS subfinder (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL,
    result_file TEXT NOT NULL,
    scan_at     DATETIME NOT NULL,
    FOREIGN KEY (target_id) REFERENCES target(target_id)
  );

  CREATE TABLE IF NOT EXISTS nmap (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id     INTEGER NOT NULL,
    result_file   TEXT NOT NULL,
    scan_at       DATETIME NOT NULL,
    extra_options TEXT,
    FOREIGN KEY (target_id) REFERENCES target(target_id)
  );

  CREATE TABLE IF NOT EXISTS payload_tool_run (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    payload_recon_id INTEGER NOT NULL,
    tool            TEXT NOT NULL,
    cmd             TEXT NOT NULL,
    output_file     TEXT NOT NULL,
    status          TEXT NOT NULL, -- running|done|error
    exit_code       INTEGER,
    started_at      DATETIME NOT NULL,
    finished_at     DATETIME,
    FOREIGN KEY (payload_recon_id) REFERENCES payload_recon(id)
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

const countFfufByTargetStmt = db.prepare(
  'SELECT COUNT(*) AS count FROM ffuf WHERE target_id = ?'
);

const insertFfufStmt = db.prepare(
  'INSERT INTO ffuf (target_id, result_file, wordlist_source, scan_at) VALUES (?, ?, ?, ?)'
);

const listFfufByTargetStmt = db.prepare(
  `SELECT id, target_id, result_file, wordlist_source, scan_at
   FROM ffuf
   WHERE target_id = ?
   ORDER BY id DESC`
);

const countPayloadReconByTargetStmt = db.prepare(
  'SELECT COUNT(*) AS count FROM payload_recon WHERE target_id = ?'
);

const insertPayloadReconStmt = db.prepare(
  'INSERT INTO payload_recon (target_id, result_file, scan_at) VALUES (?, ?, ?)'
);

const listPayloadReconByTargetStmt = db.prepare(
  `SELECT id, target_id, result_file, scan_at
   FROM payload_recon
   WHERE target_id = ?
   ORDER BY id DESC`
);

const getPayloadReconByIdStmt = db.prepare(
  `SELECT pr.id, pr.target_id, t.target_name, pr.result_file, pr.scan_at
   FROM payload_recon pr
   JOIN target t ON t.target_id = pr.target_id
   WHERE pr.id = ?`
);

const insertPayloadReconAiStmt = db.prepare(
  'INSERT INTO payload_recon_ai (payload_recon_id, result_file, model, error, scan_at) VALUES (?, ?, ?, ?, ?)'
);

const listPayloadReconAiByReconStmt = db.prepare(
  `SELECT id, payload_recon_id, result_file, model, error, scan_at
   FROM payload_recon_ai
   WHERE payload_recon_id = ?
   ORDER BY id DESC`
);

const countNucleiByTargetStmt = db.prepare(
  'SELECT COUNT(*) AS count FROM nuclei WHERE target_id = ?'
);

const insertNucleiStmt = db.prepare(
  'INSERT INTO nuclei (target_id, result_file, scan_at) VALUES (?, ?, ?)'
);

const listNucleiByTargetStmt = db.prepare(
  `SELECT id, target_id, result_file, scan_at
   FROM nuclei
   WHERE target_id = ?
   ORDER BY id DESC`
);

const countWhatwebByTargetStmt = db.prepare(
  'SELECT COUNT(*) AS count FROM whatweb WHERE target_id = ?'
);

const insertWhatwebStmt = db.prepare(
  'INSERT INTO whatweb (target_id, result_file, scan_at) VALUES (?, ?, ?)'
);

const listWhatwebByTargetStmt = db.prepare(
  `SELECT id, target_id, result_file, scan_at
   FROM whatweb
   WHERE target_id = ?
   ORDER BY id DESC`
);

const countSubfinderByTargetStmt = db.prepare(
  'SELECT COUNT(*) AS count FROM subfinder WHERE target_id = ?'
);

const insertSubfinderStmt = db.prepare(
  'INSERT INTO subfinder (target_id, result_file, scan_at) VALUES (?, ?, ?)'
);

const listSubfinderByTargetStmt = db.prepare(
  `SELECT id, target_id, result_file, scan_at
   FROM subfinder
   WHERE target_id = ?
   ORDER BY id DESC`
);

const countNmapByTargetStmt = db.prepare(
  'SELECT COUNT(*) AS count FROM nmap WHERE target_id = ?'
);

const insertNmapStmt = db.prepare(
  'INSERT INTO nmap (target_id, result_file, scan_at, extra_options) VALUES (?, ?, ?, ?)'
);

const listNmapByTargetStmt = db.prepare(
  `SELECT id, target_id, result_file, scan_at, extra_options
   FROM nmap
   WHERE target_id = ?
   ORDER BY id DESC`
);

const insertPayloadToolRunStmt = db.prepare(
  `INSERT INTO payload_tool_run (payload_recon_id, tool, cmd, output_file, status, exit_code, started_at, finished_at)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
);

const updatePayloadToolRunStmt = db.prepare(
  `UPDATE payload_tool_run
   SET status = ?, exit_code = ?, finished_at = ?
   WHERE id = ?`
);

const listPayloadToolRunsByReconStmt = db.prepare(
  `SELECT id, payload_recon_id, tool, cmd, output_file, status, exit_code, started_at, finished_at
   FROM payload_tool_run
   WHERE payload_recon_id = ?
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

function getFfufScanRound(targetId) {
  const { count } = countFfufByTargetStmt.get(targetId);
  return count + 1;
}

function insertFfufScan(targetId, resultFile, wordlistSource, scanAt) {
  const info = insertFfufStmt.run(targetId, resultFile, wordlistSource, scanAt);
  return info.lastInsertRowid;
}

function listFfufByTarget(targetId) {
  return listFfufByTargetStmt.all(targetId);
}

function getPayloadReconScanRound(targetId) {
  const { count } = countPayloadReconByTargetStmt.get(targetId);
  return count + 1;
}

function insertPayloadRecon(targetId, resultFile, scanAt) {
  const info = insertPayloadReconStmt.run(targetId, resultFile, scanAt);
  return info.lastInsertRowid;
}

function listPayloadReconByTarget(targetId) {
  return listPayloadReconByTargetStmt.all(targetId);
}

function getPayloadReconById(id) {
  return getPayloadReconByIdStmt.get(id) || null;
}

function insertPayloadReconAi(payloadReconId, resultFile, model, error, scanAt) {
  const info = insertPayloadReconAiStmt.run(payloadReconId, resultFile, model || null, error || null, scanAt);
  return info.lastInsertRowid;
}

function listPayloadReconAiByRecon(payloadReconId) {
  return listPayloadReconAiByReconStmt.all(payloadReconId);
}

function getNucleiScanRound(targetId) {
  const { count } = countNucleiByTargetStmt.get(targetId);
  return count + 1;
}

function insertNucleiScan(targetId, resultFile, scanAt) {
  const info = insertNucleiStmt.run(targetId, resultFile, scanAt);
  return info.lastInsertRowid;
}

function listNucleiByTarget(targetId) {
  return listNucleiByTargetStmt.all(targetId);
}

function getWhatwebScanRound(targetId) {
  const { count } = countWhatwebByTargetStmt.get(targetId);
  return count + 1;
}

function insertWhatwebScan(targetId, resultFile, scanAt) {
  const info = insertWhatwebStmt.run(targetId, resultFile, scanAt);
  return info.lastInsertRowid;
}

function listWhatwebByTarget(targetId) {
  return listWhatwebByTargetStmt.all(targetId);
}

function getSubfinderScanRound(targetId) {
  const { count } = countSubfinderByTargetStmt.get(targetId);
  return count + 1;
}

function insertSubfinderScan(targetId, resultFile, scanAt) {
  const info = insertSubfinderStmt.run(targetId, resultFile, scanAt);
  return info.lastInsertRowid;
}

function listSubfinderByTarget(targetId) {
  return listSubfinderByTargetStmt.all(targetId);
}

function getNmapScanRound(targetId) {
  const { count } = countNmapByTargetStmt.get(targetId);
  return count + 1;
}

function insertNmapScan(targetId, resultFile, scanAt, extraOptions = null) {
  const info = insertNmapStmt.run(targetId, resultFile, scanAt, extraOptions);
  return info.lastInsertRowid;
}

function listNmapByTarget(targetId) {
  return listNmapByTargetStmt.all(targetId);
}

function insertPayloadToolRun(payloadReconId, tool, cmd, outputFile, status, exitCode, startedAt, finishedAt) {
  const info = insertPayloadToolRunStmt.run(payloadReconId, tool, cmd, outputFile, status, exitCode ?? null, startedAt, finishedAt ?? null);
  return info.lastInsertRowid;
}

function updatePayloadToolRun(runId, status, exitCode, finishedAt) {
  updatePayloadToolRunStmt.run(status, exitCode ?? null, finishedAt ?? null, runId);
}

function listPayloadToolRunsByRecon(payloadReconId) {
  return listPayloadToolRunsByReconStmt.all(payloadReconId);
}

module.exports = {
  db,
  getOrCreateTarget,
  getKatanaScanRound,
  insertKatanaScan,
  listTargets,
  listKatanaByTarget,
  getFfufScanRound,
  insertFfufScan,
  listFfufByTarget,
  getPayloadReconScanRound,
  insertPayloadRecon,
  listPayloadReconByTarget,
  getPayloadReconById,
  insertPayloadReconAi,
  listPayloadReconAiByRecon,
  getNucleiScanRound,
  insertNucleiScan,
  listNucleiByTarget,
  getWhatwebScanRound,
  insertWhatwebScan,
  listWhatwebByTarget,
  getSubfinderScanRound,
  insertSubfinderScan,
  listSubfinderByTarget,
  getNmapScanRound,
  insertNmapScan,
  listNmapByTarget,
  insertPayloadToolRun,
  updatePayloadToolRun,
  listPayloadToolRunsByRecon,
};

