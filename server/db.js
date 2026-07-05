const initSqlJs = require("sql.js");
const fs = require("fs");
const path = require("path");

const DB_PATH = path.join(__dirname, "trustmesh.db");
let db = null;

async function init() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    const buffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buffer);
  } else {
    db = new SQL.Database();
  }

  db.run("PRAGMA foreign_keys = ON");

  db.run(`
    CREATE TABLE IF NOT EXISTS organizations (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      domain TEXT NOT NULL UNIQUE,
      verified_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS scan_runs (
      id TEXT PRIMARY KEY,
      organization_id TEXT REFERENCES organizations(id) ON DELETE CASCADE,
      domain TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'queued',
      overall_score INTEGER,
      decision TEXT,
      started_at TEXT NOT NULL DEFAULT (datetime('now')),
      completed_at TEXT
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS scan_findings (
      id TEXT PRIMARY KEY,
      scan_run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
      category TEXT NOT NULL,
      severity TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      evidence_json TEXT,
      remediation TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS score_breakdowns (
      id TEXT PRIMARY KEY,
      scan_run_id TEXT NOT NULL UNIQUE REFERENCES scan_runs(id) ON DELETE CASCADE,
      domain_score INTEGER,
      email_score INTEGER,
      exposure_score INTEGER,
      developer_score INTEGER
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS trust_requests (
      id TEXT PRIMARY KEY,
      requester_org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      target_org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'pending',
      access_level TEXT NOT NULL DEFAULT 'summary',
      purpose TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at TEXT
    )
  `);

  db.run("CREATE INDEX IF NOT EXISTS idx_organizations_domain ON organizations(domain)");
  db.run("CREATE INDEX IF NOT EXISTS idx_scan_runs_org ON scan_runs(organization_id)");
  db.run("CREATE INDEX IF NOT EXISTS idx_scan_findings_run ON scan_findings(scan_run_id)");

  save();
  return db;
}

function save() {
  if (!db) return;
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

function getUuid() {
  return require("uuid").v4();
}

function createScanRun(domain, score, decision) {
  const id = getUuid();
  db.run(
    "INSERT INTO scan_runs (id, domain, status, overall_score, decision, completed_at) VALUES (?, ?, 'completed', ?, ?, datetime('now'))",
    [id, domain, score, decision]
  );
  save();
  return id;
}

function createScoreBreakdown(scanRunId, scores) {
  const id = getUuid();
  db.run(
    "INSERT INTO score_breakdowns (id, scan_run_id, domain_score, email_score, exposure_score, developer_score) VALUES (?, ?, ?, ?, ?, ?)",
    [id, scanRunId, scores.domain, scores.email, scores.exposure, scores.developer]
  );
  save();
}

function createFindings(scanRunId, findings) {
  const stmt = db.prepare(
    "INSERT INTO scan_findings (id, scan_run_id, category, severity, title, description, evidence_json) VALUES (?, ?, ?, ?, ?, ?, ?)"
  );
  for (const finding of findings) {
    stmt.run([getUuid(), scanRunId, finding.category, finding.severity, finding.title, finding.description, JSON.stringify(finding.evidence || {})]);
  }
  stmt.free();
  save();
}

function getScanRun(id) {
  const run = db.exec("SELECT * FROM scan_runs WHERE id = ?", [id]);
  if (!run.length || !run[0].values.length) return null;

  const columns = run[0].columns;
  const values = run[0].values[0];
  const result = {};
  columns.forEach((col, i) => { result[col] = values[i]; });

  const scores = db.exec("SELECT * FROM score_breakdowns WHERE scan_run_id = ?", [id]);
  if (scores.length && scores[0].values.length) {
    const sCols = scores[0].columns;
    const sVals = scores[0].values[0];
    result.scores = {};
    sCols.forEach((col, i) => { result.scores[col] = sVals[i]; });
  }

  const findings = db.exec("SELECT * FROM scan_findings WHERE scan_run_id = ?", [id]);
  if (findings.length) {
    const fCols = findings[0].columns;
    result.findings = findings[0].values.map((row) => {
      const obj = {};
      fCols.forEach((col, i) => { obj[col] = row[i]; });
      if (obj.evidence_json) obj.evidence = JSON.parse(obj.evidence_json);
      return obj;
    });
  }

  return result;
}

function listScanRuns(limit = 10) {
  const result = db.exec("SELECT id, domain, overall_score, decision, status, started_at, completed_at FROM scan_runs ORDER BY started_at DESC LIMIT ?", [limit]);
  if (!result.length) return [];
  const cols = result[0].columns;
  return result[0].values.map((row) => {
    const obj = {};
    cols.forEach((col, i) => { obj[col] = row[i]; });
    return obj;
  });
}

module.exports = { init, createScanRun, createScoreBreakdown, createFindings, getScanRun, listScanRuns };
