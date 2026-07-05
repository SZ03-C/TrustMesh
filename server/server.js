const express = require("express");
const cors = require("cors");
const path = require("path");
const db = require("./db");
const { scanDomain, decisionForScore } = require("./scanners");

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

async function start() {
  await db.init();

app.post("/api/scans", async (req, res) => {
  try {
    const { domain } = req.body;
    if (!domain || !domain.includes(".")) {
      return res.status(400).json({ error: "Valid domain required" });
    }

    const result = await scanDomain(domain);

    const scanRunId = db.createScanRun(domain, result.scores.total, result.decision.label);
    db.createScoreBreakdown(scanRunId, result.scores);
    db.createFindings(scanRunId, result.findings);

    res.json({
      id: scanRunId,
      domain,
      scores: result.scores,
      decision: result.decision,
      findings: result.findings,
      logs: result.logs
    });
  } catch (err) {
    console.error("Scan error:", err);
    res.status(500).json({ error: "Scan failed" });
  }
});

app.get("/api/scans/:id", (req, res) => {
  const scan = db.getScanRun(req.params.id);
  if (!scan) return res.status(404).json({ error: "Scan not found" });
  res.json(scan);
});

app.get("/api/scans", (req, res) => {
  const scans = db.listScanRuns(req.query.limit || 10);
  res.json(scans);
});

app.use(express.static(path.join(__dirname, "..")));

app.listen(PORT, () => {
  console.log(`TrustMesh API running on http://localhost:${PORT}`);
  console.log(`Serving static files from: ${path.join(__dirname, "..")}`);
});
}

start().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
