const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA = process.env.DATA_DIR || path.join(ROOT, "data");
fs.mkdirSync(DATA, { recursive: true });

const readJson = (name, fallback) => {
  try { return JSON.parse(fs.readFileSync(path.join(DATA, name), "utf8")); }
  catch { return fallback; }
};
const writeJson = (name, value) => fs.writeFileSync(path.join(DATA, name), JSON.stringify(value, null, 2));
const appendJsonl = (name, value) => fs.appendFileSync(path.join(DATA, name), JSON.stringify(value) + "\n");

let metrics = readJson("metrics.json", []);
let incidents = readJson("incidents.json", []);
let seenIds = new Set(readJson("seen-ids.json", []));
let scenario = readJson("scenario.json", { type: "normal", remaining: 0 });
let connectivity = readJson("connectivity.json", { online: true });
let collector = readJson("collector.json", { online: false, lastSeen: null, version: "0.1.0" });

app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(ROOT, "public")));

const COLLECTOR_TOKEN = process.env.COLLECTOR_TOKEN || (process.env.RENDER ? "" : "aaramai-demo-token");
if (process.env.RENDER && !COLLECTOR_TOKEN) {
  throw new Error("COLLECTOR_TOKEN must be configured in the cloud service environment.");
}
function authenticateCollector(req, res, next) {
  if (req.header("x-collector-token") !== COLLECTOR_TOKEN) {
    return res.status(401).json({ error: "Unauthenticated collector" });
  }
  next();
}

function classify(m) {
  if (!m || !m.timestamp) return "Poor";
  const age = Date.now() - new Date(m.timestamp).getTime();
  if (!Number.isFinite(age) || age > 60000) return "Poor";
  if (m.cpu >= 90 || m.memory >= 95 || m.packet_loss >= 8 || m.severity === "critical") return "Poor";
  if (m.cpu >= 75 || m.memory >= 85 || m.latency_ms >= 250 || m.packet_loss >= 3 || m.severity === "high") return "Fair";
  if (m.cpu >= 60 || m.memory >= 70 || m.latency_ms >= 120 || m.severity === "medium") return "Good";
  return "Excellent";
}


function buildIncidents() {
  const now = Date.now();
  const WINDOW_MS = 2 * 60 * 1000;

  // Consider only recent telemetry.
  const recent = metrics.filter(m => {
    const time = new Date(m.timestamp).getTime();
    return Number.isFinite(time) && now - time <= WINDOW_MS;
  });

  // Identify independent incident signals.
  const cpuEvents = recent.filter(m => m.cpu >= 85);
  const latencyEvents = recent.filter(m => m.latency_ms >= 250);
  const databaseEvents = recent.filter(
    m => m.event_type === "database_failure"
  );
  const networkEvents = recent.filter(m => m.packet_loss >= 5);

  const categories = [];

  if (cpuEvents.length >= 2) categories.push("CPU_SATURATION");
  if (latencyEvents.length >= 2) categories.push("HIGH_LATENCY");
  if (databaseEvents.length >= 1) categories.push("DATABASE_FAILURE");
  if (networkEvents.length >= 2) categories.push("NETWORK_DEGRADATION");

  // Require multiple independent signals before creating an incident.
  if (categories.length < 2) return incidents;

  const fingerprint = categories.slice().sort().join("|");

  const signals = [];

  if (cpuEvents.length >= 2) {
    signals.push(
      `CPU utilization reached ${Math.max(...cpuEvents.map(m => m.cpu))}%`
    );
  }

  if (latencyEvents.length >= 2) {
    signals.push(
      `Application latency reached ${Math.max(...latencyEvents.map(m => m.latency_ms))} ms`
    );
  }

  if (databaseEvents.length >= 1) {
    signals.push(
      `${databaseEvents.length} database connection failure event(s) observed`
    );
  }

  if (networkEvents.length >= 2) {
    signals.push(
      `Packet loss reached ${Math.max(...networkEvents.map(m => m.packet_loss))}%`
    );
  }

  // Generate a transparent, rule-based likely-cause hypothesis.
  let likelyCause;
  let recommendation;

  if (
    categories.includes("CPU_SATURATION") &&
    categories.includes("DATABASE_FAILURE")
  ) {
    likelyCause =
      "Possible application resource saturation affecting database operations";

    recommendation = [
      "Inspect CPU utilization and identify processes consuming excessive resources.",
      "Check database connection-pool usage and active query load.",
      "Review application worker capacity and recent deployment changes."
    ];
  } else if (
    categories.includes("CPU_SATURATION") &&
    categories.includes("HIGH_LATENCY")
  ) {
    likelyCause =
      "Possible CPU saturation causing application response delays";

    recommendation = [
      "Inspect CPU-intensive processes and application worker utilization.",
      "Review slow requests and application execution time.",
      "Evaluate whether additional worker capacity is required."
    ];
  } else if (
    categories.includes("DATABASE_FAILURE") &&
    categories.includes("HIGH_LATENCY")
  ) {
    likelyCause =
      "Possible database bottleneck contributing to application latency";

    recommendation = [
      "Inspect database connection failures and connection-pool exhaustion.",
      "Review slow queries and database response times.",
      "Check database availability and resource utilization."
    ];
  } else if (
    categories.includes("NETWORK_DEGRADATION")
  ) {
    likelyCause =
      "Possible network degradation affecting service communication";

    recommendation = [
      "Inspect network interfaces and packet-loss statistics.",
      "Check connectivity between application and dependent services.",
      "Compare current network performance with the normal baseline."
    ];
  } else {
    likelyCause =
      "Possible combined infrastructure resource degradation";

    recommendation = [
      "Inspect CPU, memory and application performance metrics.",
      "Review related service and database events.",
      "Compare the affected metrics against their normal baseline."
    ];
  }

  // Confidence is a heuristic evidence score, not an ML probability.
  const evidenceCount =
    (cpuEvents.length >= 2 ? 1 : 0) +
    (latencyEvents.length >= 2 ? 1 : 0) +
    (databaseEvents.length >= 1 ? 1 : 0) +
    (networkEvents.length >= 2 ? 1 : 0);

  const confidence = Math.min(95, 50 + evidenceCount * 12);

  // Update an existing matching incident instead of creating duplicates.
  let existing = incidents.find(
    i => i.fingerprint === fingerprint &&
         i.status !== "Resolved"
  );

  if (existing) {
    existing.count = recent.length;
    existing.signals = signals;
    existing.evidence = categories;
    existing.confidence = confidence;
    existing.lastSeenAt = new Date().toISOString();
    existing.title = likelyCause;
    existing.recommendation = recommendation;
  } else {
    existing = {
      id: "INC-" + crypto.randomBytes(3).toString("hex").toUpperCase(),
      fingerprint,
      title: likelyCause,
      likelyCause,
      severity: "Critical",
      status: "Investigating",
      count: recent.length,
      signals,
      evidence: categories,
      confidence,
      recommendation,
      createdAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString()
    };

    incidents.unshift(existing);
  }

  incidents = incidents.slice(0, 20);
  writeJson("incidents.json", incidents);

  return incidents;
}


app.post("/api/ingest", authenticateCollector, (req, res) => {
  if (!connectivity.online) return res.status(503).json({ error: "SaaS ingestion temporarily unavailable" });
  const p = req.body;
  const allowed = ["payload_id", "tenant_id", "source_id", "timestamp", "event_type", "severity", "cpu", "memory", "disk", "latency_ms", "packet_loss", "health", "message"];
  if (!p || typeof p !== "object" || allowed.some(k => !(k in p))) {
    return res.status(400).json({ error: "Payload missing required allow-listed fields" });
  }
  if (seenIds.has(p.payload_id)) return res.json({ ok: true, duplicate: true });
  // Server-side schema boundary: reject unexpected fields, rather than storing arbitrary input.
  if (Object.keys(p).some(k => !allowed.includes(k))) return res.status(400).json({ error: "Unexpected field rejected" });
  if (p.tenant_id !== "DEMO_TENANT") return res.status(403).json({ error: "Unknown tenant" });
  seenIds.add(p.payload_id);
  metrics.push(p);
  metrics = metrics.slice(-500);
  collector = { online: true, lastSeen: new Date().toISOString(), version: "0.1.0" };
  writeJson("metrics.json", metrics);
  writeJson("seen-ids.json", [...seenIds].slice(-2000));
  writeJson("collector.json", collector);
  buildIncidents();
  appendJsonl("audit.jsonl", { action: "metadata_delivered", payload_id: p.payload_id, at: new Date().toISOString() });
  res.json({ ok: true, received: p.payload_id });
});

// The local collector polls this authenticated endpoint for demo scenarios.
app.get("/api/collector/config", authenticateCollector, (req, res) => {
  const current = { ...scenario };
  if (scenario.remaining > 0) {
    scenario.remaining -= 1;
    if (scenario.remaining <= 0) scenario.type = "normal";
    writeJson("scenario.json", scenario);
  }
  res.json({ scenario: current });
});

// Only the proof summary and already-sanitized metadata are accepted here.

app.post("/api/egress-proof", authenticateCollector, (req, res) => {
  // Simulate a real SaaS outage: proof records must remain queued locally.
  if (!connectivity.online) {
    return res.status(503).json({ error: "SaaS unavailable; keep proof locally queued" });
  }

  const proof = req.body;

  const allowed = [
    "payload_id", "tenant_id", "source_id", "timestamp",
    "event_type", "severity", "cpu", "memory", "disk",
    "latency_ms", "packet_loss", "health", "message"
  ];

  if (
    !proof ||
    proof.raw_log_exported !== false ||
    !Array.isArray(proof.detected_types) ||
    !Array.isArray(proof.fields_sent) ||
    !proof.payload ||
    typeof proof.payload !== "object" ||
    Array.isArray(proof.payload)
  ) {
    return res.status(400).json({ error: "Invalid egress proof" });
  }

  const payload = proof.payload;
  const payloadKeys = Object.keys(payload).sort();
  const proofFields = [...proof.fields_sent].sort();

  if (
    payloadKeys.some(key => !allowed.includes(key)) ||
    payloadKeys.join("|") !== proofFields.join("|") ||
    payload.payload_id !== proof.payload_id ||
    payload.tenant_id !== "DEMO_TENANT" ||
    !payload.timestamp
  ) {
    return res.status(400).json({
      error: "Egress proof failed allow-list validation"
    });
  }

  appendJsonl("egress-proof.jsonl", proof);
  res.json({ ok: true });
});


app.get("/healthz", (req, res) => res.json({ ok: true, service: "aaramai-saas" }));

app.get("/api/state", (req, res) => {
  const latest = metrics[metrics.length - 1] || null;
  const age = collector.lastSeen ? Date.now() - new Date(collector.lastSeen).getTime() : Infinity;
  const collectorOnline = age < 60000;
  const current = latest ? { ...latest, health: classify(latest) } : null;
  res.json({
    metrics: metrics.slice(-60), latest: current, incidents: buildIncidents(),
    collector: { ...collector, online: collectorOnline },
    connectivity, scenario
  });
});

app.get("/api/egress", (req, res) => {
  const file = path.join(DATA, "egress-proof.jsonl");
  let rows = [];
  try { rows = fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean).slice(-30).map(JSON.parse).reverse(); } catch {}
  res.json(rows);
});

app.get("/api/audit", (req, res) => {
  const file = path.join(DATA, "audit.jsonl");
  let rows = [];
  try { rows = fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean).slice(-30).map(JSON.parse).reverse(); } catch {}
  res.json(rows);
});

app.post("/api/scenario", (req, res) => {
  const allowed = ["normal", "cpu_incident", "secret_log"];
  if (!allowed.includes(req.body.type)) return res.status(400).json({ error: "Invalid scenario" });
  scenario = { type: req.body.type, remaining: req.body.type === "normal" ? 0 : 8, changedAt: new Date().toISOString() };
  writeJson("scenario.json", scenario);
  appendJsonl("audit.jsonl", { action: "scenario_changed", scenario: scenario.type, at: new Date().toISOString() });
  res.json({ ok: true, scenario });
});

app.post("/api/connectivity", (req, res) => {
  connectivity = { online: !!req.body.online, changedAt: new Date().toISOString() };
  writeJson("connectivity.json", connectivity);
  appendJsonl("audit.jsonl", { action: "saas_connectivity_changed", online: connectivity.online, at: new Date().toISOString() });
  res.json({ ok: true, connectivity });
});


app.post("/api/recovery", (req, res) => {
  const before = Number(req.body.cpu);
  const projected = Math.max(20, Math.round(before * 0.65));

  const record = {
    action: "recovery_simulated",
    beforeCpu: before,
    projectedCpu: projected,
    status: "SIMULATION_ONLY",
    rollback: "Restore the original worker count in the test environment.",
    at: new Date().toISOString()
  };

  appendJsonl("audit.jsonl", record);
  res.json(record);
});

app.listen(PORT, () => console.log(`AaRamAI SaaS dashboard running at http://localhost:${PORT}`));
