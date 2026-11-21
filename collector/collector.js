const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = path.join(__dirname, "..");
const DATA = path.join(ROOT, "data");
fs.mkdirSync(DATA, { recursive: true });
const API = process.env.AARAMAI_API || "http://localhost:3000";
const TOKEN = process.env.COLLECTOR_TOKEN || "aaramai-demo-token";
const sleep = ms => new Promise(r => setTimeout(r, ms));
const append = (file, obj) => fs.appendFileSync(path.join(DATA, file), JSON.stringify(obj) + "\n");
const read = (file, fallback) => { try { return JSON.parse(fs.readFileSync(path.join(DATA, file), "utf8")); } catch { return fallback; } };
const write = (file, obj) => fs.writeFileSync(path.join(DATA, file), JSON.stringify(obj, null, 2));

let tick = 0;
let previousScenario = "normal";

function rawEvent(scenario) {
  tick++;
  let cpu = 35 + Math.round(Math.random() * 15);
  let memory = 45 + Math.round(Math.random() * 12);
  let latency = 35 + Math.round(Math.random() * 30);
  let packetLoss = Math.round(Math.random() * 1.5 * 10) / 10;
  let eventType = "metric";
  let severity = "low";
  let raw = `INFO service healthy cpu=${cpu}% memory=${memory}%`;
  if (scenario === "cpu_incident") {
    cpu = 91 + Math.round(Math.random() * 8);
    latency = 280 + Math.round(Math.random() * 150);
    memory = 82 + Math.round(Math.random() * 10);
    eventType = tick % 3 === 0 ? "database_failure" : tick % 2 === 0 ? "latency_spike" : "cpu_anomaly";
    severity = "critical";
    raw = `ERROR ${eventType} user=ops@example.com password=DemoPassword123 cpu=${cpu} api_key=sk-demo-secret`;
  } else if (scenario === "secret_log") {
    eventType = "application_error";
    severity = "medium";
    raw = "ERROR login failed user=admin@company.com password=SuperSecret123 API_KEY=sk-demo-123456 SERVER=DB-PROD-01";
  }
  return { cpu, memory, latency, packetLoss, eventType, severity, raw };
}

// Scan raw text locally. Only detection categories leave this function; matched values never do.
function inspectPrivacy(raw) {
  const checks = [
    ["EMAIL_ADDRESS", /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i],
    ["PASSWORD", /\b(password|passwd|pwd)\s*[=:]\s*([^\s,;]+)/i],
    ["API_KEY_OR_TOKEN", /\b(api[_-]?key|token|secret)\s*[=:]\s*([^\s,;]+)/i],
    ["INTERNAL_HOSTNAME", /\b(server|host)\s*[=:]\s*([^\s,;]+)/i]
  ];
  const detected = checks.filter(([, pattern]) => pattern.test(raw)).map(([name]) => name);
  return {
    scanned: true,
    detected_types: [...new Set(detected)],
    sensitive_values_excluded: detected.length > 0,
    raw_log_exported: false
  };
}

// Privacy boundary: retain original logs locally and build a fresh allow-listed metadata payload.
function sanitizeForEgress(event) {
  const now = new Date().toISOString();
  const sourceId = "SRC_" + crypto.createHash("sha256").update("demo-server-01").digest("hex").slice(0, 6).toUpperCase();
  const safe = {
    payload_id: crypto.randomUUID(),
    tenant_id: "DEMO_TENANT",
    source_id: sourceId,
    timestamp: now,
    event_type: event.eventType,
    severity: event.severity,
    cpu: event.cpu,
    memory: event.memory,
    disk: 54,
    latency_ms: event.latency,
    packet_loss: event.packetLoss,
    health: "reported",
    message: event.eventType.replaceAll("_", " ")
  };
  const allowed = ["payload_id", "tenant_id", "source_id", "timestamp", "event_type", "severity", "cpu", "memory", "disk", "latency_ms", "packet_loss", "health", "message"];
  return Object.fromEntries(Object.entries(safe).filter(([k]) => allowed.includes(k)));
}

async function send(payload) {
  try {
    const response = await fetch(`${API}/api/ingest`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-collector-token": TOKEN },
      body: JSON.stringify(payload)
    });
    return response.ok;
  } catch { return false; }
}

async function getScenario() {
  try {
    const response = await fetch(`${API}/api/collector/config`, {
      headers: { "x-collector-token": TOKEN }
    });
    if (response.ok) {
      const result = await response.json();
      return result.scenario || { type: "normal", remaining: 0 };
    }
  } catch {}
  return read("scenario.json", { type: "normal", remaining: 0 });
}

async function sendProof(proof) {
  try {
    const response = await fetch(`${API}/api/egress-proof`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-collector-token": TOKEN },
      body: JSON.stringify(proof)
    });
    return response.ok;
  } catch { return false; }
}

async function flushProofQueue() {
  const queue = read("local-proof-queue.json", []);
  if (!queue.length) return;
  const remaining = [];
  for (const proof of queue) {
    if (!(await sendProof(proof))) remaining.push(proof);
  }
  write("local-proof-queue.json", remaining);
}

async function flushQueue() {
  const queue = read("local-queue.json", []);
  if (!queue.length) return;
  const remaining = [];
  for (const item of queue) {
    if (!(await send(item))) remaining.push(item);
  }
  write("local-queue.json", remaining);
}

async function run() {
  console.log("AaRamAI local collector started. Raw logs remain in data/local-raw.jsonl");
  while (true) {
    const sc = await getScenario();
    const type = sc.remaining > 0 ? sc.type : "normal";
    const event = rawEvent(type);

    append("local-raw.jsonl", { at: new Date().toISOString(), raw: event.raw });
    const privacy = inspectPrivacy(event.raw);
    const payload = sanitizeForEgress(event);
    const delivered = await send(payload);
    const proof = {
      at: new Date().toISOString(),
      payload_id: payload.payload_id,
      scan_status: "SCANNED_LOCALLY",
      detected_types: privacy.detected_types,
      sensitive_values_excluded: privacy.sensitive_values_excluded,
      raw_log_exported: false,
      raw_log_location: "LOCAL_ONLY: data/local-raw.jsonl",
      delivery_status: delivered ? "DELIVERED" : "QUEUED_OR_RETRYING",
      fields_sent: Object.keys(payload),
      payload
    };
    append("egress-proof.jsonl", proof);
    if (!(await sendProof(proof))) {
      const proofQueue = read("local-proof-queue.json", []);
      proofQueue.push(proof);
      write("local-proof-queue.json", proofQueue);
    }

    if (!delivered) {
      const queue = read("local-queue.json", []);
      if (!queue.some(x => x.payload_id === payload.payload_id)) queue.push(payload);
      write("local-queue.json", queue);
      append("audit.jsonl", { action: "metadata_queued", payload_id: payload.payload_id, at: new Date().toISOString() });
    } else {
      append("audit.jsonl", { action: "metadata_delivered", payload_id: payload.payload_id, at: new Date().toISOString() });
    }

    await flushQueue();
    await flushProofQueue();
    await sleep(2000);
  }
}

run().catch(err => { console.error(err); process.exit(1); });
