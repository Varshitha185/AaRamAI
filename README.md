# AaRamAI — Privacy-first AIOps

A runnable hackathon MVP with two separate processes:
- **Central SaaS simulator:** Express API + dashboard (`server.js`)
- **Local collector:** generates raw telemetry, redacts it, allow-lists metadata, records egress proof, and forwards only metadata (`collector/collector.js`)

## Requirements
- Node.js 18+
- npm

## Run
Open a terminal in this folder:

```bash
npm install
```

Terminal 1 — central SaaS + dashboard:
```bash
npm start
```

Terminal 2 — local collector:
```bash
npm run collector
```

Open http://localhost:3000

## Demo
Use the dashboard's **Inject CPU incident**, **Inject secret log**, and **Simulate SaaS outage** controls.
- Secret log: raw content is written only to `data/local-raw.jsonl`; sanitized metadata and a proof record are sent to SaaS.
- CPU incident: creates a burst of high CPU, latency and database errors. The server groups related signals into one incident.
- SaaS outage: collector queues approved metadata locally; switch connectivity back on to flush the queue.
- Recovery Lab: produces a simulated projection only. It does not change a real service.

## Trust boundary
`collector/collector.js` is the local Tier 1 process. `server.js` is the Tier 2 SaaS simulator.
The collector sends only the fixed allow-listed fields in `sanitizeForEgress()`. Raw logs and secret values are never included in the POST body.

## Important demo limitations
This is a local hackathon prototype, not production security software. The demo token is hard-coded, the dashboard and collector run on one machine, and JSON files are used instead of a production database/message queue. Use TLS, managed secrets, durable queues, hardened authentication and deployment isolation before production.
