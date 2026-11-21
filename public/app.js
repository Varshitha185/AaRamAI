const $ = id => document.getElementById(id);
const fmt = t => t ? new Date(t).toLocaleTimeString() : "—";
let latestState = null;
function setHealth(state) {
  const el = $("health");
  el.textContent = state || "Waiting";
  el.style.color = state === "Excellent" ? "var(--green)" : state === "Good" ? "var(--cyan)" : state === "Fair" ? "var(--yellow)" : "var(--red)";
}
function drawChart(items) {
  const canvas = $("chart"), ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1, w = canvas.clientWidth, h = 190;
  canvas.width = w*dpr; canvas.height = h*dpr; ctx.scale(dpr,dpr); ctx.clearRect(0,0,w,h);
  ctx.strokeStyle="#24364a";ctx.lineWidth=1;
  for(let y=25;y<h;y+=40){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(w,y);ctx.stroke();}
  const rows=items.slice(-35); if(rows.length<2)return;
  const plot=(key,color)=>{ctx.beginPath();ctx.strokeStyle=color;ctx.lineWidth=2;rows.forEach((m,i)=>{const x=i/(rows.length-1)*w;const y=h-12-(Math.min(100,Number(m[key])||0)/100)*(h-28);i?ctx.lineTo(x,y):ctx.moveTo(x,y)});ctx.stroke()};
  plot("cpu","#4dd6d0");plot("memory","#a78bfa");
}

function renderIncidents(items) {
  const host = $("incidentsList");

  if (!items.length) {
    host.className = "empty";
    host.textContent = "No correlated incidents. Infrastructure looks stable.";
    return;
  }

  host.className = "";

  const escapeHTML = value =>
    String(value ?? "").replace(/[&<>"']/g, char => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    })[char]);

  host.innerHTML = items.slice(0, 5).map(i => {
    const evidence = i.evidence || i.signals || [];
    const recommendations = i.recommendation || [];

    return `
      <div class="incident">
        <div class="incidenttop">
          <b>${escapeHTML(i.id)} · ${escapeHTML(i.title)}</b>
          <span class="severity">${escapeHTML(i.severity)}</span>
        </div>

        <p>
          ${escapeHTML(i.status || "Investigating")}
          · ${i.count || 0} related events grouped
          · ${new Date(i.createdAt).toLocaleString()}
        </p>

        <div class="incident-evidence">
          <b>Correlated evidence</b>
          <div>
            ${evidence.map(item =>
              `<span class="signal">${escapeHTML(item)}</span>`
            ).join("")}
          </div>
        </div>

        <div class="incident-diagnosis">
          <p><b>Likely cause</b></p>
          <p>${escapeHTML(i.likelyCause || i.title)}</p>
        </div>

        <div class="incident-confidence">
          <b>Detection confidence</b>
          <span>${Number.isFinite(Number(i.confidence))
            ? escapeHTML(i.confidence) + "%"
            : "Not available"}</span>
          <small>Heuristic score, not a calibrated probability</small>
        </div>

        <p>
          <b>Recommended investigation:</b><br>
          ${recommendations.map(x =>
            "• " + escapeHTML(x)
          ).join("<br>")}
        </p>

        <small>
          Last detected: ${i.lastSeenAt
            ? new Date(i.lastSeenAt).toLocaleString()
            : "—"}
        </small>
      </div>
    `;
  }).join("");
}

function renderPrivacy(rows) {
  const scanned = rows.length;
  const detections = rows.filter(x => (x.detected_types || []).length > 0).length;
  const exported = rows.filter(x => x.raw_log_exported === true).length;
  $("privacyScanned").textContent = scanned;
  $("privacyDetections").textContent = detections;
  $("privacyExported").textContent = exported;
  const host = $("egressList");
  if (!scanned) { host.className = "egress empty"; host.textContent = "Waiting for first local scan…"; return; }
  host.className = "egress";
  host.innerHTML = rows.slice(0,5).map(x => {
    const types = (x.detected_types || []).length ? x.detected_types.join(" · ") : "No sensitive pattern detected";
    const delivery = x.delivery_status || "RECORDED";
    return `<div class="egress-item"><div class="privacy-proof-head"><b>${x.payload_id}</b><span class="proof-status">${delivery}</span></div><small>${fmt(x.at)} · ${types}</small><div class="proof-facts"><span>✓ Scanned locally</span><span>✓ Raw log excluded</span><span>${(x.fields_sent || []).length} approved fields</span></div><details><summary>Inspect metadata payload</summary><pre>${JSON.stringify(x.payload,null,2)}</pre></details></div>`;
  }).join("");
}
async function refresh() {
  try {
    const [s,e,a]=await Promise.all([fetch("/api/state").then(r=>r.json()),fetch("/api/egress").then(r=>r.json()),fetch("/api/audit").then(r=>r.json())]);
    latestState=s;
    const m=s.latest;
    if(m){
      setHealth(m.health);$("healthReason").textContent=m.health==="Excellent"?"Metrics within expected range":m.health==="Good"?"Minor deviations detected":m.health==="Fair"?"Elevated resource or network readings":"Critical signal or stale telemetry";
      $("cpu").textContent=m.cpu+"%";$("latency").textContent=m.latency_ms+" ms";$("recoveryCpu").textContent=m.cpu+"%";
    }
    $("incidentCount").textContent=s.incidents.length;
    $("collectorBadge").textContent=s.collector.online?"ONLINE":"OFFLINE";
    $("collectorState").textContent=s.collector.online?"ONLINE":"OFFLINE";
    $("collectorState").style.color=s.collector.online?"var(--green)":"var(--red)";
    $("lastSeen").textContent=s.collector.lastSeen?"Last heartbeat "+fmt(s.collector.lastSeen):"Waiting for heartbeat";
    drawChart(s.metrics);renderIncidents(s.incidents);
    renderPrivacy(e);
    $("auditList").innerHTML=a.slice(0,8).map(x=>`<div class="auditrow"><b>${x.action}</b><span>${fmt(x.at)}</span></div>`).join("")||"No audit events yet.";
    $("outageButton").textContent=s.connectivity.online?"⇄ Simulate SaaS outage":"✓ Restore SaaS connectivity";
  } catch(e){console.error(e)}
}
document.querySelectorAll("[data-scenario]").forEach(b=>b.addEventListener("click",async()=>{await fetch("/api/scenario",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({type:b.dataset.scenario})});refresh()}));
$("outageButton").addEventListener("click",async()=>{const online=!(latestState?.connectivity?.online??true);await fetch("/api/connectivity",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({online})});refresh()});
$("simulateRecovery").addEventListener("click",async()=>{const cpu=latestState?.latest?.cpu??90;const r=await fetch("/api/recovery",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({cpu})}).then(x=>x.json());$("projectedCpu").textContent=r.projectedCpu+"%";$("recoveryResult").textContent=r.status+". "+r.rollback;refresh()});
$("clock").textContent=new Date().toLocaleTimeString();
setInterval(()=>{$("clock").textContent=new Date().toLocaleTimeString()},1000);
refresh();setInterval(refresh,2000);
