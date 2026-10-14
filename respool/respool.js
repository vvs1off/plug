const PLUGIN_ID = "respool";

let currentClientId = "";

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

function setBadge(id, text, cls) {
  const b = $(id);
  b.className = "badge " + cls;
  b.textContent = text;
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

function nodeConfig() {
  return {
    gateway: $("gatewayAddr").value.trim(),
    token: $("nodeToken").value.trim(),
    useTls: $("useTls").checked,
    maxStreams: parseInt($("maxStreams").value, 10) || 64,
    bandwidthKb: parseInt($("bandwidthKb").value, 10) || 0,
  };
}

function fmtBytes(n) {
  n = n || 0;
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + " MB";
  return (n / 1024 / 1024 / 1024).toFixed(2) + " GB";
}

function renderNodes(list) {
  $("nodeCount").textContent = list.length;
  const alive = list.filter((n) => n.alive);
  $("sNodes").textContent = alive.length;
  $("sStreams").textContent = list.reduce((a, n) => a + (n.streams || 0), 0);
  $("sUp").textContent = fmtBytes(list.reduce((a, n) => a + (n.bytesUp || 0), 0));
  $("sDown").textContent = fmtBytes(list.reduce((a, n) => a + (n.bytesDown || 0), 0));

  const body = $("nodeBody");
  body.innerHTML = "";
  if (!list.length) {
    $("nodeEmpty").style.display = "block";
    return;
  }
  $("nodeEmpty").style.display = "none";

  list.forEach((n) => {
    const tr = document.createElement("tr");
    const cells = [
      n.label || n.host || n.id,
      n.os || "-",
      String(n.streams || 0),
      fmtBytes(n.bytesUp),
      fmtBytes(n.bytesDown),
    ];
    cells.forEach((c) => {
      const td = document.createElement("td");
      td.textContent = c;
      tr.appendChild(td);
    });
    const st = document.createElement("td");
    const s = document.createElement("span");
    s.className = "state " + (n.alive ? "alive" : "dead");
    s.textContent = n.alive ? "alive" : "stale";
    st.appendChild(s);
    tr.appendChild(st);
    body.appendChild(tr);
  });
}

function handleStream(data) {
  if (!data) return;
  const evt = data.event;
  const p = data.payload ?? data;

  if (evt === "gateway") {
    setBadge("gwBadge", p.running ? "gateway on" : "gateway off", p.running ? "on" : "idle");
    log(p.running ? `gateway listening (proxy ${p.listen}, api ${p.api})` : "gateway stopped", p.running ? "ok" : "");
    return;
  }

  if (p && p.clientId && p.clientId !== currentClientId) return;

  switch (evt) {
    case "status":
      setBadge("statusBadge", p.state || "idle", p.state === "connected" ? "on" : (p.state === "error" ? "error" : "working"));
      if (p.detail) log(p.detail, p.state === "connected" ? "ok" : "");
      break;
    case "stats":
      loadNodes();
      break;
    case "error":
      setBadge("statusBadge", "error", "error");
      log(p.message || "error", "err");
      break;
    default:
      break;
  }
}

function connectStream() {
  const es = new EventSource(`/api/plugins/${PLUGIN_ID}/stream`);
  ["status", "stats", "gateway", "error", "pong"].forEach((ch) => {
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

async function loadNodes() {
  try { renderNodes(await rpc("list_nodes")); } catch (e) {}
}

async function loadGatewaySettings() {
  try {
    const gs = await rpc("get_gateway_settings");
    $("listenPort").value = gs.listenPort;
    $("apiPort").value = gs.apiPort;
    if (gs.token) {
      $("token").value = gs.token;
      if (!$("nodeToken").value) $("nodeToken").value = gs.token;
    }
    $("autostart").checked = !!gs.autostart;
    setBadge("gwBadge", gs.running ? "gateway on" : "gateway off", gs.running ? "on" : "idle");
    $("gwInfo").textContent = gs.binaryPresent
      ? (gs.lastError ? `last error: ${gs.lastError}` : "gateway binary present")
      : "gateway binary NOT found in plugin data dir — it ships inside the zip";
  } catch (e) {}
}

async function loadConfig() {
  if (!currentClientId) return;
  try {
    const cfg = await rpc("get_config", { clientId: currentClientId });
    if (cfg.gateway) $("gatewayAddr").value = cfg.gateway;
    if (cfg.token) $("nodeToken").value = cfg.token;
    if (typeof cfg.useTls === "boolean") $("useTls").checked = cfg.useTls;
    if (cfg.maxStreams) $("maxStreams").value = cfg.maxStreams;
    if (typeof cfg.bandwidthKb === "number") $("bandwidthKb").value = cfg.bandwidthKb;
  } catch (e) {}
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
    }
  } catch (e) {}
}

function bind() {
  $("clientId").addEventListener("change", (e) => {
    currentClientId = e.target.value.trim();
    loadConfig();
  });

  $("refreshClients").addEventListener("click", refreshClients);

  $("genToken").addEventListener("click", () => {
    const bytes = new Uint8Array(24);
    crypto.getRandomValues(bytes);
    const t = Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
    $("token").value = t;
    $("nodeToken").value = t;
    log("token regenerated — update the node config before starting");
  });

  $("startGw").addEventListener("click", async () => {
    try {
      await rpc("save_gateway_settings", {
        listenPort: parseInt($("listenPort").value, 10),
        apiPort: parseInt($("apiPort").value, 10),
        token: $("token").value.trim() || undefined,
        autostart: $("autostart").checked,
      });
      const res = await rpc("start_gateway", {
        listenPort: parseInt($("listenPort").value, 10),
        apiPort: parseInt($("apiPort").value, 10),
      });
      if (res.ok) {
        $("token").value = res.token;
        $("nodeToken").value = res.token;
        setBadge("gwBadge", "gateway on", "on");
        log("gateway started", "ok");
      } else {
        log("gateway failed: " + res.error, "err");
      }
    } catch (e) {
      log("start failed: " + e.message, "err");
    }
  });

  $("stopGw").addEventListener("click", async () => {
    try {
      await rpc("stop_gateway");
      setBadge("gwBadge", "gateway off", "idle");
      log("gateway stopped");
    } catch (e) {
      log("stop failed: " + e.message, "err");
    }
  });

  $("nodeStart").addEventListener("click", async () => {
    const cfg = nodeConfig();
    if (!cfg.gateway) {
      log("set the gateway host:port first", "err");
      return;
    }
    if (!cfg.token) {
      log("set the shared token", "err");
      return;
    }
    try {
      await rpc("save_config", { clientId: currentClientId, config: cfg });
      await sendEvent("start", cfg);
      setBadge("statusBadge", "connecting", "working");
      log("node starting");
    } catch (e) {
      log("start failed: " + e.message, "err");
    }
  });

  $("nodeStop").addEventListener("click", async () => {
    await sendEvent("stop");
    setBadge("statusBadge", "idle", "idle");
    log("node stop sent");
  });

  $("copyProxy").addEventListener("click", () => {
    navigator.clipboard.writeText($("proxyUrl").value).then(() => log("copied", "ok"));
  });
}

bind();
connectStream();
loadGatewaySettings();
loadNodes();
loadConfig();
refreshClients();
setInterval(loadNodes, 5000);
