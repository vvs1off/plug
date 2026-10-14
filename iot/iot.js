const PLUGIN_ID = "iot";

let currentClientId = "";
let devices = [];

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

function lines(id) {
  return $(id).value.split("\n").map((s) => s.trim()).filter(Boolean);
}

function collectSettings() {
  return {
    targets: lines("targets"),
    users: lines("users"),
    passwords: lines("passwords"),
  };
}

function renderDevices(list) {
  devices = list || [];
  $("devCount").textContent = devices.length;
  const body = $("devBody");
  body.innerHTML = "";
  if (!devices.length) {
    $("devEmpty").style.display = "block";
    return;
  }
  $("devEmpty").style.display = "none";

  devices.forEach((d) => {
    const tr = document.createElement("tr");

    const host = document.createElement("td");
    host.className = "host";
    host.textContent = d.host;

    const kind = document.createElement("td");
    const k = document.createElement("span");
    k.className = "kind " + (d.kind || "");
    k.textContent = d.kind || "?";
    kind.appendChild(k);

    const vendor = document.createElement("td");
    vendor.textContent = d.vendor || "-";

    const model = document.createElement("td");
    model.textContent = d.model || "-";

    const ports = document.createElement("td");
    const wrap = document.createElement("div");
    wrap.className = "ports";
    (d.ports || []).slice(0, 10).forEach((p) => {
      const s = document.createElement("span");
      s.className = "port";
      s.textContent = p;
      wrap.appendChild(s);
    });
    ports.appendChild(wrap);

    tr.appendChild(host);
    tr.appendChild(kind);
    tr.appendChild(vendor);
    tr.appendChild(model);
    tr.appendChild(ports);
    body.appendChild(tr);
  });
}

function renderSnapshotCount(list) {
  $("snapCount").textContent = list.length;
  const el = $("snapGrid");
  if (!list.length) {
    $("snapEmpty").style.display = "block";
    return;
  }
  $("snapEmpty").style.display = "none";
  el.innerHTML = "";
  list.forEach((s) => {
    const card = document.createElement("div");
    card.className = "snap";
    const img = document.createElement("img");
    img.alt = s.host;
    img.title = "click to load full image";
    img.style.cursor = "pointer";
    img.onclick = async () => {
      try {
        const full = await rpc("get_snapshot", { id: s.id });
        img.src = full.data.startsWith("data:") ? full.data : "data:image/jpeg;base64," + full.data;
      } catch (e) {
        log("snapshot load failed: " + e.message, "err");
      }
    };
    const cap = document.createElement("div");
    cap.className = "cap";
    cap.textContent = `${s.host}  ${(s.size / 1024).toFixed(0)}KB`;
    card.appendChild(img);
    card.appendChild(cap);
    el.appendChild(card);
  });
}

function feed(elId, html) {
  const el = $(elId);
  if (el.classList.contains("empty")) {
    el.classList.remove("empty");
    el.innerHTML = "";
  }
  const row = document.createElement("div");
  row.className = "row-item";
  row.innerHTML = html;
  el.appendChild(row);
  while (el.children.length > 120) el.removeChild(el.firstChild);
  el.scrollTop = el.scrollHeight;
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
    case "device":
      loadDevices();
      break;
    case "devices":
      renderDevices(p.devices || []);
      log(`${(p.devices || []).length} device(s) found`, "ok");
      break;
    case "snapshot":
      if (p.ok) {
        log(`snapshot from ${p.host} ${p.user ? `(${p.user}/${p.password})` : "(no auth)"}`, "ok");
      } else {
        log(`${p.host}: ${p.error}`, "err");
      }
      loadSnapshots();
      break;
    case "hub":
      feed("hubList", `<span class="hl">${p.kind}</span> ${p.host}:${p.port}` +
        (p.anonymous ? ` <span class="anon">ANONYMOUS MQTT</span>` : ""));
      break;
    case "tv":
      log(p.ok ? `tv ${p.host} launched` : `tv ${p.host} failed: ${p.error}`, p.ok ? "ok" : "err");
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
  ["status", "device", "devices", "snapshot", "hub", "hubs", "tv", "progress", "error", "pong"].forEach((ch) => {
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

async function loadDevices() {
  if (!currentClientId) return;
  try { renderDevices(await rpc("list_devices", { clientId: currentClientId })); } catch (e) {}
}

async function loadSnapshots() {
  if (!currentClientId) return;
  try { renderSnapshotCount(await rpc("list_snapshots", { clientId: currentClientId })); } catch (e) {}
}

async function loadHubs() {
  if (!currentClientId) return;
  try {
    const hubs = await rpc("list_hubs", { clientId: currentClientId });
    const el = $("hubList");
    el.innerHTML = "";
    if (!hubs.length) {
      el.className = "feed empty";
      el.textContent = "no hubs found";
      return;
    }
    el.className = "feed";
    hubs.forEach((h) => feed("hubList", `<span class="hl">${h.kind}</span> ${h.host}:${h.port}` +
      (h.anonymous ? ` <span class="anon">ANONYMOUS MQTT</span>` : "")));
  } catch (e) {}
}

async function loadConfig() {
  if (!currentClientId) return;
  try {
    const cfg = await rpc("get_config", { clientId: currentClientId });
    if (cfg.targets) $("targets").value = (cfg.targets || []).join("\n");
    if (cfg.users) $("users").value = (cfg.users || []).join("\n");
    if (cfg.passwords) $("passwords").value = (cfg.passwords || []).join("\n");
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
      loadConfig(); loadDevices(); loadSnapshots(); loadHubs();
    }
  } catch (e) {}
}

async function save() {
  try { await rpc("save_config", { clientId: currentClientId, config: collectSettings() }); } catch (e) {}
}

function bind() {
  $("clientId").addEventListener("change", (e) => {
    currentClientId = e.target.value.trim();
    loadConfig(); loadDevices(); loadSnapshots(); loadHubs();
  });

  $("refreshClients").addEventListener("click", refreshClients);

  $("scan").addEventListener("click", async () => {
    await save();
    setBadge("scanning");
    sendEvent("scan", collectSettings());
  });

  $("hubDump").addEventListener("click", async () => {
    await save();
    setBadge("scanning");
    sendEvent("hub_dump", collectSettings());
  });

  $("snapshot").addEventListener("click", async () => {
    await save();
    setBadge("working");
    sendEvent("snapshot", collectSettings());
  });

  $("tvLaunch").addEventListener("click", () => {
    const host = $("tvHost").value.trim();
    if (!host) {
      log("no tv host set", "err");
      return;
    }
    sendEvent("tv_command", { host, app: $("tvApp").value.trim() });
  });
}

bind();
connectStream();
loadConfig(); loadDevices(); loadSnapshots(); loadHubs();
refreshClients();
