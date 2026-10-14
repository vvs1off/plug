const PLUGIN_ID = "admap";

let currentClientId = "";
let filterType = "";
let searchText = "";

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
    baseDn: $("baseDn").value.trim(),
    user: $("user").value.trim(),
    password: $("password").value,
  };
}

function renderDomain(info) {
  const el = $("domainInfo");
  if (!info) {
    el.className = "info empty";
    el.textContent = "not discovered yet";
    return;
  }
  el.className = "info";
  el.innerHTML = "";
  const rows = [
    ["domain", info.domain],
    ["base dn", info.baseDn],
    ["dcs", (info.dcs || []).join(", ")],
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

function renderFindings(list) {
  $("fCount").textContent = list.length;
  const el = $("findings");
  el.innerHTML = "";
  if (!list.length) {
    el.className = "findings empty";
    el.textContent = "no findings — run enumerate";
    return;
  }
  el.className = "findings";
  list.forEach((f) => {
    const d = document.createElement("div");
    d.className = "finding " + (f.severity || "info");
    const t = document.createElement("div");
    t.className = "title";
    t.textContent = f.title;
    const det = document.createElement("div");
    det.className = "detail";
    det.textContent = f.detail;
    d.appendChild(t);
    d.appendChild(det);
    el.appendChild(d);
  });
}

function renderObjects(list) {
  const body = $("objBody");
  body.innerHTML = "";
  if (!list.length) {
    $("objEmpty").style.display = "block";
    return;
  }
  $("objEmpty").style.display = "none";

  list.slice(0, 500).forEach((o) => {
    const tr = document.createElement("tr");

    const sam = document.createElement("td");
    sam.className = "sam";
    sam.textContent = o.sam || o.name || "-";

    const type = document.createElement("td");
    type.textContent = o.type || "-";

    const flags = document.createElement("td");
    if (!o.enabled) {
      const s = document.createElement("span");
      s.className = "flag disabled";
      s.textContent = "disabled";
      flags.appendChild(s);
    }
    if (o.adminCount) {
      const s = document.createElement("span");
      s.className = "flag priv";
      s.textContent = "priv";
      flags.appendChild(s);
    }
    if (o.asrep) {
      const s = document.createElement("span");
      s.className = "flag asrep";
      s.textContent = "as-rep";
      flags.appendChild(s);
    }
    if ((o.spns || []).length) {
      const s = document.createElement("span");
      s.className = "flag spn";
      s.textContent = "spn";
      flags.appendChild(s);
    }

    const spns = document.createElement("td");
    spns.className = "desc";
    spns.textContent = (o.spns || []).slice(0, 2).join(", ");

    const desc = document.createElement("td");
    desc.className = "desc";
    desc.textContent = o.description || "";
    desc.title = o.description || "";

    tr.appendChild(sam);
    tr.appendChild(type);
    tr.appendChild(flags);
    tr.appendChild(spns);
    tr.appendChild(desc);
    body.appendChild(tr);
  });
}

function renderStats(s) {
  $("sUsers").textContent = s.users || 0;
  $("sGroups").textContent = s.groups || 0;
  $("sComps").textContent = s.computers || 0;
  $("sPriv").textContent = s.privileged || 0;
  $("sAsrep").textContent = s.asrep || 0;
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
    case "domain":
      renderDomain(p);
      log(`domain ${p.domain} — ${(p.dcs || []).length} DC(s)`, "ok");
      break;
    case "graph":
      log(`enumerated ${p.count} object(s), ${p.findings} finding(s)`, "ok");
      refreshAll();
      break;
    case "roast_targets":
      log(`${p.count} ${p.kind} target(s)`, "ok");
      loadRoast();
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
  ["status", "domain", "graph", "roast_targets", "progress", "error", "pong"].forEach((ch) => {
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

async function loadObjects() {
  if (!currentClientId) return;
  try {
    renderObjects(await rpc("list_objects", {
      clientId: currentClientId, type: filterType, search: searchText,
    }));
  } catch (e) {}
}

async function loadFindings() {
  if (!currentClientId) return;
  try { renderFindings(await rpc("list_findings", { clientId: currentClientId })); } catch (e) {}
}

async function loadStats() {
  if (!currentClientId) return;
  try { renderStats(await rpc("stats", { clientId: currentClientId })); } catch (e) {}
}

async function loadRoast() {
  if (!currentClientId) return;
  try {
    const list = await rpc("list_roast", { clientId: currentClientId });
    const el = $("roastList");
    el.innerHTML = "";
    if (!list.length) {
      el.className = "feed empty";
      el.textContent = "none listed";
      return;
    }
    el.className = "feed";
    list.forEach((r) => {
      const d = document.createElement("div");
      d.className = "row-item";
      d.innerHTML = `<span class="hl">${r.kind}</span> ${r.sam || ""} ${r.spn || ""}`;
      el.appendChild(d);
    });
  } catch (e) {}
}

function refreshAll() {
  loadObjects(); loadFindings(); loadStats(); loadRoast();
}

async function loadDomain() {
  if (!currentClientId) return;
  try { renderDomain(await rpc("get_domain", { clientId: currentClientId })); } catch (e) {}
}

async function loadConfig() {
  if (!currentClientId) return;
  try {
    const cfg = await rpc("get_config", { clientId: currentClientId });
    if (cfg.domain) $("domain").value = cfg.domain;
    if (cfg.dc) $("dc").value = cfg.dc;
    if (cfg.baseDn) $("baseDn").value = cfg.baseDn;
    if (cfg.user) $("user").value = cfg.user;
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
      loadConfig(); loadDomain(); refreshAll();
    }
  } catch (e) {}
}

async function save() {
  try { await rpc("save_config", { clientId: currentClientId, config: collectSettings() }); } catch (e) {}
}

function bind() {
  $("clientId").addEventListener("change", (e) => {
    currentClientId = e.target.value.trim();
    loadConfig(); loadDomain(); refreshAll();
  });

  $("refreshClients").addEventListener("click", refreshClients);

  $("discover").addEventListener("click", async () => {
    await save();
    setBadge("scanning");
    sendEvent("discover", collectSettings());
  });

  $("enumerate").addEventListener("click", async () => {
    await save();
    setBadge("enumerating");
    sendEvent("enumerate", collectSettings());
  });

  $("kerberoast").addEventListener("click", async () => {
    await save();
    sendEvent("kerberoast", collectSettings());
  });

  $("asrep").addEventListener("click", async () => {
    await save();
    sendEvent("asrep", collectSettings());
  });

  document.querySelectorAll(".filter").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".filter").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      filterType = btn.dataset.type || "";
      loadObjects();
    });
  });

  let timer = null;
  $("search").addEventListener("input", (e) => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      searchText = e.target.value.trim();
      loadObjects();
    }, 300);
  });
}

bind();
connectStream();
loadConfig(); loadDomain(); refreshAll();
refreshClients();
