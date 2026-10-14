const PLUGIN_ID = "lanmap";

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
    setBadge("error");
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

// Device role guess from the MAC OUI + open ports. Crude on purpose — it is a
// hint for the operator, not a verdict.
function guessRole(d) {
  const mac = (d.mac || "").toUpperCase();
  const p = d.ports || [];

  if (p.includes(3389)) return "windows host (rdp)";
  if (p.includes(445) && p.includes(139)) return "windows / file share";
  if (p.includes(548)) return "mac / file share";
  if (p.includes(9100) || p.includes(515) || p.includes(631)) return "printer";
  if (p.includes(554) || p.includes(8554)) return "camera (rtsp)";
  if (p.includes(8009) || p.includes(8008)) return "chromecast";
  if (p.includes(53)) return "dns / router";
  if (p.includes(80) && p.includes(443) && p.includes(53)) return "router";
  if (p.includes(23)) return "iot (telnet)";

  const oui = mac.slice(0, 8);
  const ouis = {
    "B8:27:EB": "raspberry pi",
    "DC:A6:32": "raspberry pi",
    "E4:5F:01": "raspberry pi",
    "00:1A:79": "apple",
    "3C:5A:B4": "google",
    "F4:F5:D8": "google / nest",
    "44:65:0D": "amazon",
    "68:54:FD": "amazon / echo",
    "00:17:88": "philips hue",
    "EC:FA:BC": "espressif (smart device)",
    "24:0A:C4": "espressif (smart device)",
  };
  if (ouis[oui]) return ouis[oui];

  // locally administered / randomized MAC = modern phone
  const first = parseInt(mac.slice(0, 2), 16);
  if (!Number.isNaN(first) && (first & 0x02)) return "phone (randomized mac)";

  return "";
}

function render(devices) {
  const body = $("deviceBody");
  body.innerHTML = "";

  if (!devices.length) {
    $("empty").style.display = "block";
    updateStats([]);
    return;
  }
  $("empty").style.display = "none";

  devices.forEach((d) => {
    const tr = document.createElement("tr");

    const ip = document.createElement("td");
    ip.className = "ip";
    ip.textContent = d.ip;

    const mac = document.createElement("td");
    mac.className = "mac";
    mac.textContent = d.mac || "-";

    const ports = document.createElement("td");
    const wrap = document.createElement("div");
    wrap.className = "ports";
    (d.ports || []).forEach((p) => {
      const s = document.createElement("span");
      s.className = "port" + ([445, 3389, 23, 554].includes(p) ? " hot" : "");
      s.textContent = p;
      wrap.appendChild(s);
    });
    if (!(d.ports || []).length) {
      wrap.textContent = "-";
    }
    ports.appendChild(wrap);

    const g = document.createElement("td");
    g.className = "guess";
    g.textContent = guessRole(d);

    tr.appendChild(ip);
    tr.appendChild(mac);
    tr.appendChild(ports);
    tr.appendChild(g);
    body.appendChild(tr);
  });

  updateStats(devices);
}

function updateStats(devices) {
  const has = (p) => devices.filter((d) => (d.ports || []).includes(p)).length;
  $("statHosts").textContent = devices.length;
  $("statSmb").textContent = has(445);
  $("statRdp").textContent = has(3389);
  $("statWeb").textContent = devices.filter((d) => (d.ports || []).some((p) => p === 80 || p === 443)).length;
}

async function loadDevices() {
  if (!currentClientId) return;
  try {
    const devices = await rpc("list_devices", { clientId: currentClientId });
    render(devices);
    if (devices.length && devices[0].scannedAt) {
      $("lastScan").textContent = "last scan: " + new Date(devices[0].scannedAt).toLocaleString();
    }
  } catch (e) {
    setBadge("error");
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
    case "devices":
      render(p.devices || []);
      $("lastScan").textContent = "last scan: " + new Date().toLocaleString();
      break;
    case "error":
      setBadge("error");
      break;
    default:
      break;
  }
}

function connectStream() {
  const es = new EventSource(`/api/plugins/${PLUGIN_ID}/stream`);
  ["status", "devices", "error", "pong"].forEach((ch) => {
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
    $("clientCount").textContent =
      clients.length ? `${clients.length} client(s) seen` : "no clients seen yet";
    if (clients.length && !currentClientId) {
      currentClientId = clients[0].clientId;
      $("clientId").value = currentClientId;
      loadDevices();
    }
  } catch (e) {
    setBadge("error");
  }
}

function bind() {
  $("clientId").addEventListener("change", (e) => {
    currentClientId = e.target.value.trim();
    loadDevices();
  });
  $("refreshClients").addEventListener("click", refreshClients);
  $("scan").addEventListener("click", () => {
    if (!currentClientId) {
      setBadge("error");
      return;
    }
    setBadge("scanning");
    sendEvent("scan");
  });
}

bind();
connectStream();
loadDevices();
refreshClients();
