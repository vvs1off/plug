function norm(payload) {
  if (payload == null) return {};
  if (typeof payload === "string") {
    try { return JSON.parse(payload); } catch { return { raw: payload }; }
  }
  if (payload instanceof Uint8Array || payload instanceof ArrayBuffer) {
    const s = new TextDecoder().decode(payload);
    try { return JSON.parse(s); } catch { return { raw: s }; }
  }
  return payload;
}

export default {
  setup(ctx) {
    ctx.clients = new Map();
    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        ip TEXT NOT NULL,
        mac TEXT,
        ports TEXT,
        scanned_at INTEGER NOT NULL
      )`);
    ctx.db.run(`CREATE INDEX IF NOT EXISTS devices_client ON devices(client_id)`);
  },

  onEvent(ctx, clientId, event, payload) {
    if (!clientId) return;
    ctx.clients.set(clientId, Date.now());
    const p = norm(payload);
    const now = Date.now();

    if (event === "status") {
      ctx.broadcast("status", { clientId, ...p });
    } else if (event === "devices") {
      const list = Array.isArray(p) ? p : (p.devices || []);
      const tx = ctx.db.transaction(() => {
        ctx.db.run(`DELETE FROM devices WHERE client_id = ?`, clientId);
        const ins = ctx.db.prepare(
          `INSERT INTO devices (client_id, ip, mac, ports, scanned_at) VALUES (?, ?, ?, ?, ?)`
        );
        for (const d of list) {
          ins.run(clientId, d.ip, d.mac || null, JSON.stringify(d.ports || []), now);
        }
      });
      tx();
      ctx.broadcast("devices", { clientId, devices: list });
    } else if (event === "error") {
      ctx.broadcast("error", { clientId, ...p });
    } else if (event === "pong") {
      ctx.broadcast("pong", { clientId, ...p });
    }
  },

  rpc: {
    list_clients(ctx) {
      return Array.from(ctx.clients.entries()).map(([clientId, lastSeen]) => ({ clientId, lastSeen }));
    },

    list_devices(ctx, params = {}) {
      const rows = ctx.db
        .query(`SELECT ip, mac, ports, scanned_at AS scannedAt FROM devices WHERE client_id = ? ORDER BY ip`)
        .all(params.clientId || "");
      return rows.map((r) => ({
        ip: r.ip,
        mac: r.mac,
        ports: JSON.parse(r.ports || "[]"),
        scannedAt: r.scannedAt,
      }));
    },
  },
};
