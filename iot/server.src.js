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
        host TEXT NOT NULL,
        kind TEXT,
        vendor TEXT,
        model TEXT,
        ports TEXT,
        endpoints TEXT,
        needs_auth INTEGER DEFAULT 0,
        seen_at INTEGER NOT NULL
      )`);
    ctx.db.run(`CREATE UNIQUE INDEX IF NOT EXISTS iot_dev ON devices(client_id, host)`);

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        host TEXT,
        path TEXT,
        user TEXT,
        password TEXT,
        size INTEGER,
        data TEXT,
        captured_at INTEGER NOT NULL
      )`);
    ctx.db.run(`CREATE INDEX IF NOT EXISTS iot_snap ON snapshots(client_id)`);

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS hubs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        host TEXT,
        port INTEGER,
        kind TEXT,
        anonymous INTEGER DEFAULT 0,
        seen_at INTEGER NOT NULL
      )`);

    ctx.db.run(`CREATE TABLE IF NOT EXISTS config (client_id TEXT PRIMARY KEY, config TEXT NOT NULL)`);
  },

  onEvent(ctx, clientId, event, payload) {
    if (!clientId) return;
    ctx.clients.set(clientId, Date.now());
    const p = norm(payload);
    const now = Date.now();

    if (event === "device") {
      ctx.db.run(
        `INSERT INTO devices (client_id, host, kind, vendor, model, ports, endpoints, needs_auth, seen_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(client_id, host) DO UPDATE SET
           kind = excluded.kind, vendor = excluded.vendor, model = excluded.model,
           ports = excluded.ports, endpoints = excluded.endpoints,
           needs_auth = excluded.needs_auth, seen_at = excluded.seen_at`,
        clientId, p.host, p.kind || null, p.vendor || null, p.model || null,
        JSON.stringify(p.ports || []), JSON.stringify(p.endpoints || []),
        p.needsAuth ? 1 : 0, now
      );
      ctx.broadcast("device", { clientId, ...p });
    } else if (event === "devices") {
      ctx.broadcast("devices", { clientId, devices: Array.isArray(p) ? p : [] });
    } else if (event === "snapshot") {
      if (p.ok && p.data) {
        ctx.db.run(
          `INSERT INTO snapshots (client_id, host, path, user, password, size, data, captured_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          clientId, p.host, p.path || null, p.user || null, p.password || null, p.size || 0, p.data, now
        );
      }
      ctx.broadcast("snapshot", {
        clientId, host: p.host, ok: !!p.ok, error: p.error || null,
        size: p.size || 0, user: p.user || null, password: p.password || null,
      });
    } else if (event === "hub") {
      ctx.db.run(
        `INSERT INTO hubs (client_id, host, port, kind, anonymous, seen_at) VALUES (?, ?, ?, ?, ?, ?)`,
        clientId, p.host, p.port || 0, p.kind || null, p.anonymous ? 1 : 0, now
      );
      ctx.broadcast("hub", { clientId, ...p });
    } else if (event === "hubs") {
      ctx.broadcast("hubs", { clientId, hubs: Array.isArray(p) ? p : [] });
    } else if (event === "tv") {
      ctx.broadcast("tv", { clientId, ...p });
    } else if (event === "progress") {
      ctx.broadcast("progress", { clientId, ...p });
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

    list_devices(ctx, params = {}) {
      return ctx.db
        .query(`SELECT host, kind, vendor, model, ports, endpoints, needs_auth AS needsAuth, seen_at AS at
                FROM devices WHERE client_id = ? ORDER BY host`)
        .all(params.clientId || "")
        .map((r) => ({
          ...r,
          ports: JSON.parse(r.ports || "[]"),
          endpoints: JSON.parse(r.endpoints || "[]"),
          needsAuth: !!r.needsAuth,
        }));
    },

    list_snapshots(ctx, params = {}) {
      return ctx.db
        .query(`SELECT id, host, path, user, password, size, captured_at AS at
                FROM snapshots WHERE client_id = ? ORDER BY id DESC LIMIT 200`)
        .all(params.clientId || "");
    },

    get_snapshot(ctx, params = {}) {
      const row = ctx.db.query(`SELECT host, data FROM snapshots WHERE id = ?`).get(params.id);
      if (!row) throw new Error("snapshot not found");
      return { host: row.host, data: row.data };
    },

    list_hubs(ctx, params = {}) {
      return ctx.db
        .query(`SELECT host, port, kind, anonymous, seen_at AS at FROM hubs WHERE client_id = ? ORDER BY host`)
        .all(params.clientId || "");
    },
  },
};
