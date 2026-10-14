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
      CREATE TABLE IF NOT EXISTS domains (
        client_id TEXT PRIMARY KEY,
        domain TEXT,
        base_dn TEXT,
        dcs TEXT,
        seen_at INTEGER NOT NULL
      )`);

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS objects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        dn TEXT NOT NULL,
        name TEXT,
        sam TEXT,
        type TEXT,
        enabled INTEGER,
        admin_count INTEGER,
        spns TEXT,
        groups TEXT,
        asrep INTEGER,
        description TEXT,
        seen_at INTEGER NOT NULL
      )`);
    ctx.db.run(`CREATE UNIQUE INDEX IF NOT EXISTS adobj ON objects(client_id, dn)`);
    ctx.db.run(`CREATE INDEX IF NOT EXISTS adobj_type ON objects(client_id, type)`);

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        severity TEXT,
        title TEXT,
        detail TEXT,
        seen_at INTEGER NOT NULL
      )`);

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS roast (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        kind TEXT,
        sam TEXT,
        spn TEXT,
        dn TEXT,
        seen_at INTEGER NOT NULL
      )`);

    ctx.db.run(`CREATE TABLE IF NOT EXISTS config (client_id TEXT PRIMARY KEY, config TEXT NOT NULL)`);
  },

  onEvent(ctx, clientId, event, payload) {
    if (!clientId) return;
    ctx.clients.set(clientId, Date.now());
    const p = norm(payload);
    const now = Date.now();

    if (event === "domain") {
      ctx.db.run(
        `INSERT INTO domains (client_id, domain, base_dn, dcs, seen_at) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(client_id) DO UPDATE SET
           domain = excluded.domain, base_dn = excluded.base_dn,
           dcs = excluded.dcs, seen_at = excluded.seen_at`,
        clientId, p.domain || null, p.baseDn || null, JSON.stringify(p.dcs || []), now
      );
      ctx.broadcast("domain", { clientId, ...p });
    } else if (event === "graph") {
      const objects = Array.isArray(p.objects) ? p.objects : [];
      const findings = Array.isArray(p.findings) ? p.findings : [];
      const tx = ctx.db.transaction(() => {
        ctx.db.run(`DELETE FROM objects WHERE client_id = ?`, clientId);
        ctx.db.run(`DELETE FROM findings WHERE client_id = ?`, clientId);
        const ins = ctx.db.prepare(
          `INSERT INTO objects (client_id, dn, name, sam, type, enabled, admin_count, spns, groups, asrep, description, seen_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        );
        for (const o of objects) {
          ins.run(clientId, o.dn, o.name || null, o.sam || null, o.type || null,
            o.enabled ? 1 : 0, o.adminCount ? 1 : 0,
            JSON.stringify(o.spns || []), JSON.stringify(o.groups || []),
            o.asrep ? 1 : 0, o.description || null, now);
        }
        const inf = ctx.db.prepare(
          `INSERT INTO findings (client_id, severity, title, detail, seen_at) VALUES (?, ?, ?, ?, ?)`
        );
        for (const f of findings) {
          inf.run(clientId, f.severity || "info", f.title || "", f.detail || "", now);
        }
      });
      tx();
      ctx.broadcast("graph", { clientId, count: objects.length, findings: findings.length });
    } else if (event === "roast_targets") {
      const list = Array.isArray(p.targets) ? p.targets : [];
      const tx = ctx.db.transaction(() => {
        ctx.db.run(`DELETE FROM roast WHERE client_id = ? AND kind = ?`, clientId, p.kind || "");
        const ins = ctx.db.prepare(
          `INSERT INTO roast (client_id, kind, sam, spn, dn, seen_at) VALUES (?, ?, ?, ?, ?, ?)`
        );
        for (const t of list) {
          ins.run(clientId, p.kind || "", t.user || null, t.spn || null, t.dn || null, now);
        }
      });
      tx();
      ctx.broadcast("roast_targets", { clientId, kind: p.kind, count: list.length });
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

    get_domain(ctx, params = {}) {
      const row = ctx.db
        .query(`SELECT domain, base_dn AS baseDn, dcs, seen_at AS at FROM domains WHERE client_id = ?`)
        .get(params.clientId || "");
      if (!row) return null;
      return { ...row, dcs: JSON.parse(row.dcs || "[]") };
    },

    list_objects(ctx, params = {}) {
      const cid = params.clientId || "";
      const type = params.type || "";
      const search = String(params.search || "").trim();
      const wheres = ["client_id = ?"];
      const args = [cid];
      if (type) {
        wheres.push("type = ?");
        args.push(type);
      }
      if (search) {
        wheres.push("(sam LIKE ? OR name LIKE ? OR description LIKE ?)");
        args.push(`%${search}%`, `%${search}%`, `%${search}%`);
      }
      const rows = ctx.db
        .query(`SELECT dn, name, sam, type, enabled, admin_count AS adminCount,
                       spns, groups, asrep, description
                FROM objects WHERE ${wheres.join(" AND ")} ORDER BY type, sam LIMIT 2000`)
        .all(...args);
      return rows.map((r) => ({
        ...r,
        enabled: !!r.enabled,
        adminCount: !!r.adminCount,
        asrep: !!r.asrep,
        spns: JSON.parse(r.spns || "[]"),
        groups: JSON.parse(r.groups || "[]"),
      }));
    },

    list_findings(ctx, params = {}) {
      return ctx.db.query(
        `SELECT severity, title, detail, seen_at AS at FROM findings
         WHERE client_id = ? ORDER BY
           CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END`
      ).all(params.clientId || "");
    },

    list_roast(ctx, params = {}) {
      return ctx.db.query(
        `SELECT kind, sam, spn, dn FROM roast WHERE client_id = ? ORDER BY kind, sam`
      ).all(params.clientId || "");
    },

    stats(ctx, params = {}) {
      const cid = params.clientId || "";
      const row = ctx.db.query(
        `SELECT
           COUNT(*) AS total,
           SUM(CASE WHEN type='user' THEN 1 ELSE 0 END) AS users,
           SUM(CASE WHEN type='group' THEN 1 ELSE 0 END) AS groups,
           SUM(CASE WHEN type='computer' THEN 1 ELSE 0 END) AS computers,
           SUM(CASE WHEN admin_count=1 THEN 1 ELSE 0 END) AS privileged,
           SUM(CASE WHEN asrep=1 THEN 1 ELSE 0 END) AS asrep
         FROM objects WHERE client_id = ?`
      ).get(cid);
      return row || { total: 0, users: 0, groups: 0, computers: 0, privileged: 0, asrep: 0 };
    },
  },
};
