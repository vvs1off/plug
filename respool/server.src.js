import { spawn } from "child_process";
import { existsSync } from "fs";
import { join } from "path";

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

const GATEWAY_BIN = process.platform === "win32" ? "respool-gateway.exe" : "respool-gateway";

export default {
  setup(ctx) {
    ctx.clients = new Map();
    ctx.gateway = { proc: null, startedAt: 0, lastError: "" };

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS nodes (
        id TEXT PRIMARY KEY,
        client_id TEXT,
        label TEXT,
        host TEXT,
        os TEXT,
        arch TEXT,
        streams INTEGER DEFAULT 0,
        total_opened INTEGER DEFAULT 0,
        bytes_up INTEGER DEFAULT 0,
        bytes_down INTEGER DEFAULT 0,
        connected_at INTEGER,
        last_seen INTEGER NOT NULL
      )`);

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS config (client_id TEXT PRIMARY KEY, config TEXT NOT NULL)`);

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS gateway_settings (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        listen_port INTEGER DEFAULT 1080,
        api_port INTEGER DEFAULT 8081,
        token TEXT DEFAULT '',
        autostart INTEGER DEFAULT 0
      )`);
    ctx.db.run(`INSERT OR IGNORE INTO gateway_settings (id) VALUES (1)`);

    // Restore autostart.
    const gs = ctx.db.query(`SELECT * FROM gateway_settings WHERE id = 1`).get();
    if (gs && gs.autostart) {
      try {
        startGateway(ctx, gs);
      } catch (e) {
        ctx.gateway.lastError = String(e && e.message ? e.message : e);
      }
    }
  },

  async teardown(ctx) {
    stopGateway(ctx);
  },

  onEvent(ctx, clientId, event, payload) {
    if (!clientId) return;
    ctx.clients.set(clientId, Date.now());
    const p = norm(payload);
    const now = Date.now();

    if (event === "status") {
      ctx.broadcast("status", { clientId, ...p });
    } else if (event === "stats") {
      ctx.db.run(
        `INSERT INTO nodes (id, client_id, streams, total_opened, bytes_up, bytes_down, last_seen)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           streams = excluded.streams, total_opened = excluded.total_opened,
           bytes_up = excluded.bytes_up, bytes_down = excluded.bytes_down,
           last_seen = excluded.last_seen`,
        `node-${clientId}`, clientId, p.streams || 0, p.totalOpened || 0,
        p.bytesUp || 0, p.bytesDown || 0, now
      );
      ctx.broadcast("stats", { clientId, ...p });
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

    get_gateway_settings(ctx) {
      const row = ctx.db.query(`SELECT * FROM gateway_settings WHERE id = 1`).get();
      return {
        listenPort: row.listen_port,
        apiPort: row.api_port,
        token: row.token,
        autostart: !!row.autostart,
        running: !!ctx.gateway.proc,
        startedAt: ctx.gateway.startedAt,
        lastError: ctx.gateway.lastError,
        binaryPresent: existsSync(join(ctx.dataDir, GATEWAY_BIN)),
      };
    },

    save_gateway_settings(ctx, params = {}) {
      const token = params.token || randomToken();
      ctx.db.run(
        `UPDATE gateway_settings SET listen_port = ?, api_port = ?, token = ?, autostart = ? WHERE id = 1`,
        params.listenPort || 1080, params.apiPort || 8081, token, params.autostart ? 1 : 0
      );
      return { ok: true, token };
    },

    start_gateway(ctx, params = {}) {
      const gs = ctx.db.query(`SELECT * FROM gateway_settings WHERE id = 1`).get();
      if (!gs.token) {
        const token = randomToken();
        ctx.db.run(`UPDATE gateway_settings SET token = ? WHERE id = 1`, token);
        gs.token = token;
      }
      if (params.listenPort) gs.listen_port = params.listenPort;
      if (params.apiPort) gs.api_port = params.apiPort;
      try {
        startGateway(ctx, gs);
        return { ok: true, running: true, token: gs.token };
      } catch (e) {
        ctx.gateway.lastError = String(e && e.message ? e.message : e);
        return { ok: false, error: ctx.gateway.lastError };
      }
    },

    stop_gateway(ctx) {
      stopGateway(ctx);
      return { ok: true };
    },

    list_nodes(ctx) {
      return ctx.db
        .query(`SELECT id, client_id AS clientId, label, host, os, arch, streams,
                       total_opened AS totalOpened, bytes_up AS bytesUp,
                       bytes_down AS bytesDown, connected_at AS connectedAt,
                       last_seen AS lastSeen
                FROM nodes ORDER BY last_seen DESC`)
        .all()
        .map((r) => ({ ...r, alive: Date.now() - r.lastSeen < 90000 }));
    },

    clear_nodes(ctx) {
      ctx.db.run(`DELETE FROM nodes`);
      return { ok: true };
    },
  },
};

function randomToken() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function startGateway(ctx, gs) {
  if (ctx.gateway.proc) throw new Error("gateway already running");
  const bin = join(ctx.dataDir, GATEWAY_BIN);
  if (!existsSync(bin)) {
    throw new Error(`${GATEWAY_BIN} not found in plugin data dir — it ships inside the zip`);
  }

  const proc = spawn(bin, [
    "-listen", `:${gs.listen_port}`,
    "-api", `:${gs.api_port}`,
    "-token", gs.token,
  ], { stdio: ["ignore", "pipe", "pipe"] });

  ctx.gateway.proc = proc;
  ctx.gateway.startedAt = Date.now();
  ctx.gateway.lastError = "";

  const onLine = (buf) => {
    const text = String(buf).trim();
    if (text) ctx.log.info(`[respool-gateway] ${text}`);
  };
  proc.stdout?.on("data", onLine);
  proc.stderr?.on("data", onLine);

  proc.on("exit", (code) => {
    ctx.log.warn(`[respool-gateway] exited with code ${code}`);
    ctx.gateway.proc = null;
    ctx.gateway.lastError = `exited with code ${code}`;
    ctx.broadcast("gateway", { running: false, code });
  });

  ctx.broadcast("gateway", { running: true, listen: gs.listen_port, api: gs.api_port });
  return proc;
}

function stopGateway(ctx) {
  const proc = ctx.gateway.proc;
  if (!proc) return;
  try {
    proc.kill();
  } catch (_) {}
  ctx.gateway.proc = null;
  ctx.broadcast("gateway", { running: false, code: null });
}
