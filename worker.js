// Posts — posts.fyi
//
// A reader where everything is a feed, and some feeds are private.
//
//   GET  /                      the app
//   GET  /c                     public contact page          (accepts nothing)
//   GET  /c/contact.json        signed hook record            (accepts nothing)
//   POST /h/{three-words}       a hook. the only thing that accepts.
//   GET  /f/{feed}.json?key=    read a feed
//   GET  /f/{feed}/rss?key=     same, as RSS
//
// The bare domain accepts nothing and reveals nothing.
// This Worker never holds a private key and never signs: contact.json is
// produced and signed in the browser and stored here as an opaque blob.

import { WORDS } from "./words.js";
// Served to the browser as-is. This Worker never runs it: it holds no keys.
import CRYPTO_SRC from "./crypto-src.js";
import APP_SRC from "./app-src.js";

const LIMITS = {
  hooks: 500,
  bodyBytes: 128 * 1024,
  itemsPerDay: 10000,
  unknownPathsPerSec: 10, // §10: the primary defence
  feedPage: 100,
  retireTailDays: 90,
  blobBytes: 256 * 1024, // ciphertext, when there is no R2 bucket bound
};

const CFG = "_cfg";
const enc = new TextEncoder();

/* ---------- small helpers ---------- */

const json = (o, status = 200, headers = {}) =>
  new Response(JSON.stringify(o), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...headers },
  });

const text = (s, status = 200, headers = {}) =>
  new Response(s, { status, headers: { "content-type": "text/plain; charset=utf-8", ...headers } });

const html = (s, status = 200) =>
  new Response(s, { status, headers: { "content-type": "text/html; charset=utf-8" } });

const now = () => new Date().toISOString();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const sha256 = async (s) => hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// Unbiased pick from the wordlist. Rejection sampling — never modulo.
function pickWord() {
  const n = WORDS.length; // 7776
  const limit = Math.floor(65536 / n) * n;
  const a = new Uint16Array(1);
  for (;;) {
    crypto.getRandomValues(a);
    if (a[0] < limit) return WORDS[a[0] % n];
  }
}

// §10: three words = 38.8 bits. Four when asked for.
const mintWords = (count = 3) => Array.from({ length: count }, pickWord).join("-");

const token = () => crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");

/* ---------- config ---------- */

const readCfg = async (env) => (await env.POSTS.get(CFG, "json")) || null;
const writeCfg = (env, cfg) => env.POSTS.put(CFG, JSON.stringify(cfg));

async function authed(req, env) {
  const cfg = await readCfg(env);
  if (!cfg) return null;
  const m = /^Bearer (.+)$/.exec(req.headers.get("authorization") || "");
  if (!m) return null;
  return (await sha256(m[1])) === cfg.secretHash ? cfg : null;
}

/* ---------- rate limiting (per isolate, best effort) ---------- */

const buckets = new Map();
function allow(key, perSec) {
  const t = Math.floor(Date.now() / 1000);
  const k = key + ":" + t;
  const n = (buckets.get(k) || 0) + 1;
  buckets.set(k, n);
  if (buckets.size > 5000) for (const bk of buckets.keys()) if (!bk.endsWith(":" + t)) buckets.delete(bk);
  return n <= perSec;
}

/* ---------- hooks ---------- */

function hookState(cfg, words) {
  const h = cfg.hooks[words];
  if (!h) return { status: "unknown" };
  if (h.status === "retired" && h.retires && Date.parse(h.retires) < Date.now()) return { ...h, status: "dead" };
  return h;
}

/* ---------- rules ---------- */
//
// Two dropdowns, no syntax: if <field> contains <value>, then <action>.
// Read top to bottom, first match wins, so exactly one ever applies.

function runRules(rules, item) {
  for (const r of rules || []) {
    const hay = String(
      r.field === "sender" ? item.sender : r.field === "subject" ? item.subject : item.body
    ).toLowerCase();
    const needle = String(r.value || "").toLowerCase();
    const hit = r.op === "is" ? hay === needle : hay.includes(needle);
    if (needle && hit) return r.then || null;
  }
  return null;
}

/* ---------- receiving ---------- */

async function receive(req, env, ctx, words, ip) {
  const cfg = await readCfg(env);
  // A miss and a dead hook must look the same (§15: enumeration).
  if (!cfg) return gone();

  const h = hookState(cfg, words);
  if (h.status === "unknown" || h.status === "dead") {
    if (!allow("unknown:" + ip, LIMITS.unknownPathsPerSec)) return text("", 429);
    return gone();
  }

  // Per-hook flood cap. Exceeding it auto-retires the hook (§9).
  if (!allow("hook:" + words, 20)) {
    h.status = "retired";
    h.retires = new Date(Date.now() + 864e5).toISOString();
    cfg.hooks[words] = h;
    ctx.waitUntil(writeCfg(env, cfg));
    return text("", 429);
  }

  const raw = await req.text();
  if (raw.length > LIMITS.bodyBytes) return text("too large", 413);

  const eventId = req.headers.get("x-event-id") || crypto.randomUUID();

  // A hook accepts anything. Posts clients send a signed envelope; a CI
  // webhook sends whatever it sends. Both are items in the hook's feed.
  let item = { subject: "", body: raw, enc: 0, sender: h.label || words };
  try {
    const j = JSON.parse(raw);
    if (j && typeof j === "object") {
      if (j.cipher || j.type === "encrypted_item" || j.type === "first_contact") {
        item = { subject: "", body: raw, enc: 1, sender: j.reply_hook ? "new" : h.label || words };
      } else {
        item.subject = String(j.subject || j.title || j.event || "").slice(0, 200);
        item.body = typeof j.text === "string" ? j.text : raw;
      }
    }
  } catch { /* not JSON: keep as plain text */ }

  const q = new URL(req.url).searchParams;
  if (q.get("subject")) item.subject = q.get("subject").slice(0, 200);

  // Rules belong to the hook, run in order, and exactly one ever applies.
  let feed = h.feed, tags = "";
  const applied = runRules(h.rules, item);
  if (applied) {
    if (applied.action === "ignore") return json({ status: "ignored", rule: applied.value || "" }, 202, CORS);
    if (applied.action === "feed" && cfg.feeds[applied.value]) feed = applied.value;
    if (applied.action === "tag") tags = String(applied.value || "").slice(0, 40);
    if (applied.action === "important") tags = "important";
  }

  const id = crypto.randomUUID();
  const parts = [];
  if (h.status === "retired") parts.push("old-hook");
  if (tags) parts.push(tags);
  // A daily feed holds its items until the cron writes the digest.
  if (cfg.feeds[feed]?.arrive === "daily") parts.push("queued");
  const flags = parts.join(" ");

  try {
    await env.DB.prepare(
      `INSERT INTO items (id, feed, hook, created, sender, subject, body, enc, event_id, flags)
       VALUES (?,?,?,?,?,?,?,?,?,?)`
    )
      .bind(id, feed, words, now(), item.sender, item.subject, item.body, item.enc, eventId, flags)
      .run();
  } catch (e) {
    // UNIQUE(event_id) — a duplicate delivery is a success, not an error (§8).
    if (String(e).includes("UNIQUE")) return json({ event_id: eventId, status: "duplicate" }, 202, CORS);
    throw e;
  }

  return json(
    { event_id: eventId, status: "stored", receipt: id, hook: flags || "active" },
    202,
    CORS
  );
}

const gone = () =>
  json({ error: "gone" }, 410, { "cache-control": "no-store", ...CORS });

// A hook has to be postable, and a contact record readable, from any origin —
// that is the whole point of handing one out. Neither exposes anything private.
const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "content-type, x-event-id",
  "access-control-max-age": "86400",
};

/* ---------- feeds ---------- */

async function feedItems(env, feed, before, includeQueued = false) {
  const rows = await env.DB.prepare(
    `SELECT id, created, sender, subject, body, enc, flags FROM items
     WHERE feed = ? AND created < ? ORDER BY created DESC LIMIT ?`
  )
    .bind(feed, before || "9999", LIMITS.feedPage)
    .all();
  const out = rows.results || [];
  return includeQueued ? out : out.filter((r) => !String(r.flags || "").includes("queued"));
}

/* ---------- digests ---------- */
//
// "Put these in the digest" is just "send them to a feed that arrives daily".
// The cron turns everything queued into one item and releases the rest.

async function writeDigests(env) {
  const cfg = await readCfg(env);
  if (!cfg) return 0;
  let written = 0;
  for (const [id, f] of Object.entries(cfg.feeds)) {
    if (f.arrive !== "daily") continue;
    const held = (await feedItems(env, id, null, true)).filter((r) => String(r.flags).includes("queued"));
    if (!held.length) continue;

    const summary = held
      .map((i) => "• " + (i.subject || i.sender || "(no subject)") + (i.enc ? " [encrypted]" : ""))
      .join("\n");

    await env.DB.prepare(
      `INSERT INTO items (id, feed, hook, created, sender, subject, body, enc, event_id, flags)
       VALUES (?,?,?,?,?,?,?,?,?,?)`
    )
      .bind(crypto.randomUUID(), id, "", now(), "digest",
            `${held.length} item${held.length === 1 ? "" : "s"}`, summary, 0, crypto.randomUUID(), "digest")
      .run();

    for (const i of held)
      await env.DB.prepare(`UPDATE items SET flags = REPLACE(flags, 'queued', 'digested') WHERE id = ?`)
        .bind(i.id).run();
    written++;
  }
  return written;
}

async function serveFeed(req, env, feedId, as, bySlug = false) {
  const cfg = await readCfg(env);
  if (!cfg) return gone();

  let f = cfg.feeds[feedId];
  if (bySlug) {
    const hit = Object.entries(cfg.feeds).find(([, v]) => v.slug === feedId && v.kind === "published");
    if (!hit) return gone();
    [feedId, f] = hit;
  } else {
    const key = new URL(req.url).searchParams.get("key");
    if (!f || key !== f.key) return gone();
  }
  const pub = bySlug;

  const items = await feedItems(env, feedId, new URL(req.url).searchParams.get("before"));
  const origin = new URL(req.url).origin;

  if (as === "rss") {
    const body = items
      .map(
        (i) => `  <item>
    <title>${esc(i.subject || i.sender || "(no subject)")}</title>
    <guid isPermaLink="false">${esc(i.id)}</guid>
    <pubDate>${new Date(i.created).toUTCString()}</pubDate>
    <description>${esc(i.enc ? "[encrypted — open in Posts]" : i.body.slice(0, 4000))}</description>
  </item>`
      )
      .join("\n");
    return new Response(
      `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <title>${esc(f.name)}</title>
  <link>${origin}${pub ? "/p/" + esc(f.slug) + ".json" : "/f/" + esc(feedId) + ".json"}</link>
  <description>Posts feed</description>
${body}
</channel></rss>`,
      { headers: { "content-type": "application/rss+xml; charset=utf-8", "cache-control": pub ? "public, max-age=300" : "private, max-age=45", ...(pub ? CORS : {}) } }
    );
  }

  return json(
    {
      version: "1.0",
      title: f.name,
      self: pub ? `${origin}/p/${f.slug}.json` : `${origin}/f/${feedId}.json`,
      items: items.map((i) => ({
        id: i.id,
        published: i.created,
        sender: i.sender,
        subject: i.subject,
        encrypted: !!i.enc,
        flags: i.flags || undefined,
        content: i.body,
      })),
    },
    200,
    { "cache-control": pub ? "public, max-age=300" : "private, max-age=45", ...(pub ? CORS : {}) }
  );
}

/* ---------- public feed polling (the reader half) ---------- */

function parseFeed(xml) {
  const out = [];
  const blocks = xml.match(/<(item|entry)\b[\s\S]*?<\/\1>/gi) || [];
  for (const b of blocks.slice(0, 50)) {
    const pick = (t) => {
      const m = new RegExp(`<${t}\\b[^>]*>([\\s\\S]*?)</${t}>`, "i").exec(b);
      return m ? m[1].replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1").trim() : "";
    };
    const linkAttr = /<link\b[^>]*href="([^"]+)"/i.exec(b);
    out.push({
      title: pick("title").replace(/<[^>]+>/g, ""),
      link: linkAttr ? linkAttr[1] : pick("link"),
      body: (pick("content:encoded") || pick("description") || pick("summary") || pick("content")).slice(0, 20000),
      date: pick("pubDate") || pick("updated") || pick("published") || now(),
    });
  }
  return out;
}

async function pollSources(env) {
  const cfg = await readCfg(env);
  if (!cfg) return;
  for (const [sid, s] of Object.entries(cfg.sources || {})) {
    try {
      const r = await fetch(s.url, { headers: { "user-agent": "Posts/1.0 (+https://posts.fyi)" } });
      if (!r.ok) continue;
      const items = parseFeed(await r.text());
      for (const it of items.reverse()) {
        const eventId = await sha256(sid + "|" + (it.link || it.title));
        await env.DB.prepare(
          `INSERT OR IGNORE INTO items (id, feed, hook, created, sender, subject, body, enc, event_id, flags)
           VALUES (?,?,?,?,?,?,?,?,?,?)`
        )
          .bind(crypto.randomUUID(), s.feed, "", new Date(it.date).toISOString(), s.title || s.url, it.title, readable(it.body), 0, eventId, "")
          .run();
      }
      s.lastPolled = now();
    } catch { /* a bad feed must never stop the others */ }
  }
  await writeCfg(env, cfg);
}

// HTML → text at storage time: trackers, scripts and styles dropped.
function readable(s) {
  return String(s || "")
    .replace(/<(script|style)[\s\S]*?<\/\1>/gi, "")
    .replace(/<img[^>]*alt="([^"]*)"[^>]*>/gi, "$1")
    .replace(/<img[^>]*>/gi, "")
    .replace(/<li[^>]*>/gi, "\n• ")
    .replace(/<\/(p|div|h[1-6]|li|tr)>/gi, "\n")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/[\u200b-\u200d\uFEFF]/g, "")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

/* ---------- attachments ---------- */
//
// Only ciphertext is ever stored or served. The file key travels inside the
// sealed message, so a blob is public without being useful — which is what
// lets a recipient fetch it straight from the sender's host.

const b64bytes = (u8) => {
  let s = "";
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode(...u8.subarray(i, i + 0x8000));
  return btoa(s);
};
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function putBlob(env, body) {
  const id = crypto.randomUUID().replace(/-/g, "");
  if (env.MEDIA) {
    await env.MEDIA.put(id, body);
  } else {
    if (body.byteLength > LIMITS.blobBytes) return null;
    await env.DB.prepare(`INSERT INTO blobs (id, created, bytes, data) VALUES (?,?,?,?)`)
      .bind(id, now(), body.byteLength, b64bytes(new Uint8Array(body)))
      .run();
  }
  return id;
}

async function getBlob(env, id) {
  if (env.MEDIA) {
    const o = await env.MEDIA.get(id);
    return o ? await o.arrayBuffer() : null;
  }
  const row = await env.DB.prepare(`SELECT data FROM blobs WHERE id = ?`).bind(id).first?.()
    ?? (await env.DB.prepare(`SELECT data FROM blobs WHERE id = ?`).bind(id).all()).results?.[0];
  return row ? unb64(row.data).buffer : null;
}

/* ---------- owner API ---------- */

async function api(req, env, path) {
  const method = req.method;

  if (path === "/api/register" && method === "POST") {
    if (await readCfg(env)) return json({ error: "taken" }, 403);
    const secret = token();
    const inbox = "f_" + (await sha256(secret + ":inbox")).slice(0, 12);
    const publicHook = mintWords(3);
    const cfg = {
      secretHash: await sha256(secret),
      created: now(),
      contact: null,
      hooks: {
        [publicHook]: { label: "Public hook", kind: "public", status: "active", feed: inbox, created: now() },
      },
      feeds: { [inbox]: { name: "New", key: token().slice(0, 32), kind: "hook" } },
      sources: {},
      conversations: {},
    };
    await writeCfg(env, cfg);
    return json({ secret, public_hook: publicHook, inbox });
  }

  const cfg = await authed(req, env);
  if (!cfg) return json({ error: "unauthorized" }, 401);

  if (path === "/api/state" && method === "GET") {
    const counts = await env.DB.prepare(
      `SELECT feed, COUNT(*) n, MAX(created) last FROM items GROUP BY feed`
    ).all();
    const by = Object.fromEntries((counts.results || []).map((r) => [r.feed, r]));
    return json({
      hooks: Object.entries(cfg.hooks).map(([h, v]) => ({ hook: h, ...hookState(cfg, h) })),
      feeds: Object.entries(cfg.feeds).map(([id, f]) => ({ id, ...f, ...(by[id] || { n: 0 }) })),
      sources: Object.entries(cfg.sources || {}).map(([id, s]) => ({ id, ...s })),
      conversations: Object.entries(cfg.conversations || {}).map(([id, c]) => ({ id, ...c })),
      contact: !!cfg.contact,
    });
  }

  if (path === "/api/hooks" && method === "POST") {
    if (Object.keys(cfg.hooks).length >= LIMITS.hooks) return json({ error: "too many hooks" }, 400);
    const { label = "Untitled", words = 3, feed } = await req.json().catch(() => ({}));
    let h = mintWords(Math.min(5, Math.max(3, words)));
    while (cfg.hooks[h]) h = mintWords(Math.min(5, Math.max(3, words)));
    let feedId = feed;
    if (!feedId || !cfg.feeds[feedId]) {
      feedId = "f_" + crypto.randomUUID().replace(/-/g, "").slice(0, 12);
      cfg.feeds[feedId] = { name: label, key: token().slice(0, 32), kind: "hook" };
    }
    cfg.hooks[h] = { label, kind: "private", status: "active", feed: feedId, created: now() };
    await writeCfg(env, cfg);
    return json({ hook: h, feed: feedId, url: new URL(req.url).origin + "/h/" + h });
  }

  const retire = /^\/api\/hooks\/([^/]+)\/retire$/.exec(path);
  if (retire && method === "POST") {
    const h = decodeURIComponent(retire[1]);
    if (!cfg.hooks[h]) return json({ error: "not found" }, 404);
    const { days = LIMITS.retireTailDays } = await req.json().catch(() => ({}));
    cfg.hooks[h].status = "retired";
    cfg.hooks[h].retires = new Date(Date.now() + days * 864e5).toISOString();
    // Rotating the public hook mints its replacement (§5).
    let replacement = null;
    if (cfg.hooks[h].kind === "public") {
      replacement = mintWords(3);
      cfg.hooks[replacement] = {
        label: "Public hook",
        kind: "public",
        status: "active",
        feed: cfg.hooks[h].feed,
        created: now(),
      };
    }
    await writeCfg(env, cfg);
    return json({ retired: h, until: cfg.hooks[h].retires, replacement });
  }

  const del = /^\/api\/hooks\/([^/]+)$/.exec(path);
  if (del && method === "DELETE") {
    const h = decodeURIComponent(del[1]);
    if (!cfg.hooks[h]) return json({ error: "not found" }, 404);
    // A tombstone, not a removal: the words must never be minted again (§15).
    cfg.hooks[h] = { status: "dead", killed: now() };
    await writeCfg(env, cfg);
    return json({ deleted: h });
  }

  if (path === "/api/conversations" && method === "POST") {
    // Replying to a stranger mints them a hook of their own. From here the
    // thread never touches the public hook again — which is what makes
    // rotating the public hook free (§5, the doorway principle).
    const { their_hook, their_key, petname = "someone", words = 3 } = await req.json();
    if (!their_hook || !their_key) return json({ error: "need their_hook and their_key" }, 400);
    if (Object.keys(cfg.hooks).length >= LIMITS.hooks) return json({ error: "too many hooks" }, 400);

    const existing = Object.entries(cfg.conversations || {}).find(([, c]) => c.their_key === their_key);
    if (existing) return json({ id: existing[0], ...existing[1], reused: true });

    let h = mintWords(Math.min(5, Math.max(3, words)));
    while (cfg.hooks[h]) h = mintWords(Math.min(5, Math.max(3, words)));
    const feedId = "f_" + crypto.randomUUID().replace(/-/g, "").slice(0, 12);
    const id = "c_" + crypto.randomUUID().replace(/-/g, "").slice(0, 12);

    cfg.feeds[feedId] = { name: petname, key: token().slice(0, 32), kind: "conversation" };
    cfg.hooks[h] = { label: petname, kind: "private", status: "active", feed: feedId, conversation: id, created: now() };
    cfg.conversations = cfg.conversations || {};
    cfg.conversations[id] = { petname, their_hook, their_key, my_hook: h, feed: feedId, created: now() };
    await writeCfg(env, cfg);
    return json({ id, petname, my_hook: h, my_hook_url: new URL(req.url).origin + "/h/" + h, feed: feedId, their_hook });
  }

  if (path === "/api/contact" && method === "PUT") {
    // Stored verbatim. This Worker cannot verify the signature and must not
    // try: the client that already trusts the key is the one that checks it.
    const blob = await req.text();
    if (blob.length > 8192) return json({ error: "too large" }, 413);
    JSON.parse(blob); // must at least be JSON
    cfg.contact = blob;
    await writeCfg(env, cfg);
    return json({ ok: true });
  }

  const rules = /^\/api\/hooks\/([^/]+)\/rules$/.exec(path);
  if (rules && method === "POST") {
    const h = decodeURIComponent(rules[1]);
    if (!cfg.hooks[h] || cfg.hooks[h].status === "dead") return json({ error: "not found" }, 404);
    const { rules: list } = await req.json();
    if (!Array.isArray(list) || list.length > 50) return json({ error: "bad rules" }, 400);
    cfg.hooks[h].rules = list.map((r) => ({
      field: ["sender", "subject", "body"].includes(r.field) ? r.field : "subject",
      op: r.op === "is" ? "is" : "contains",
      value: String(r.value || "").slice(0, 200),
      then: {
        action: ["feed", "tag", "important", "ignore"].includes(r.then?.action) ? r.then.action : "tag",
        value: String(r.then?.value || "").slice(0, 200),
      },
    }));
    await writeCfg(env, cfg);
    return json({ hook: h, rules: cfg.hooks[h].rules });
  }

  const arrive = /^\/api\/feeds\/([a-z0-9_]+)\/arrive$/.exec(path);
  if (arrive && method === "POST") {
    const f = cfg.feeds[arrive[1]];
    if (!f) return json({ error: "not found" }, 404);
    const { arrive: how } = await req.json();
    f.arrive = how === "daily" ? "daily" : "each";
    await writeCfg(env, cfg);
    return json({ feed: arrive[1], arrive: f.arrive });
  }

  if (path === "/api/digest" && method === "POST") {
    return json({ digests: await writeDigests(env) });
  }

  if (path === "/api/publish" && method === "POST") {
    // Your own public feed. Pull, named, readable by anyone — which is safe
    // precisely because a feed accepts nothing (§2).
    const { slug, title, subject = "", text = "" } = await req.json();
    if (!/^[a-z0-9][a-z0-9-]{0,40}$/.test(slug || "")) return json({ error: "bad slug" }, 400);

    let feedId = Object.keys(cfg.feeds).find((id) => cfg.feeds[id].slug === slug);
    if (!feedId) {
      feedId = "f_" + crypto.randomUUID().replace(/-/g, "").slice(0, 12);
      cfg.feeds[feedId] = { name: title || slug, key: token().slice(0, 32), kind: "published", slug };
      await writeCfg(env, cfg);
    }
    if (text || subject) {
      await env.DB.prepare(
        `INSERT INTO items (id, feed, hook, created, sender, subject, body, enc, event_id, flags)
         VALUES (?,?,?,?,?,?,?,?,?,?)`
      )
        .bind(crypto.randomUUID(), feedId, "", now(), cfg.feeds[feedId].name, subject, text, 0, crypto.randomUUID(), "")
        .run();
    }
    const origin = new URL(req.url).origin;
    return json({ feed: feedId, slug, json: `${origin}/p/${slug}.json`, rss: `${origin}/p/${slug}/rss` });
  }

  if (path === "/api/blobs" && method === "POST") {
    const body = await req.arrayBuffer();
    if (body.byteLength > LIMITS.blobBytes && !env.MEDIA)
      return json({ error: "too large", limit: LIMITS.blobBytes }, 413);
    const id = await putBlob(env, body);
    if (!id) return json({ error: "too large" }, 413);
    return json({ id, url: new URL(req.url).origin + "/b/" + id, bytes: body.byteLength });
  }

  if (path === "/api/sources" && method === "POST") {
    const { url, title } = await req.json();
    new URL(url);
    const id = "s_" + crypto.randomUUID().replace(/-/g, "").slice(0, 12);
    const feedId = "f_" + crypto.randomUUID().replace(/-/g, "").slice(0, 12);
    cfg.feeds[feedId] = { name: title || url, key: token().slice(0, 32), kind: "source" };
    cfg.sources[id] = { url, title: title || url, feed: feedId, added: now() };
    await writeCfg(env, cfg);
    await pollSources(env);
    return json({ id, feed: feedId });
  }

  if (path === "/api/poll" && method === "POST") {
    await pollSources(env);
    return json({ ok: true });
  }

  if (path === "/api/items" && method === "GET") {
    const u = new URL(req.url);
    const feed = u.searchParams.get("feed");

    // "*" is everything, newest first — what the filter needs to search across
    // sources. Still only this account's feeds, still behind the owner secret.
    if (feed === "*") {
      const all = [];
      for (const id of Object.keys(cfg.feeds)) {
        for (const i of await feedItems(env, id, u.searchParams.get("before")))
          all.push({ ...i, feed: id, feed_name: cfg.feeds[id].name });
      }
      all.sort((x, y) => (x.created < y.created ? 1 : -1));
      return json({ items: all.slice(0, LIMITS.feedPage) });
    }

    if (!cfg.feeds[feed]) return json({ error: "not found" }, 404);
    return json({ items: await feedItems(env, feed, u.searchParams.get("before")) });
  }

  return json({ error: "not found" }, 404);
}

/* ---------- pages ---------- */

const MARK = `<svg viewBox="0 0 512 512" width="28" height="28" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="1.5" aria-hidden="true"><g transform="translate(30.72,30.72) scale(0.88)"><g transform="matrix(1.33066,0,0,1.33066,-1620.81,-474.069)"><g transform="matrix(0,-5.02704,5.02704,0,817.039,-11231.4)"><path d="M-2308.17,94.189C-2308.17,87.941 -2313.25,82.868 -2319.49,82.868L-2359.4,82.868C-2365.64,82.868 -2370.72,87.941 -2370.72,94.189L-2370.72,114.214C-2370.65,114.179 -2350.08,114.357 -2350.25,114.214C-2350.78,143.17 -2350.39,144.547 -2330.64,144.759C-2315.81,144.918 -2308.11,143.054 -2308.17,134.239L-2308.17,94.189Z" stroke-width="6.19"/></g><g transform="translate(-1070.14,550.813)"><path d="M2392,-60.611L2530,-60.611" stroke-width="22.92"/></g></g></g></svg>`;

const CSS = `:root{color-scheme:light dark;--bg:#fff;--fg:#111;--dim:#666;--line:#e5e5e3;--panel:#fafaf9;--accent:#d83b01}
@media(prefers-color-scheme:dark){:root{--bg:#161615;--fg:#eee;--dim:#999;--line:#2c2c2a;--panel:#1d1d1b}}
*{box-sizing:border-box}body{margin:0;font:14px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--fg)}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
a{color:inherit}`;

function contactPage(cfg, origin) {
  const rec = cfg?.contact ? JSON.parse(cfg.contact) : null;
  const published = Object.values(cfg?.feeds || {}).filter((f) => f.kind === "published");
  return html(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Contact</title><link rel=icon href="/icon.svg">
<link rel="posts-hook" href="/c/contact.json">
<style>${CSS}
body{display:grid;place-items:center;min-height:100vh;padding:24px}
.card{max-width:34rem;width:100%}
h1{font-size:1.4rem;margin:.6rem 0 .2rem;display:flex;align-items:center;gap:.5rem}
p{color:var(--dim)}
.hook{font-family:ui-monospace,monospace;font-size:1.05rem;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:.8rem 1rem;word-break:break-all}
.fp{font-family:ui-monospace,monospace;font-size:.8rem;color:var(--dim);margin-top:.8rem}</style>
<div class=card>
  <h1>${MARK} Contact</h1>
  ${
    rec
      ? `<p>Send to this hook. It accepts one message from anyone, and carries your reply address back.</p>
         <div class=hook>${esc(rec.hook || "")}</div>
         <div class=fp>key fingerprint &nbsp;${esc(rec.fingerprint || "—")}</div>
         <p style="margin-top:1.4rem;font-size:.85rem">This page accepts nothing. Only the hook above does, and it can be replaced at any time — clients re-read this page and carry on.</p>
         ${
           published.length
             ? `<p style="margin-top:1.4rem">Feeds you can subscribe to:</p><ul style="padding-left:1.1rem">` +
               published.map((f) => `<li><a href="/p/${esc(f.slug)}.json">${esc(f.name)}</a> &nbsp;<a href="/p/${esc(f.slug)}/rss" class=fp>rss</a></li>`).join("") +
               `</ul>`
             : ""
         }`
      : `<p>No contact record published yet.</p>`
  }
</div>`);
}

const APP = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Posts</title><link rel=icon href="/icon.svg"><style>${CSS}
body{height:100vh;display:grid;grid-template-columns:280px 1fr}
@media(max-width:720px){body{grid-template-columns:1fr}}
#side{border-right:1px solid var(--line);background:var(--panel);overflow-y:auto;padding:10px;display:flex;flex-direction:column}
#main{display:flex;flex-direction:column;overflow:hidden}
h1{font-size:15px;margin:6px 8px 10px;display:flex;align-items:center;gap:8px}
.src{display:flex;justify-content:space-between;gap:8px;padding:8px 10px;border-radius:8px;cursor:pointer}
.src:hover{background:var(--bg)}.src.on{background:var(--bg);box-shadow:inset 0 0 0 1px var(--line)}
.src b{font-weight:600;font-size:13px;display:block}.src small{color:var(--dim);font-size:11px}
.manage{border:0;background:none;color:var(--dim);padding:0 4px;font-size:16px;line-height:1;opacity:0}
.src:hover .manage,.src.on .manage{opacity:1}
#rules select,#rules input{padding:4px 6px;font-size:12px}
.sec{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--dim);margin:14px 10px 6px}
#list{overflow-y:auto;flex:1;padding:16px 20px}
.item{border-bottom:1px solid var(--line);padding:14px 0}
.item h3{margin:0 0 4px;font-size:14px}
.item .meta{font-family:ui-monospace,monospace;font-size:11px;color:var(--dim)}
.item pre{white-space:pre-wrap;word-break:break-word;margin:8px 0 0;font:13px/1.6 ui-sans-serif,system-ui,sans-serif}
.lock{color:var(--accent)}
#bar{border-top:1px solid var(--line);padding:10px 20px;display:flex;gap:8px;align-items:center}
#compose{border-top:1px solid var(--line);padding:10px 20px;display:none;gap:8px;align-items:center}
#compose.on{display:flex}
mark{background:var(--accent);color:#fff;border-radius:3px;padding:0 2px}
.src.hide,.item.hide{display:none}
input,button,textarea,select{font:inherit;border:1px solid var(--line);background:var(--bg);color:var(--fg);border-radius:8px;padding:8px 10px}
input,textarea{flex:1}button{cursor:pointer}button.p{background:var(--fg);color:var(--bg);border-color:var(--fg)}
.pill{font-family:ui-monospace,monospace;font-size:11px;border:1px solid var(--line);border-radius:999px;padding:2px 8px;color:var(--dim);white-space:nowrap}
.empty{color:var(--dim);padding:40px 0;text-align:center}
dialog{border:1px solid var(--line);border-radius:14px;background:var(--bg);color:var(--fg);max-width:34rem;width:92%;padding:20px}
dialog h3{margin:0 0 8px}
.k{font-family:ui-monospace,monospace;font-size:12px;background:var(--panel);padding:10px;border-radius:8px;word-break:break-all;border:1px solid var(--line)}
.fp{font-family:ui-monospace,monospace;font-size:12px;color:var(--dim)}
.foot{margin-top:auto;padding:10px 8px;font-size:11px;color:var(--dim);border-top:1px solid var(--line)}
</style>
<div id=side>
  <h1>${MARK} Posts</h1>
  <div id=srcs></div>
  <div class=sec>Add</div>
  <div style="padding:0 6px">
    <input id=addurl placeholder="feed URL, or someone's /c" style="width:100%;margin-bottom:6px">
    <button onclick=add() style="width:100%;margin-bottom:6px">Add</button>
    <button onclick=mint() style="width:100%">Mint a hook</button>
  </div>
  <div class=foot id=me></div>
</div>
<div id=main>
  <div id=list><div class=empty>Pick a source.</div></div>
  <div id=bar><input id=filter placeholder="Filter…" autocomplete=off><span class=pill id=fcount></span></div>
  <div id=compose></div>
</div>
<dialog id=dlg><div id=dlgbody></div><p style="text-align:right;margin:16px 0 0"><button onclick="dlg.close()">Close</button></p></dialog>

<script type=module src="/app.js"></script>`;

/* ---------- router ---------- */

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const ip = req.headers.get("cf-connecting-ip") || "0";

    // The only thing that accepts.
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });

    const hook = /^\/h\/([a-z-]{5,64})$/.exec(path);
    if (hook) {
      if (req.method !== "POST") return gone();
      return receive(req, env, ctx, hook[1], ip);
    }

    if (path === "/crypto.js" || path === "/app.js")
      return new Response(path === "/app.js" ? APP_SRC : CRYPTO_SRC, {
        headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "public, max-age=3600" },
      });

    if (path.startsWith("/api/")) return api(req, env, path);

    if (path === "/c/contact.json") {
      const cfg = await readCfg(env);
      if (!cfg?.contact) return gone();
      return new Response(cfg.contact, {
        headers: { "content-type": "application/json", "cache-control": "public, max-age=300", ...CORS },
      });
    }
    if (path === "/c") return contactPage(await readCfg(env), url.origin);

    const blob = /^\/b\/([a-f0-9]{32})$/.exec(path);
    if (blob) {
      const data = await getBlob(env, blob[1]);
      if (!data) return gone();
      return new Response(data, {
        headers: {
          "content-type": "application/octet-stream",
          "cache-control": "public, max-age=31536000, immutable",
          ...CORS,
        },
      });
    }

    // Feeds are read, never written. Anything but GET is nothing (§2).
    const feed = /^\/f\/([a-z0-9_]+)(\.json|\/rss)$/.exec(path);
    if (feed) return req.method === "GET" ? serveFeed(req, env, feed[1], feed[2] === "/rss" ? "rss" : "json") : gone();

    const pubFeed = /^\/p\/([a-z0-9-]+)(\.json|\/rss)$/.exec(path);
    if (pubFeed)
      return req.method === "GET" ? serveFeed(req, env, pubFeed[1], pubFeed[2] === "/rss" ? "rss" : "json", true) : gone();

    if (path === "/") return html(APP);
    if (path === "/icon.svg" || path === "/favicon.ico")
      return new Response(MARK.replace('width="28" height="28"', 'width="512" height="512"'), {
        headers: { "content-type": "image/svg+xml", "cache-control": "public, max-age=86400" },
      });

    // Everything else: nothing, and nothing revealed.
    if (!allow("unknown:" + ip, LIMITS.unknownPathsPerSec)) return text("", 429);
    return gone();
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(pollSources(env).then(() => writeDigests(env)));
  },
};

export { mintWords, readable, parseFeed, hookState, runRules, writeDigests, LIMITS };
