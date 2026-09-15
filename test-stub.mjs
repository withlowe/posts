// In-memory KV and D1 so the real Worker can be driven without Cloudflare.
import worker from "./worker.js";

export const KV = () => {
  const m = new Map();
  return {
    get: async (k, t) => (m.has(k) ? (t === "json" ? JSON.parse(m.get(k)) : m.get(k)) : null),
    put: async (k, v) => void m.set(k, v),
  };
};

export const DB = () => {
  const rows = [];
  const blobs = new Map();
  const cols = ["id", "feed", "hook", "created", "sender", "subject", "body", "enc", "event_id", "flags"];
  return {
    prepare(sql) {
      let args = [];
      const self = {
        bind: (...a) => ((args = a), self),
        run: async () => {
          if (/INTO blobs/i.test(sql)) { blobs.set(args[0], args[3]); return { success: true }; }
          if (/^UPDATE items SET flags/i.test(sql)) {
            const row = rows.find((r) => r.id === args[0]);
            if (row) row.flags = row.flags.replace("queued", "digested");
            return { success: true };
          }
          if (/^INSERT/i.test(sql)) {
            const r = Object.fromEntries(cols.map((c, i) => [c, args[i]]));
            if (rows.some((x) => x.event_id === r.event_id)) {
              if (/OR IGNORE/i.test(sql)) return { success: true };
              throw new Error("UNIQUE constraint failed: items.event_id");
            }
            rows.push(r);
          }
          return { success: true };
        },
        all: async () => {
          if (/FROM blobs/i.test(sql)) {
            const b = blobs.get(args[0]);
            return { results: b ? [{ data: b }] : [] };
          }
          if (/GROUP BY feed/i.test(sql)) {
            const by = {};
            for (const r of rows) (by[r.feed] ??= { feed: r.feed, n: 0, last: "" }).n++;
            return { results: Object.values(by) };
          }
          const [feed, before, limit] = args;
          return {
            results: rows
              .filter((r) => r.feed === feed && r.created < before)
              .sort((a, b) => (a.created < b.created ? 1 : -1))
              .slice(0, limit),
          };
        },
      };
      return self;
    },
    _rows: rows,
  };
};

export const env = () => ({ POSTS: KV(), DB: DB() });
export const ctx = { waitUntil: (p) => p };

export const call = (e, path, init = {}, origin = "https://posts.test") =>
  worker.fetch(new Request(origin + path, init), e, ctx);

export const auth = (secret, extra = {}) => ({ authorization: "Bearer " + secret, ...extra });

/** A tiny network: maps an origin to the instance that serves it. */
export function network(instances) {
  return async (url, init = {}) => {
    const u = new URL(url);
    const inst = instances[u.origin];
    if (!inst) throw new Error("no such host: " + u.origin);
    return worker.fetch(new Request(url, init), inst, ctx);
  };
}

export const counter = () => {
  const s = { pass: 0, fail: 0 };
  s.ok = (name, cond, extra = "") => {
    if (cond) { s.pass++; console.log("  ok   " + name); }
    else { s.fail++; console.log("  FAIL " + name + (extra ? "  → " + extra : "")); }
  };
  s.done = () => {
    console.log(`\n${s.pass} passed, ${s.fail} failed\n`);
    process.exit(s.fail ? 1 : 0);
  };
  return s;
};
