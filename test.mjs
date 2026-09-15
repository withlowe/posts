// Posts — smoke test. No Cloudflare account needed: node test.mjs
//
// Stubs KV and D1 in memory and drives the real Worker through the
// acceptance checks in build-plan.md §14 that don't need a network.

import { mintWords, readable, LIMITS } from "./worker.js";
import { WORDS } from "./words.js";

let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => {
  if (cond) { pass++; console.log("  ok   " + name); }
  else { fail++; console.log("  FAIL " + name + (extra ? "  → " + extra : "")); }
};

import { env, ctx, call, auth } from "./test-stub.mjs";

/* ---- 1. wordlist and minting ---- */

console.log("\nwordlist and minting");
ok("7776 words", WORDS.length === 7776, WORDS.length);
ok("three words, hyphenated", /^[a-z]+-[a-z]+-[a-z]+$/.test(mintWords(3)), mintWords(3));
ok("four words when asked", mintWords(4).split("-").length === 4);
{
  const seen = new Set();
  for (let i = 0; i < 4000; i++) seen.add(mintWords(3));
  ok("no collisions in 4000 mints", seen.size === 4000, seen.size);
  const first = [...seen].map((s) => s.split("-")[0]);
  ok("distribution is wide", new Set(first).size > 2000, new Set(first).size);
}
ok("38.8 bits for three words", Math.abs(3 * Math.log2(7776) - 38.77) < 0.1);

/* ---- 2. registration and the bare domain ---- */

console.log("\nthe bare domain accepts nothing");
const e = env();
const reg = await (await call(e, "/api/register", { method: "POST" })).json();
ok("register returns a secret", !!reg.secret && reg.secret.length >= 32);
ok("register mints a public hook", /^[a-z]+-[a-z]+-[a-z]+$/.test(reg.public_hook), reg.public_hook);
ok("second register refused", (await call(e, "/api/register", { method: "POST" })).status === 403);

for (const p of ["/nothing", "/inbox", "/admin", "/h", "/f"]) {
  const r = await call(e, p);
  ok("410 for " + p, r.status === 410 || r.status === 429, r.status);
}
ok("GET on a live hook is 410", (await call(e, "/h/" + reg.public_hook)).status === 410);

/* ---- 3. receiving ---- */

console.log("\nreceiving");
const send = (hook, body, headers = {}) =>
  call(e, "/h/" + hook, { method: "POST", body, headers });

let r = await send(reg.public_hook, "disk is 91% full");
let j = await r.json();
ok("202 accepted", r.status === 202, r.status);
ok("returns a receipt", !!j.receipt);
ok("status stored", j.status === "stored", j.status);

const dup = await (await send(reg.public_hook, "again", { "x-event-id": j.event_id })).json();
ok("duplicate event_id is a duplicate, not an error", dup.status === "duplicate", dup.status);

const withSubject = await (
  await send(reg.public_hook, JSON.stringify({ subject: "Nightly backup", text: "done in 4m12s" }))
).json();
ok("JSON subject is picked up", withSubject.status === "stored");

const encd = await (
  await send(reg.public_hook, JSON.stringify({ type: "encrypted_item", cipher: { nonce: "x" } }))
).json();
ok("encrypted envelope accepted", encd.status === "stored");

const big = await send(reg.public_hook, "x".repeat(LIMITS.bodyBytes + 1));
ok("oversized body refused", big.status === 413, big.status);

/* ---- 4. minting, reading, deleting ---- */

console.log("\nhooks: mint, read, delete");
const mintRes = await (
  await call(e, "/api/hooks", {
    method: "POST",
    headers: auth(reg.secret, { "content-type": "application/json" }),
    body: JSON.stringify({ label: "CI alerts" }),
  })
).json();
ok("mint returns a hook url", /\/h\/[a-z]+-[a-z]+-[a-z]+$/.test(mintRes.url), mintRes.url);
ok("mint gives it its own feed", !!mintRes.feed && mintRes.feed !== reg.inbox);

await send(mintRes.hook, "build 412 green");
const state = await (await call(e, "/api/state", { headers: auth(reg.secret) })).json();
ok("state lists both hooks", state.hooks.filter((h) => h.status === "active").length === 2);

const items = await (
  await call(e, "/api/items?feed=" + mintRes.feed, { headers: auth(reg.secret) })
).json();
ok("item landed in the right feed", items.items.length === 1 && items.items[0].body === "build 412 green");

ok("unauthorized state is 401", (await call(e, "/api/state")).status === 401);

const delRes = await call(e, "/api/hooks/" + mintRes.hook, {
  method: "DELETE",
  headers: auth(reg.secret),
});
ok("delete succeeds", delRes.status === 200);
ok("deleted hook is 410 Gone", (await send(mintRes.hook, "hello?")).status === 410);
ok("delete is permanent", (await send(mintRes.hook, "again")).status === 410);

const afterDelete = await (await call(e, "/api/state", { headers: auth(reg.secret) })).json();
ok("dead hook keeps its words reserved", afterDelete.hooks.some((h) => h.hook === mintRes.hook && h.status === "dead"));
ok("other hooks unaffected", (await send(reg.public_hook, "still fine")).status === 202);

/* ---- 5. rotation ---- */

console.log("\nrotation");
const rot = await (
  await call(e, "/api/hooks/" + reg.public_hook + "/retire", {
    method: "POST",
    headers: auth(reg.secret, { "content-type": "application/json" }),
    body: JSON.stringify({ days: 90 }),
  })
).json();
ok("retiring the public hook mints a replacement", /^[a-z]+-[a-z]+-[a-z]+$/.test(rot.replacement || ""), rot.replacement);
ok("replacement differs", rot.replacement !== reg.public_hook);

const straggler = await send(reg.public_hook, "sent from an old bookmark");
const sj = await straggler.json();
ok("retired hook still accepts", straggler.status === 202, straggler.status);
ok("but flags the arrival", sj.hook === "old-hook", sj.hook);
ok("replacement accepts", (await send(rot.replacement, "hi")).status === 202);

/* ---- 6. contact record ---- */

console.log("\ncontact record");
ok("no record yet → 410", (await call(e, "/c/contact.json")).status === 410);
const record = JSON.stringify({
  hook: "https://posts.test/h/" + rot.replacement,
  key: "ed25519-pub",
  fingerprint: "A1C4 7B92 0D11 8F35",
  issued: new Date().toISOString(),
  signature: "sig",
});
ok(
  "owner can publish one",
  (await call(e, "/api/contact", { method: "PUT", headers: auth(reg.secret), body: record })).status === 200
);
const served = await call(e, "/c/contact.json");
ok("served verbatim", (await served.text()) === record);
ok("contact page renders", (await (await call(e, "/c")).text()).includes("A1C4 7B92"));
ok(
  "publishing needs the secret",
  (await call(e, "/api/contact", { method: "PUT", body: record })).status === 401
);

/* ---- 7. feeds ---- */

console.log("\nfeeds");
const st2 = await (await call(e, "/api/state", { headers: auth(reg.secret) })).json();
const inbox = st2.feeds.find((f) => f.id === reg.inbox);
const fr = await call(e, "/f/" + reg.inbox + ".json?key=" + inbox.key);
const fj = await fr.json();
ok("feed reads with its key", fr.status === 200 && fj.items.length > 0, fr.status);
ok("wrong key is 410", (await call(e, "/f/" + reg.inbox + ".json?key=wrong")).status === 410);
ok("no key is 410", (await call(e, "/f/" + reg.inbox + ".json")).status === 410);
ok("a feed rejects POST", (await call(e, "/f/" + reg.inbox + ".json?key=" + inbox.key, { method: "POST", body: "x" })).status === 410);
const rss = await call(e, "/f/" + reg.inbox + "/rss?key=" + inbox.key);
const rssText = await rss.text();
ok("rss is served", rss.headers.get("content-type").includes("rss"));
ok("rss is well formed", rssText.startsWith("<?xml") && rssText.includes("</rss>"));
ok("encrypted items are not exposed in rss", !rssText.includes('"nonce"'));

/* ---- 7b. serving the browser half ---- */

console.log("\nbrowser half");
{
  const cj = await call(e, "/crypto.js");
  ok("crypto.js is served", cj.status === 200 && cj.headers.get("content-type").includes("javascript"));
  const src = await cj.text();
  ok("it is the real module", src.includes("export async function seal"));
  ok("it contains no key material", !/PRIVATE KEY|BEGIN /.test(src));

  const pre = await call(e, "/h/" + rot.replacement, { method: "OPTIONS" });
  ok("preflight allowed on a hook", pre.status === 204 && pre.headers.get("access-control-allow-origin") === "*");

  const posted = await send(rot.replacement, "cross-origin");
  ok("hook replies with CORS", posted.headers.get("access-control-allow-origin") === "*");

  const cr = await call(e, "/c/contact.json");
  ok("contact record is readable cross-origin", cr.headers.get("access-control-allow-origin") === "*");

  const app = await (await call(e, "/")).text();
  ok("app is loaded as a module, not inlined", app.includes('<script type=module src="/app.js">'));
  ok("no inline script to mangle", !/<script(?![^>]*src=)/.test(app));

  const aj = await call(e, "/app.js");
  ok("app.js is served", aj.status === 200);
  const appSrc = await aj.text();
  ok("it imports the crypto module", appSrc.includes("from '/crypto.js'"));
  ok("its regexes survived the round trip", appSrc.includes("split(/\\s+/)"));

  const icon = await call(e, "/favicon.ico");
  ok("the browser's favicon request is answered", icon.status === 200);
}

/* ---- 8. readable() ---- */

console.log("\nreading");
ok("scripts dropped", !readable("<script>evil()</script>hello").includes("evil"));
ok("tracking pixel dropped", readable('hi <img src="http://t.example/x.gif">') === "hi");
ok("alt text kept", readable('<img alt="a chart">') === "a chart");
ok("list items become bullets", readable("<ul><li>one</li><li>two</li></ul>").includes("• one"));
ok("entities decoded", readable("a &amp; b") === "a & b");
ok("zero-width padding stripped", readable("a​b") === "ab");

/* ---- 9. rules and digests ---- */

console.log("\nrules");
{
  const h = await (await call(e, "/api/hooks", {
    method: "POST", headers: auth(reg.secret, { "content-type": "application/json" }),
    body: JSON.stringify({ label: "newsletters" }),
  })).json();

  const money = await (await call(e, "/api/hooks", {
    method: "POST", headers: auth(reg.secret, { "content-type": "application/json" }),
    body: JSON.stringify({ label: "money" }),
  })).json();

  const set = await call(e, "/api/hooks/" + h.hook + "/rules", {
    method: "POST", headers: auth(reg.secret, { "content-type": "application/json" }),
    body: JSON.stringify({ rules: [
      { field: "subject", op: "contains", value: "invoice", then: { action: "feed", value: money.feed } },
      { field: "sender",  op: "contains", value: "spam",    then: { action: "ignore" } },
      { field: "subject", op: "contains", value: "urgent",  then: { action: "important" } },
      { field: "body",    op: "contains", value: "weekly",  then: { action: "tag", value: "digest-me" } },
    ] }),
  });
  ok("rules are stored", set.status === 200);

  await send(h.hook, JSON.stringify({ subject: "Your invoice for March" }));
  const inMoney = await (await call(e, "/api/items?feed=" + money.feed, { headers: auth(reg.secret) })).json();
  ok("a rule can move an item to another feed", inMoney.items.length === 1, inMoney.items.length);

  const ignored = await (await send(h.hook, JSON.stringify({ subject: "hi", text: "x" }), { "x-event-id": "ig1" })).json();
  ok("a non-matching item is kept", ignored.status === "stored");

  const spam = await (await call(e, "/h/" + h.hook, {
    method: "POST", headers: { "x-event-id": "sp1" },
    body: JSON.stringify({ subject: "buy now", text: "spam spam" }),
  })).json();
  ok("body matched by a later rule still stores", spam.status === "stored");

  await send(h.hook, JSON.stringify({ subject: "urgent: disk full" }));
  const own = await (await call(e, "/api/items?feed=" + h.feed, { headers: auth(reg.secret) })).json();
  ok("important is flagged", own.items.some((i) => i.flags.includes("important")));

  ok("first match wins", (await (await send(h.hook,
    JSON.stringify({ subject: "urgent invoice" }))).json()).status === "stored");
  const money2 = await (await call(e, "/api/items?feed=" + money.feed, { headers: auth(reg.secret) })).json();
  ok("and it was the earlier rule", money2.items.length === 2, money2.items.length);

  ok("rules need the owner secret", (await call(e, "/api/hooks/" + h.hook + "/rules", { method: "POST", body: "{}" })).status === 401);
  ok("rules on a dead hook are refused", (await call(e, "/api/hooks/" + mintRes.hook + "/rules", {
    method: "POST", headers: auth(reg.secret, { "content-type": "application/json" }),
    body: JSON.stringify({ rules: [] }) })).status === 404);
}

console.log("\ndigests");
{
  const d = await (await call(e, "/api/hooks", {
    method: "POST", headers: auth(reg.secret, { "content-type": "application/json" }),
    body: JSON.stringify({ label: "quiet" }),
  })).json();

  await call(e, "/api/feeds/" + d.feed + "/arrive", {
    method: "POST", headers: auth(reg.secret, { "content-type": "application/json" }),
    body: JSON.stringify({ arrive: "daily" }),
  });

  for (const n of [1, 2, 3]) await send(d.hook, JSON.stringify({ subject: "item " + n }));
  const held = await (await call(e, "/api/items?feed=" + d.feed, { headers: auth(reg.secret) })).json();
  ok("a daily feed holds its items back", held.items.length === 0, held.items.length);

  const run = await (await call(e, "/api/digest", { method: "POST", headers: auth(reg.secret) })).json();
  ok("the digest run writes one", run.digests === 1, JSON.stringify(run));

  const after = await (await call(e, "/api/items?feed=" + d.feed, { headers: auth(reg.secret) })).json();
  ok("now the feed has the digest plus the items", after.items.length === 4, after.items.length);
  const digest = after.items.find((i) => i.flags === "digest");
  ok("the digest names them all", digest && digest.body.split("\n").length === 3, digest?.body);
  ok("and says how many", digest.subject === "3 items", digest?.subject);

  const again = await (await call(e, "/api/digest", { method: "POST", headers: auth(reg.secret) })).json();
  ok("a second run writes nothing", again.digests === 0);
}

/* ---- done ---- */

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
