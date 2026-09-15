// Posts — the client, in a real browser. node test-browser.mjs
//
// Serves the Worker over HTTP and drives it with Chromium, so the half that
// holds the keys is exercised the way a person would: register, generate an
// identity, publish a signed contact record, read, filter.
//
// Skipped automatically where Playwright or Chromium is unavailable.

import { createServer } from "node:http";
import worker from "./worker.js";
import { env, ctx, counter } from "./test-stub.mjs";

let chromium;
try {
  ({ chromium } = await import("playwright"));
} catch {
  console.log("\nbrowser tests skipped — playwright not installed\n");
  process.exit(0);
}

const t = counter();
const e = env();

/* ---- the Worker, over real HTTP ---- */

const server = createServer(async (req, res) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const r = await worker.fetch(
    new Request("http://" + (req.headers.host || "localhost") + req.url, {
      method: req.method,
      headers: req.headers,
      body: chunks.length ? Buffer.concat(chunks) : undefined,
    }),
    e,
    ctx
  );
  res.writeHead(r.status, Object.fromEntries(r.headers));
  res.end(Buffer.from(await r.arrayBuffer()));
});
await new Promise((ok) => server.listen(0, ok));
const origin = "http://127.0.0.1:" + server.address().port;

// The container ships a Chromium that may not match Playwright's expected
// build, so use it directly rather than downloading another.
const CHROME = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome";
const { existsSync } = await import("node:fs");
const browser = await chromium.launch(
  existsSync(CHROME) ? { executablePath: CHROME, args: ["--no-sandbox"] } : {}
).catch((err) => {
  console.log("\nbrowser tests skipped — " + String(err).split("\n")[0] + "\n");
  process.exit(0);
});
const page = await browser.newPage();
const errors = [];
page.on("pageerror", (err) => errors.push(String(err)));
page.on("console", (m) => m.type() === "error" && errors.push(m.text()));

/* ---- first run ---- */

console.log("\nfirst run");
await page.goto(origin);
await page.waitForSelector("#dlgbody .k", { timeout: 15000 });
const secret = (await page.textContent("#dlgbody .k")).trim();
t.ok("the owner secret is shown once", secret.length >= 32);
await page.click("dialog button");

t.ok("keys were generated in the browser", await page.evaluate(async () => {
  const d = await new Promise((ok) => { const r = indexedDB.open("posts", 1); r.onsuccess = () => ok(r.result); });
  return new Promise((ok) => {
    const q = d.transaction("kv").objectStore("kv").get("identity");
    q.onsuccess = () => ok(!!q.result?.signPub && !!q.result?.boxPub);
  });
}));

await page.waitForFunction(() => document.querySelector("#me")?.textContent.includes("fingerprint"), null, { timeout: 15000 });
const fp = (await page.textContent("#me")).match(/([0-9A-F]{4} ){3}[0-9A-F]{4}/);
t.ok("the fingerprint is shown", !!fp, await page.textContent("#me"));

/* ---- the contact record was signed here and published ---- */

console.log("\ncontact record");
const rec = await (await fetch(origin + "/c/contact.json")).json();
t.ok("a signed record was published", !!rec.signature && !!rec.hook);
t.ok("it carries the same fingerprint", rec.fingerprint === fp[0]);
t.ok("the Worker only stored it — the signature verifies against the browser's key",
  await page.evaluate(async (r) => {
    const C = await import("/crypto.js");
    return (await C.acceptContact(r, r.key)).ok;
  }, rec));

const page2 = await (await fetch(origin + "/c")).text();
t.ok("the public contact page shows the hook", page2.includes(rec.hook));

/* ---- receiving, and the filter ---- */

console.log("\nthe filter");
for (const [subject, body] of [
  ["Nightly backup", "done in 4m12s"],
  ["Disk warning", "disk is 91 percent full"],
  ["Deploy", "build 412 green"],
]) {
  await fetch(rec.hook, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ subject, text: body }),
  });
}

await page.click("#srcs .src");
await page.waitForSelector(".item", { timeout: 10000 });
const visible = () => page.$$eval(".item:not(.hide)", (n) => n.length);
t.ok("three items arrived", (await visible()) === 3, await visible());

await page.fill("#filter", "disk");
await page.waitForTimeout(150);
t.ok("filtering narrows to one", (await visible()) === 1, await visible());
t.ok("the count is shown", (await page.textContent("#fcount")).includes("1 of 3"));
t.ok("the match is highlighted", (await page.$$("mark")).length > 0);

await page.fill("#filter", "disk backup");
await page.waitForTimeout(150);
t.ok("two terms means both must match", (await visible()) === 0, await visible());

await page.fill("#filter", "green");
await page.waitForTimeout(150);
t.ok("it searches the body, not just the subject", (await visible()) === 1);

await page.fill("#filter", "");
await page.waitForTimeout(150);
t.ok("clearing restores everything", (await visible()) === 3);
t.ok("and removes the highlights", (await page.$$("mark")).length === 0);

await page.fill("#filter", "nothingmatchesthis");
await page.waitForTimeout(150);
t.ok("no matches hides the sources too", (await page.$$eval("#srcs .src:not(.hide)", (n) => n.length)) === 0);
await page.fill("#filter", "");

/* ---- managing a hook: rules, arrival, delete ---- */

console.log("\nmanaging a hook");
{
  page.once("dialog", (d) => d.accept("newsletters"));
  await page.click("button:has-text('Mint a hook')");
  await page.waitForSelector("#dlgbody .k", { timeout: 10000 });
  const nl = (await page.textContent("#dlgbody .k")).trim();
  await page.click("dialog button");
  await page.waitForTimeout(200);

  // The manage control sits on the source, not behind a menu somewhere else.
  const btn = page.locator('.src:has-text("newsletters") .manage');
  await btn.click({ force: true });
  await page.waitForSelector("#addrule", { timeout: 10000 });
  t.ok("the hook url is shown for copying", (await page.textContent("#dlgbody .k")).trim() === nl);

  // A rule, built from the dropdowns.
  await page.click("#addrule");
  await page.selectOption('[data-k="field"]', "subject");
  await page.fill('[data-k="value"]', "invoice");
  await page.selectOption('[data-k="action"]', "ignore");
  await page.click("#saverules");
  await page.waitForFunction(() => document.querySelector("#saverules")?.textContent === "Saved", null, { timeout: 10000 });
  t.ok("the rule saves", true);

  const ignored = await (await fetch(nl, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ subject: "Your invoice for March" }),
  })).json();
  t.ok("a matching item is ignored, not stored", ignored.status === "ignored", ignored.status);

  const kept = await (await fetch(nl, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ subject: "Something else" }),
  })).json();
  t.ok("anything else still arrives", kept.status === "stored");

  // Arrival is a property of the feed, not a rule.
  await page.selectOption("#arr", "daily");
  await page.waitForTimeout(400);
  t.ok("the sidebar shows it arrives daily",
    (await page.textContent('.src:has-text("newsletters")')).includes("daily"));

  // And the promise the whole design rests on, with a button behind it.
  page.once("dialog", (d) => d.accept());
  await page.click("#kill");
  await page.waitForTimeout(500);
  t.ok("the source is gone from the sidebar",
    (await page.$$eval("#srcs .src", (n) => n.map((x) => x.textContent).join(" "))).includes("newsletters") === false);

  const afterDelete = await fetch(nl, { method: "POST", body: "hello?" });
  t.ok("and the hook is refused for good", afterDelete.status === 410, afterDelete.status);
}

/* ---- All, and filtering across feeds ---- */

console.log("\nall feeds");
{
  page.once("dialog", (d) => d.accept("second source"));
  await page.click("button:has-text('Mint a hook')");
  await page.waitForSelector("#dlgbody .k", { timeout: 10000 });
  const other = (await page.textContent("#dlgbody .k")).trim();
  await page.click("dialog button");
  await fetch(other, { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ subject: "Elsewhere", text: "a different source entirely" }) });

  await page.click('[data-f="*"]');
  await page.waitForTimeout(400);
  const n = await page.$$eval(".item", (x) => x.length);
  t.ok("All shows items from every feed", n >= 4, n);

  await page.fill("#filter", "elsewhere");
  await page.waitForTimeout(150);
  t.ok("the filter crosses feeds", (await page.$$eval(".item:not(.hide)", (x) => x.length)) === 1);
  await page.fill("#filter", "");
}

/* ---- settings: backup and rotation ---- */

console.log("\nsettings");
{
  await page.click("#settings");
  await page.waitForSelector("#bdo", { timeout: 10000 });
  t.ok("the fingerprint is offered for checking", (await page.textContent("#dlgbody .k")).trim() === fp[0]);

  const before = await page.evaluate(() => document.querySelector("#me").textContent);

  const rotated = await page.evaluate(async () => {
    const C = await import("/crypto.js");
    const rec = await (await fetch("/c/contact.json")).json();
    return { key: rec.key, ok: (await C.acceptContact(rec, rec.key)).ok };
  });
  t.ok("the published record still verifies before rotating", rotated.ok);

  page.once("dialog", (d) => d.accept());
  await page.click("#rotdo");
  await page.waitForFunction(
    () => document.querySelector("#dlgbody h3")?.textContent === "Rotated",
    null, { timeout: 15000 }
  );

  const after = await page.evaluate(async (oldKey) => {
    const C = await import("/crypto.js");
    const rec = await (await fetch("/c/contact.json", { cache: "no-store" })).json();
    return {
      key: rec.key,
      followed: (await C.acceptContact(rec, oldKey)).rotated === true,
      strangerOk: (await C.acceptContact(rec, null)).ok,
      hasRotation: !!rec.rotation,
    };
  }, rotated.key);

  t.ok("rotation publishes a new key", after.key !== rotated.key);
  t.ok("a contact who trusted the old key follows it", after.followed);
  t.ok("a stranger accepts the new record too", after.strangerOk);
  t.ok("the record carries the rotation", after.hasRotation);
  await page.click("dialog button");
  t.ok("the sidebar shows the new fingerprint",
    (await page.evaluate(() => document.querySelector("#me").textContent)) !== before);
}

/* ---- minting a hook ---- */

console.log("\nminting");
page.once("dialog", (d) => d.accept("CI alerts"));
await page.click("button:has-text('Mint a hook')");
await page.waitForSelector("#dlgbody .k", { timeout: 10000 });
const minted = (await page.textContent("#dlgbody .k")).trim();
t.ok("a three-word hook is offered", /\/h\/[a-z]+-[a-z]+-[a-z]+$/.test(minted), minted);
await page.click("dialog button");

const posted = await fetch(minted, { method: "POST", body: "build 999 green" });
t.ok("it accepts", posted.status === 202);

/* ---- nothing broke along the way ---- */

console.log("\nconsole");
t.ok("no page errors", errors.length === 0, errors.slice(0, 3).join(" | "));

await browser.close();
server.close();
t.done();
