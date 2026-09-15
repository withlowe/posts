// Posts — end to end. node test-e2e.mjs
//
// Two independent instances on two hosts, real Worker, real cryptography,
// nothing stubbed but storage. This walks build-plan.md §14 acceptance 4–11:
// contact page, first contact, the New tray, the grant that moves a thread
// off the public hook, rotation healing itself, and deletion sticking.

import * as C from "./crypto.js";
import { env, call, auth, network, counter } from "./test-stub.mjs";

const t = counter();
const ALICE = "https://alice.test", BOB = "https://bob.test";
const a = env(), b = env();
const net = network({ [ALICE]: a, [BOB]: b });

const post = (url, body) =>
  net(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

/* ---- two accounts ---- */

console.log("\ntwo accounts");
const aReg = await (await call(a, "/api/register", { method: "POST" }, ALICE)).json();
const bReg = await (await call(b, "/api/register", { method: "POST" }, BOB)).json();
const alice = await C.newKeys();
const bob = await C.newKeys();
t.ok("both registered with their own public hook", aReg.public_hook !== bReg.public_hook);

/* ---- alice publishes a signed contact page ---- */

console.log("\ncontact page");
const aliceHookUrl = ALICE + "/h/" + aReg.public_hook;
let rec = await C.makeContact(aliceHookUrl, alice);
await call(a, "/api/contact", { method: "PUT", headers: auth(aReg.secret), body: JSON.stringify(rec) }, ALICE);

// Bob reads it cold, the way a stranger would.
const fetched = await (await net(ALICE + "/c/contact.json")).json();
const accepted = await C.acceptContact(fetched, null);
t.ok("bob reads and verifies it", accepted.ok);
t.ok("the fingerprint is what alice would read out", fetched.fingerprint === (await C.fingerprint(alice.signPub)));

// What Bob stores. contact_url is what lets him heal later.
let bobsAlice = {
  petname: "@alice",
  key: accepted.key,
  box: accepted.box,
  hook: accepted.hook,
  contact_url: ALICE + "/c/contact.json",
};

/* ---- first contact ---- */

console.log("\nfirst contact");
const bobConv = await C.newKeys();
const bobReplyHook = BOB + "/h/" + bReg.public_hook;
const fc = await C.firstContact(
  { subject: "About the plan", text: "Is this thing on?" },
  bobsAlice.box,
  bobConv,
  bobReplyHook
);
const sent = await post(bobsAlice.hook, fc);
t.ok("alice's hook accepts it", sent.status === 202, sent.status);
t.ok("the relay stored it as encrypted", (await sent.json()).status === "stored");

// It lands in New, not somewhere private.
const aState = await (await call(a, "/api/state", { headers: auth(aReg.secret) }, ALICE)).json();
const newFeed = aState.feeds.find((f) => f.name === "New");
const inNew = await (await call(a, "/api/items?feed=" + newFeed.id, { headers: auth(aReg.secret) }, ALICE)).json();
t.ok("it is in the New tray", inNew.items.length === 1);

const envelope = JSON.parse(inNew.items[0].body);
t.ok("the relay never saw the subject", !inNew.items[0].subject.includes("About the plan"));
const opened = await C.open(envelope, alice);
t.ok("alice decrypts it", opened.text === "Is this thing on?");
t.ok("and gets a reply hook in the clear", envelope.reply_hook === bobReplyHook);
t.ok("and bob's agreement key, so she can reply", envelope.from_box === bobConv.boxPub);

/* ---- the grant: the thread leaves the public hook ---- */

console.log("\nthe doorway principle");
const conv = await (
  await call(a, "/api/conversations", {
    method: "POST",
    headers: auth(aReg.secret, { "content-type": "application/json" }),
    body: JSON.stringify({ their_hook: envelope.reply_hook, their_key: envelope.from_key, petname: "@bob" }),
  }, ALICE)
).json();
t.ok("alice mints bob a hook of his own", /^[a-z]+-[a-z]+-[a-z]+$/.test(conv.my_hook), conv.my_hook);
t.ok("it differs from her public hook", conv.my_hook !== aReg.public_hook);
t.ok("and gets its own feed", conv.feed !== newFeed.id);

const aliceConv = await C.newKeys();
const grant = await C.grantHook(conv.my_hook_url, conv.id, aliceConv);
const reply = await C.seal({ text: "Loud and clear." }, envelope.from_box, aliceConv, { grant });
const replied = await post(envelope.reply_hook, reply);
t.ok("the reply reaches bob", replied.status === 202);

// Bob reads it and takes the hook.
const bState = await (await call(b, "/api/state", { headers: auth(bReg.secret) }, BOB)).json();
const bNew = bState.feeds.find((f) => f.name === "New");
const bItems = await (await call(b, "/api/items?feed=" + bNew.id, { headers: auth(bReg.secret) }, BOB)).json();
const replyEnv = JSON.parse(bItems.items[0].body);
t.ok("bob decrypts the reply with his conversation key", (await C.open(replyEnv, bobConv)).text === "Loud and clear.");
t.ok("his account key cannot open it — the thread is on its own keys", await C.open(replyEnv, bob).then(() => false, () => true));

// From her reply Bob learns the key to seal to for the rest of the thread.
bobsAlice.box = replyEnv.from_box;

const granted = await C.acceptGrant(replyEnv.grant, replyEnv.from_key);
t.ok("bob accepts the grant", granted === conv.my_hook_url, granted);
bobsAlice.hook = granted;

// A grant signed by anyone else must not be taken.
const impostor = await C.newKeys();
const badGrant = await C.grantHook("https://evil.test/h/attacker-owned-hook", conv.id, impostor);
t.ok("a grant from another key is refused", (await C.acceptGrant(badGrant, replyEnv.from_key)) === null);

// From here the thread is private.
const onPrivate = await post(bobsAlice.hook, await C.seal({ text: "second message" }, bobsAlice.box, bobConv));
t.ok("bob's next message goes to the private hook", onPrivate.status === 202);
const convItems = await (await call(a, "/api/items?feed=" + conv.feed, { headers: auth(aReg.secret) }, ALICE)).json();
t.ok("it lands in the conversation feed, not New", convItems.items.length === 1);
const stillNew = await (await call(a, "/api/items?feed=" + newFeed.id, { headers: auth(aReg.secret) }, ALICE)).json();
t.ok("New is untouched", stillNew.items.length === 1);

/* ---- an attachment, end to end ---- */

console.log("\nattachments");
{
  const file = crypto.getRandomValues(new Uint8Array(20000));
  const { bytes, meta } = await C.sealBytes(file);

  const up = await (await call(b, "/api/blobs", {
    method: "POST", headers: auth(bReg.secret), body: bytes,
  }, BOB)).json();
  t.ok("ciphertext uploads", !!up.id && up.bytes === bytes.byteLength, JSON.stringify(up));

  // Alice fetches it from Bob's host with no credentials at all.
  const fetchedBlob = await net(up.url);
  t.ok("anyone may fetch the ciphertext", fetchedBlob.status === 200);
  t.ok("it is served cross-origin", fetchedBlob.headers.get("access-control-allow-origin") === "*");
  const ct = new Uint8Array(await fetchedBlob.arrayBuffer());
  t.ok("byte-identical", C.b64(ct) === C.b64(bytes));

  // The file key rides inside the sealed body, never in the envelope.
  const withFile = await C.seal(
    { text: "the design", attachments: [{ name: "design.webp", media_type: "image/webp", url: up.url, ...meta }] },
    bobsAlice.box, bobConv
  );
  t.ok("no file key in the envelope", !JSON.stringify(withFile).includes(meta.file_key));
  t.ok("no hash in the envelope either", !JSON.stringify(withFile).includes(meta.sha256));

  await post(bobsAlice.hook, withFile);
  const cf = await (await call(a, "/api/items?feed=" + conv.feed, { headers: auth(aReg.secret) }, ALICE)).json();
  const got = await C.open(JSON.parse(cf.items[0].body), aliceConv);
  t.ok("alice gets the attachment metadata", got.attachments[0].name === "design.webp");
  const plain = await C.openBytes(ct, got.attachments[0]);
  t.ok("and recovers the file", C.b64(plain) === C.b64(file));

  // A host that swaps the bytes is caught by the hash, not trusted.
  const swapped = crypto.getRandomValues(new Uint8Array(20000));
  t.ok("a substituted file is refused", await C.openBytes(swapped, got.attachments[0]).then(() => false, () => true));

  const huge = new Uint8Array(300 * 1024);
  const tooBig = await call(b, "/api/blobs", { method: "POST", headers: auth(bReg.secret), body: huge }, BOB);
  t.ok("oversized upload refused without a bucket", tooBig.status === 413, tooBig.status);
  t.ok("uploading needs the owner secret", (await call(b, "/api/blobs", { method: "POST", body: bytes }, BOB)).status === 401);
  t.ok("an unknown blob is 410", (await net(BOB + "/b/" + "0".repeat(32))).status === 410);
}

/* ---- rotation heals itself ---- */

console.log("\nrotation heals itself");
const rot = await (
  await call(a, "/api/hooks/" + aReg.public_hook + "/retire", {
    method: "POST",
    headers: auth(aReg.secret, { "content-type": "application/json" }),
    body: JSON.stringify({ days: 0 }),
  }, ALICE)
).json();
// days:0 makes the old hook dead immediately — the abuse case, no tail.
rec = await C.makeContact(ALICE + "/h/" + rot.replacement, alice);
await call(a, "/api/contact", { method: "PUT", headers: auth(aReg.secret), body: JSON.stringify(rec) }, ALICE);

// A cold stranger holding the old hook.
const cold = { key: alice.signPub, box: alice.boxPub, hook: aliceHookUrl, contact_url: ALICE + "/c/contact.json" };
const strangerConv = await C.newKeys();
let first = await post(cold.hook, await C.firstContact({ text: "hi" }, cold.box, strangerConv, BOB + "/h/x"));
t.ok("the old hook is gone", first.status === 410, first.status);

// Heal: re-read, verify against the key already trusted, retry.
const fresh = await (await net(cold.contact_url, { cache: "no-store" })).json();
const ok2 = await C.acceptContact(fresh, cold.key);
t.ok("the new record is signed by the same key", ok2.ok);
cold.hook = ok2.hook;
first = await post(cold.hook, await C.firstContact({ text: "hi" }, cold.box, strangerConv, BOB + "/h/x"));
t.ok("the retry succeeds — the sender never noticed", first.status === 202, first.status);
t.ok("bob's private hook was never disturbed", (await post(bobsAlice.hook, await C.seal({ text: "third" }, bobsAlice.box, bobConv))).status === 202);
{
  const cf = await (await call(a, "/api/items?feed=" + conv.feed, { headers: auth(aReg.secret) }, ALICE)).json();
  t.ok("alice reads the thread with its own key, not her account key", (await C.open(JSON.parse(cf.items[0].body), aliceConv)).text === "third");
}

// A hijacked page cannot redirect the cold sender.
const attacker = await C.newKeys();
const hijack = await C.makeContact("https://evil.test/h/attacker-owned-hook", attacker);
t.ok("a record signed by another key is refused", !(await C.acceptContact(hijack, cold.key)).ok);

/* ---- publishing: the pull half ---- */

console.log("\npublishing");
{
  const pub = await (await call(a, "/api/publish", {
    method: "POST", headers: auth(aReg.secret, { "content-type": "application/json" }),
    body: JSON.stringify({ slug: "notes", title: "Alice's notes", subject: "First note", text: "Hello, world." }),
  }, ALICE)).json();
  t.ok("publishing returns both formats", pub.json.endsWith("/p/notes.json") && pub.rss.endsWith("/p/notes/rss"));

  // No key, no account, no permission — that is the point of a feed.
  const r = await net(pub.json);
  const j = await r.json();
  t.ok("anyone may read it", r.status === 200 && j.items.length === 1, r.status);
  t.ok("the item is there in the clear", j.items[0].content === "Hello, world.");
  t.ok("it is cacheable at the edge", /public, max-age=/.test(r.headers.get("cache-control")));
  t.ok("and readable cross-origin", r.headers.get("access-control-allow-origin") === "*");

  const rss = await net(pub.rss);
  const x = await rss.text();
  t.ok("rss works too", x.includes("<title>First note</title>") && x.includes("</rss>"));

  // Publishing is the only thing a feed does. It still accepts nothing.
  t.ok("a public feed rejects POST", (await net(pub.json, { method: "POST", body: "x" })).status === 410);
  t.ok("an unknown slug is 410", (await net(ALICE + "/p/nothing.json")).status === 410);
  t.ok("a private feed is not reachable by slug", (await net(ALICE + "/p/" + conv.feed + ".json")).status === 410);
  t.ok("publishing needs the owner secret", (await call(a, "/api/publish", { method: "POST", body: "{}" }, ALICE)).status === 401);

  const page = await (await net(ALICE + "/c")).text();
  t.ok("the contact page lists it", page.includes("/p/notes.json") && page.includes("Alice&#39;s notes"));
}

/* ---- deletion sticks ---- */

console.log("\ndeletion");
await call(a, "/api/hooks/" + conv.my_hook, { method: "DELETE", headers: auth(aReg.secret) }, ALICE);
const afterDelete = await post(bobsAlice.hook, await C.seal({ text: "anyone there?" }, bobsAlice.box, bobConv));
t.ok("bob is gone for good", afterDelete.status === 410, afterDelete.status);

// And healing must not resurrect him: the contact page carries the public
// hook, which is a doorway, not his room.
const healAttempt = await (await net(bobsAlice.contact_url)).json();
const healed = await C.acceptContact(healAttempt, bobsAlice.key);
t.ok("the contact page still resolves", healed.ok);
t.ok("but only to the public hook, not his deleted one", healed.hook !== bobsAlice.hook);

const others = await post(ALICE + "/h/" + rot.replacement, await C.seal({ text: "unrelated" }, alice.boxPub, strangerConv));
t.ok("everyone else is unaffected", others.status === 202);

t.done();
