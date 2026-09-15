// Posts — cryptography tests. node test-crypto.mjs
//
// Covers build-plan.md §15: grant integrity, healing safety, forged moves,
// hash mismatch, and the negative cases that matter more than the happy path.

import {
  newKeys, fingerprint, sign, verify, canon, b64, ub64,
  makeContact, acceptContact, rotateContact, certify, checkCertificate,
  seal, open, sealBytes, openBytes,
  firstContact, grantHook, acceptGrant,
  backup, restore, supported,
} from "./crypto.js";

let pass = 0, fail = 0;
const ok = (n, c, x = "") => { c ? (pass++, console.log("  ok   " + n)) : (fail++, console.log("  FAIL " + n + (x ? "  → " + x : ""))); };
const throws = async (n, fn) => { try { await fn(); ok(n, false, "did not throw"); } catch { ok(n, true); } };

console.log("\nengine");
ok("Ed25519 and X25519 available", await supported());

/* ---- canonical form ---- */
console.log("\ncanonical form");
ok("key order does not matter", canon({ b: 1, a: 2 }) === canon({ a: 2, b: 1 }));
ok("signature is excluded", canon({ a: 1, signature: "x" }) === canon({ a: 1 }));
ok("nested keys sorted", canon({ x: { z: 1, y: 2 } }) === '{"x":{"y":2,"z":1}}');
ok("undefined dropped", canon({ a: 1, b: undefined }) === '{"a":1}');

/* ---- encoding ---- */
console.log("\nencoding");
{
  const r = crypto.getRandomValues(new Uint8Array(97));
  ok("b64url round-trips", b64(ub64(b64(r))) === b64(r));
  ok("no padding or unsafe chars", !/[+/=]/.test(b64(r)));
}

/* ---- identities ---- */
console.log("\nidentities");
const alice = await newKeys();
const bob = await newKeys();
ok("signing pub is 32 bytes", ub64(alice.signPub).length === 32);
ok("box pub is 32 bytes", ub64(alice.boxPub).length === 32);
ok("two identities differ", alice.signPub !== bob.signPub);

const fp = await fingerprint(alice.signPub);
ok("fingerprint is groups of four", /^([0-9A-F]{4} ){3}[0-9A-F]{4}$/.test(fp), fp);
ok("fingerprint is stable", fp === (await fingerprint(alice.signPub)));
ok("fingerprint differs per key", fp !== (await fingerprint(bob.signPub)));

/* ---- signing ---- */
console.log("\nsigning");
const signed = await sign({ hello: "world" }, alice.sign);
ok("verifies", await verify(signed, alice.signPub));
ok("wrong key fails", !(await verify(signed, bob.signPub)));
ok("tampered body fails", !(await verify({ ...signed, hello: "mars" }, alice.signPub)));
ok("missing signature fails", !(await verify({ hello: "world" }, alice.signPub)));
ok("garbage signature fails", !(await verify({ ...signed, signature: "AAAA" }, alice.signPub)));

/* ---- contact records ---- */
console.log("\ncontact records");
const rec = await makeContact("https://posts.test/h/river-lamp-copper", alice);
ok("record carries the fingerprint", rec.fingerprint === fp);
const acc = await acceptContact(rec, alice.signPub);
ok("accepted when signed by the trusted key", acc.ok && acc.hook.endsWith("river-lamp-copper"));

// Rotation: a new hook, same key — the client must follow it.
const rotated = await makeContact("https://posts.test/h/silver-orbit-thistle", alice);
const acc2 = await acceptContact(rotated, alice.signPub);
ok("healing: a new hook signed by the same key is accepted", acc2.ok && acc2.hook.endsWith("silver-orbit-thistle"));

// A host takeover: attacker publishes their own record at the same page.
const hijack = await makeContact("https://evil.test/h/attacker-owned-hook", bob);
const acc3 = await acceptContact(hijack, alice.signPub);
ok("host takeover refused — denial of service, not theft", !acc3.ok, acc3.why);

// Substituting only the hook, keeping Alice's key, must break the signature.
const tampered = { ...rec, hook: "https://evil.test/h/attacker-owned-hook" };
ok("swapped hook fails the signature", !(await acceptContact(tampered, alice.signPub)).ok);

/* ---- key rotation ---- */
console.log("\nkey rotation");
{
  const next = await newKeys();
  const rot = await rotateContact("https://posts.test/h/river-lamp-copper", next, alice);

  const follow = await acceptContact(rot, alice.signPub);
  ok("a contact who trusted the old key follows it", follow.ok && follow.rotated && follow.key === next.signPub, follow.why);
  ok("and gets the new agreement key", follow.box === next.boxPub);

  const cold = await acceptContact(rot, null);
  ok("a stranger just sees the new key", cold.ok && cold.key === next.signPub);

  // An attacker with their own key cannot claim someone else's contacts.
  const attacker = await newKeys();
  const forged = await rotateContact("https://evil.test/h/attacker-owned-hook", attacker, attacker);
  ok("a rotation not signed by the old key is refused",
     !(await acceptContact(forged, alice.signPub)).ok);

  // Nor can they staple a valid rotation onto a record naming a third key.
  const mismatched = { ...rot, key: attacker.signPub };
  ok("a rotation that does not name this key is refused",
     !(await acceptContact(mismatched, alice.signPub)).ok);

  // And the old key keeps working for anything signed before the rotation.
  ok("messages signed by the old key still verify", await verify(signed, alice.signPub));

  // Rotating again chains from the key that is current now.
  const third = await newKeys();
  const rot2 = await rotateContact("https://posts.test/h/river-lamp-copper", third, next);
  ok("the next rotation chains from the current key", (await acceptContact(rot2, next.signPub)).ok);
  ok("but not from the one before it", !(await acceptContact(rot2, alice.signPub)).ok);
}

/* ---- conversation keys ---- */
console.log("\nconversation keys");
const aliceConv = await newKeys();
const cert = await certify(aliceConv, alice);
ok("certificate verifies against the account key", await checkCertificate(cert, alice.signPub));
ok("certificate refused for another account", !(await checkCertificate(cert, bob.signPub)));
ok("conversation key is unlinkable to the account key", aliceConv.signPub !== alice.signPub);

/* ---- sealing ---- */
console.log("\nsealing");
const msg = { subject: "Project update", text: "The design is ready.", html: "<p>The design is ready.</p>" };
const env = await seal(msg, bob.boxPub, aliceConv);
ok("envelope is typed", env.type === "encrypted_item");
ok("plaintext is nowhere in the envelope", !JSON.stringify(env).includes("design is ready"));
ok("subject is not leaked", !JSON.stringify(env).includes("Project update"));
ok("algorithm is named", env.cipher.algorithm === "AES-256-GCM");
ok("carries the sender's agreement key, so a reply is possible", env.from_box === aliceConv.boxPub);

const got = await open(env, bob, aliceConv.signPub);
ok("bob decrypts", got.text === msg.text && got.subject === msg.subject);

const stranger = await newKeys();
await throws("a third party cannot decrypt", () => open(env, stranger, aliceConv.signPub));
await throws("wrong expected sender is refused before decrypting", () => open(env, bob, bob.signPub));
await throws("tampered ciphertext fails", () =>
  open({ ...env, cipher: { ...env.cipher, ciphertext: b64(ub64(env.cipher.ciphertext).fill(0, 0, 4)) } }, bob, aliceConv.signPub)
);
await throws("stripped signature fails", () => open({ ...env, signature: undefined }, bob, aliceConv.signPub));

{
  // A forged envelope claiming Alice's conversation key.
  const forged = await seal(msg, bob.boxPub, bob);
  forged.from_key = aliceConv.signPub;
  await throws("forged sender key fails", () => open(forged, bob, aliceConv.signPub));
}

{
  const a = await seal(msg, bob.boxPub, aliceConv);
  const b = await seal(msg, bob.boxPub, aliceConv);
  ok("ephemeral key is fresh per message", a.eph !== b.eph);
  ok("nonce is fresh per message", a.cipher.nonce !== b.cipher.nonce);
  ok("same plaintext gives different ciphertext", a.cipher.ciphertext !== b.cipher.ciphertext);
}

{
  const carol = await newKeys();
  const multi = await seal(msg, [bob.boxPub, carol.boxPub], aliceConv);
  ok("two recipients, two wrapped keys", multi.to.length === 2);
  ok("bob opens it", (await open(multi, bob, aliceConv.signPub)).text === msg.text);
  ok("carol opens it", (await open(multi, carol, aliceConv.signPub)).text === msg.text);
}

/* ---- attachments ---- */
console.log("\nattachments");
{
  const data = crypto.getRandomValues(new Uint8Array(4096));
  const { bytes, meta } = await sealBytes(data);
  ok("ciphertext differs from plaintext", b64(bytes) !== b64(data));
  ok("metadata records the true size", meta.size === 4096);
  const back = await openBytes(bytes, meta);
  ok("round-trips", b64(back) === b64(data));
  await throws("a corrupted file is refused by its hash", () => openBytes(bytes.slice(0, -1), meta));
  await throws("a swapped file is refused by its hash", () => openBytes(crypto.getRandomValues(new Uint8Array(4096)), meta));
}

/* ---- first contact and grants ---- */
console.log("\nfirst contact and hook grants");
{
  const fc = await firstContact({ text: "hello" }, bob.boxPub, aliceConv, "https://posts.test/h/quiet-falcon-marble");
  ok("typed as first contact", fc.type === "first_contact");
  ok("carries a reply hook in the clear", fc.reply_hook.endsWith("quiet-falcon-marble"));
  ok("body still encrypted", !JSON.stringify(fc).includes("hello"));
  ok("bob reads it", (await open(fc, bob, aliceConv.signPub)).text === "hello");

  const bobConv = await newKeys();
  const grant = await grantHook("https://posts.test/h/silver-orbit-thistle", "c_123", bobConv);
  ok("alice accepts the grant", (await acceptGrant(grant, bobConv.signPub)) !== null);
  ok("a grant from an unexpected key is refused", (await acceptGrant(grant, aliceConv.signPub)) === null);

  // The interception the plan warns about: substitute the hook in transit.
  const swapped = { ...grant, hook: "https://evil.test/h/attacker-owned-hook" };
  ok("a substituted hook is refused", (await acceptGrant(swapped, bobConv.signPub)) === null);

  // The full round trip: Bob replies using only what the envelope gave him.
  const reply = await seal({ text: "got it" }, fc.from_box, bobConv, { grant });
  ok("bob can reply without fetching anything", (await open(reply, { boxPub: aliceConv.boxPub, box: aliceConv.box }, bobConv.signPub)).text === "got it");
  const swappedBox = { ...fc, from_box: (await newKeys()).boxPub };
  ok("a substituted from_box breaks the signature", !(await verify(swappedBox, fc.from_key)));
}

/* ---- backup ---- */
console.log("\nencrypted backup");
{
  const blob = await backup(alice, "correct horse battery staple");
  ok("no key material in the blob", !JSON.stringify(blob).includes(alice.signPub));
  ok("iterations recorded", blob.iterations >= 600000);
  const back = await restore(blob, "correct horse battery staple");
  ok("public keys survive", back.signPub === alice.signPub && back.boxPub === alice.boxPub);
  const proof = await sign({ a: 1 }, back.sign);
  ok("restored key still signs", await verify(proof, alice.signPub));
  await throws("wrong passphrase fails", () => restore(blob, "wrong"));
}

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
