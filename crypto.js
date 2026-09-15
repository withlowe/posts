// Posts — cryptography.
//
// Everything here is native WebCrypto. Ed25519 and X25519 ship in the stable
// releases of all three major engines, so there is no library to bundle and
// no algorithm implemented here by hand.
//
//   Ed25519        signing — contact records, envelopes, hook grants
//   X25519         key agreement, ephemeral-static (sender forward secrecy)
//   AES-256-GCM    content
//   HKDF-SHA256    deriving the key-wrapping key
//
// The plan prefers XChaCha20-Poly1305. WebCrypto does not offer it, and
// bundling a library to get it would be a worse trade than using the engine's
// own audited AES-GCM — which the plan lists as the alternative.
//
// Three key layers, three lifetimes (build-plan.md §6):
//
//   account key        long-lived. what a fingerprint pins.
//     └── conversation key   per conversation, certified by the account key
//           └── hook         the URL. not a key at all.

const S = crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

/* ---------- encoding ---------- */

export const b64 = (b) =>
  btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

export const ub64 = (s) => {
  const t = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(t + "=".repeat((4 - (t.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};

const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

// Deterministic JSON for signing: keys sorted, `signature` excluded.
export function canon(obj) {
  const walk = (v) => {
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === "object") {
      const out = {};
      for (const k of Object.keys(v).sort()) {
        if (k === "signature") continue;
        if (v[k] !== undefined) out[k] = walk(v[k]);
      }
      return out;
    }
    return v;
  };
  return JSON.stringify(walk(obj));
}

/* ---------- keys ---------- */

const genSign = () => S.generateKey("Ed25519", true, ["sign", "verify"]);
const genBox = () => S.generateKey("X25519", true, ["deriveBits"]);
const rawPub = async (k) => b64(await S.exportKey("raw", k));

/** A fresh keypair set — used for both accounts and conversations. */
export async function newKeys() {
  const [sign, box] = await Promise.all([genSign(), genBox()]);
  return {
    sign: sign.privateKey,
    box: box.privateKey,
    signPub: await rawPub(sign.publicKey),
    boxPub: await rawPub(box.publicKey),
  };
}

const importSignPub = (raw) => S.importKey("raw", ub64(raw), "Ed25519", true, ["verify"]);
const importBoxPub = (raw) => S.importKey("raw", ub64(raw), "X25519", true, []);

/** Human-comparable fingerprint of a signing public key. */
export async function fingerprint(signPubB64) {
  const h = new Uint8Array(await S.digest("SHA-256", ub64(signPubB64)));
  return [...h.slice(0, 8)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase()
    .match(/.{4}/g)
    .join(" ");
}

/* ---------- signing ---------- */

export async function sign(obj, signPriv) {
  const sig = await S.sign("Ed25519", signPriv, enc.encode(canon(obj)));
  return { ...obj, signature: b64(sig) };
}

export async function verify(obj, signPubB64) {
  if (!obj?.signature) return false;
  try {
    return await S.verify("Ed25519", await importSignPub(signPubB64), ub64(obj.signature), enc.encode(canon(obj)));
  } catch {
    return false;
  }
}

/* ---------- contact records ---------- */

/** Build the record a contact page carries. Signed by the account key. */
export async function makeContact(hookUrl, account) {
  return sign(
    {
      hook: hookUrl,
      key: account.signPub,
      box: account.boxPub,
      fingerprint: await fingerprint(account.signPub),
      issued: new Date().toISOString(),
    },
    account.sign
  );
}

/**
 * Replace your account key. The record is signed by the NEW key and carries a
 * rotation attested by the OLD one, so a contact who trusts the old key can
 * follow you — and nobody else can claim to be you.
 */
export async function rotateContact(hookUrl, newAccount, oldAccount) {
  const rotation = await sign(
    { from: oldAccount.signPub, to: newAccount.signPub, at: new Date().toISOString() },
    oldAccount.sign
  );
  return sign(
    {
      hook: hookUrl,
      key: newAccount.signPub,
      box: newAccount.boxPub,
      fingerprint: await fingerprint(newAccount.signPub),
      issued: new Date().toISOString(),
      rotation,
    },
    newAccount.sign
  );
}

/**
 * Accept a contact record only if it is signed by a key we already trust, or
 * by one the trusted key has signed over to. This is what makes rotation safe:
 * a compromised host can deny service but cannot redirect messages to itself
 * (build-plan.md §5).
 */
export async function acceptContact(record, trustedSignPub) {
  if (!(await verify(record, record.key))) return { ok: false, why: "bad signature" };

  if (trustedSignPub && record.key !== trustedSignPub) {
    const r = record.rotation;
    if (!r) return { ok: false, why: "different key" };
    if (r.from !== trustedSignPub || r.to !== record.key) return { ok: false, why: "rotation does not match" };
    if (!(await verify(r, trustedSignPub))) return { ok: false, why: "rotation not signed by the old key" };
    return { ok: true, hook: record.hook, key: record.key, box: record.box, rotated: true };
  }

  return { ok: true, hook: record.hook, key: record.key, box: record.box };
}

/* ---------- certifying a conversation key ---------- */

export const certify = (conversation, account) =>
  sign({ conversation_key: conversation.signPub, conversation_box: conversation.boxPub, account_key: account.signPub }, account.sign);

export async function checkCertificate(cert, expectedAccountKey) {
  if (expectedAccountKey && cert.account_key !== expectedAccountKey) return false;
  return verify(cert, cert.account_key);
}

/* ---------- sealing ---------- */

const WRAP_INFO = enc.encode("posts/v1/wrap");

async function wrapKey(messageKeyRaw, ephPriv, recipientBoxPubB64, ephPubB64) {
  const bits = await S.deriveBits(
    { name: "X25519", public: await importBoxPub(recipientBoxPubB64) },
    ephPriv,
    256
  );
  const hk = await S.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
  const kek = await S.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: ub64(ephPubB64), info: WRAP_INFO },
    hk,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  const iv = rand(12);
  const wrapped = await S.encrypt({ name: "AES-GCM", iv }, kek, messageKeyRaw);
  return { key: recipientBoxPubB64, wrapped: b64(wrapped), wrap_iv: b64(iv) };
}

/**
 * Encrypt for one or more recipients and sign with the conversation key.
 *
 * A fresh X25519 pair per message means the sender's long-term key never
 * touches the wrap, so a later compromise of it does not open past messages.
 */
export async function seal(plaintext, recipientBoxPubs, conversation, extra = {}) {
  const mk = await S.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const mkRaw = await S.exportKey("raw", mk);
  const iv = rand(12);
  const ct = await S.encrypt({ name: "AES-GCM", iv }, mk, enc.encode(JSON.stringify(plaintext)));

  const eph = await genBox();
  const ephPub = await rawPub(eph.publicKey);
  const to = [];
  for (const pub of [].concat(recipientBoxPubs)) to.push(await wrapKey(mkRaw, eph.privateKey, pub, ephPub));

  return sign(
    {
      version: "1.0",
      type: "encrypted_item",
      created: new Date().toISOString(),
      from_key: conversation.signPub,
      from_box: conversation.boxPub,
      eph: ephPub,
      to,
      cipher: { algorithm: "AES-256-GCM", nonce: b64(iv), ciphertext: b64(ct) },
      ...extra,
    },
    conversation.sign
  );
}

/**
 * Verify then decrypt. A bad signature is never decrypted.
 * `envelope.from_box` is the key to seal the reply to — it is covered by the
 * signature, so a substituted one fails before any plaintext exists.
 */
export async function open(envelope, myKeys, expectedFromKey) {
  if (expectedFromKey && envelope.from_key !== expectedFromKey) throw new Error("unexpected sender key");
  if (!(await verify(envelope, envelope.from_key))) throw new Error("bad signature");

  const mine = envelope.to.find((t) => t.key === myKeys.boxPub);
  if (!mine) throw new Error("not a recipient");

  const bits = await S.deriveBits({ name: "X25519", public: await importBoxPub(envelope.eph) }, myKeys.box, 256);
  const hk = await S.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
  const kek = await S.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: ub64(envelope.eph), info: WRAP_INFO },
    hk,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  const mkRaw = await S.decrypt({ name: "AES-GCM", iv: ub64(mine.wrap_iv) }, kek, ub64(mine.wrapped));
  const mk = await S.importKey("raw", mkRaw, "AES-GCM", false, ["decrypt"]);
  const pt = await S.decrypt({ name: "AES-GCM", iv: ub64(envelope.cipher.nonce) }, mk, ub64(envelope.cipher.ciphertext));
  return JSON.parse(dec.decode(pt));
}

/* ---------- attachments ---------- */

/** Attachments get their own key, so one can be shared without the message. */
export async function sealBytes(bytes) {
  const k = await S.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const iv = rand(12);
  const ct = await S.encrypt({ name: "AES-GCM", iv }, k, bytes);
  const digest = await S.digest("SHA-256", ct);
  return {
    bytes: new Uint8Array(ct),
    meta: { encrypted: true, nonce: b64(iv), sha256: b64(digest), size: bytes.byteLength, file_key: b64(await S.exportKey("raw", k)) },
  };
}

export async function openBytes(ct, meta) {
  const got = b64(await S.digest("SHA-256", ct));
  if (got !== meta.sha256) throw new Error("hash mismatch");
  const k = await S.importKey("raw", ub64(meta.file_key), "AES-GCM", false, ["decrypt"]);
  return new Uint8Array(await S.decrypt({ name: "AES-GCM", iv: ub64(meta.nonce) }, k, ct));
}

/* ---------- first contact and hook grants ---------- */

export const firstContact = (plaintext, theirBox, conversation, replyHook) =>
  seal(plaintext, theirBox, conversation, { type: "first_contact", reply_hook: replyHook });

/**
 * Signed by the conversation key — otherwise anyone able to intercept the
 * reply substitutes their own hook and becomes the recipient.
 */
export const grantHook = (hookUrl, conversationId, conversation) =>
  sign({ type: "hook_granted", hook: hookUrl, conversation: conversationId, expires: null, granted_by: conversation.signPub }, conversation.sign);

export async function acceptGrant(grant, expectedConvKey) {
  if (grant.granted_by !== expectedConvKey) return null;
  return (await verify(grant, grant.granted_by)) ? grant.hook : null;
}

/* ---------- encrypted backup ---------- */

const PBKDF2_ITER = 600000;

async function kdf(passphrase, salt) {
  const base = await S.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return S.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITER, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/** Private keys leave the device only wrapped under the user's passphrase. */
export async function backup(keys, passphrase) {
  const bundle = {
    v: 1,
    sign: await S.exportKey("jwk", keys.sign),
    box: await S.exportKey("jwk", keys.box),
    signPub: keys.signPub,
    boxPub: keys.boxPub,
  };
  const salt = rand(16), iv = rand(12);
  const ct = await S.encrypt({ name: "AES-GCM", iv }, await kdf(passphrase, salt), enc.encode(JSON.stringify(bundle)));
  return { v: 1, kdf: "PBKDF2-SHA256", iterations: PBKDF2_ITER, salt: b64(salt), nonce: b64(iv), data: b64(ct) };
}

export async function restore(blob, passphrase) {
  const pt = await S.decrypt(
    { name: "AES-GCM", iv: ub64(blob.nonce) },
    await kdf(passphrase, ub64(blob.salt)),
    ub64(blob.data)
  );
  const b = JSON.parse(dec.decode(pt));
  return {
    sign: await S.importKey("jwk", b.sign, "Ed25519", true, ["sign"]),
    box: await S.importKey("jwk", b.box, "X25519", true, ["deriveBits"]),
    signPub: b.signPub,
    boxPub: b.boxPub,
  };
}

/** Does this engine have everything Posts needs? */
export async function supported() {
  try {
    await genSign();
    await genBox();
    return true;
  } catch {
    return false;
  }
}
