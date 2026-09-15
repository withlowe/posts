# Posts

A reader where everything is a feed, and some feeds are private.

Subscribe to public feeds and read them. Give every sender its own **hook** — three random words — and delete it when you're done. One Worker on your own Cloudflare account.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/withlowe/posts)

```text
posts.example/                         nothing. accepts nothing, reveals nothing.
posts.example/c                        a contact page. readable by anyone. accepts nothing.
posts.example/h/river-lamp-copper      a hook. the only thing that accepts.
```

## How it works

A **hook** is one sender's way in: three words from a 7,776-word list, which is 38.8 bits — past guessing when unknown paths are throttled. Give it to a person, a webhook, a newsletter signup. Delete it and that sender is stopped for good; every other hook is untouched.

A **feed** is where items land and how you read them — here, or in any RSS reader. Every hook delivers to a feed, and so does every public feed you subscribe to. That's the whole model: subscribing and being written to are two ways of filling the same container.

Your **public hook** sits on your contact page and carries first contact only. When you reply you mint that person a private hook, and the conversation leaves the public one. So rotating the public hook never disturbs a live conversation.

Rotation has a tail. A retired hook still accepts for ninety days but flags arrivals as `old-hook`, so someone working from an archived copy still gets through while a flood can be cut off immediately.

**This Worker never holds a private key and never signs anything.** `contact.json` is produced and signed in the browser and stored here as an opaque blob. A client accepts a replacement hook only if the record is signed by the key it already trusts — so a compromised host can deny service, but cannot redirect your mail to itself.

## Files

```text
posts/
├── worker.js        the relay and the app shell
├── app.js           the client — sidebar, reading, filtering, composing
├── crypto.js        keys, signing, sealing
├── *-src.js         generated: the browser files as strings, so the Worker
│                    can serve them without ever running them
├── words.js         the EFF large wordlist (7,776 words, CC BY 3.0)
├── schema.sql       the database, applied at deploy time
├── wrangler.toml    bindings and cron
├── package.json     deploy and test scripts
├── .gitignore       keeps node_modules out of the repository
├── tools/bundle.mjs regenerates crypto-src.js
├── test.mjs         the relay
├── test-crypto.mjs  the cryptography
├── test-e2e.mjs     two instances, two hosts, the whole flow
├── test-browser.mjs the client, in real Chromium
└── test-stub.mjs    in-memory KV and D1
```

`npm test` runs all four — 241 checks, none of which need a Cloudflare account.

`wrangler` is the only dependency, because Cloudflare's builder installs from `package.json` and then runs the deploy script. Playwright is deliberately **not** one — a deploy would download a browser every time. Add it when you want the browser suite:

```
npm i playwright --no-save && npx playwright install chromium
```

Without it that suite skips itself and the other three still run. The browser suite skips itself where Playwright or Chromium is missing.

`app.js` and `crypto.js` are plain files served to the browser, never imported by the Worker. `tools/bundle.mjs` turns them into strings for it to serve; `npm run deploy` does that first.

## Setup

Two routes to the same result. The button is quicker and needs nothing installed; the command line gives you a local copy to work on.

### Before you start

- A Cloudflare account. The free plan is enough.
- For the button: a GitHub or GitLab account.
- For the command line: Node 18 or newer.

### Route A — the deploy button

**A1. Put the files in a Git repository.** Create one on GitHub or GitLab and add every file above at the top level. If you use GitHub's web uploader, drag them in together and check the list afterwards — a deploy fails if `schema.sql` didn't make it.

**A2. Point the button at your copy.** In this README, change `YOUR-USERNAME` in the button link to your account:

```
[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/YOUR-USERNAME/posts)
```

The link is just `https://deploy.workers.cloudflare.com/?url=` followed by your repository URL, so it works pasted into a browser too.

**A3. Press it.** Cloudflare asks you to connect your Git account, copies the repository to your account, reads `wrangler.toml` and creates the KV namespace and D1 database, writes the real ids into the copy, runs the deploy script from `package.json` — which bundles the browser files, applies `schema.sql`, then deploys — and sets up builds so every later push deploys automatically. It ends on your worker's URL.

If Cloudflare names the copied repository something else — `posts` taken means you might get `posts-1` — that is fine. The worker takes the same name, and your button link should point at the new repository from then on.

**A4. One setting.** Workers & Pages → your worker → Settings → **Observability → Logs** → off, and leave Logpush off. Hook and feed URLs contain keys, and logs would capture them.

Then skip to **Check it works**. If the deploy fails, the build log is under the worker's Deployments tab; the usual causes are a file missing from the repository and an edited deploy script.

### Route B — the command line

**B1. Install wrangler and sign in.**

```
npm install -g wrangler
wrangler login
```

**B2. Put the files in a folder and check they run.**

```
mkdir posts && cd posts
# copy the files here
npm test          # needs nothing from Cloudflare
```

**B3. Create the KV namespace.** It holds configuration only: the account, hooks, feeds, rules, sources.

```
wrangler kv namespace create POSTS
```

Copy the id into `wrangler.toml` over the placeholder. Leave the binding as `POSTS` — the code looks for `env.POSTS`.

**B4. Create the D1 database.** It holds items and encrypted attachment bytes, one row each.

```
wrangler d1 create posts
```

Copy `database_id` into `wrangler.toml`. Leave the binding as `DB`.

**B5. Deploy.**

```
npm run deploy
```

That bundles the browser files, applies `schema.sql` with `--remote`, then deploys. `--remote` matters: without it the tables go into a local file and the deployed Worker has an empty database.

Confirm the tables exist:

```
wrangler d1 execute DB --remote --command "SELECT name FROM sqlite_master WHERE type='table'"
```

You should see `items` and `blobs`.

Then do **A4** — turn the logs off.

## Check it works

Open the site. It registers the first account, shows an owner secret once — **save it** — and gives you your public hook.

```
curl -X POST "https://posts.you.workers.dev/h/YOUR-THREE-WORDS" -d "hello from curl"
```

Reload and open the **New** feed. It's there.

Then:

1. Mint a hook labelled `CI alerts`; post to it; watch it land in its own feed.
2. Delete that hook. Post again — `410 Gone`, permanently.
3. Subscribe to a public feed URL and let the cron poll it.
4. Retire the public hook. It mints a replacement, and the old one still accepts but flags arrivals as `old-hook`.

## Publishing a contact page

`PUT /api/contact` with a signed record, then `posts.example/c` renders it and `posts.example/c/contact.json` serves it verbatim:

```json
{
  "hook": "https://posts.example/h/river-lamp-copper",
  "key": "ed25519-public-key",
  "fingerprint": "A1C4 7B92 0D11 8F35",
  "issued": "2026-09-15T00:00:00Z",
  "signature": "..."
}
```

Clients read the page, verify the signature against the key they already hold, and cache the hook. When a hook dies they re-read the page and carry on — so rotation costs the sender nothing and needs no announcement.

## API

```text
POST   /h/{three-words}          accept an item. 410 if unknown, dead, or wrong method.
GET    /c                        contact page
GET    /c/contact.json           the signed record, verbatim
GET    /f/{feed}.json?key=       read a feed
GET    /f/{feed}/rss?key=        the same, as RSS 2.0
GET    /p/{slug}.json            your published feed — no key, anyone
GET    /p/{slug}/rss             the same, as RSS 2.0
GET    /b/{id}                   encrypted attachment bytes — no key, anyone

POST   /api/register             first call claims the deployment
GET    /api/state                hooks, feeds, sources, counts
POST   /api/hooks                mint  {label, words: 3|4|5}
POST   /api/hooks/{h}/retire     begin the tail; mints a replacement for a public hook
DELETE /api/hooks/{h}            kill now. permanent.
PUT    /api/contact              publish the signed record
POST   /api/conversations        reply to a stranger: mints them a private hook
POST   /api/publish              your own public feed  {slug, title, subject, text}
POST   /api/hooks/{h}/rules      set a hook's rules, in order
POST   /api/feeds/{f}/arrive     {arrive: "each" | "daily"}
POST   /api/digest               write the daily digests now
GET    /api/items?feed=*         everything, newest first — what All reads
POST   /api/blobs                upload encrypted attachment bytes
POST   /api/sources              subscribe  {url, title}
POST   /api/poll                 poll subscribed feeds now
GET    /api/items?feed=          read items
```

Everything under `/api` needs `Authorization: Bearer <owner secret>`.

## If something goes wrong

**`No such file or directory: schema.sql`** in the build log — the file didn't make it into the repository. Add it at the top level and push; the push starts a new build.

**`D1_ERROR: no such table: items`** — the schema didn't run, or ran without `--remote`. Run `wrangler d1 execute DB --remote --file=schema.sql`.

**No sign-up on a fresh deployment, or "Already claimed"** — a configuration record is already in KV, so an account was made at some point. If you reused a namespace from an earlier instance, that is where it came from: create a new namespace, or paste the original owner secret.

**The page loads but nothing appears in the sidebar** — the browser script threw. Open the console. `npm test` runs that script in real Chromium and would normally catch it before a deploy.

**`sh: 1: wrangler: not found`** in the build log — `wrangler` is missing from `devDependencies`. The builder installs only what `package.json` asks for, and a globally installed wrangler on your own machine is not there. Check the `devDependencies` block is intact and push again.

**`reached the Workers Free limit of 5 cron triggers`** — the worker itself deployed; only the schedule didn't register. The limit is per account, so old workers you have stopped using are still holding theirs. Delete them under Workers & Pages, then retry.

**Attachments refused with 413** — there is no R2 bucket bound, so they fall back to D1 at 256 KB of ciphertext. Uncomment the `[[r2_buckets]]` block in `wrangler.toml`, create the bucket, and deploy again.

**`Unknown or deleted hook`, or a `410` you did not expect** — the hook was deleted or its retirement tail ran out. Deleted hooks are tombstoned and refuse forever; that is deliberate.

## Notes

- **Deletion is a tombstone, not a removal.** A dead hook's words are never minted again, and a miss looks the same as a deletion — neither reveals whether a hook ever existed.
- **Rate limits are per isolate and best effort**, like the unknown-path throttle. Move them to a Durable Object if you need exact numbers. Ten per second per IP on unknown paths is the primary defence: it turns five days of guessing into a year and a half at 500 live hooks.
- **Three words is right for personal use.** Past a few hundred hooks, mint with `words: 4` — a word is worth 12.9 bits, a digit only 3.3.
- **Caps** live in `LIMITS` at the top of `worker.js`: 500 hooks, 128 KB per item, 10,000 items a day.
- **A hook accepts anything.** A Posts client sends a signed encrypted envelope; a CI webhook sends whatever it sends. Both are items in a feed, and encrypted ones are stored opaque and never rendered in RSS.
- **Feeds are cached 45 s** at the edge. Cache invalidation clears the local datacentre only; the TTL is what keeps them correct.
- The wordlist is the [EFF large wordlist](https://www.eff.org/dice), © Electronic Frontier Foundation, CC BY 3.0.

## Encryption

All of it is native WebCrypto — Ed25519, X25519, AES-256-GCM, HKDF-SHA256 — so there is no library bundled and nothing implemented by hand. Those curves ship in the stable releases of all three major engines; a browser without them is told so rather than silently falling back.

The build plan prefers XChaCha20-Poly1305. WebCrypto doesn't offer it, and bundling a library to get it would be a worse trade than using the engine's own audited AES-GCM, which the plan lists as the alternative.

**Keys are generated in the browser and stay in IndexedDB.** The Worker never sees a private key, never signs, and cannot: `contact.json` arrives already signed and is stored and served as an opaque blob. That is what makes rotation safe — a client accepts a replacement hook only when the record is signed by the key it already trusts, so a compromised host can deny service but cannot redirect your mail to itself.

Each message gets a fresh AES-256-GCM key, wrapped for the recipient through an **ephemeral** X25519 agreement, so the sender's long-term key never touches the wrap and a later compromise of it does not open past messages. Envelopes are signed with a per-message conversation key, not the account key, so two recipients cannot prove they share a correspondent. Signatures are verified *before* anything is decrypted.

Attachments get their own key and carry a SHA-256 of the ciphertext; a corrupted or swapped file is refused rather than decrypted.

`backup(keys, passphrase)` wraps private keys under PBKDF2-SHA256 at 600,000 iterations. Nothing else ever leaves the device.

## Conversations

A stranger's first message arrives on your public hook and lands in **New**, carrying their reply hook and their agreement key in the clear — everything else is sealed.

Reply, and the client mints them a hook of their own, sends it back as a signed `hook_granted`, and the thread moves to its own feed. It never touches the public hook again, which is what makes rotating the public hook free: no live conversation is disturbed.

Each thread runs on its own conversation keys, certified by your account key. Two correspondents cannot tell they share you, and your account key signs nothing but the certificate and your contact record.

## Healing

Every send goes through one place. On `410` the client re-reads the sender's contact page, accepts the new hook **only if the record is still signed by the key it already trusts**, and retries once. A rotation on the far end is invisible; a hijacked page is refused rather than followed.

`test-e2e.mjs` walks the whole of this across two instances: contact page, first contact, the grant, the thread moving, a rotation healing itself, and a deleted hook staying dead while everyone else carries on.

## Attachments

A file is encrypted in the browser with its own key, and only the ciphertext is uploaded. The file key travels inside the sealed message, so the bytes can be served to anyone without being useful to them — which is what lets a recipient fetch an attachment straight from the sender's host with no credentials.

Every attachment carries a SHA-256 of its ciphertext. A host that swaps the bytes is caught before anything is decrypted.

Bind an R2 bucket as `MEDIA` for real file sizes. Without one, attachments fall back to D1 and are capped at 256 KB of ciphertext.

## Publishing

`POST /api/publish` with a slug gives you a public feed at `/p/{slug}.json` and `/p/{slug}/rss` — no key, readable by anyone, cached at the edge, and linked from your contact page.

That is safe for exactly the reason a hook isn't: a feed is **pull**. Subscribers fetch it on their own schedule and can push nothing back, so a guessable name costs nothing. Feeds answer `GET` and nothing else.

## The filter

The bar under the timeline filters what you are looking at. Type and the items narrow, matches highlight, and the sidebar hides sources whose names do not match. Several words mean all of them must match; Escape clears.

**All**, at the top of the sidebar, is every feed newest-first — so the filter searches across sources, not just the one you have open.

It works on text that is already decrypted, in memory, on your device. Nothing is sent anywhere and no model is involved — which is the only way a filter over private feeds can work without breaking the promise the rest of the design makes.

## Managing a hook

Hover a private source and the ⋯ opens everything that hook can do:

- **The URL**, to copy and hand over.
- **Arrives** — item by item, or once a day.
- **Rules** — built from two dropdowns, no syntax: *if subject contains "invoice", then ignore it*. Read top to bottom, first match wins, so exactly one ever applies. A rule can move an item to another feed, tag it, mark it important, or ignore it.
- **Retire** for ninety days, or **Rotate** if it is your public hook — which mints the replacement and republishes your contact page in one step.
- **Delete permanently.** This is the button the whole design is for. Anything sent afterwards is refused for good, the words are never minted again, and no other hook is touched.

"Put these in the digest" is just "send them to a feed that arrives daily" — queued items are held back until the cron writes one summary, then released alongside it.

## Keys, backup and rotation

Settings, in the sidebar footer, is where the account actually lives.

**Back up** wraps your private keys under a passphrase (PBKDF2-SHA256, 600,000 iterations) before anything leaves the device, and downloads the result. Lose the keys with no backup and the account is gone — nothing on any server can bring it back, by design.

**Rotate** publishes a new key in a record signed by the new key, carrying a rotation attested by the old one. A contact who already trusts the old key follows it automatically; anyone who does not have it sees only the new key; and an attacker cannot claim your contacts, because they cannot produce the old key's signature. Messages signed before the rotation still verify.

A client checking for a rotation must fetch `contact.json` with `cache: "no-store"` — it is deliberately cached for five minutes, and a stale copy will look like no rotation happened.

## What isn't built yet

- **Multiple devices.** Backup and restore move an account between devices, but there is no device-key hierarchy and no sync — two devices are two copies.
- **Forward secrecy per message** (phase 8). Each message already uses an ephemeral agreement key, but there is no ratchet.

A plain webhook — CI, a monitor, a form — cannot encrypt, so what it posts is stored as plaintext by design. Encryption covers Posts-to-Posts messages.
