# Cawala - web app

Svelte 5 + Vite static PWA. The wasm-bindgen client (`cawala-client`) spawns an
iroh endpoint in the browser and talks to Rust nodes over the N0 public relay
(browsers cannot dial UDP directly). The browser is a **user leaf**: it holds an
Ed25519 operator identity and a user-level secp256k1 (Ethereum) identity, but
never a node operator or ledger key.

Project-wide context lives in the root `README.md`, `PLAN.md` (living design +
roadmap), `PLAN-ARCHIVE.md` (delivered history), and `HANDOFF.md` (current
state). This file covers only how to build and run the web app.

## Modes

- **Live (default)** - joins a leaf via a `cawala://join?...` invite over
  `cawala/control/0`, then sends payments and reads a cryptographically verified
  balance. Join, same-leaf and cross-leaf payments, identity portability, exit,
  and administration are live.
- **Mock (`?mock`)** - the full synthetic UI, used for development/review and as
  the automatic fallback when wasm init fails.

A second tab in the same profile runs in mock by design (the identity lock is
held by the first tab).

Live mode also adapts to the origin: on a secure origin (`https` or `localhost`)
passkey unlock is offered; on `file://` the passkey panel is **hidden** (passkeys
need a real secure origin - `file://` is "potentially trustworthy" but has no
WebAuthn origin), the service worker is skipped, and unlock is **mnemonic only**.
This is the degraded `file://` distribution build (see below).

## Prerequisites

- Node.js (v24 used) and npm; run `npm install` from `web/`.
- Rust wasm target: `rustup target add wasm32-unknown-unknown`
- wasm-bindgen CLI pinned to the crate's version:
  `cargo install wasm-bindgen-cli --version 0.2.122`
- A C compiler (`clang`) on PATH - the `ring` crate needs it for
  `wasm32-unknown-unknown`. On Ubuntu: `sudo apt install clang`.

## Build and run

```sh
cd web
npm run dev              # builds debug wasm glue, then starts Vite
npm run build            # release wasm + vite build + stamp sw.js -> web/dist/
npm run build:singlefile # release wasm + single self-contained dist-single/index.html
npm run preview          # serve the production build
npm test                 # node test runner over web/test/*.test.mjs
```

`npm run build:wasm` runs `cargo build --target wasm32-unknown-unknown -p
cawala-client` (artifacts in `web/.cargo-target`) and `wasm-bindgen` (output to
`web/src/wasm/`). `web/src/wasm/` is generated and gitignored: **rebuild it
after any `crates/client-wasm` change**, or the JS/wasm arity can desync.
`npm run build` and `npm run build:singlefile` use the **release** profile
(`build:wasm:release`; ~6 MB vs ~24 MB debug).

`npm run build:singlefile` writes **one** `dist-single/index.html` with all
JS/CSS inlined and the wasm embedded as base64, initialized from **bytes** (no
`file://` fetch). It then runs `scripts/check-singlefile.mjs` to assert
self-containment (no external `src=`/`href=`, no dynamic-import chunks). This is
the artifact for `file://`/zip/email. **Do not serve it under a host CSP without
`script-src 'unsafe-inline'`** - the file's meta CSP and the host header CSP
intersect and blank the inline bundle (see `../DEPLOYMENT.md`).

The build uses `base: './'` so `web/dist/` deploys as-is under the GitHub Pages
subpath `/cawala/`.

## Deploying and security headers

GitHub Pages is fine for demos but cannot set response headers and restricts
commercial/financial use. See `../DEPLOYMENT.md` for the full strategy
(no-SPOF topology, self-hosting, mirrors, verification). Quick version:

- Header config is **per host, one source of truth**: `web/public/_headers`
  (Cloudflare Pages), `web/netlify.toml` `[[headers]]` (Netlify; the build drops
  `dist/_headers` because Netlify is first-match), `web/vercel.json` (Vercel),
  and nginx/Caddy snippets in `DEPLOYMENT.md`. Adjust `connect-src` if you
  self-host an iroh-relay.
- The service worker is versioned per deploy: `web/scripts/stamp-sw.mjs`
  (run by `npm run build`) replaces the `__BUILD_ID__` placeholder in
  `dist/sw.js` with `GITHUB_SHA` (or a fallback), so a new deploy installs a new
  worker and purges the old cache. Navigation is network-first; hashed
  `/assets/*` are cache-first.
- Each `v*` release attaches a checksummed, provenance-attested
  `cawala-web-<tag>.tar.gz` so third parties can verify and self-host.

## Routes and navigation

Hash routes (`web/src/lib/constants.js`):

| Nav | Route | Notes |
| --- | --- | --- |
| Home | `#/` | Dashboard; My Account is reached from here |
| Join | `#/join` | only while this browser is unjoined |
| Accounts | `#/accounts` | balances / accounting |
| Activity | `#/activity` | transfer and settlement history |
| Settings | `#/settings` | identity create/restore + transport export/import |
| Admin | `#/admin` | locked by default (below) |

My Account (`#/account`) is not a tab.

## Admin

Administration is by **explicit designation**: a node lists the children (node
or browser) allowed to administer it. A browser's reach is the strict ancestor
chain from its own leaf, hop by hop; it has no automatic authority.

- The **Admin** page is **locked by default**. Unlocking shows and requires
  acknowledgement of `ADMIN_POLICY.md` (at the repo root); the acknowledgement
  is stored by document hash, so editing the policy invalidates it. The unlocked
  flag is in-memory only - a reload returns to the lock gate.
- The **AdminTargetSwitcher** moves the administered node **up/down the ancestor
  chain** (no dropdown/selector).
- Admin surfaces: designated administrators (designate/revoke), pending-join
  approve/reject/resend, topology (re-slot/detach a child node), and value
  issue/burn (issue is uncapped; burn is limited by the account balance). The
  action is authorized by the designation set; there is no operator-side value
  policy. Creating a child is not a live web action - children appear by
  approving a join request, or from the node CLI.
- All admin requests are **tree-routed**; the direct `cawala/control/0` link is
  used only for the browser's own leaf (join handshake, payments).

## Identity

The user identity (R3) is a secp256k1 Ethereum account derived from a 12-word
BIP-39 recovery phrase (`m/44'/60'/0'/0/0`; EIP-55 address). Derivation runs the
**real wasm** engine (`UserIdentity.fromMnemonic`), injected by `api.js` after
wasm init; the UI under `components/identity/` never imports wasm itself.

**Settings -> Your Account Identity** lets you **create** a new phrase (back it
up + confirm) or **restore** an existing one (with an address preview). Because
the same phrase also derives the browser's Ed25519 transport key (its iroh
NodeId), **one phrase restores both the account and the transport identity on any
host**. The derived secrets are persisted on-device - the transport seed in
`cawala.identity.v1`, the ETH secret in `cawala.user-identity.v1` (both
authoritative-local) - so a reload needs no unlock; the **phrase itself is never
stored**.

The **passkey panel** (WebAuthn unlock) is shown only on a **secure origin**
(`https`/`localhost`). On `file://` it is **hidden**, because `file://` has no
WebAuthn origin, and the phrase is the only unlock path. The WebAuthn PRF
key-wrap backend is still deferred (`PASSKEY_BACKEND_READY = false`), so passkey
actions report honestly as unavailable; a passkey is an **unlock factor, never a
signer** (P-256 ≠ secp256k1).

**Settings -> Identity Portability** separately exports/imports the legacy
passphrase-encrypted `IdentityBundleV1` (PBKDF2-SHA-256 600k + AES-256-GCM)
carrying the 32-byte transport seed plus the secret-free join/ledger state - use
it to move an existing install's transport seed. The mnemonic remains the
portable account credential. Concurrent use of one identity on two devices is
**not** prevented; run one device at a time.

## Smoke scripts (network-dependent)

`web/scripts/` drives the wasm module (or a browser-equivalent client) against
live nodes. They print `SKIP:` and exit 0 when the N0 relay/pkarr path is
genuinely unreachable; set `SMOKE_*_REQUIRE_NETWORK=1` to hard-fail instead.

```sh
cd web
node scripts/smoke.mjs            # spawn-only wasm endpoint
node scripts/smoke-tabs.mjs       # tab-to-tab ping
node scripts/smoke-join.mjs       # join + reject
node scripts/smoke-payment.mjs    # same-leaf payment
node scripts/smoke-crossleaf.mjs  # LCA cross-leaf settlement
node scripts/smoke-admin.mjs      # tree-routed admin (query/approve/designate/revoke)
```

## Layout

```
web/
├── index.html               # app shell, links manifest
├── vite.config.js           # base './', svelte plugin
├── vite.config.singlefile.js# self-contained dist-single/index.html build
├── scripts/build-wasm.mjs   # cargo + wasm-bindgen (cwd-robust; --release)
├── scripts/check-singlefile.mjs  # self-containment assertions
├── scripts/stamp-sw.mjs     # per-deploy sw.js versioning
├── public/                  # manifest.webmanifest, sw.js, _headers
├── test/                    # *.test.mjs (node test runner)
└── src/
    ├── main.js              # entry; registers SW in prod (skipped on file://)
    ├── App.svelte           # hash router + layout
    ├── components/          # account, accounts, activity, admin, dashboard,
    │                        # identity, join-flow, layout, settings, shared
    ├── lib/                 # api.js, storage.js, userIdentity.js, bip39.js,
    │                        # stores, router, adminPolicy, wasm/
    └── wasm/                # GENERATED by build:wasm (gitignored)
```
