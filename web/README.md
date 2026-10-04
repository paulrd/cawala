# Cawala - web app

Svelte 5 + Vite static PWA. The wasm-bindgen client (`cawala-client`) spawns an
iroh endpoint in the browser and talks to Rust nodes over the N0 public relay
(browsers cannot dial UDP directly). The browser is a **user leaf**: it holds an
Ed25519 operator identity but never a node operator or ledger key.

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
npm run dev        # builds the wasm glue, then starts Vite
npm run build      # build:wasm + vite build -> web/dist/
npm run preview    # serve the production build
npm test           # node test runner over web/test/*.test.mjs
```

`npm run build:wasm` runs `cargo build --target wasm32-unknown-unknown -p
cawala-client` (artifacts in `web/.cargo-target`) and `wasm-bindgen` (output to
`web/src/wasm/`). `web/src/wasm/` is generated and gitignored: **rebuild it
after any `crates/client-wasm` change**, or the JS/wasm arity can desync.

The build uses `base: './'` so `web/dist/` deploys as-is under the GitHub Pages
subpath `/cawala/`.

## Routes and navigation

Hash routes (`web/src/lib/constants.js`):

| Nav | Route | Notes |
| --- | --- | --- |
| Home | `#/` | Dashboard; My Account is reached from here |
| Join | `#/join` | only while this browser is unjoined |
| Accounts | `#/accounts` | balances / accounting |
| Activity | `#/activity` | transfer and settlement history |
| Settings | `#/settings` | identity export/import |
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

## Identity portability

**Settings -> Identity** exports/imports a passphrase-encrypted
`IdentityBundleV1` (PBKDF2-SHA-256 600k + AES-256-GCM) carrying the 32-byte seed
plus the secret-free join/ledger state. The seed is both the iroh endpoint id and
the account's operator key, so exporting/importing moves the account. Concurrent
use of one identity on two devices is **not** prevented; run one device at a
time. Lost-seed recovery is not available in v1.

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
├── scripts/build-wasm.mjs   # cargo + wasm-bindgen (cwd-robust)
├── public/                  # manifest.webmanifest, sw.js
├── test/                    # *.test.mjs (node test runner)
└── src/
    ├── main.js              # entry; registers SW in prod
    ├── App.svelte           # hash router + layout
    ├── components/          # account, accounts, activity, admin, dashboard,
    │                        # join-flow, layout, settings, shared
    ├── lib/                 # api.js, stores, router, adminPolicy, ...
    └── wasm/                # GENERATED by build:wasm (gitignored)
```
