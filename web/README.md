# Cawala — web app

Svelte 5 + Vite static app. The wasm-bindgen client (`cawala-client`) spawns an
iroh endpoint in the browser and talks to Rust nodes over the N0 public relay
(browsers cannot dial UDP directly, so connections go through the relay).

Two modes:

- **Live (default)** — a *user leaf*: the client uses a stable Ed25519 identity
  persisted in browser storage, parses a `cawala://join?...` invite, performs
  the join handshake over `cawala/control/0`, and shows the locally assigned
  address/topology. Live support is intentionally limited (see *Live mode
  limits*).
- **Mock (`?mock`)** — the full synthetic UI, used for development/review and
  as the automatic fallback when wasm init fails.

## Prerequisites

- Node.js (v24 used) and npm
- Rust with the wasm target:
  `rustup target add wasm32-unknown-unknown`
- wasm-bindgen CLI pinned to the version the crate was built against:
  `cargo install wasm-bindgen-cli --version 0.2.122`
- A C compiler (`clang`) on PATH — the `ring` crate needs it when compiled
  for `wasm32-unknown-unknown`. On Ubuntu: `sudo apt install clang`.
  (CI's `ubuntu-latest` already has it.)
- npm dependencies:
  `npm install` (run from `web/`)

## Run

```sh
cd web
npm run dev
```

`npm run dev` first builds the wasm glue (`npm run build:wasm`), which runs
`cargo build --target wasm32-unknown-unknown -p cawala-client` (workspace
root, artifacts in `web/.cargo-target`) and `wasm-bindgen` (output to
`web/src/wasm/`), then starts the Vite dev server.

In another terminal, from the repo root, run a Rust node to get a peer:

```sh
cargo run -p cawala-node
```

## Live user join (manual)

1. Start a node and give it an asserted address:
   `cawala-node topo set-address 0`.
2. Generate an invite: `cawala-node control invite` (optionally with
   `--relay`/`--ip` transport hints).
3. `npm run dev`, open the app, go to **Join**, paste the invite, and Connect.
4. On the node: `cawala-node control joins` to list the request, then
   `cawala-node control approve <browser-endpoint-id>` (or `reject`).
5. The browser polls its persisted state and flips to *joined* with the assigned
   address. Reloading mid-wait keeps the pending state.

### Live mode limits

The join handshake, Rust invite parsing, stable identity, ping, the local
topology snapshot, and same-leaf value messaging (send a payment; read a
cryptographically verified balance and outbound activity) are live. **Not
available in the web client:** approving or rejecting joins, pending-join
listing, any other admin action, issuing/burning value, and cross-leaf/multi-hop
payments. Funding is an operator act run from the node CLI, never the browser.
Only *outbound* activity is enumerable in v1 (the receipt history lists the
transfers touching this account; funding is not represented as activity). The
browser is a user leaf — it is never a node admin and never holds a ledger key
(it signs orders with its own operator key).

## Sending value (live)

Users of the same leaf can pay each other. The browser signs a `PaymentOrder`
with its operator key; the leaf verifies and appends the transfer and replies
with a signed balance receipt that the browser checks against the leaf's ledger
key (trust-on-first-use pinned).

1. Join the leaf and have the operator approve you (see above). Approval opens
   your ledger account.
2. The operator funds you — an explicit CLI act, run from the repo root against
   the live node's data dir:
   `cargo run -p cawala-node -- --data-dir <node-data> ledger fund --to <your-endpoint-id> --amount 100`
   Each run issues value again; there is no browser-side issue path.
3. In the app, open **My Account → Send payment**, enter the recipient's
   endpoint id and an amount, and send. The recipient must also be a user of the
   same leaf (same-leaf `Direct` only in v1).
4. The verified **balance** and **activity** update once the leaf's receipt
   verifies. Only outbound activity is enumerable in v1 (the receipt history
   lists your transfers); cross-leaf/multi-hop payments are not implemented.

Approval and funding run as separate `cawala-node` processes while the node is
running. That is safe: the node's ledger service re-reads and replays the log
before every mutation and authoritative read, so external appends are picked up
without a restart.

## Identity portability (move to another device)

A browser user's identity is a 32-byte Ed25519 seed stored in this origin's
`localStorage`. It is both the iroh endpoint id and the account's operator key,
so the same seed restores the same address and balance.

**Settings → Identity** provides:

- **Export identity** — encrypts the seed plus the join/ledger state into one
  passphrase-protected file (`cawala-identity-<id>.json`). The passphrase is
  never stored and cannot be recovered; anyone with the file *and* passphrase can
  spend from the account.
- **Import identity** — paste or load a bundle on another device, preview the
  incoming endpoint id, confirm, and reload. This replaces the identity on that
  device.
- **Remove identity** — deletes this device's local identity (export first).

Cross-device note: using the same identity on two devices at the same time is
**not prevented**. Run one device at a time; concurrent use can produce confusing
connection behavior because the relay keeps the most recent connection for an
endpoint id. Recovery from a lost seed is not available in v1.

Within a single browser, opening a second tab keeps the identity lock held by
the first tab, so the second tab runs in mock mode by design.

## Test (manual round-trip checklist)

1. Open the app at the Vite URL (e.g. http://localhost:5173). It should log
   "endpoint spawned" and show **Our EndpointId** with a copy button.
2. Copy the browser's EndpointId and paste it into the node binary to ping the
   browser, **or** copy the node's EndpointId and paste it into the page's
   **target EndpointId** field.
3. Enter a message (the default is fine) and press **Send ping**.
4. Expected log sequence: "connecting to …" → "connected, sent N bytes,
   response received: "<message>" (X ms round-trip)". A rejection logs
   "ping failed after X ms: <error>".

Two-browser tab variant (no Rust node needed): open the app in two tabs, copy
one tab's EndpointId into the other tab's target field, and ping tab-to-tab
over the relay.

### Automated smoke test (Node.js)

Run the same wasm module under Node (n0's tested WASM runtime) against a live
Rust node — no browser needed:

```sh
# terminal 1: start a Rust node (repo root)
cargo run -p cawala-node
# terminal 2: run the smoke test with the node's EndpointId
cd web
node scripts/smoke.mjs <node-EndpointId> "hello from wasm"
# expected: "[smoke] round-trip OK"
```

Spawn-only check (proves the wasm endpoint binds + registers on the relay,
without a peer): `node scripts/smoke.mjs`.

Tab-to-tab equivalent (two wasm endpoints in one process — proves a browser
tab can both answer and initiate pings):

```sh
cd web
node scripts/smoke-tabs.mjs
# expected: "[smoke-tabs] round-trip OK"
```

End-to-end join handshake (browser join -> CLI approve -> joined, plus the
reject path). Network-dependent on the N0 relay/pkarr:

```sh
cd web
node scripts/smoke-join.mjs
# expected: "[smoke-join] ALL CHECKS PASSED"
```

End-to-end same-leaf payment (two browser clients join -> CLI approve -> CLI
`ledger fund` -> A sends 25 -> A sees balance 75, B sees 25). Network-dependent
on the N0 relay/pkarr; prints `SKIP:` and exits 0 only if that path is genuinely
unreachable (set `SMOKE_PAYMENT_REQUIRE_NETWORK=1` to make that a hard failure):

```sh
cd web
node scripts/smoke-payment.mjs
# expected: "[smoke-payment] ALL CHECKS PASSED"
```

### Production build / preview

```sh
npm run build   # build:wasm + vite build
npm run preview
```

The build uses `base: './'` (relative URLs) so `web/dist/` deploys as-is under
the GitHub Pages subpath `/cawala/`.

## Layout

```
web/
├── index.html              # app shell, links manifest
├── vite.config.js          # base './', svelte plugin
├── package.json
├── scripts/build-wasm.mjs  # cargo + wasm-bindgen (cwd-robust)
├── public/
│   ├── manifest.webmanifest
│   └── sw.js               # M0 app-shell service worker
└── src/
    ├── main.js             # entry; registers SW in prod
    ├── App.svelte          # debug harness UI
    ├── app.css
    └── wasm/               # GENERATED by build:wasm (gitignored)
        ├── cawala_client.js
        └── cawala_client_bg.wasm
```
