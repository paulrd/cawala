# Cawala — Manual Web Testing Guide

How to manually exercise Cawala through the browser client. Covers mock mode,
a live single-leaf network, same-leaf and cross-leaf payments, browser
administration by designation, identity portability, exit/recovery, and the
headless smoke scripts.

> See `web/README.md` for how to build and run the app, and `PLAN.md` for the
> current authority model. There is no ping/debug UI (`#/debug` is a 404); the
> send form takes a receive **URI**, not a bare endpoint id.

## 0. Setup

Prerequisites (run from `web/`):

- Node.js (v24 used) and npm: `npm install` once.
- Rust wasm target: `rustup target add wasm32-unknown-unknown`
- wasm-bindgen CLI pinned to the crate's version:
  `cargo install wasm-bindgen-cli --version 0.2.122`
- A C compiler (`clang`) on PATH — the `ring` crate needs it for
  `wasm32-unknown-unknown`. On Ubuntu: `sudo apt install clang`.

Start the app:

```sh
cd web
npm run dev          # builds the wasm glue, then starts Vite
```

Open <http://localhost:5173>. Live mode is the default. `npm run dev` regenerates
`web/src/wasm/` from `crates/client-wasm`, so rebuild after any client change.

Node CLI is always `cargo run -p cawala-node -- <args>` from the repo root.
`--data-dir` is a **global flag that must precede the subcommand**.

---

## 1. Mock mode — exercise the whole UI with no node

Open <http://localhost:5173/?mock>. This is the full synthetic UI and the
automatic fallback when wasm init fails.

Walk each nav item and confirm it renders and reacts. The nav is **Home**,
**Join** (only while unjoined), **Accounts**, **Activity**, **Settings**, and
**Admin**; My Account is reached from Home, not a tab.

- **Home** — balance/address/pending/children stat cards, "Mock mode" banner,
  sample children/accounts, My Account links.
- **Join** — shows "Running in mock mode… no real connection will be made."
- **Accounts** — accounting equation + accounts table.
- **Activity** — log with a type filter.
- **Settings** — identity portability; mock surfaces are clearly banner-marked.
- **Admin** — locked by default behind the policy gate; unlocking shows the
  target switcher and the admin cards with fake successes.
- **My Account** (`#/account`, from Home) — mode badge "Mock", fixed sample
  receive URI, send form.

Caveats: a second tab in the same browser profile runs in mock by design (the
identity lock is held by the first tab); mock returns fake successes, so it
tests layout/flow, not real crypto or ledger behavior.

---

## 2. Live mode — one leaf node + browser users

### 2a. Start the leaf and generate an invite

Terminal A:

```sh
cargo run -p cawala-node -- --data-dir /tmp/cawala-leaf init
cargo run -p cawala-node -- --data-dir /tmp/cawala-leaf topo set-address 0
cargo run -p cawala-node -- --data-dir /tmp/cawala-leaf run
# note the printed EndpointId
```

Terminal B (invite):

```sh
cargo run -p cawala-node -- --data-dir /tmp/cawala-leaf control invite --label test
```

Copy the `cawala://join?parent=...&op=...` line. The `op=` value is also the
node's 64-hex operator id.

### 2b. Join flow (browser)

1. Open <http://localhost:5173> (live), go to **Join**, paste the invite,
   **Paste & check**, then **Connect**. State → **"Waiting for approval"**
   (persists across reload).
2. In Terminal B: `... control joins` → lists the pending browser.
3. `... control approve --node <browser-endpoint-id>`
   (or `control reject --node <id> --reason ...`).
4. Browser flips to **"You're connected"** at address `0.<slot>`.
5. **Restart the node** after the CLI `approve` — the CLI's short-lived endpoint
   can overwrite the node's pkarr record; the smoke scripts restart before
   dialing for payment.
6. Reject path: re-join a fresh browser, run `control reject`; the UI shows the
   reason and offers "Try a different invite".

### 2c. Verified balance + funding

```sh
cargo run -p cawala-node -- --data-dir /tmp/cawala-leaf ledger fund --to <browser-endpoint-id> --amount 100
```

`fund` auto-opens the account. In **My Account**, press **Request balance** →
verified balance; check **Activity** and the Dashboard Verified/Stale badge.

### 2d. Same-leaf payment

You need **two independent live browser contexts** (two profiles, or one normal
+ one incognito window — two tabs in the same profile force the second into
mock). Both join the same leaf and get approved.

1. On B: **My Account → Receive payments → Copy** the
   `cawala://pay?to=...&addr=...&ln=...&lk=...` URI (`ln`/`lk` pin the payee leaf
   key).
2. On A: **My Account → Send payment**, paste B's receive URI, amount `25`,
   **Send payment**.
3. Expect Pending → **Applied**; A balance `75`, B balance `25`; Activity shows
   the transfer truthfully.
4. Edge cases: a URI without `ln`/`lk` shows **"No pin"** (TOFU); a tampered
   `lk` must not show success; sending more than the balance must render a
   distinct failure/partial state.

### 2e. Cross-leaf / LCA settlement (3 nodes, optional)

Per `web/scripts/smoke-crossleaf.mjs`, build root `P` at `0` with node children
`A=0.1`, `B=0.2`:

```sh
cawala-node --data-dir P init
cawala-node --data-dir P topo set-address 0
cawala-node --data-dir P topo attach-child --child <A-id> --kind node --slot 1
cawala-node --data-dir P topo attach-child --child <B-id> --kind node --slot 2

cawala-node --data-dir A init
cawala-node --data-dir A topo set-parent --parent <P-id> --slot 1
cawala-node --data-dir A topo set-address 0.1

cawala-node --data-dir B init
cawala-node --data-dir B topo set-parent --parent <P-id> --slot 2
cawala-node --data-dir B topo set-address 0.2
```

Run all three, invite browsers into A and B, approve/fund each leaf, then send
from an A-user to a B-user's receive URI. Expect settlement at `P` (the LCA),
`Applied`, with balances moving on both leaves.

---

## 3. Browser administration (by explicit designation)

The browser never holds a node operator or ledger key. It signs admin requests
with its own operator key; the target applies a request only if the authenticated
direct neighbor that handed it over is one of the target's **designated
administrators**. All admin requests are **tree-routed**; there is no direct dial
to an admin target.

1. **Designate the browser** with the local CLI (always works, and bootstraps the
   first administrator). The child must be a current child of the node:

   ```sh
   cargo run -p cawala-node -- --data-dir /tmp/cawala-leaf control admin add <browser-endpoint-id>
   cargo run -p cawala-node -- --data-dir /tmp/cawala-leaf control admin list
   cargo run -p cawala-node -- --data-dir /tmp/cawala-leaf control admin remove <browser-endpoint-id>
   ```

2. In the app, open **Admin**. It is **locked by default**: read
   `ADMIN_POLICY.md` and tick the acknowledgement to unlock. Unlocking is
   in-memory only - a reload returns to the gate. Editing the policy invalidates
   a stored acknowledgement (it is stored by document hash).
3. **Switch target** with the up/down switcher over the strict ancestor chain
   (the browser's own leaf, then parent, ...); the ends disable their buttons.
4. Test each surface on the administered node:
   - **Designated Administrators** - each child row shows whether it is
     designated; **Designate** / **Revoke** send routed `AdminDesignate` /
     `AdminRevoke`. The node has the final say and the list refreshes.
   - **Pending joins** - Approve / Reject / Resend (Resend appears only after a
     non-delivered attempt).
   - **Topology** - select a node child row, then **Re-slot…** / **Detach…**
     (browser `User` leaves cannot be re-slotted in v1). **Create child** is a
     mock-only control; live children appear by approving a join request or from
     the node CLI.
   - **Value Issue & Burn** - pick an account, enter an amount and a required
     reason (posting against the node's equity, bounded per admin child by
     `value_policy.json`).
5. Negative tests: a browser that is **not** in the target's designation set is
   refused (`unauthorized`); `control admin remove <id>` then refresh; a locked
   Admin page shows the policy gate; a reload re-locks.
6. Value policy is deny-by-default when `value_policy.json` is absent; inspect
   and set caps locally with `control admin value-policy show` /
   `control admin value-policy set --per-request <n> --window-secs <n>
   --window-max <n> --per-account <n>`. The `admins` overrides name each
   **admin child's** operator key (the same id used by `control admin add`),
   not each browser's: a browser under a relaying admin child shares that
   child's limits.

---

## 4. Identity portability (Settings → Identity Portability)

- **Export identity**: passphrase (≥12 chars) + confirm → downloads
  `cawala-identity-<id>.json`.
- **Import identity**: load the file on another profile/device, preview
  "Incoming node", confirm → reload. Same seed = same address and balance.
- **Wrong passphrase / tampered file** must fail inline.
- **Remove identity**: confirm → wipes the seed + join/ledger state; reload
  shows a fresh identity.
- Cross-device: using one identity on two devices concurrently is *not
  prevented* — run one device at a time.

---

## 5. Exit, recovery, and clean settlement

- **Leave network**: My Account → Network → **Leave network** → confirm.
  Address clears; Dashboard/My Account show "Not connected"; re-join via a
  fresh invite.
- **Parent unreachable**: stop the parent; after ~2 failed balance probes a
  "Parent unreachable" notice appears with "Re-join via invitation".
- CLI-side:
  - `control exit` — unilateral; warns if the `Parent` balance is non-zero.
  - `ledger edge-close` — detached-only full write-off of the pooled `Parent`
    balance.
  - `control claim-export` / `control claim-review <file>` /
    `control parent-status`.

---

## 6. Repeatable headless smoke tests

Scripted verification of the live paths. They build the node if missing; they
print `SKIP:` and exit 0 if the N0 relay/pkarr path is genuinely unreachable.

```sh
cd web
node scripts/smoke.mjs                 # spawn-only
node scripts/smoke-tabs.mjs            # tab-to-tab ping
node scripts/smoke-join.mjs            # join + reject
node scripts/smoke-payment.mjs         # same-leaf payment
node scripts/smoke-crossleaf.mjs       # LCA cross-leaf
node scripts/smoke-admin.mjs           # tree-routed admin (query/approve/designate/revoke)
```

Set `SMOKE_*_REQUIRE_NETWORK=1` to turn a SKIP into a hard failure. All live
flows need outbound HTTPS/DNS/UDP to N0 (`dns.iroh.link` + public relays).

---

## 7. Gotchas / resets

- **No ping/debug UI exists anymore.** Use the smoke scripts for raw
  connectivity; `#/debug` is a 404.
- **Storage keys** (clear to reset): `cawala.identity.v1`,
  `cawala.state.v1:<nodeId>`, `cawala.ledger.v1:<nodeId>`,
  `cawala.value.pending.v1`, `cawala.recovery.v1`,
  `cawala.admin.policy.v1` (policy acknowledgement hash). There is no
  `cawala.admin.*` key store.
- **Hard breaks** (control format 8, routed control 2, reply 5, ledger entry 4,
  ledger meta 3, settlement/browser payload 3): when these change, delete the
  test `node-data` and run `npm run build:wasm` so JS/wasm arity and wire
  versions stay in lockstep.
- Browser users are always `ChildKind::User`; only node children can be
  moved/re-slotted. Cross-leaf payments require the multi-node tree, not just
  the root leaf.
- Cargo-heavy commands are resource-sensitive in this repo: use
  `CARGO_BUILD_JOBS=1` for workspace-wide `test`/`clippy`.
