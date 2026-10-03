# Cawala — Manual Web Testing Guide

How to manually exercise Cawala through the browser client. Covers mock mode,
a live single-leaf network, same-leaf and cross-leaf payments, delegated browser
admin, identity portability, exit/recovery, and the headless smoke scripts.

> Note: `web/README.md` is partly stale. It still describes a ping/debug harness
> and claims there is no browser admin or issue/burn path. The current code has
> no ping UI (`#/debug` is a 404), and the Joins page, delegated admin grants,
> and Accounts issue/burn all exist. The send form takes a receive **URI**, not a
> bare endpoint id.

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

Walk each nav item and confirm it renders and reacts:

- **Dashboard** — balance/address/pending/children stat cards, "Mock mode"
  banner, sample children/accounts.
- **Join** — shows "Running in mock mode… no real connection will be made."
- **My Node** — administered node + children.
- **Join Requests** — approve/reject rows (fake success).
- **Accounts** — accounting equation + accounts table.
- **Activity** — log with a type filter.
- **My Account** — mode badge "Mock", fixed sample receive URI, send form.
- **Settings** — mock hides "Generate admin key" (needs a live node) and
  identity portability.

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
node's 64-hex operator id (reused later for admin keys).

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

## 3. Delegated browser admin (joins / topology / value)

The browser never holds the node operator key; it receives a scoped, time-boxed
delegated admin key.

1. Get the node's 64-hex id from the invite's `op=` value.
2. **Settings → Node administration → Generate key**: enter Node ID (64 hex),
   optional label, provisional TTL (days), optional target address → **Generate
   key** → **Copy** the public key.
3. On the node:

   ```sh
   cargo run -p cawala-node -- --data-dir /tmp/cawala-leaf control admin grant \
     --key <admin-pub-hex> --scope joins --scope topology --scope value --label manual
   ```

   Copy the printed `cawala://admin?node=...&grant=...` bundle.
4. In **Settings**, paste it into **Import operator-signed grant** → **Import
   bundle**.
5. Test each scoped surface:
   - **joins** → **Join Requests**: Approve / Reject / Resend (redeliver).
     "Resend" appears only after a non-delivered attempt.
   - **topology** → **My Node**: move/detach a *node* child (browser `User`
     leaves cannot be re-slotted in v1).
   - **value** → **Accounts**: select a liability row → **Issue…** / **Burn…**
     (amount + required reason). The first value action forces **Protect value
     key** (passphrase + confirm); afterwards **Lock now** and re-test the unlock
     dialog. Pending value ops survive reload with Retry/Discard.
6. Negative tests: grant only `joins` → Accounts/My Node gate with
   `GrantEmptyState`; run `control admin revoke --key <pub>` → refresh → query
   fails unauthorized; let a short grant expire.
7. Value policy is deny-by-default when `value_policy.json` is absent; set caps
   with `control admin value-policy set --per-request <n> --window-secs <n>
   --window-max <n> --per-account <n>`.

---

## 4. Identity portability (Settings → Identity Portability)

- **Export identity**: passphrase (≥12 chars) + confirm → downloads
  `cawala-identity-<id>.json`.
- **Import identity**: load the file on another profile/device, preview
  "Incoming node", confirm → reload. Same seed = same address and balance.
- **Wrong passphrase / tampered file** must fail inline.
- **Remove identity**: confirm → wipes seed + admin keys; reload shows a fresh
  identity.
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
node scripts/smoke-admin.mjs           # delegated admin grant/revoke
```

Set `SMOKE_*_REQUIRE_NETWORK=1` to turn a SKIP into a hard failure. All live
flows need outbound HTTPS/DNS/UDP to N0 (`dns.iroh.link` + public relays).

---

## 7. Gotchas / resets

- **No ping/debug UI exists anymore.** Use the smoke scripts for raw
  connectivity; `#/debug` is a 404.
- **Storage keys** (clear to reset): `cawala.identity.v1`,
  `cawala.state.v1:<nodeId>`, `cawala.ledger.v1:<nodeId>`, `cawala.admin.v3`,
  `cawala.value.pending.v1`, `cawala.recovery.v1`.
- **Hard breaks** (control format 7, admin grant format 2, ledger entry 4,
  ledger meta 3, settlement/browser payload 3): when these change, delete the
  test `node-data` and run `npm run build:wasm` so JS/wasm arity and wire
  versions stay in lockstep.
- Browser users are always `ChildKind::User`; only node children can be
  moved/re-slotted. Cross-leaf payments require the multi-node tree, not just
  the root leaf.
- Cargo-heavy commands are resource-sensitive in this repo: use
  `CARGO_BUILD_JOBS=1` for workspace-wide `test`/`clippy`.
