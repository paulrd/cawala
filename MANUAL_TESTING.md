# Cawala — Manual Web Testing Guide

How to manually exercise Cawala through the browser client. Covers mock mode,
a live single-leaf network, same-leaf and cross-leaf payments, the user account
identity (mnemonic, passkey lock, rotation, portability), browser
administration by designation, exit/recovery, the single-file build, and the
headless smoke scripts.

> See `web/README.md` for build/run and the component-level detail, `PLAN.md`
> for the current authority model and wire versions, `CLI.md` for the full
> `cawala-node` command reference, `ADMIN_POLICY.md` for the policy text the
> admin gate renders, and `DEPLOYMENT.md` / `MIRRORS.md` for hosting.
> There is no ping/debug UI (`#/debug` is a 404); the send form takes a
> receive **URI**, not a bare endpoint id.

## 0. Setup

Prerequisites (run from `web/`):

- Node.js (v24 used) and npm: `npm install` once.
- Rust **1.98.0** (see `rust-toolchain.toml`) and the wasm target:
  `rustup target add wasm32-unknown-unknown`
- wasm-bindgen CLI pinned to the crate's exact version:
  `cargo install wasm-bindgen-cli --version 0.2.122` (`crates/client-wasm`
  pins `wasm-bindgen = "=0.2.122"`; a mismatched CLI fails at startup).
- A C compiler (`clang`) on PATH — the `ring` crate needs it for
  `wasm32-unknown-unknown`. On Ubuntu: `sudo apt install clang`.

Scripts (`web/package.json`):

```sh
cd web
npm run dev              # debug wasm + Vite on http://localhost:5173
npm test                 # Node test runner over web/test (no node, no network)
npm run build            # release wasm + dist/ + service worker stamp
npm run build:singlefile # release wasm + dist-single/index.html (one file)
```

Open <http://localhost:5173>. Live mode is the default. `npm run dev`
regenerates `web/src/wasm/` from `crates/client-wasm`, so rebuild after any
client change (`npm run build:wasm` alone regenerates the glue without Vite).

Node CLI is `cargo run -p cawala-node -- <args>` from the repo root (examples
below that show `cawala-node` directly assume it is on PATH; the smoke scripts
default to `target/debug/cawala-node`, override with `CAWALA_NODE_BIN`).
`--data-dir` is a **global flag**: clap accepts it before or after the
subcommand.

### Single-file build (`file://`)

`npm run build:singlefile` produces `web/dist-single/index.html` with the wasm
inlined as base64; `check-singlefile.mjs` asserts it emits exactly one file with
no external `src=`/`href=`/wasm fetch. Open it directly
(`file:///…/web/dist-single/index.html`). On `file://` the app still runs live,
but:

- no service worker (registration is skipped),
- the **passkey panel is hidden** (no WebAuthn origin; the phrase is the only
  unlock path),
- storage stays best-effort, so "Session only" is more likely.

Do not serve the single file from the canonical origin — its meta CSP and the
host header CSP intersect and blank the page (`DEPLOYMENT.md`).

---

## 1. Modes and fallback

Mode precedence at boot (`web/src/lib/api.js`):

1. `?mock` in the URL → **mock**, and wasm is never even imported.
2. Otherwise load wasm, install the identity backend, take the
   `cawala-identity` Web Lock, then spawn the live client.
3. If another tab holds the lock → **mock**, with the multi-tab warning.
4. Any wasm init/spawn failure → teardown, release the lock, **mock**.

There is **no `?live` override**. Web Locks are best-effort: a browser without
`navigator.locks` runs both tabs live.

---

## 2. Mock mode — exercise the UI layout with no node

Open <http://localhost:5173/?mock>. This is the full synthetic UI and the
automatic fallback when wasm init fails. The mock client is always connected at
`0.3.1`, so **the Join tab is not in the nav**; `#/join` shows "You are already
connected to the network."

Walk each nav item and confirm it renders and reacts. The nav is **Home**,
**Accounts**, **Activity**, **Settings**, **Admin** (mobile order is Home,
Accounts, Activity, Admin, Settings); My Account (`#/account`) is reached from
Home, and identity (`#/identity`) from Settings.

- **Home** — stat cards, mock children/accounts, My Account quick action.
- **Accounts** — accounting equation + accounts table with sample rows.
- **Activity** — static sample log with a type filter.
- **Settings** — real cards, mock values. Connection shows the **Mock (no live
  node)** badge; Identity Portability says it is not available in mock mode;
  Location Service says "Mock mode (not connected)"; About says WASM "Not
  loaded (mock mode)".
- **Admin** — locked gate by default; unlock with the policy acknowledgement,
  then the target switcher (a fake two-level chain: `0.3`, then `0`) and the
  admin cards. **Create child** is a mock-only control.
- **My Account** — fixed receive URI (no `ln`/`lk`), send form.

Mock limitations that matter when reading results:

- **The mock join flow is unreachable.** Mock `leave()` returns a fake
  `detached` without clearing the address, and join state is never synced into
  the store in mock, so the browser stays at `0.3.1`: the Join tab stays hidden
  and `#/join` keeps saying "You are already connected to the network". (The
  Admin → Network Membership card promises the Join tab reappears — it does
  not, in mock.)
- A mock send never enters the pending-orders store, so the poller always ends
  at **"Still pending"**, and the send does not appear in Recent Transactions.
- Mock issue/burn reports a fake `applied` and does not move account balances
  (`balanceAfter` is just the amount), and the pending-op Retry/Discard block
  is never left in place.
- With `?mock` the identity backend is not loaded at all: **Create/Restore**
  fail with "crypto engine has not finished loading", and **Rotate** fails
  earlier with "Client is not initialized. Call initApi() before this
  operation." Mock reached via a *spawn* failure behaves differently: wasm
  loaded, so identity derivation still works.

Caveat: a second tab in the same browser profile runs in mock by design (the
first tab holds the identity lock). The reason is surfaced in Settings →
**Multi-Tab**. Mock returns fake successes, so it tests layout/flow, not real
crypto or ledger behavior.

---

## 3. Live mode — one leaf node + browser users

### 3a. Start the leaf and generate an invite

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

### 3b. Join flow (browser)

1. Open <http://localhost:5173> (live), go to **Join**, paste the invite,
   **Paste & check**. The summary shows the parent, the pinned operator key
   (copyable), optional slot/label, relay/direct transport hints, the expiry
   date and an **Expired** badge with **Connect** disabled when past it. Then
   **Connect**.
2. State → **"Waiting for approval"**. The page polls every 2 s and says it
   will update automatically.
3. In Terminal B: `... control joins` → lists the pending browser.
4. `... control approve --node <browser-endpoint-id>` (optionally
   `--slot <0-7>`), or `control reject --node <id> --reason ...`.
5. Browser flips to **"You're connected"** at address `0.<slot>`.
6. **Restart the node** after the CLI `approve` — the CLI's short-lived
   endpoint can overwrite the node's pkarr record; the smoke scripts restart
   before dialing for payment.
7. Reject path: re-join a fresh browser, run `control reject`; the UI shows the
   reason (preferring a stable reject code: `unauthorized`, `slot_taken`,
   `slot_out_of_range`, `not_attached`, `expired`, `replay`, `internal`) and
   offers **"Try a different invite"**.
8. Reload during "Waiting for approval" only restores the waiting state if the
   best-effort `cawala.state.v1:<nodeId>` blob is still present.

### 3c. Verified balance + trust

```sh
cargo run -p cawala-node -- --data-dir /tmp/cawala-leaf ledger fund --to <browser-endpoint-id> --amount 100
```

`fund` auto-opens the account. In **My Account** press **Request balance**
(shown while no balance exists; afterwards the control is **Refresh balance**)
→ verified balance; check the Dashboard Verified/Stale badge. Funding is an
issue posting, and the balance receipt's `history` carries only `Direct`
transfers, so a fund does **not** appear in **Activity** — that list is for
transfers and settlements.

Trust is separate from the number. Settings → **Leaf Ledger Trust** shows the
pinned leaf key: a key pinned on first use is **unconfirmed** until you press
**Confirm this leaf key**. That confirmation is persisted and survives reload.

### 3d. Same-leaf payment

You need **two independent live browser contexts** (two profiles, or one normal
+ one incognito window — two tabs in the same profile force the second into
mock). Both join the same leaf and get approved.

1. On B: **My Account → Receive payments → Copy** the pay URI.
2. On A: **My Account → Send payment**, paste B's URI, amount `25`,
   **Send payment**.
3. Expect **Pending** → **Applied**; with both browsers funded `100` as in §3c,
   A balance `75`, B balance `25`; Activity shows the transfer truthfully.

The URI is `cawala://pay?to=...&addr=...` and carries `ln`/`lk` **only when the
payee's routing leaf key is already pinned** (a verified balance receipt does
that). So:

- Pinned URI → the payee card shows **Pinned** ("Settlement will be verified
  against the payee leaf key").
- Freshly joined payee → **No pin**, trust-on-first-use.

Terminal states are honest, not binary, and each renders distinctly:

| Status | Card | Meaning |
| --- | --- | --- |
| `applied` | **Applied** | leaf reports it applied; the signed balance receipt is the confirmation |
| `duplicate` | **Duplicate** | already applied; no double charge |
| `unverified` | **Unverified** | proof could not be checked — **do not resend** |
| `partial` | **Sent, not confirmed** | debit committed, payee not credited; reconciliation in progress |
| `indeterminate` | **Outcome unknown** | debit committed — **do not resend** |
| `rejected` | **Rejected** | reason is mapped (`insufficient_balance` → "Insufficient balance", etc.) |

The send form polls for ~60 s (30 × 2 s), then reports **"Still pending"**.
**Retry payment** on a rejected card only clears the result card — the URI and
amount were already cleared on submit, so retrying means re-pasting the URI.
Pending results are in-memory: a reload drops the card even if the order is
still resolving (persisted activity/settlement records rebuild Recent
Transactions).

Pinning is **fail-closed**:

- A URI with `ln`/`lk` pins the payee leaf *before* sending. If pinning fails,
  nothing is sent: **"Payment not sent: could not pin the payee leaf (…)"**.
- A *different* key for an already-pinned leaf is recorded but **never
  adopted**; the send aborts and Settings shows a pin-change warning with
  **Keep pinned key** / **Adopt presented key**.
- A terminal proof that does not verify under the pin is `unverified`, never
  success. Test this with a tampered `lk`.

### 3e. Cross-leaf / LCA settlement

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

Run all three, invite browsers into A and B, approve each leaf, then fund the
tree the way `smoke-crossleaf.mjs` does — a leaf's users cannot spend from a
parent-funded balance without the child leg:

```sh
# P holds the children's liabilities.
cawala-node --data-dir P ledger fund --to <A-id> --kind node --amount 150
cawala-node --data-dir P ledger fund --to <B-id> --kind node --amount 1000
# Each leaf prefunds its browser child (this writes the hop the order spends).
cawala-node --data-dir A ledger prefund --to <A-browser-id> --kind user --amount 1000
cawala-node --data-dir B ledger prefund --to <B-browser-id> --kind user --amount 1000
```

Then send from an A-user to a B-user's receive URI. Expect settlement at `P`
(the LCA), **Applied**, with balances moving on both leaves
(`[payer_leaf, LCA, payee_leaf]`). Note A is funded to `150` on purpose: a
second `100` payment exceeds the payer leaf's remaining liability and should
surface as **Sent, not confirmed** (`partial`, `failed_at` = the LCA), not as
success.

The settlement route is the **full tree path** — `[payer_leaf, …ascend…, LCA,
…descend…, payee_leaf]` — with **no depth-1 limitation**; up to 32 signers (≤ 30
intermediates) are allowed. A deeper tree (e.g. `P=0`, `A=0.1`, `B=0.2`,
`A1=0.1.1`, `B1=0.2.1`, browsers under the sub-leaves) is worth an exploratory
run, but note that automated transport coverage only exercises the depth-1
`P/A/B` tree: the deeper route is unit-tested for derivation and origin audit,
and the one transport test for a deep route is the *negative* case ("payee leaf
not in the known topology"), which surfaces as **Outcome unknown /
`indeterminate`** after the origin reserves its hop. Treat a deep-route failure
as in-scope evidence, not a UI bug.

---

## 4. Account identity (R3)

The user account is a secp256k1/Ethereum account derived from a 12-word BIP-39
phrase (`m/44'/60'/0'/0/0`, EIP-55 address) with the **real wasm** engine. The
same phrase derives the Ed25519 transport key, so one phrase restores both the
account and the browser's NodeId. Nothing gates the app on identity: there is no
pre-use identity screen, and joining does not require one.

### 4a. Create / restore

Settings → **Your Account Identity** → **Set up identity** (`#/identity`):

- **Create a new identity** — masked 12-word grid, **Show my words**, write-down
  checkbox, **Continue**, then type 3 random words back and **Finish setup**.
  The final step shows the address and the optional passkey setup.
- **Restore a phrase I already have** — paste, word count and "Phrase checks
  out", optional BIP-39 passphrase, address preview ("This phrase gives"),
  then **Restore identity** and the confirm dialog.
- The phrase is shown **once** and never stored. After setup it cannot be
  viewed again — only rotate or restore replaces it.

### 4b. Passkey lock (optional, secure origins only)

The **passkey panel** appears only on `https`/`localhost` (hidden on
`file://`). States: checking / **Not available** / **Not set up** / **Locked** /
**Unlocked**. Setup runs WebAuthn with the **PRF extension**, HKDF-SHA-256 →
AES-256-GCM wraps the stored secp256k1 secret, and the plaintext secret is
removed from the identity record (v3). A locked device installs nothing at boot
until **Unlock with passkey** or **Use my recovery phrase**. **Remove
passkey** returns the key to plain storage after a confirm. A passkey is an
unlock factor, never a signer.

### 4c. Rotation

Identity page → **Rotate to a new phrase**: enter or generate the new phrase,
optional passphrase, preview the new address, confirm the **before → after**
address change, **Rotate identity**. The frame is signed by the **incumbent**
key, so a stolen transport seed cannot move the anchor; the commit is
idempotent (a lost reply is resent unchanged and `Replay` reconciles as
applied), and the new secret is persisted only on success. If the node lacks
the ETH-identity feature, rotation reports that the node "does not support
rotating an account identity yet" — expected against an old node.

Registration of the anchor happens **automatically after a successful join**,
gated on the capabilities handshake (`NODE_FEATURE_ETH_IDENTITY`). On a fresh
join an accept raises the toast "Account address registered with the network.";
a refusal raises "The network did not accept your account address (<code>)".
Boot-time registration stays silent (readable via `getEthRegistrationStatus()`),
and nothing is written to the Activity log. Registration is first-writer
trust-on-first-use: anyone holding the child's transport key can register
before an anchor exists.

### 4d. Portability (export / import / remove)

- **Export identity**: passphrase (≥12 chars) + confirm → downloads
  `cawala-identity-<first 12 chars of endpoint id>.json`. The bundle is **v2**
  (PBKDF2-SHA-256 600k + AES-256-GCM, `nodeId` bound as AAD) and carries the
  transport seed, the derived secp256k1 secret + EIP-55 address, and the
  secret-free join/ledger blobs. **v1** bundles still import (transport only;
  importing one clears any local ETH identity).
- **Import identity**: load the file or paste it; the preview shows incoming vs
  current node with **Same identity** or **Different identity -- this will
  replace the current one**, then a confirm. Same seed = same address and
  balance.
- **Wrong passphrase / tampered file** must fail inline.
- **Remove identity** wipes `cawala.identity.v1`, `cawala.user-identity.v1`
  (including the passkey wrap) and the current identity-scoped state/ledger
  blobs; reload shows a fresh identity. It does **not** clear the admin-policy
  acknowledgement, the recovery tracker, the value journal, or a quarantined
  ledger backup.
- Cross-device: using one identity on two devices concurrently is *not*
  prevented — run one device at a time.

---

## 5. Browser administration (by explicit designation)

The browser never holds a node operator or ledger key. It signs admin requests
with its own operator key; the target applies a request only if the
authenticated direct neighbor that handed it over is one of the target's
**designated administrators**. All admin requests are **tree-routed**; there is
no direct dial to an admin target. Once admin mode is unlocked and an ancestor
target is selected, the **Admin** nav item badges that target's pending-join
count (while locked there is no query, so no badge).

1. **Designate the browser** with the local CLI (always works, and bootstraps the
   first administrator). The child must be a current child of the node:

   ```sh
   cargo run -p cawala-node -- --data-dir /tmp/cawala-leaf control admin add <browser-endpoint-id>
   cargo run -p cawala-node -- --data-dir /tmp/cawala-leaf control admin list
   cargo run -p cawala-node -- --data-dir /tmp/cawala-leaf control admin remove <browser-endpoint-id>
   ```

2. In the app, open **Admin**. It is **locked by default**: the gate renders
   `ADMIN_POLICY.md` and requires ticking the acknowledgement. Unlocking is
   in-memory only — a reload returns to the gate. The acknowledgement is stored
   by document hash (`cawala.admin.policy.v1`), so editing the policy
   invalidates it and the gate says it changed.
3. **Switch target** with the up/down switcher over the strict ancestor chain
   (direct parent at depth 1, then its parent, …; the browser's own leaf is the
   "This browser" crumb, not a selectable step); the ends disable their
   buttons. The chain is designation-bounded: it stops at the first undesignated
   hop and shows "No ancestor found … Retry" when empty.
4. Test each surface on the administered node:
   - **Designated Administrators** — each child row of the *administered
     ancestor* shows whether it is designated; **Designate** / **Revoke** send
     routed `AdminDesignate` / `AdminRevoke`. That list includes the browser's
     own leaf, so designating yourself from an ancestor target is the intended
     bootstrap path (the button is disabled for your own leaf as the target, or
     before a target is chosen, where requests are not routable). The node has
     the final say and the list refreshes.
   - **Pending joins** — **Approve** (optional slot 0-7) / **Reject** (optional
     reason). **Resend** is wired to a non-delivered attempt, but the current
     join-request rows carry no delivery field, so in practice it does not
     appear — do not treat its absence as a defect.
   - **Topology** — select a node child row, then **Re-slot…** / **Detach…**
     (browser `User` leaves cannot be re-slotted in v1). Child rows show the
     kind reported in the snapshot; the **Target** card infers the admin
     target's own kind from its children and labels it "Inferred from the
     node's children", never guessing. **Create child** is a mock-only control;
     live children appear by approving a join request or via the node CLI
     (`control create-child` / `topo attach-child`).
   - **Value Issue & Burn** — pick a **liability** account (only liability rows
     are selectable), enter a **positive whole-number** amount and a required
     reason (posting against the node's equity). Issue is **uncapped**; burn is
     limited by the account's current balance (`insufficient_balance`). The same
     **Issue…/Burn…** actions appear on the **Accounts** page once a
     value-capable target is selected; a pending op shows **Retry** /
     **Discard** and is persisted across reload (`cawala.value.pending.v1`).
   - **Network Membership** — **Leave network…** detaches this browser's own
     leaf (independent of the selected target; My Account has the same action).
5. Negative tests: a browser that is **not** in the target's designation set is
   refused (`unauthorized`); `control admin remove <id>` then refresh; a locked
   Admin page shows the policy gate; a reload re-locks.
6. There is no value policy: value authority is the designation set alone
   (`control admin add|remove|list`), plus the local CLI.

---

## 6. Exit, recovery, and clean settlement

- **Leave network**: My Account → Network → **Leave network** → confirm
  (Admin → **Network Membership** has the same action; it detaches this
  browser's own leaf). Immediately after leaving, the Dashboard shows **"Not
  connected to a network"** ("You have left your previous network…") and My
  Account clears its Network card. That copy is driven by the detached control
  event in memory: **after a reload** the event is gone and the Dashboard shows
  the generic **"Join the network"** prompt (My Account: "Not assigned yet —
  waiting for join approval"). Re-join via a fresh invite either way.
- **Parent unreachable**: stop the parent. The 20 s balance poll doubles as the
  liveness probe; after **2 consecutive failed probes** My Account shows a
  **Parent unreachable** card with the duration and **Re-join via invitation**
  (leave, then the join flow). Nothing happens automatically; any balance stays
  on the old parent's books.
- CLI-side:
  - `control exit` — unilateral; warns if the `Parent` balance is non-zero.
  - `ledger edge-close` — detached-only full write-off of the pooled `Parent`
    balance.
  - `control claim-export` / `control claim-review <file>` /
    `control parent-status`.
  - `ledger net` / `ledger verify-cascade` for an operator-side check of
    balances and settlement proofs.

---

## 7. Repeatable headless smoke tests

Scripted verification of the live paths. The node-backed scripts build the node
if `target/debug/cawala-node` is missing (`CAWALA_NODE_BIN` overrides), use a
temp data dir, and print `SKIP:` and exit 0 if the N0 relay/pkarr path is
genuinely unreachable.

```sh
cd web
node scripts/smoke.mjs                 # wasm endpoint spawn (pings only if given a target)
node scripts/smoke-tabs.mjs            # two wasm endpoints, tab-to-tab ping
node scripts/smoke-join.mjs            # join + reject
node scripts/smoke-payment.mjs         # same-leaf payment + balances
node scripts/smoke-crossleaf.mjs       # P/A/B LCA settlement + ln/lk pinning
```

- `smoke.mjs` and `smoke-tabs.mjs` need no node binary and read the wasm from
  `web/src/wasm` (build it first).
- Per-script network gates: `SMOKE_JOIN_REQUIRE_NETWORK`,
  `SMOKE_PAYMENT_REQUIRE_NETWORK`, `SMOKE_CROSSLEAF_REQUIRE_NETWORK`.
  `SMOKE_JOIN_SKIP_REJECT=1` skips the reject half of the join test.
- `node scripts/check-singlefile.mjs` is not a network smoke test: it
  statically asserts `dist-single/index.html` self-containment and runs as part
  of `npm run build:singlefile`.

All live flows need outbound HTTPS/DNS/UDP to N0 (`dns.iroh.link` + public
relays).

> **Known-stale:** `web/scripts/smoke-admin.mjs` predates the designation model.
> It calls wasm exports that no longer exist (`set_admin_key`,
> `admin_public_key`) and the removed `control admin grant|revoke --key`
> commands, so it fails immediately. Use the manual admin flow in §5; rewriting
> it against the routed admin API is tracked in `HANDOFF.md` → Open items.

---

## 8. Packaged artifact checks (optional)

Only if you are testing a release rather than a local build:

- Static musl binaries per target plus `.sha256`; `packaging/install.sh`
  verifies the checksum, installs `/usr/local/bin/cawala-node`, and can install
  `cawala-node@.service` (which runs `--data-dir /var/lib/cawala/%i run`).
  Restart the unit after an out-of-band `control approve`, as in §3b.
- The web artifact ships with `SHA256SUMS` and a Sigstore attestation
  (`gh attestation verify <file> --repo <owner>/<repo> --signer-workflow …`).
- Per-host security headers are in `_headers` / `netlify.toml` / `vercel.json`
  with nginx/Caddy recipes in `DEPLOYMENT.md`. GitHub Pages cannot set headers.
- Mirrors: `/.well-known/mirrors.json` advertises a signed mirror list; the
  mnemonic identity is portable across origins (`MIRRORS.md`).

---

## 9. Gotchas / resets

- **No ping/debug UI exists.** `#/debug` is a 404 and unknown routes render the
  in-shell "Page not found". The legacy `#/node` (and `#/node/...`) redirect to
  `#/admin`, but **only on initial load** — setting the hash later lands on the
  404. Use the smoke scripts, or
  `cargo run -p cawala-node -- msg send --to <addr>`, for raw connectivity.
- **Storage keys.** The node is the source of truth; browser storage is layered
  (`web/src/lib/storage.js` is the authoritative table):
  - **authoritative-local** (never discard): `cawala.identity.v1` (transport
    seed), `cawala.user-identity.v1` (ETH address + derived secret + passkey
    wrap, record v3), the TOFU pins carried inside the ledger blob,
    `cawala.ledger.backup.v1:<nodeId>` (quarantine copy of an unreadable ledger
    blob — the only recoverable copy of the pins once the live blob is
    overwritten).
  - **best-effort cache** (absence tolerated): `cawala.state.v1:<nodeId>`,
    `cawala.ledger.v1:<nodeId>`; legacy un-suffixed `cawala.state.v1` /
    `cawala.ledger.v1` are read once as a fallback.
  - **non-authoritative**: `cawala.recovery.v1` (parent-liveness tracker),
    `cawala.admin.policy.v1` (policy acknowledgement hash), `cawala.value.pending.v1`
    (value-op retry journal).
  - Consequences: clearing only `cawala.identity.v1` generates a new random
    transport NodeId while keeping the old ETH identity — use **Remove
    identity** (or clear both identity keys). Clearing storage while the app is
    running is not an immediate reset: the live client rewrites its cache on the
    next persist, so reload after clearing. Losing the ledger blob loses the
    pins; the next receipt is unconfirmed until you **Confirm this leaf key**.
- **Wire versions** (bump = hard break): control format **9** (accepts inbound
  7/8/9), routed control 2, routed reply 1, control reply **6** (`Capabilities`
  = discriminant 9), ledger entry 4, node ledger meta 3, settlement payload 3,
  browser ledger payload **v4** (v2 fallback), browser ledger state **5**,
  browser local state 1, user-identity record **3**, identity bundle **2**.
- **Stale test data:** stop the nodes, delete the test data dirs
  (`rm -rf /tmp/cawala-* node-data`) — ledger/control formats are not migrated
  — rebuild the wasm (`npm run build:wasm`, or `npm run dev`), and clear the
  old `cawala.state.v1:<id>` / `cawala.ledger.v1:<id>` blobs in the browser.
  A ledger blob from an older state version is discarded and its bytes
  quarantined to `cawala.ledger.backup.v1:<nodeId>`.
- Browser users are always `ChildKind::User`; only node children can be
  moved/re-slotted. Cross-leaf payments require the multi-node tree, not just
  the root leaf.
- Settlement routes use any tree depth (the depth-1 limitation is gone); the
  signer cap is 32 (≤ 30 intermediates).
- **Capabilities handshake (R1b):** after a join the client asks its direct
  parent for `clientApiVersion` + features. An old node that cannot answer is a
  silent "capabilities unavailable" — nothing regresses, and ETH registration
  falls back to a best-effort attempt. There is no UI banner for it; watch the
  console and the rotation/registration messages.
- Cargo-heavy commands are resource-sensitive in this repo: use
  `CARGO_BUILD_JOBS=1` for workspace-wide `test`/`clippy`.
