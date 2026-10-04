# Cawala — `cawala-node` CLI Guide

What each operator command does and when to reach for it. The command surface
lives in `crates/node/src/main.rs` (clap derive); this guide is the operator
view. For the wire/design context see `PLAN.md`; for browser flows see
`MANUAL_TESTING.md`; for terminology see `README.md`.

> Scope: this is the **local operator** CLI. Online administration of *other*
> nodes is not exposed here — it happens from the browser's tree-routed Admin
> page. The CLI's guaranteed role is local administration and recovery.

## 0. Invocation and conventions

Run from the repo root:

```sh
cargo run -p cawala-node -- <args>
```

or, when the binary is on `PATH`, `cawala-node <args>`.

- `--data-dir <DIR>` — global option, default `node-data`. Because it is
  declared `global = true`, clap accepts it **before or after** the subcommand.
- **No subcommand ⇒ `run`.** `topo`, `ledger`, `msg`, and `control` each require
  a nested subcommand (bare invocation errors).
- Argument types used below:
  - `<ID>` / `<ENDPOINT_ID>` — an iroh `EndpointId` (hex or base32). This is the
    node's immutable identity and is the same string Cawala calls the **NodeId**.
  - `<ADDR>` — an octal address such as `0.1.2`.
  - `<SLOT>` — an octal digit `0..=7` (a node's position among its parent's
    children).
- **Identity side effect:** nearly every command loads — and therefore creates if
  absent — the operator `secret_key` and the `ledger_key` before doing its work.
  Even read-only commands (`topo show`, `ledger show`, `control joins`) will
  materialize identity files on first run. The one exception is
  `control claim-export`, which *requires* an existing ledger key and never
  creates one.
- On-disk state under `<data-dir>`: `secret_key`, `ledger_key`, `node.json`,
  `ledger/` (`meta.json`, `entries.log`, `commitments.log`, `orders.jsonl`,
  `.lock`), `ledger_peers.json`, `pending_joins.json`, `outbound_join.json`,
  `admin_state.json`, `control_seen.json`, `control_audit.jsonl`, and the
  process-instance lock `node.lock`.

### Direct dial vs tree-routed administration

Two different mechanisms share the word "control", and it matters which one the
CLI uses:

- **The CLI dials directly.** Every `control` command opens a direct QUIC
  connection to the named neighbor; there is no routed flag. A direct request is
  authorized at its target only as the target's **own operator**
  (`Authority::SelfOperator`).
- **The browser is tree-routed.** The web Admin page reaches ancestors hop by hop
  over the message layer, authorized by each node's designation set.

A consequence today: the five "neighbor" commands — `control create-child`,
`detach-child`, `move-child`, `set-address`, and `query` — are gated by
`ensure_local_target`, so `--node` must be **this node itself** despite the help
wording ("ask a directly-controlled neighbor"). Remote targets are refused
(`crates/node/src/main.rs:1925`). Treat them as local self-operator operations.
Cross-node topology and value administration is done from the browser Admin
page, or recovered locally with `control admin add|remove|list`.

---

## 1. Lifecycle — `init`, `run`

| Command | What it does | Use when |
| --- | --- | --- |
| `init` | Creates the operator key, node record (`node.json`), ledger key, and an empty ledger if absent; prints `EndpointId` and `LedgerId`. Idempotent. | First step before anything else. Safe to re-run. |
| `run` | Default when no subcommand is given. Acquires `node.lock`, loads identity/record, and serves `cawala/ping/0`, `cawala/msg/0`, and `cawala/control/0`. Does a startup `RebasePull`, drains envelopes, sweeps settlements and pending rebases (5 s), and re-pulls the parent prefix (~30 s). With **no address set it only serves ping + control** and warns that messaging is disabled. Blocks forever. | Routine operation. One instance per data dir. |

Notes:

- `node.lock` refuses a second `run` on the same data dir.
- You can run other CLI commands against a live node concurrently (they use the
  ledger lock separately), but a short-lived CLI process that dials out
  (`approve`, `join`, `msg send`, `parent-status`) can overwrite the running
  node's pkarr record. After an out-of-band `control approve`, **restart the
  node** before dialing it for payments (the smoke scripts do this).

```sh
cargo run -p cawala-node -- --data-dir /tmp/leaf init
cargo run -p cawala-node -- --data-dir /tmp/leaf run
```

---

## 2. Local topology — `topo`

`topo` edits this node's links in `node.json` only. It **never dials anyone** and
never notifies the other side. Slot/address validation lives in
`crates/node/src/record.rs` (≤ 8 children, unique slots, a non-root address must
match the parent slot).

| Command | What it does | Use when |
| --- | --- | --- |
| `topo show` | Prints node id, address, parent `{id, slot}`, children, and derived parent/child addresses. Read-only. | First diagnostic: "what does this node think its links are?" |
| `topo attach-child --child <ID> --kind node\|user [--slot <0..7>] [--date-joined <EPOCH>]` | Adds a child link. `--slot` omitted picks the lowest free slot. `--date-joined` defaults to now; pass the child's **original** value when re-attaching a moved child. | Offline/manual repair or test fixtures. Prefer a real join (`control approve`) for live children. |
| `topo detach-child --child <ID>` | Removes a child link. Errors if not present. Sends no notice — the child still believes it is attached. | Local cleanup of a dead/offline link. For a **live** child use `control detach-child`. |
| `topo set-parent --parent <ID> --slot <0..7>` | Sets the parent link. Fails if an existing address's last digit ≠ `--slot`. | Manual re-parenting / test fixtures. Does not register the parent in `ledger_peers.json`. |
| `topo unset-parent` | Clears the parent link (and clears a non-root address; root `0` survives). | Detach locally without notifying the parent. Prefer `control exit` for a live exit. |
| `topo set-address <ADDR>` | Asserts the octal address. A non-root address requires a parent whose slot matches; root `0` is allowed alone. Bumps the address epoch. | Seed an address before `run`, or repair one. |
| `topo unset-address` | Clears the asserted address (always legal). | Stop messaging on next restart. |

**Gotcha:** `topo attach-child`/`set-parent` do **not** create the peer registry
row (`ledger_peers.json`) that the target's later signed control/settlement hops
rely on. Use them for recovery or fixtures, not as a substitute for a real join.

---

## 3. Ledger — `ledger`

`ledger` operates on this node's on-disk ledger. The handler always loads/creates
both keys first. Mutations take the exclusive lock in `ledger/.lock`; reads take
a shared lock. A contended lock fails fast.

| Command | What it does | Use when |
| --- | --- | --- |
| `ledger show` | Replays the log and prints node id, ledger id, entry count/height, head hash, root/parent balances, equity, and per-child balances. | Routine inspection of a node's books. |
| `ledger verify` | Replays and reports chain/conservation validity; non-zero exit on failure. | Health check, especially after manual repair or a hard-break upgrade. |
| `ledger init` | Creates the ledger key and empty log/meta. Idempotent. | Explicitly ensure ledger files exist (also implied by `init`). |
| `ledger open-account --node <ID> [--kind user\|node]` | Appends an `OpenAccount` entry if absent. Idempotent. | Pre-create an account before funding. Does **not** verify the target is a current child. |
| `ledger fund --to <ID> --amount <N> [--kind user\|node]` | Auto-opens the account, then appends an `Issue` (`{Child:+N}`) against this node's equity. Prints amount/seq/hash/new balance. | Operator issuing value into a child/user account (the manual equivalent of Admin → Issue). |
| `ledger prefund --to <ID> --amount <N> [--kind user\|node]` | **Non-root only.** Appends a `Descend` transfer crediting both the `Parent` asset account and the child, establishing the linked-ledger mirror. Rejects a root and a replayed request hash. | Back a child's balance with value this node holds from *its* parent. |
| `ledger edge-close [--from <ID>]` | Writes off the **entire** pooled `Parent` balance. `--from` is non-authoritative audit context. | Settle a severed parent edge after `control exit`. |
| `ledger commit` | Appends one signed commitment at the current ledger head; refuses if the head has not advanced. Prints height/roots/prev/hash. | Freeze the current head as evidence (e.g. before a claim export). |
| `ledger chain [--json]` | Verifies and prints the stored signed commitment chain. | Audit that no commitment was tampered with. |
| `ledger net [--peer <DIR>]... [--orders <FILE\|->] [--topology <FILE>] [--primary-root <ID>] [--json] [--strict]` | Loads peer dirs (defaults to the global `--data-dir`), merges registries/orders, runs reconciliation, and prints peers/advisories/findings/nets. | Diagnostics: reconcile balances across a set of node data dirs. |
| `ledger verify-cascade [--peer <DIR>]... (--order <JSON> \| --orders <FILE\|-> --order-hash <HEX>) [--primary-root <ID>] [--json]` | Reconstructs and verifies one order's cross-leaf settlement cascade. | Diagnostics: prove how a specific cross-leaf payment settled. |

Notes:

- **`ledger fund` has no replay guard.** Every run issues again. It is
  deliberately operator-only and is never reachable from a browser order. It also
  performs no child-link check, so `--to` can name any id.
- `ledger prefund` is replay-guarded and refunds a real top-level claim; it
  refuses to run on a root ("use `ledger fund`").
- `ledger net` prints `RouteInvalid` findings as **advisories** (topology is live
  state) and does not fail unless `--strict` is passed. Route advisories still
  suppress netting until resolved; pass `--topology` with a saved snapshot to
  remove stale-geography false positives. `--strict` requires an order source.
- `ledger verify-cascade` exits non-zero when the cascade is invalid.

```sh
# Issue 100 to a browser user (auto-opens the account)
cargo run -p cawala-node -- --data-dir /tmp/leaf ledger fund --to <browser-id> --amount 100
# Confirm the books
cargo run -p cawala-node -- --data-dir /tmp/leaf ledger verify
```

---

## 4. Raw messaging — `msg send`

Diagnostic/low-level transport. Binds a short-lived endpoint, sends a single
`cawala/msg/0` envelope, prints `msg_id`/status, and shuts down.

```sh
cawala-node msg send --to <ADDR> [--type <u16=1>] \
  [--payload <TEXT> | --payload-hex <HEX>] [--hint <ID=ENDPOINT_ADDR>]...
```

- `--type` defaults to `1` (ledger).
- `--payload` (UTF-8) conflicts with `--payload-hex`.
- `--hint ID=ADDR` is a repeatable direct next-hop hint. Transports are
  `ip:HOST:PORT`, `relay:URL`, or `custom:<id>_<hex>`; an empty `ADDR` means
  "id only".

**Use when:** you need to test raw connectivity/routing or hand-craft an envelope
with no ping/debug UI available. Requires a local record/endpoint; it is not
gated by an asserted address.

---

## 5. Control plane — `control`

All `control` commands **dial directly** to the named neighbor (no tree routing).

### 5a. Onboarding a child

| Command | What it does | Use when |
| --- | --- | --- |
| `control invite [--slot <0..7>] [--expiry <EPOCH>] [--label <L>] [--relay <URL>] [--ip <HOST:PORT>]` | Prints a `cawala://join?parent=…&op=…` URI carrying this node's endpoint id and operator public key, plus optional slot/expiry/label/transport hints. Purely local. | Routine: hand someone the invite that lets them join under this node. The `op=` value is this node's 64-hex operator id. |
| `control joins` | Lists pending join requests from `pending_joins.json` (node, kind, desired slot, expiry). | Parent side: see who is waiting. |
| `control approve --node <ID> [--slot <0..7>]` | Consumes the pending row, assigns slot/address, attaches the child, registers its peer row, opens the account first for a `User` applicant (avoids a half-approved state), then dials the applicant and prints delivery status. Idempotent re-approval reconciles a ledger-key rotation. | Accept a joiner. |
| `control reject --node <ID> [--reason <R>]` | Removes the pending row and dials the applicant a `JoinRejected` (default reason `rejected`). If no pending row exists it still sends with `nonce=0`. | Decline a joiner. |
| `control join (--parent <ID> \| --invite <URI>) [--kind node\|user] [--slot <0..7>] [--location <HINT>]` | Applicant side: writes the pending outbound request to `outbound_join.json`, then dials the prospective parent and prints the reply. A node joiner contributes its ledger key; a user joiner does not. | A non-browser node joining a parent (browsers join from the web UI). |

Notes:

- `control join --parent` is **trust-on-first-use** (no pinned operator). Prefer
  `--invite`, which pins the parent's operator key and can carry relay/ip hints.
- Join requests carry a default TTL of 3600 s.
- `control approve` requires this node to have an asserted address
  (`NotAttached` otherwise), a live pending row, and a free slot / space.
  **Restart the node after an out-of-band approve** (see §1).
- `control reject` with no pending row sends a zero-nonce rejection; the
  applicant accepts it (a documented residual).

```sh
cawala-node control invite --label test
cawala-node control joins
cawala-node control approve --node <browser-endpoint-id>
```

### 5b. Tree operations (local self-operator only)

These five commands accept `--node`, but `ensure_local_target` requires it to be
**this node**; passing a remote id is refused. They then self-dial.

| Command | What it does | Use when |
| --- | --- | --- |
| `control create-child --node <self> --child <ID> --kind node\|user --operator <HEX64> [--ledger <HEX64>] [--slot <0..7>]` | Registers the child's operator (and ledger) keys and attaches the link, without an interactive join. `--ledger` is required for a node and omitted for a user (not enforced by clap). | Provision a child you already know out of band (e.g. seeding a test tree). |
| `control detach-child --node <self> --child <ID>` | Removes the child link and queues a best-effort `DetachNotice`; the registry row is retained so the child can re-attach. | Remove a **live** child with a notice, unlike silent `topo detach-child`. |
| `control move-child --node <self> --child <ID> [--slot <0..7>]` | Re-slots a **node** child under the same parent (a `User` leaf is refused); bumps the address epoch, preserves kind/join date, and pushes one best-effort `Rebase`. | Manual downward-only re-slotting. |
| `control set-address --node <self> [--address <ADDR>]` | Sets or clears this node's asserted address. Self-operator only — a parent pushes `Rebase` instead. | Change your own address. |
| `control query --node <self>` | Returns and prints a `NodeSnapshot` (node id, address, parent, children). | Local diagnostic snapshot over the control path. |

### 5c. Exit and recovery

| Command | What it does | Use when |
| --- | --- | --- |
| `control exit` | Unilateral: best-effort notifies the parent (audited if it fails), then unconditionally re-roots locally — clears the parent, sets address `0`, bumps the epoch, and pushes `Rebase` to every child. Warns (but proceeds) if the `Parent` balance is non-zero. | Leave the current network and take your subtree with you. |
| `ledger edge-close` | See §3 — the companion step that writes off the pooled `Parent` balance after an exit. | Immediately after `control exit`, **before** a new parent prefunds. |
| `control claim-export [--from <ID>] [--out <FILE>]` | Builds a self-attested stranded-claim evidence bundle: appends a fresh commitment if the ledger is ahead, produces a `Parent` Merkle state proof, signs it, self-verifies, prints JSON (or writes `--out`), and audits. Requires an existing ledger key. | Produce out-of-band evidence of a stranded balance to show a prospective foster parent. |
| `control claim-review <FILE>` | Reads (≤ 1 MiB), verifies a bundle, and prints presenter, detached-from, state-proof-checked balance, commitment height, and reviewer exposure guidance. Non-zero on verification failure; always audited. | As a prospective parent, evaluate someone's stranded claim. |
| `control parent-status` | One-shot liveness probe of the recorded parent (5 s timeout). Prints `reachable: true\|false` and `attachment: parented\|root\|no parent`. No local state mutation. | Quick "is my parent up?" check. A still-attached parent audits a `rebase-pull` line and persists a replay mark. |

Notes:

- `control exit` is not admin-gated — it is the child's own operator key.
- `ledger edge-close` is **irreversible** and forfeits the *whole* pooled
  `Parent` balance (possibly another former parent's claim plus any extension a
  new parent already made). It is detached-only, so run it after `control exit`
  and before re-attaching.
- `claim-export`/`claim-review` bundles are **evidence only** — never authority,
  never sent on the wire, and never gate anything.

Recovery sequence:

```sh
cargo run -p cawala-node -- --data-dir /tmp/leaf control exit
cargo run -p cawala-node -- --data-dir /tmp/leaf ledger edge-close
# then re-join under a new parent with a fresh invite
```

### 5d. Administrators — `control admin`

Local, no network. These operate on `<data-dir>/admin_state.json`, the node's
explicit designation set (up to 8 current children of any kind). This is the
guaranteed fallback when remote administrators are unavailable or locked out.

| Command | What it does | Use when |
| --- | --- | --- |
| `control admin add <CHILD_NODE_ID>` | Designates a **current child** (any kind). Refuses a non-child, a duplicate, or a full set (max 8). Prints the listing. | Bootstrap the first administrator, or add one locally. |
| `control admin remove <CHILD_NODE_ID>` | Revokes any designated id (current child or stale). Errors if not designated. | Remove an administrator / recover from a bad remote change. |
| `control admin list` | Prints the designated set, marking non-current-child entries `(stale: not a current child)`, plus `updated_at`/`updated_by`. | Audit who can administer this node. |

Notes:

- The file is loaded leniently: a corrupt `admin_state.json` yields an empty set
  with a warning and an `admin-state-load-failed` audit, so an operator is never
  locked out.
- `control admin add|remove|list` is the **only** administrative authority the
  CLI exposes. Everything else (approve/reject, topology, value issue/burn,
  designate/revoke) is available online from the browser Admin page, tree-routed
  and gated by the designation set. There is no CLI value-policy command and no
  grant/priority/lease subsystem.

```sh
cargo run -p cawala-node -- --data-dir /tmp/leaf control admin add <browser-endpoint-id>
cargo run -p cawala-node -- --data-dir /tmp/leaf control admin list
```

---

## 6. Intended use at a glance

- **Routine:** `init`, `run`, `topo set-address` / `topo show`, `control invite`,
  `control joins`, `control approve` / `reject`, `ledger fund`,
  `control admin add` / `list`.
- **Recovery:** `control exit`, `ledger edge-close`, `control claim-export` /
  `claim-review`, `control parent-status`, `control admin add` (lockout), and the
  `topo attach-child` / `set-parent` / `unset-*` repair commands.
- **Diagnostics:** `topo show`, `ledger show` / `verify` / `chain` / `net` /
  `verify-cascade`, `msg send`, `control query`.

## 7. Destructive or irreversible operations

- `ledger fund` — issues value on every run (no replay guard).
- `ledger edge-close` — forfeits the entire pooled `Parent` balance; detached-only.
- `control exit` — unilateral local re-root; warns on a non-zero `Parent` balance.
- `topo detach-child` / `topo unset-parent` — silently break links with no notice;
  prefer the `control` equivalents for live nodes.
- `control create-child` with a changed ledger key — refused unless self-operator.
- `control claim-export` — appends a commitment to `commitments.log`.

## 8. Common operator workflows

**Bootstrap a leaf node**

```sh
cargo run -p cawala-node -- --data-dir /tmp/leaf init
cargo run -p cawala-node -- --data-dir /tmp/leaf topo set-address 0
cargo run -p cawala-node -- --data-dir /tmp/leaf run      # Terminal A
cargo run -p cawala-node -- --data-dir /tmp/leaf control invite --label test
```

**Onboard a browser user** — send the invite, then on the parent:

```sh
cawala-node control joins
cawala-node control approve --node <browser-endpoint-id>
# restart the node so its pkarr record is re-published, then:
cawala-node ledger fund --to <browser-endpoint-id> --amount 100
```

**Seed a test tree** (root `P` with children `A=0.1`, `B=0.2`) — use
`control create-child` to register a known child, or `topo attach-child` plus
`topo set-parent` / `topo set-address` for a purely local fixture. See
`web/scripts/smoke-crossleaf.mjs` for the canonical scripted version.

**Designate the first administrator** — from the local CLI on the node host:

```sh
cawala-node control admin add <child-endpoint-id>   # child of any kind, must be current
```

**Leave and settle** — `control exit`, then `ledger edge-close`, then re-join with
a fresh invite.

**Recover evidence after a parent vanishes** — `control parent-status` to confirm,
then `control claim-export`; the prospective parent runs `control claim-review`.
