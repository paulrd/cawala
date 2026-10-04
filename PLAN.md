# Cawala - Project Plan

  Status: Living design + roadmap. Delivered-phase history (M0-M5 and the
  superseded unified-console P1-P6) lives in `PLAN-ARCHIVE.md`; the short current
  handoff is `HANDOFF.md`. Last updated 2026-10-04.

# What We Are Building
  A community-owned, hierarchical value-transfer network: Rust/Iroh nodes
  forming a geographic tree, browser clients (Iroh WASM) talking only to leaf
  nodes, value created/destroyed/transferred via signed messages between
  "sovereign" nodes. Each node holds accounts for its children/users. Each
  node's administration is delegated only by **explicit designation**: a node
  keeps a set of children allowed to administer it. Nothing is automatic, and
  there is no "senior" child.

  A **leaf** node is a node whose children are users (browser clients); a
  browser is a user leaf that holds a key but no ledger of its own.

## Load-Bearing Architecture Decisions
  These two decisions make the rest of the design work:
  1. **Splits are downward only (subdivision)** - a split never re-parents a
     node: the full node keeps its children by inserting one or more new
     intermediate children below itself, so every child stays within the
     geographic region of its parents/grandparents. The exact split shape is
     the admin's decision. Topology changes, addressing, and routing stay
     locally scoped, with no global renumbering.
  2. **Operator keys != ledger keys** - control authority never confers the
     ability to forge another node's ledger: control grants operational power,
     never ledger forgery.

# Communication Rule
  - A **node** communicates only with its parent and up to 8 children
    (`OctAddr`, one routing hop per level); it never dials a non-neighbor for
    data or control.
  - A **browser** (user leaf) communicates only with its leaf node - its direct
    parent. Its direct `cawala/control/0` link is used for the join handshake,
    payments, and the direct parent's `Rebase`/`DetachNotice`/`Query`.
  - **Administration follows the same rule**: every admin request is
    **tree-routed** hop by hop (no direct dial to an admin target), and the
    reply follows the same path. Each hop re-signs; the target checks the
    msg-layer-authenticated last hop. `RoutedForward.hop` strings are never
    authority.

# Authority and Administration (current model)
  - Each node persists an explicit **designation set** of administrator
    children in `<data-dir>/admin_state.json`:
    ```jsonc
    {
      "version": 1,
      "admins": ["<child_id>", "..."], // current children, any ChildKind
      "updated_at": 0,
      "updated_by": "local"            // "local" | "<admin_node_id>"
    }
    ```
    Entries must be current children of the node. A child of **any** kind - a
    child node or a browser leaf - may be designated, and all designated
    administrators hold equal, full rights.
  - There is **no** priority order, TTL, lease, epoch, automatic failover,
    grant, or scope, and no `senior`/senior-child role. **Browsers have no
    automatic authority**: a browser is designated like any other child.
  - The only authorization question a node asks is: *is the authenticated
    direct neighbor that handed me this request one of my designated
    administrators?* (or the origin is the node's own operator key).
  - **Who may change the set**: the **local operator** via CLI (always) and any
    **currently designated administrator** (remotely, routed, via
    `AdminDesignate`/`AdminRevoke`). A locked-out node is recovered by local CLI.
  - **Local CLI** `cawala-node control admin add|remove|list` always works
    (operator key + `<data-dir>` on the host) and is the universal fallback.
  - **Reach is transitive hop by hop**: to reach an ancestor, every link on the
    path must designate the next child. A browser's upward reach is the strict
    ancestor chain (with the node-id discovery walk), bounded by each ancestor's
    own designation set.
  - The browser never holds a node operator or ledger key; it signs admin
    requests with its own operator key and the node applies them under its own
    authority. A browser's automatic authority was removed; its reach comes only
    from being a designated child somewhere on its ancestor chain.

# Tech Stack (verified against Iroh's current state, 2026-07)
| Layer | Choice |
| --- | --- |
| Nodes | Rust + iroh 1.0.3 (stable, API frozen since 1.0.0) |
| Node<->node msg | Custom QUIC-stream protocol - ALPN + length-prefixed postcard |
|  | framing (or irpc for RPC). NOT gossip/docs/blobs - wrong fit |
| Web<->node | Small Rust wasm-bindgen wrapper crate (no npm WASM SDK exists) - |
|  | same custom protocol over relayed e2e-encrypted connection |
| Web client | TypeScript PWA on GitHub Pages - no COOP/COEP/SharedArrayBuffer/ |
|  | service worker needed (n0 browser-echo demo proves it) |
| Relay | Browser clients cannot do direct UDP - need reachable relays. |
|  | Public N0 relays for dev; self-hosted iroh-relay on VPS for |
|  | sovereignty |
| Persistence | Ed25519 SecretKey persisted to file (required, or node ID changes |
|  | every run); ledger store via redb-backed iroh stores |
| Location DB | Separate small SQLite service - hint only, never authority; leaf |
|  | validates and issues final address |

# Deployment Model
  A node is a separate process (the cawala-node binary) with its own data
  directory (SecretKey, topology record, ledger). Physical provisioning is
  out-of-band - bare process, systemd, or docker as convenience; multiple
  nodes per server via separate data dirs. "Creating a node" in the network
  sense = control-plane identity + link operations, not a server command.

# Architecture Summary
## Addresses
  - Dot-separated octal digits, one per tree level. Nodes at depth d have
    d+1 digits; users = leaf address + 1 digit.
  - Identity = immutable Iroh NodeId; address is a routable position that may
    change.
  - Routing = longest-prefix match with O(8) routing tables. No hard cap on
    tree depth; depth grows with subdivision.
## Topology Changes (v1: manual, downward-only)
  - Automatic node splitting is deferred to post-v1 (decision 8). In v1, a
    node's administrator can create new nodes and edit the child/parent links
    of nodes they administer (their own node, and via designation, the nodes
    whose designation sets reach them). This is how a full node is split
    manually.
  - A split is a downward subdivision, and the node's admin decides the exact
    arrangement: they may create one or more new nodes under the full node and
    redistribute the full node's children among them (e.g., create three new
    nodes that become the only children, then move the old children under
    those new nodes). Every descendant stays within the full node's region, so
    geographic containment holds by construction. Ancestors are untouched and
    prefix routing still works. Location DB rows are hints only and are
    updated by the admin.
  - Moved-pointers are **rejected, not deferred**: in-flight messages to a
    just-moved address fail and are retried via a fresh address discovered out
    of band (no redirects, no pointers).
  - Strict 8-cap applies at every level, including the root (decision 2).
    Downward subdivision needs no free ancestor slot and there is no hard
    depth cap; the per-node 8-cap is the only topology limit. The rare
    coordinated renumbering event remains deferred with automatic
    splitting.
## Trust
  - Authority = the node's explicit designation set plus the msg-layer
    authenticated last hop, over operator-key signing. Operator keys != ledger
    keys.
  - Control = change the designation set, approve joins, create nodes + edit
    child/parent links (topology), config, value issue/burn (bounded per admin
    child by the operator-side `value_policy.json`, keyed on the requesting
    child's operator key), per-child credit limits.
  - Every balance mutation is signed + append-only + visible to all children;
    any child can exit/detach.
  - Failed parent: automatic foster-parent recovery is **cut**. Reconnection is
    out of band - leave (if needed) + invitation - informed by a signed
    stranded-claim evidence bundle a prospective new parent may choose to
    honor.
## Accounts & Double-Entry
  - Each account is a single obligation with two views: the account an
    internal node holds for a child is a **liability** of that node and an
    **asset** of the child. Both sides mirror the same signed balance; any
    mismatch is detectable.
  - Ledger shape: an internal node holds at most 8 liability accounts, one per
    child node; a leaf node holds at most 8 accounts for its users; every
    non-root node also holds exactly one asset account with its parent. The
    8-account cap is a per-node fan-out limit, independent of tree depth.
  - Per-node accounting equation: Assets (the account with the parent) minus
    Liabilities (accounts held for children/users) equals Equity. The root has
    no parent account, so its books are liabilities plus equity (negative
    equity = value issued into the tree).
  - Transfers conserve value: a payment posts to two accounts that are both
    held by the common parent (an intra-parent move between sibling rows) or by
    the least common ancestor (cross-subtree settlement, cascading down each
    branch one balanced hop at a time).
  - Issue/burn is the only exception: an admin increasing or decreasing an
    account posts against the node's own equity, so value enters or leaves the
    closed system only through signed issue/burn entries.
## Settlement
  - Cross-subtree payments settle at the least common ancestor (LCA) between
    prefunded settlement accounts - prefunded only, no overdraw (decision 5).
  - Periodic netting reconciles balances.
  - Value creation/destruction = signed issue/burn entries propagated with
    ledger commitments.
## Accepted Risks (cannot be guaranteed in this model)
  - Payment-time double-spend prevention across subtrees (detectable at
    netting instead).
  - Defense against colluding parent + designated administrator.
  - Privacy from routing-path nodes.
  - Nodes are intentionally not zero-trust.
  - Address/key identity binding is routing-based, not cryptographically distributed:
    fabricated non-neighbor hops and address/key substitution are detectable (audit,
    netting, carried-prefix Phase 2, `EdgeClose`) but not preventable - signed
    topology/registry distribution is **rejected** (decision 10).
  - In-flight messages to just-moved addresses fail during manual topology
    rewires (v1; moved pointers are **rejected** - retry with fresh addresses
    discovered out of band; automatic splitting is deferred).
  - A compromised designated administrator reaches every ancestor for which its
    parent chain is designated - potentially the root, with full rights. This
    is by design (transitive hop-by-hop reach); local CLI is the recovery tool.
## Anonymity
  - Transmit only: addresses, NodeIds, amounts, coarse timestamps,
    commitments.
  - Never transmit: names, free-text memos (E2E-encrypted to recipient leaf
    only if needed), full balances, IPs.
  - Accepted tradeoff: subtree-level pseudonymity, not transaction privacy.

# Current Storage & Wire Facts
  - On-disk control-plane state under `<data-dir>`: `admin_state.json`,
    `value_policy.json`, `control_seen.json`, `control_audit.jsonl`,
    `pending_joins.json`, `outbound_join.json`, `ledger_peers.json`,
    `node.json`, plus `secret_key`, `ledger_key`, and the ledger store.
    `admins.json` no longer exists.
  - Wire versions: **control format 8** (mint 8; accept 7|8), **routed control
    2** (the carried grant was dropped), **reply version 5**
    (`AdminSnapshot` carries `admins`); ledger entry format 4; node on-disk
    ledger meta format 3; settlement payload 3; browser ledger payload 3;
    browser ledger state 4; browser local state 1.
  - Hard breaks: recreate `node-data` and rebuild the wasm bundle when a format
    changes (control 8 / routed 2 / reply 5 are the current admin-refactor
    breaks).

# Roadmap
  - Base network M0-M5 is delivered on `main` (records in `PLAN-ARCHIVE.md`).
  - **Administration refactor P0-P5 is delivered, gate-passed, merged to `main`,
    and pushed** (`ec31535`): P1 authority core (control format 8, routed 2,
    reply 5, `admin_state.json`), P2 delegated-grant subsystem deleted, P3 wasm
    client always-routed admin, P4 web lock gate + admin page + ancestor up/down
    + simplified nav, P5 docs consolidation (R2).
  - Shipped as **one lockstep release** (the format/routed changes do not
    interoperate with the old wasm/web).
  - Deferred / settled backlog: control version negotiation (single lockstep
    codebase); no `OctAddr` depth cap; foster-parent recovery cut; moved
    pointers rejected; signed topology/registry distribution rejected; browser
    create-child deferred (provisioning stays invite/CLI).

# Administration Refactor Requirements (R1-R9 intent)
  1. **R1 - all admin is tree-routed.** Every admin exchange (`AdminQuery`,
     `AdminLedgerQuery`, join approve/reject/redeliver, topology, value,
     designation changes) is carried hop by hop over `MSG_CONTROL_V1`; there is
     no direct `cawala/control/0` dial to an admin target. The direct ALPN
     remains only for the join handshake and the browser's own-leaf
     payments/notices.
  2. **R2 - docs consolidation.** One job per doc; delivered history archived in
     `PLAN-ARCHIVE.md`; `PLAN.md` is living design + roadmap; `HANDOFF.md` stays
     small; `web/README.md` matches the current app.
  3. **R3 - delegated grants removed.** `AdminGrant`/`AdminGrantV2`,
     `admins.json` + verification, the `cawala://admin` bundle, the
     `control admin grant|revoke|list` CLI, the browser `cawala.admin.*` store
     and seed protection, and the `AdminScope` set are all deleted. Authority
     derives from designation.
  4. **R4 - explicit per-node designation.** Persisted `<data-dir>/admin_state.json`;
     any child kind may be designated; all designated admins are equal and
     full-power; **no priority, TTL, lease, epoch, or automatic failover**;
     browsers have no automatic authority.
  5. **R5 - superseded.** The priority-ordered list and TTL/lease failover are
     removed; `senior`/`senior_child` carries no role. The local CLI covers the
     all-admins-offline case.
  6. **R6 - admin lock gate.** Admin actions (issue/burn, invite creation,
     pending-join approve/reject, node topology/leave/join) live on a dedicated
     **Admin** page, locked by default behind a policy acknowledgement of
     `ADMIN_POLICY.md`; unlocking is in-memory and resets on reload.
  7. **R7 - up/down target switching.** While unlocked, the administered node is
     changed with up/down buttons over the ancestor chain (no selector/dropdown).
  8. **R8 - simplified UI.** Nav: **Home**, **Join** (only while unjoined),
     **Accounts**, **Activity**, **Settings**, **Admin**.
  9. **R9 - local CLI is the universal fallback.** The operator with filesystem
     access to `<data-dir>` and the operator key can always administer locally;
     `control admin add|remove|list` is guaranteed.

## Resolved decisions (2026-10-03 / 2026-10-04)
  - Scopes are dropped; every designated administrator is full-power. Value
    issue/burn is bounded per admin child by the operator-configured,
    deny-by-default `value_policy.json`, keyed on the requesting child's
    operator key.
  - Authority is the explicit designation set; no automatic seeding, no
    priority/lease/epoch, no failover. First admin is bootstrapped via local CLI.
  - The format-8 control break (and routed 2 / reply 5) is accepted; lockstep
    release.
  - The policy document is `ADMIN_POLICY.md` in-repo, rendered in the unlock
    dialog; acknowledgement is stored by document hash so an edit invalidates it.
  - Admin mode is locked by default and does **not** persist across reloads.
  - Up/down traverses the strict ancestor chain (with the node-id discovery walk).
  - Delivered-phase docs are **archived** to `PLAN-ARCHIVE.md` (not deleted);
    git history remains the backstop.

# Top Risks
  1. Iroh WASM maturity -> de-risked by the M0 spike (retired).
  2. Cross-subtree double-spend/inflation -> prefunded LCA + Merkle ledgers +
     adversarial netting harness (built in M2/M5).
  3. LCA concentration (deep tree = high nodes become de-facto banks) -> no
     depth cap; mitigate by proactively splitting hot levels and accepting the
     hub role with capacity planning.
  4. Administrator abuse -> key separation, exit rights, audit trail, revoke
     designation, and local CLI override are the checks (no senior special case).
  5. Control-key compromise cascading up via designation -> transitive reach is
     bounded only by each ancestor's designation set; scoped operator keys and
     documented compromise paths, plus local CLI recovery.
  6. Address instability from manual rewires -> downward-only subdivision
     (geography preserved by construction), admin link editing, location-DB
     (hint) updates, accepted retries in v1 (moved pointers rejected, no
     redirects; automatic splitting deferred).
  7. Scope creep (no DHTs/ZK/consensus) -> freeze v1: one credit message type,
     one ledger format, 8-entry routing tables.

# Decisions
## Current
  1. **Authority**: explicit per-node designation set; any child kind; all equal;
     no priority/TTL/lease/failover; browsers no automatic authority; local CLI
     universal fallback. (2026-10-04, supersedes the seniority rule.)
  2. **Root cap**: strict 8-cap at every level including root; "everything full"
     handled by a rare, coordinated renumbering event. Depth growth is
     independent of the root cap (via local subdivision).
  3. **Currency model**: single nominal unit + per-node trust limits.
  4. **Balance changes**: any designated administrator (or the local operator)
     may issue/burn, bounded per admin child by `value_policy.json`; mitigated
     by exit rights + audit trail + key separation. (Supersedes the sole
     senior-child admin.)
  5. **Overdraw**: prefunded only - no uncollateralized credit.
  6. **Frontend framework**: Svelte (lightest, great PWA support).
  7. **Relay**: public N0 relays for development; self-hosted iroh-relay on a VPS
     before public launch.
  8. **Node splitting**: automatic split algorithm deferred to post-v1; moved
     pointers are **rejected** (a changed topology changes the parent-child
     trust relationship, so an in-flight transaction must fail and be retried
     with fresh addresses discovered out of band - no redirects). Splitting is a
     manual administrative operation; splits are downward-only (subdivision),
     preserving geographic containment.
  9. **Tree depth**: no hard cap on depth. The only topology limits are the
     per-node 8-cap and geographic sense. Mitigate LCA concentration by
     proactively splitting hot levels (see risk 3).
  10. **Signed topology/registry distribution**: **rejected**. The live network
     topology (each node's authoritative parent/child links, healed by
     `Rebase`/`RebasePull`) is the source of truth; there is no distributed
     snapshot to sign, cache, refresh, revoke, or reconcile. Consequence:
     fabricated non-neighbor hops and address/key substitution remain
     **detectable** (audit, netting, carried-prefix Phase 2, `EdgeClose`) but
     not **prevented** - consistent with the accepted risks.

## Superseded (recorded for history)
  - **Seniority rule** (earliest `date_joined` = most senior, senior child
    controls its parent; reset/keep on moves) - removed 2026-10-04 in favour of
    explicit designation; `senior`/`senior_child` carries no authority or
    ordering role.
  - **Delegated admin grants / scopes / browser `cawala.admin.*` store** -
    removed by R3; full rights now come from designation, not a grant.
