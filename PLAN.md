# Cawala - Project Plan

  Status: Living design + roadmap. Delivered-phase history (M0-M5 and the
  superseded unified-console P1-P6) lives in `PLAN-ARCHIVE.md`; the short current
  handoff is `HANDOFF.md`. Last updated 2026-10-12.

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
  Prebuilt static Linux binaries, a systemd template unit
  (`packaging/cawala-node@.service`), and an installer (`packaging/install.sh`,
  published by `.github/workflows/release.yml`) cover the common VPS path.

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
    child/parent links (topology), config, value issue/burn (uncapped; authorized
    solely by the designation set, with burn bounded by the account balance),
    per-child credit limits.
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
    `control_seen.json`, `control_audit.jsonl`,
    `pending_joins.json`, `outbound_join.json`, `ledger_peers.json`,
    `node.json`, plus `secret_key`, `ledger_key`, and the ledger store.
    `admins.json` no longer exists.
  - Wire versions: **control format 9** (mint 9; accept 7|8|9 - adds variant 23
    `Capabilities` and variant 24 `RegisterEthAddress`), **routed control 2**
    (the carried grant was dropped), **reply version 6** (`AdminSnapshot`
    carries `admins`; `ControlReply::Capabilities` is discriminant 9); ledger
    entry format 4; node on-disk ledger meta format 3; settlement payload 3;
    browser ledger payload 3 + **v4** (the browser sends V4 `OrderV4` with an
    `EthIdentity`; it still receives V3 `OrderResult`); browser ledger state
    **5**; browser local state 1; user-identity record **3**; portable identity
    bundle **2**.
  - Browser storage keys. **Authoritative-local** (never discard):
    `cawala.identity.v1` (the Ed25519 transport seed; mnemonic-derived on new
    installs, a legacy random seed is preserved) and `cawala.user-identity.v1`
    (the R3 record: EIP-55 address + the derived secp256k1 secret used to sign
    V4 orders; the **mnemonic is never stored**; **v3** adds the optional
    passkey wrap `{credentialId, salt, iv, ct}` and allows the plaintext secret
    to be absent while the passkey lock is engaged - v2 records still import),
    plus the TOFU anchor fields `pinned_ledger`/`pinned_leaf_keys` carried inside
    `cawala.ledger.v1`.
    **Best-effort cache** (absence tolerated): `cawala.state.v1:<nodeId>` and
    `cawala.ledger.v1:<nodeId>`. **Non-authoritative local**: `cawala.recovery.v1`,
    `cawala.admin.policy.v1`, `cawala.value.pending.v1`.
  - Leaf-key pinning is **fail-closed** (F6). A pin is only *established* trust
    when explicitly confirmed: the routing pin installed from the authenticated
    `JoinApproval.parent_ledger` is `confirmed`, a first-receipt trust-on-first-use
    pin is `unconfirmed`, and a *different* key presented for an already-pinned
    leaf is recorded as a change and never adopted. `pin_status()` reports the
    aggregate (`none`/`unconfirmed`/`confirmed`/`changed`); `confirm_pin()` /
    `confirmPin()` keeps the existing key, flips it `confirmed`, and persists.
    Bumping the ledger state to v5 discards a v4 blob on import (fail-closed reset
    to `unconfirmed`); the web preserves an unreadable blob at boot (boot-scoped)
    but a later persist overwrites it.
  - Hard breaks: recreate `node-data` and rebuild the wasm bundle when a format
    changes (control 9 / routed 2 / reply 6 / ledger payload v4 / browser ledger
    state v5 are the current portable-client breaks).

# Portable-Client Refactor (R1 / R1b / R2 / R3)
  The web app is made host-agnostic and identity-portable. The base refactor
  (R1 / R1b types / R2 / R3) was delivered on branch `refactor/portable-client`
  and merged to `main` as PR #2 (`8ccab19`); the follow-up work (F1-F6) is on
  branch `refactor/portable-client-followups` (6 commits, not yet merged). The
  frozen design is `.slim/deepwork/portable-client-refactor-spec.md`
  (Addenda A/B/C); the phase log is `.slim/deepwork/portable-client-refactor.md`.
  - **R1 - node as source of truth over a best-effort local cache.**
    localStorage is reclassified, not removed: the node is authoritative for
    account balance, ledger height, and admin/topology views (re-validated via
    `ledger_status()`/`balance_receipt`). `cawala.state.v1:<nodeId>` /
    `cawala.ledger.v1:<nodeId>` are best-effort cache - a missing or corrupt
    blob never blocks boot (empty local state, re-validate from the node). The
    identity seed and the TOFU pins stay **authoritative-local**. New pure wasm
    read getters (`pending_orders`, `pinned_leaf_keys`, `pending_join_outbound`,
    `client_state_info`; extended `JoinStatus`, `LedgerStatusDto`,
    `SettlementRecordDto`) expose locally-held state without a wire change.
  - **R1b - versioned node client API (complete).** The node-read surface ships
    as the R1 getters, and both halves of the `Capabilities` handshake ship:
    control variant 23 + `ControlReply::Capabilities` (discriminant 9, reply 6).
    The **client half** (F1) sends variant 23 (`ClientNode::node_capabilities`, advertising
    `CLIENT_API_VERSION`) on boot (when joined) and after a successful join,
    mapping reply discriminant 9 to a `NodeCapabilitiesDto`
    (`available` / `clientApiVersion` / `features` / `supportsEthIdentity`). An
    old node's decode failure, an unexpected reply, or a timeout is a graceful
    "capabilities unavailable" (`available === false`), never a hang.
    `CONTROL_REPLY_VERSION` stays inert (the version rides in the payload). The
    web facade (`getNodeCapabilities()`, `apiCapabilities.nodeSupportsEthIdentity`)
    gates ETH-identity registration on `NODE_FEATURE_ETH_IDENTITY`, degrading to
    the legacy best-effort path when capabilities are unavailable.
  - **R3 - user-level secp256k1 identity.** A secp256k1 key from a BIP-39
    mnemonic (`m/44'/60'/0'/0/0`; EIP-55 address) is the user's identity, done
    in Rust wasm (`k256`/`sha3`/`coins-bip39`) so key material never reaches JS
    for signing. The **transport Ed25519 key is mnemonic-derived** (BLAKE3
    domain-separated over the BIP-39 seed → Ed25519 seed), so one mnemonic
    restores both the ETH identity and the iroh NodeId on any host. The user's
    signature is **additive** to the Ed25519 envelope and rides the msg/ledger
    plane: a new `LedgerPayloadV4`/`OrderV4 { order, auth, payee_addr, eth }`
    with an EIP-712 digest (low-`s` + validated recovery id). The address is
    anchored via control variant 24 `RegisterEthAddress` as a **write-once**
    `ChildEntry.eth_address`; rotation is verified against the **incumbent**
    anchor (the old key authorizes). The direct parent enforces a fail-closed,
    **version-scoped** anchor gate: an anchored sender MUST use V4, V1/V2 orders
    are rejected (`apply_same_leaf_order`/`handle_settlement_order`, not the
    downstream forwarders). The derived secret is persisted; the **mnemonic is
    never persisted**. F2 adds end-to-end node integration tests
    (`crates/node/tests/eth_identity.rs`) driving the real control transport for
    registration + rotation (`Capabilities` reply included).
  - **R3 follow-ups (F3/F4/F5).** The **portable identity bundle is v2**: it
    carries the derived secp256k1 `ethSecretHex` + EIP-55 address alongside the
    transport seed and blobs, so import re-keys the ETH identity on a new device
    (v1 bundles still import - seed + blobs, no ETH identity; crypto unchanged:
    PBKDF2-SHA-256 600k, AES-256-GCM, `nodeId` AAD). **Client anchor rotation**
    is delivered: the incumbent key signs the node's rotation challenge, the new
    key is adopted only on acceptance, and the commit is **idempotent** - the
    signed frame is retained and resent unchanged on an ambiguous transport
    failure, with a `Replay` reply to the unique nonce reconciled as applied, so
    local and parent anchors cannot silently diverge. The web has a dedicated
    rotate surface (enter or generate a phrase, address-diff confirm) and
    persists the new secret only on success. **Optional passkey lock** is
    delivered: a WebAuthn **PRF** result is run through HKDF-SHA256 into an
    AES-256-GCM wrap key over the stored secp256k1 secret; enrolling moves the
    user-identity record to **v3** (wrap present, plaintext secret removed) so a
    locked boot installs nothing until a passkey unlock or phrase restore. The
    passkey is an unlock factor, never a signer (P-256 ≠ secp256k1); support is
    feature-detected with no weaker gate-only fallback; the recovery phrase
    remains the only recovery path.
  - **R2 - dual-target packaging.** Wasm is built **release**; a single-file
    `dist-single/index.html` inlines all JS/CSS + base64 wasm and initializes
    from **bytes** (never `instantiateStreaming` on `file://`). On `file://` the
    service worker is skipped and the passkey panel is hidden (mnemonic unlock
    only). The **served** deployment stays the multi-asset `dist/`; the
    single-file build is the distributable for `file://`/zip/email/header-less
    hosts (see `DEPLOYMENT.md` for the CSP caveat).
  - **Accepted limits:** ETH authorization is not embedded in the frozen ledger
    `Entry`, so audit/replay of authorization is only verifiable at the live
    parent (an `ENTRY_FORMAT_VERSION` break is deferred). Pre-anchor squatting:
    before a child's anchor exists, any holder of that child's transport key may
    register their own ETH address for it (first-writer TOFU); the rotation rules
    protect an *existing* anchor, not the initial registration. The atomicity
    guarantee covers the rotation commit only; a definitive rejection leaves the
    incumbent in place. See the F6 notes above for the pin-trust limits.
  - **Identity/deployment decisions:** identity is user/browser-level only (nodes
    and iroh NodeIds stay Ed25519); derived secrets are persisted on-device
    unencrypted so a reload needs no unlock, and the mnemonic (off-device
    recovery credential) is the only portable restore path. The transport seed is
    mnemonic-derived **only when no stored seed exists** (a legacy seed is
    preserved, keeping its NodeId and nodeId-scoped blobs/TOFU pins valid).

# Roadmap
  - Base network M0-M5 is delivered on `main` (records in `PLAN-ARCHIVE.md`).
  - **Administration refactor P0-P5 is delivered, gate-passed, merged to `main`,
    and pushed** (`ec31535`): P1 authority core (control format 8, routed 2,
    reply 5, `admin_state.json`), P2 delegated-grant subsystem deleted, P3 wasm
    client always-routed admin, P4 web lock gate + admin page + ancestor up/down
    + simplified nav, P5 docs consolidation (R2).
  - Shipped as **one lockstep release** (the format/routed changes do not
    interoperate with the old wasm/web).
  - **Portable-client refactor (R1 / R1b / R2 / R3) is delivered and merged to
    `main`** (base PR #2 `8ccab19`; follow-ups F1-F6 `523cef9`); the F6 pinning
    follow-ups (F7) are delivered on `main` too. Wire: control format 9, reply 6,
    ledger payload v4, browser ledger state v5. This is the next lockstep
    release.
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
    issue/burn is **uncapped**, bounded only by the designation set and the local
    CLI; burn additionally cannot exceed the account balance. There is no value
    policy file.
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
     may issue/burn. Issue is uncapped; burn is bounded by the account balance.
     Mitigated by designation + local CLI + exit rights + audit trail + key
     separation. (Supersedes the sole senior-child admin.)
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
  11. **Identity scope**: user/browser-level secp256k1 (BIP-39) only; nodes and
      iroh NodeIds stay Ed25519. The user signature is additive to the Ed25519
      envelope and rides the msg/ledger plane, not control. (2026-10-12,
      portable-client refactor.)
  12. **Key persistence & portability**: persist *derived* secrets on-device
      unencrypted (transport seed + ETH secret) so a reload needs no unlock; the
      mnemonic is the root of trust and is **never persisted**. The transport
      Ed25519 key is mnemonic-derived only when no stored seed exists; a legacy
      seed is preserved. An **optional passkey lock** (WebAuthn PRF →
      HKDF-SHA256 → AES-256-GCM key-wrap) can seal the ETH secret on-device;
      passkey is an unlock factor, never a signer. The portable identity bundle
      is **v2** and carries the derived ETH secret/address (v1 still imports).
      (2026-10-12; passkey lock + bundle v2 added 2026-10-12 follow-ups.)
  13. **Packaging/deployment**: the served deployment stays the multi-asset
      `dist/`; `dist-single/index.html` is a distributable single file for
      `file://`/zip/email/header-less hosts. Do not serve `dist-single` under a
      host CSP that lacks `script-src 'unsafe-inline'` (header + meta CSP
      intersect and blank the inline bundle). On `file://` passkeys and service
      workers are unavailable (mnemonic unlock only). (2026-10-12.)
  14. **Leaf-key pinning is fail-closed**: a pin is only established trust when
      explicitly confirmed; a first-receipt TOFU pin is `unconfirmed` and a
      different key presented for a pinned leaf is recorded (never adopted).
      `LEDGER_STATE_VERSION` 5 resets old v4 blobs to `unconfirmed` so the user
      re-confirms. (2026-10-12, F6.)

## Superseded (recorded for history)
  - **Seniority rule** (earliest `date_joined` = most senior, senior child
    controls its parent; reset/keep on moves) - removed 2026-10-04 in favour of
    explicit designation; `senior`/`senior_child` carries no authority or
    ordering role.
  - **Delegated admin grants / scopes / browser `cawala.admin.*` store** -
    removed by R3; full rights now come from designation, not a grant.
