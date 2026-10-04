# Cawala - Plan Archive

Historical record: delivered build increments and the superseded/settled
administration-refactor plans. The **living design and current roadmap live in
`PLAN.md`**; this file exists only so that accurate delivered detail is preserved
without cluttering the living plan.

Contents:

- **Part 1** - Delivered milestones (M0-M5).
- **Part 2** - Unified node administration console (P1-P6; superseded by the
  topology-admin refactor).
- **Part 3** - Topology-derived administration refactor plan (historical; the
  R1-R9 requirements and the phased P0-P5 plan).
- **Part 4** - Refactor requirements (historical, from the former
  `REFACTOR.md`).

> Authority-model note: the delegated grants, scopes, browser `cawala.admin.*`
> key store, priority list, TTL/lease/epoch failover, and `senior`/senior-child
> described in Parts 2-4 were superseded on 2026-10-04 by the explicit per-node
> **designation set** now documented in `PLAN.md`. The later v2 amendment inside
> Part 3 records that supersession. None of the superseded terms are current.

---

**Part 1 - Delivered milestones (M0-M5).**

# Milestones (risk-sequenced)
  1. **M0 - WASM spike** (DONE 2026-08-21): wasm-bindgen wrapper crate <-> Rust
     node message round-trip over relay, hosted on GitHub Pages. De-risks the
     biggest unknown first. Pin all versions.
     - Verified end-to-end: node relay ping/pong test, wasm compile + glue,
       vite build, and a Node.js smoke test driving the wasm module against a
       live node over the N0 relay (round-trip OK).
     - Env requirements for local wasm builds: wasm32 target, wasm-bindgen-cli
       0.2.122, and clang (ring needs a C compiler on wasm32).
     - To finish: enable GitHub Pages -> "GitHub Actions" in repo settings
       (workflow in .github/workflows/pages.yml); then confirm in a real
       browser (web/README.md has the manual checklist).
  2. **M1 - Topology & addressing** (DONE 2026-08-21): octal address scheme,
     node identity/persistence, admin topology-editing primitives (create
     node; set/update parent & child links for nodes the admin controls).
     - OctAddr in proto: dotted one-digit-per-level addresses, root "0",
       parent/child/slot/ancestor/lca helpers, no depth cap (decision 9).
     - crates/topology (pure std): attach/detach/move_child with
       downward-only enforcement, validate() invariant walk (link
       reciprocity, single root, no orphans, no cycles, address
       injectivity). 21 unit + 4 property tests (random op sequences,
       routing reachability, address consistency after moves). The property
       tests caught an attach-cycle bug, which was fixed.
     - Node: SecretKey persisted to <data-dir>/secret_key -> stable
       EndpointId across restarts (verified); links-only record persisted to
       <data-dir>/node.json (never derived addresses); clap CLI: run / init /
       topo (show, attach-child, detach-child, set-parent, unset-parent).
     - Seniority via date_joined (decision 1): each child entry records when
       it first joined; CLI attach-child --date-joined keeps a moved child's
       original date or resets to now when omitted.
     - 59 workspace tests green, including the relay ping/pong test.
   3. **M2 - Ledger & settlement** (DONE 2026-09-10): append-only signed
      Merkle-committed ledgers, operator/ledger key separation, prefunded-only
      LCA settlement + netting, adversarial double-spend harness.
      - New pure, sync, wasm-safe crate `crates/ledger`: double-entry postings
        over `{Parent, Child(NodeId), Equity}` validated by one conservation +
        non-negativity rule; versioned canonical signed format
        (`ENTRY_FORMAT_VERSION`) with golden vectors for every entry body.
      - Append-only per-entry hash chain plus an RFC 6962 Merkle tree (blake3,
        domain-separated) with entry-inclusion and account-state proofs; signed
        periodic commitments (`SignedCommitment`, `BalanceAttestation`) and a
        genesis-anchored `verify_chain`.
      - Key separation: the operator key (`<data-dir>/secret_key` -> NodeId)
        authorizes intent (orders, issue/burn); a distinct ledger key
        (`<data-dir>/ledger_key`) signs entries and commitments and never leaves
        the node. `PeerRegistry` binds key -> identity (users carry an operator
        key only) with decode-time re-validation.
      - Prefunded-only LCA settlement: `plan_transfer` builds the
        ascend/LCA/descend cascade from `OctAddr::lca`, preflights every debit
        and credit, and `execute_plan` applies it atomically (staged clone).
      - Netting (`net`) detects commitment forks, chain-invalid histories,
        edge mirror mismatches, route redirects, replay/double-spend
        (`payment_id` in >1 cascade) and reconstructed overdraw, and only emits
        net transfers when the books are clean.
      - Adversarial harness proves detection at netting: replayed order,
        equivocation, a fully-mirrored branch redirect (all hops append, caught
        only by route reconstruction), mirror tamper, substituted `payment_id`,
        and overdraw.
      - Node integration: `<data-dir>/ledger_key`, `<data-dir>/ledger_peers.json`,
        a filesystem append-only `FileLog` (length-prefixed postcard frames,
        fsync, replay-on-open re-derives balances), and CLI
        `ledger init | show | verify`.
      - Tests: 177 in `crates/ledger` (138 unit + 12 ledger + 9 netting +
        3 property + 15 settlement) and 27 node lib tests; workspace clippy
        clean. The relay ping/pong test still requires network.
   4. **M3 - Messaging/routing protocol** (DONE 2026-09-10): ALPN framing,
      envelope (src, dst, msg_id, type, nonce, payload, hop_chain),
      longest-prefix routing, replay/ordering protection.
      - New pure, wasm-safe crate `crates/msg`: versioned `Envelope` with a
        frozen postcard field order and an allocation-bounded hop-chain decode,
        `Ack`/`AckStatus`/`RejectReason`, hierarchical `next_step`/`route` with
        unique-path `validate_hop_chain` + `append_hop`, and a bounded in-memory
        `SeenSet` replay guard keyed on `(origin node, msg_id)` with
        `unobserve` rollback so transient forward failures are retryable.
        `cawala/msg/0` ALPN; `MAX_NODE_ID_LEN` and a per-frame `MAX_MSG_FRAME`
        cap blunt pre-auth allocation. Generic length-prefixed postcard framing
        (`read_framed_with_limit`) moved into `crates/proto`, ping unchanged.
      - Node integration: `crates/node/src/msg.rs` (`MsgHandler` with the
        validate -> chain -> self-in-chain -> neighbor -> replay -> route order;
        `RoutableSnapshot` derived from the recorded asserted address;
        `spawn_msg_node`/`send_envelope` hop-by-hop forwarding); persisted
        `address` field with `topo set-address`/`unset-address` and `msg send`.
      - Browser integration: `cawala/msg/0` accept as a leaf plus
        `spawn_with_address`/`send_envelope` (timeout-bounded)/
        `try_recv_envelope`; the M0 ping API is unchanged.
      - Trust/scope: envelope metadata (src, hop_chain, nonce, ttl, type) is
        unauthenticated by design; authenticity is payload-level at the
        destination, each hop authenticates only its direct QUIC neighbor, and
        `SeenSet` is a best-effort (non-security) guard. Ordering is payload-
        level (M2 `seq`/`height`/`prev_hash`), not a transport guarantee; the
        envelope `nonce` is carried but not used for dedup.
      - Tests: workspace green (ledger 177, msg 28, node 52 incl. 12 hermetic
        multi-node messaging tests, proto 18, topology 25, relay ping/pong);
        `clippy --workspace --all-targets -D warnings` clean; wasm target
        check clean. Independently reviewed (routing/replay); the three
        network-reachable findings (decode amplification, unbounded node-id
        retention, retry poisoning) were fixed and re-verified.
   5. **M4 - Control & web client** (DONE; PHASE 1 DONE 2026-09-10; USER-LIVE
      WIRING + BROWSER VALUE MESSAGING V1 DONE 2026-09-13; remaining increments
      DONE):
      senior-child control flow, indirect multi-node control, Svelte PWA,
      join flow (parent approves -> leaf issues address). Onboarding is
      invite-based so nodes stay undiscoverable; the location **suggestion**
      service is out of scope (an optional, independently hosted companion
      that only suggests an octal address from lat/lon or a map click).
      - New pure, wasm-safe crate `crates/control`: versioned signed control
        payloads (`JoinRequest`/`JoinApproved`/`JoinRejected`, `CreateChild`,
        `DetachChild`, `MoveChild`, `SetAddress`, `Query`) using the same
        operator-key domain-separated signing as `ledger::auth`,
        `verify_control` against the peer registry, `senior_child` (earliest
        `date_joined`, ties by node id), a bounded reply/query surface
        (`ControlReply`, `NodeSnapshot`), and hardened bounds
        (`MAX_CONTROL_FRAME` 64 KiB; capped node-id/location-hint/reason
        strings).
      - Node integration: direct `cawala/control/0` protocol (one
        request/response per bi stream, not tree-routed), `ControlNode`
        authorizing self-admin or the senior child, persisted pending/outbound
        join state, the join handshake (apply -> parent approves -> parent
        issues slot/address), and the `cawala-node control
        join|joins|approve|reject|create-child|detach-child|move-child|
        set-address|query` CLI. Hermetic multi-node join/control tests cover
        non-senior rejection, capacity, snapshot query, and a bounded pending
        queue.
      - Onboarding invite (`crates/control::invite`): a portable
        `cawala://join?parent=<EndpointId>&op=<operator-pubkey>[&slot&exp&label][&relay&ip]`
        URI carrying the parent's EndpointId, a pinned operator key, and
        optional transport hints (`relay` URL / direct `ip`) so the joiner can
        dial without an iroh address-lookup service. The node CLI generates it
        (`control invite`) and consumes it (`control join --invite`); pinning
        the parent operator key closes the phase-1 trust-on-first-use gap on
        `JoinApproved`.
      - PWA (foundation): Svelte 5 shell, dark design-token system, 14 shared
        components, hash router, rune stores, and a single `lib/api.js` adapter
        insulating the UI from the wasm/control surface.
      - Web client live wiring (A' user-live, DONE 2026-09-13): the browser runs
        as a user leaf, not a node admin. `crates/client-wasm` now exposes a
        stable Ed25519 control identity (`generate_secret_key`/`spawn_control`;
        the seed is persisted by the PWA so `endpoint_id == operator key`),
        Rust invite parsing (`parse_invite`), the full join handshake
        (`join_via_invite` -> parent replies Pending -> CLI approves -> parent
        reverse-dials `JoinApproved`/`JoinRejected` over `cawala/control/0`), a
        native-testable local state machine (`export_state`/`import_state`,
        `join_status`, a control-event queue), and a local topology snapshot.
        `api.js` wires the live path with an honest `?mock`/wasm-init fallback,
        a best-effort multi-tab identity lock, and a typed
        `AdminUnavailableError` for admin actions. The invite flow pins the
        invite operator key and polls `getJoinStatus()` while waiting.
      - Hardening (same increment): `ControlNode::seniority()` now excludes
        `ChildKind::User`, so a browser user can never become the senior child
        and mutate its parent's topology; hermetic regression test added.
      - Same-leaf browser value messaging (v1, DONE 2026-09-13): a joined
        browser can now send a same-leaf `Direct` payment and read a
        cryptographically verified balance. `crates/msg::ledger_payload` defines
        the frozen `LedgerPayloadV1` wire variants (`Order`/`OrderResult`/
        `BalanceQuery`/`BalanceReceipt`) carried in `MSG_LEDGER_V1` envelopes;
        `crates/node/src/ledger_service.rs` is the leaf half (open/fund/
        apply/balance-receipt over the persisted `FileLog`, with a `payment_id`
        replay guard rebuilt by replay so duplicates survive restarts). The
        browser signs a `PaymentOrder` with its operator key, the leaf verifies
        and appends a `Direct` transfer, and replies with an `OrderResult`
        carrying a signed balance receipt the browser verifies against the leaf
        ledger key it pins trust-on-first-use (`client-wasm`'s `LedgerStateV1`);
        a retried order is reported `Duplicate` and moves nothing. Outbound
        activity is enumerable from the receipt history; `ledger fund` is the
        explicit, operator-only issue path. `control approve` and `ledger fund`
        run as separate CLI processes against the live node: the service
        re-reads and replays the log before every mutation and authoritative
        read, so those external appends are observed without a restart
        (concurrent appenders remain unsynchronized; see the `LedgerService`
        resync note). The Svelte rune stores were also split into `.svelte.js`
        modules (`router.svelte.js`, `stores.svelte.js`) to fix the runes
        compile error.
      - Verification for the browser-value increment: the hermetic
        `crates/node/tests/ledger_orders.rs` drives the real `cawala/msg/0`
        transport against a leaf with two user children (signed order ->
        `Applied` + verified balance receipt -> balance query -> duplicate with
        no ledger movement -> reopen from disk -> removed record rejects the
        sender), and the network-dependent `web/scripts/smoke-payment.mjs`
        drives two wasm clients through join, CLI approve, CLI fund, a 25 payment
        and both verified balances over N0.
      - Verification for the increment: 17 native client state/DTO tests; wasm
        build + `wasm32-unknown-unknown` check; `clippy --workspace --all-targets
        -D warnings`; `cargo test --workspace`; `npm run build`; and an
        end-to-end `web/scripts/smoke-join.mjs` (browser join -> CLI approve ->
        joined at `0.<slot>`, plus the reject path), network-dependent on N0.
      - Cross-subtree settlement (DONE, `66500f1` + the P4 web increment): a
        browser user under one leaf can pay a user under another leaf, settled
        at the least common ancestor. Ledger reworked to boundary ops + derived
        equity (`ENTRY_FORMAT_VERSION` 3; node ledger `format_version` 2): every
        ledger stores `{Parent, Child}`, `Issue`/`Burn` are child-only boundary
        ops, there is no internal equity account, and rootness is dynamic
        (attach/detach never bricks replay; a stranded `Parent` is preserved).
        Transport is `MSG_SETTLE_V1` over `cawala/msg/0` with `LedgerPayloadV2`
        (`OrderV2` carries the payee address; `OrderResultV2` /
        `SettlementStatusV2` expose applied/duplicate/partial/rejected/
        indeterminate); each expected signer derives and applies its own hop
        (never wire input) with neighbor-verified sender authentication; a
        bounded pending/terminal manager plus a 5 s timeout sweep; and
        per-transaction single-writer locking. Web: a receive-URI send form and
        truthful settlement states. Verification: the hermetic
        `crates/node/tests/settlement_transport.rs` (real transport; success +
        LCA/terminal rejection + forged-hop adversarial + timeout), the hop
        executor differential test vs `execute_plan`, `clippy`, the wasm check,
        `npm run build`, and the network-dependent `smoke-crossleaf.mjs`.
      - Deferred: browser issue/burn (value creation/destruction stays an
        explicit operator-only act - `ledger fund` - and is deliberately not
        reachable from a browser order); remote admin from the browser
        (pending-join listing + approve/reject would need a
        `CONTROL_FORMAT_VERSION` bump and a node operator-key custody
        decision); and tree-routed indirect multi-node control. `MoveChild`
        remains limited to re-slotting under the same node; no control replay
        nonce (authority is re-evaluated live per request). The location
        suggestion service is out of scope for now: a separate, independently
        hostable, non-authoritative companion (lat/lon or map click -> suggested
        octal address); the leaf still validates and issues the final address.
      - Cross-subtree hardening (P5, DONE): `CONTROL_FORMAT_VERSION` 2 carries
        the parent's ledger key in `JoinApproval`; a child persists the parent
        `PeerKeys` row on join, so `carried_hops_match` verifies each carried
        settlement hop under an **address-bound** signer->ledger-key resolver
        (rejecting an entry that names one signer but is signed by another
        registered key); `MirrorMismatch` now carries a
        `MirrorDirection` (unbacked claim vs unmirrored extension).
      - Result-path signature verification (DONE): a settlement result is no
        longer an unpaid claim. The terminal leaf builds an `EntryProofV1` (its
        signed terminal entry + a fresh `SignedCommitment` + an RFC-6962
        `EntryInclusionProof`); the origin cryptographically self-verifies it
        before accepting `Applied`; the browser verifies it end to end against
        the payee leaf's ledger key, pinned out-of-band by the receive URI
        (`ln`/`lk`; TOFU fallback). A missing/invalid proof surfaces as a new
        `unverified` outcome (never success) and the UI says do-not-resend.
        Wire: `SETTLE_PAYLOAD_VERSION` 2, `LEDGER_PAYLOAD_V3_VERSION` 3,
        `LedgerStateV1` v3 (hard break). Accepted residual: the origin binds
        self-consistency only (it cannot know a sibling leaf's key), so a fully
        self-consistent forgery is accepted there - the browser's pinned leaf key
        is the security boundary, and first-use substitution is still possible
        without a URI pin. Equivocation/withholding and negative-claim
        falsification stay out of scope (commitment chains / per-hop signed
        rejections).
      - Commitment chains + netting operator harness (DONE): each node persists
        a prev-linked `<data-dir>/ledger/commitments.log` (`ledger commit`) and
        journals applied orders to `<data-dir>/ledger/orders.jsonl` (dedup by
        hash; only orders with an applied hop, so a rejected order cannot pollute
        the route audit). The offline operator harness
        (`crates/node/src/netting_harness.rs`) merges peer data dirs into the
        `net`/`verify_cascade` inputs (topology from `node.json` records or a
        `--topology` snapshot, one `PeerRegistry`, `LedgerSet`, chains, orders)
        and exposes `ledger net` / `ledger verify-cascade` with stable exit codes
        (0 clean/advisory-only, 1 hard finding or invalid cascade, 2 usage/IO).
        `RouteInvalid` is classified advisory because topology is live state
        (re-slotting can make an honest historical route look invalid); `nets`
        are still gated on zero findings by `cawala-ledger`, so advisories
        suppress them until resolved. No wire change. Verified by a hermetic
        on-disk multi-peer matrix (`crates/node/tests/netting_harness.rs`, 9
        tests incl. a genuine `NetTransfer`, `Replay`, `MirrorMismatch`, `Fork`,
        broken/gapped chain, conflicting registry, advisory, missing chain).
        Known limitation: the loader validates chains strictly, so a same-height
        fork on disk is a hard load error rather than a `Fork` finding; nodes
        themselves keep only local links (self + parent + <=8 children), so the
        whole-tree view lives with the auditor.
      - Carried-prefix hardening, Phase 1 (DONE): every carried settlement hop
        is now internally hardened - its entry must be signed by the `ledger_id`
        it declares and must have the role-canonical posting shape
        (`cawala_ledger::entry_hop_accounts`), independent of whether the signer
        is resolvable. The previously silent unresolvable-signer case now logs
        once per distinct signer address (bounded). No wire change. Residual: a
        fabricated non-neighbor hop is still only structurally checked (no
        address<->key binding), which is evidence-integrity only in the depth-1
        route. (Superseded by the next entry.)
      - Carried-prefix Phase 2 (DONE): `SETTLE_PAYLOAD_VERSION` 3; `SettleHopV3`
        carries an optional `EntryProofV1`; `Applied` echoes the intermediate hops
        between origin and terminal; the origin binds the LCA hop's **posting
        accounts** (debited child == its own node id, credited child == the
        verified terminal signer's node id), verifies the entry under its own
        persisted parent row and the hop's inclusion proof, and on any failure
        records `degraded` + a `settle-intermediate-degraded` audit line while
        still accepting the verified terminal `Applied` (the terminal proof
        remains the funds-correctness gate). Residuals: a colluding LCA+terminal
        can still fabricate a self-consistent cascade only when the terminal **is**
        the compromised payee leaf (whose `Descend` must still credit the payee
        user); a legit LCA ledger rotation makes the origin's persisted row stale
        and degrades the audit until re-attach; the audit is forensic-only and
        losing it on I/O failure does not change the funds outcome; the browser
        wire (`OrderResultV3`) cannot distinguish degraded from clean `Applied`.
      - Reload activity reconstruction (DONE): the persisted browser ledger state
        (`LEDGER_STATE_VERSION` 4) records cross-leaf settlement outcomes with
        amount/counterparty/entry-seq and exposes them plus the value-notice
        activity via `ledger_activity()` / `settlement_records()`; the web layer
        rebuilds the UI activity list from both on load and after each sync,
        deduped with live events, and the Activity page renders settlement status
        truthfully (applied/duplicate proven; partial/indeterminate/unverified
        warn; rejected danger). Local blob bump only - not a wire break.
      - Browser re-attach stale ledger pin (DONE): a browser re-attached to a new
        parent now re-pins its leaf ledger key from the authenticated
        `JoinApproval.parent_ledger` synchronously inside the control handler
        (before `reset_rebase_guard()` and before the accepted event, so the
        balance request the event triggers cannot race a stale pin), replacing
        the former parent's TOFU pin; the parent-scoped validated balance and
        in-flight `pending` are cleared (display-only `activity`/`settlements`
        and leaf-scoped `pinned_leaf_keys` are retained). `DetachNotice` and
        local `leave()` clear the binding before their detached event, and the
        web layer persists the ledger blob before the join-state blob on
        `accepted`/`detached` (clearing a stale `ledger_key_mismatch`). No
        version bump - `JoinApproval.parent_ledger` already existed, and
        `verify_receipt`'s `None`-TOFU fallback is unchanged (a same-parent
        ledger-key mismatch still hard-rejects). Residuals: a pre-fix persisted
        blob or identity bundle may already hold an inconsistent (state=B,
        pin=A) pair and stay wedged - heal is leave + re-join; a same-parent
        ledger-key rotation without re-approval still hard-rejects until a
        re-join (the browser has no authenticated rotation channel); and
        persistence is best-effort, so a failed ledger-blob write with a
        succeeding join-state write can still leave that inconsistent pair
        (low probability: the larger ledger blob fails first against a
        near-full quota).
      - Still owed: no global supply anchor by design; manual prefund liquidity (an
        underfunded LCA parent yields a `Partial`: payer debited, payee not
        credited); control format 4 / settlement payload 3 / browser ledger
        payload 3 / ledger (entry) format 4 (node on-disk meta format 3) are hard
        breaks.
  6. **M5 - Hardening**: exit rights, foster-parent recovery, compromise-path
     docs, audit tooling, governance/regulatory surface (Hawala exposure is
     real - community question, not code).
     - Browser identity portability (increment 1, DONE `58f725e`): the browser
       user's 32-byte seed is both the iroh endpoint id and the operator key, so
       moving the seed moves the account. Settings exports a passphrase-encrypted
       `IdentityBundleV1` (PBKDF2-SHA-256 600k -> AES-256-GCM, nodeId bound as
       AAD) carrying the seed plus the secret-free join/ledger state, and imports
       it on another device; the state blob must travel with the seed because
       re-joining an existing NodeId is rejected (`DuplicatePeer`). Storage is
       identity-scoped, with a one-time fallback to the legacy un-namespaced
       keys. Client-side only; no protocol change. `web/test` covers round-trip,
       wrong-passphrase, tamper/AAD, and a no-seed-in-plaintext guard.
     - Decision: encrypt the exported file only (no at-rest localStorage
       encryption in v1); concurrent use of one identity across devices is NOT
       enforced (relays last-connect-wins with no app-visible signal) and is
       documented rather than implied. Deferred: a human-transcribable recovery
       phrase (same seed, different encoding) and the account-key vs
       per-device-key split (`PeerRef.node` is an EndpointId everywhere;
       post-v1).
     - Owed: lost-seed recovery is custodial by nature - the account is keyed by
       the NodeId, so a parent/quorum would authorize a re-key. Needs a control
       request variant + `CONTROL_FORMAT_VERSION` bump, a control replay
       nonce/expiry (none exists today; only joins echo one), and a
       `PeerRegistry` update/remove primitive (today only a rebuild workaround
       exists). Old-key-signed rotation is safe but does not cover loss; decide
       who holds recovery authority, the delay, and the audit trail. Optional
       hardening: derive the endpoint id from the seed in `client-wasm` so import
       can verify the cleartext nodeId.
     - Browser admin control (increment 1, DONE): a **delegated admin key**
       `K_admin`. The browser sends `AdminQuery` / `AdminApproveJoin` /
       `AdminRejectJoin` to a node it has been granted; the **node** re-signs and
       delivers the applicant-facing `JoinApproved` / `JoinRejected` with its own
       operator key (required - the applicant pins the invite operator and
       nonce/parent/child, so a browser-signed approval is rejected;
       `node/src/control.rs` `handle_join_approved`, `client-wasm/src/state.rs`
       `on_join_approved`). `CONTROL_FORMAT_VERSION` 3: `SignedControl` gains
       `nonce` + `expiry` (signed preimage); `ControlRequest`/`ControlReply` gain
       admin variants (append-only, postcard order frozen); an operator-signed
       `AdminGrant {node, admin, scope, granted_at, expiry, label}`. Authority is
       a node-local `admins.json` (NOT `PeerRegistry`, which cannot hold a second
       operator per NodeId); a delegated controller may only reach the three
       admin requests (never topology/issue/self `Query`). Replay: per-node
       `msg::SeenSet` keyed `(origin, controller)`; request TTL 120 s client /
       300 s server cap. CLI `control admin grant|revoke|list`.
     - Admin decisions: grant TTL 7 d default / 30 d hard max (no "never");
       user account open stays lazy (materialized by `ledger fund`/first issue -
       the browser path deliberately does not couple `LedgerService` into the
       control handler); approval delivery retries (`AdminRedeliverJoin` + a
       bounded in-memory child->approval map) so an unreachable applicant is not
       left attached-but-uninformed; admin keys are device-local and are cleared
       on identity wipe. Audit: `<data-dir>/control_audit.jsonl` (grant/revoke/
       request/delivery).
     - Built: control v3 (`SignedControl` `nonce`/`expiry`, the four admin
       requests, admin replies + `DeliveryStatus`, `Expired`/`Replay` reject
       codes), node engine (fail-closed `admins.json`, `authorize_admin`,
       per-node `SeenSet` replay guard, outbound delivery + reply patching +
       `AdminRedeliverJoin` retry, `control_audit.jsonl`), CLI
       `control admin grant|revoke|list`, `client-wasm` (`set_admin_key` +
       `admin_query/approve/reject/redeliver`), and web (`adminKeys.js`,
       live `JoinsPage`, Settings "Node administration" card). Verified:
       `cargo test -p cawala-node` incl. the hermetic
       `crates/node/tests/control_admin.rs` matrix (8 tests: delegated
       allow/deny + surface isolation, peer isolation, expiry window, replay,
       revoke, MemoryLookup `Delivered` and no-lookup `Unreachable`), control +
       client crate tests, the wasm32 check, `web npm test` (24) and
       `npx vite build`, and a live N0 `web/scripts/smoke-admin.mjs`
       (grant -> query -> approve delivered -> applicant joined -> revoke ->
       unauthorized).
     - Routed control (increment 2, DONE): `MSG_CONTROL_V1` (reserved at
       `crates/msg/src/envelope.rs`) now carries `RoutedControlV1` (frozen
       postcard, `ROUTED_CONTROL_VERSION` 1, new `crates/control/src/routed.rs`)
       hop-by-hop along the tree; `crates/msg` itself is unchanged. The wrapper
       holds the advisory end-to-end `SignedControl` intent, an optional carried
       `AdminGrant` (audit evidence only - a carried-but-unstored grant never
       authorizes), and one `RoutedForward` (hop ref + that hop's own
       `SignedControl` over the same request) per transmitting hop. Authority is
       the **structural per-hop (H1)** model: every transmitter re-signs the same
       request with its own operator key, each receiver `verify_control`s its
       predecessor against its own registry, and the destination dispatches the
       **intent** for admin/self-operator classes (the intent origin is already
       the destination, so `authorize_admin` and every handler apply verbatim) or
       the **last hop's** control for topology (senior node child; `User`
       children excluded); `Join`/join decisions are refused on the routed path.
       Relays disambiguate request vs reply by full decode plus envelope
       coherence (both share leading byte 1) and drop expired intents. Replies
       are node-operator-signed `SignedRoutedReply`s correlated by `reply_to` =
       request `msg_id` and descend to the requester; the browser verifies them
       against the target node id (the node-id == operator-key invariant) and
       never surfaces an unverified reply. An additive `event:"routed"` audit
       line records requester/forwarder/hops/kind/outcome. No
       `CONTROL_FORMAT_VERSION` bump, no new `ControlRequest` variant, and the
       direct `cawala/control/0` path is byte-identical. Web: admin entries carry
       an optional octal `nodeAddr`; when set, admin calls try direct first and
       fall back to routed on a transport error. Verified by the hermetic
       `crates/node/tests/routed_control.rs` (13 cases over the real
       `cawala/msg/0` transport: admin query/approve + delivery, revoke wins,
       target/requester mismatch, expiry/replay, forged predecessor, senior vs
       non-senior topology, join refusal, oversize pre-decode, reply-through-relay
       disambiguation, forward-count mismatch), 21 `routed.rs` unit tests, 7
        browser host tests, `web npm test` (29) and `npm run build`. Deferred:
        non-senior topology over route (needs authority threaded through the
        handlers); non-ancestor targets (need address discovery or
        `AdminGrant.node_addr`); CLI routed admin; direct-dial replies; automatic
        redeliver orchestration; more than one outstanding routed request per
        browser client; control-reply reflection rate limiting. Rejected
        alternatives: holding the node operator seed in the browser; collapsing
        user/leaf identity. Signed topology/registry distribution (previously
        named the "only true prevention") is **rejected** - see decision 10.
     - Companion gap (DONE): `JoinRejected` now requires the invite-pinned
       parent operator on both applicants (native `handle_join_rejected` and
       wasm `on_join_rejected`), mirroring `JoinApproved`; a spoofed self-signed
       rejection can no longer cancel an in-flight join (the outbound join is
       left intact on mismatch). The deferred `rejection.nonce` staleness check
       is now in place on both paths: a mismatched non-zero nonce (the parent
       echoes the request nonce; `handle_admin_reject_join` uses the pending
       row's) is denied `Unauthorized` with the outbound retained. Residual
       (documented): a `0` rejection nonce is a wildcard because the CLI
       `control reject` sends `0` when the parent has no pending row, so an
       unpinned TOFU join can still be cancelled by a zero-nonce rejection;
       closing it fully means requiring a pending row in the CLI.
     - Control replay-guard durability (DONE): the guard behind `receive_at`'s
       `(origin, controller, nonce)` check is no longer in-memory only.
       `crates/node/src/seen_store.rs` pairs the `msg::SeenSet` with an ordered,
       capped sidecar persisted to `<data-dir>/control_seen.json` (version 1;
       temp file + `sync_all` + rename) and re-observed on `ControlNode::open`.
       `receive_at` persists a `Seen::Fresh` mark **before** dispatch and returns
       `Rejected(Internal)` if the mark cannot be made durable (fail closed), so a
       restart no longer reopens the <=120 s delegated-admin replay window.
       Verified by `seen_store` unit tests and `crates/node/tests/seen_restart.rs`
       (restart replay is `Replay`, a corrupt sidecar does not block `open`, a
       failed persist is `Rejected(Internal)` with no dispatch). Documented
       residuals: the sidecar's cross-origin eviction is insertion-order LRU
       while `SeenSet` evicts by `last_touch`, so under cap pressure a still-valid
       in-memory mark can be absent after a restart; durability is scoped to a
       process restart (the parent dir is not fsynced, so power loss is
       best-effort); pruning uses the wall clock. Advisories (not done):
       parent-dir fsync, corrupt-sidecar observability, write coalescing for the
       per-`Fresh` rewrite, cap-only eviction.
     - Exit rights (DONE): any node may leave unilaterally, non-leaf included;
       the subtree becomes an independent network with **topology-true
       addresses** (independence rebases onto root `0`; re-homing swaps the
       prefix). `CONTROL_FORMAT_VERSION` 4 (inbound-only dual-accept of 3/4 -
       minted frames are always v4, so mixed-version control is effectively
       lockstep for node->child and routed frames) adds four appended variants:
       `Exit` (child -> parent, self-operator, not seniority-gated),
       `DetachNotice` (parent -> child, best-effort; also sent by `DetachChild`),
       `Rebase` (each direct parent signs its child's new address; requires
       `address == parent_address.child(slot)`) and `RebasePull` (child -> parent,
       self-operator, answered with the existing `Snapshot`). Direct
       `cawala/control/0` only; all four are refused on the routed path. Exit is
       best-effort and convergent: notify the parent, flip to root `0` locally in
       one validated `rebase_to_root()` (so an unreachable parent cannot trap the
       node), then push `Rebase` down the subtree; offline descendants heal via an
       in-memory pending-notice retry plus a startup/periodic `RebasePull`.
       Stranded value is tolerated (this entry adds no `ENTRY_FORMAT_VERSION`
       bump; the M5 `EdgeClose` entry below advances it to 4): the severed edge
       pair remains, and the operational rule is "exit with a zero `Parent`
       balance for a clean re-attach" - otherwise the stranded claim surfaces as a
       hard `MirrorMismatch::UnbackedClaim` on the new parent's books until the
       node writes it off with `ledger edge-close` (CLI `control exit` warns on a
       non-zero balance and still succeeds). Re-attach is idempotent for a former
       parent (its retained
       `PeerKeys` row no longer fails the approval) and for a stale row left by an
       unprocessed exit. `receive_at` re-reads `node.json` (record) and
       `ledger_peers.json` (peer registry) per request, warn-and-continue, so a
       live node observes external CLI writes. Audit is component-aware: one
       `Topology` per weakly connected component, the child's own parent link wins
       over a stale parent-side row (`Finding::StaleChildLink`), each island
       reports `Finding::Detached { root, nodes, stranded_parent, parent_balance
       }`, both are advisory, and `nets` are suppressed by
       `Finding::suppresses_netting()` (everything except those two) so islands no
       longer disable reconciliation; exit codes unchanged. Browser: `leave()`
       (self-signed; clears parent+address regardless of the reply, replacing the
       mock-only `detachChild`), `Rebase`/`DetachNotice` handlers, a `"detached"`
       control event, the MyAccountPage "Leave network" card (confirm + aftermath
       + balance-stays-on-their-books warning) and a Dashboard post-detach CTA; no
       `LOCAL_STATE_VERSION` change. Leaf rejoin uses the existing join flow.
       Verified: `crates/node/tests/exit_rebase.rs` (7), `routed_control` (13),
       `netting_harness` (15), `seen_restart` (3), ledger 223, client 82, plus
       workspace clippy and the wasm32 check; web `npm test` (29) + `npm run
         build`. Deferred to v2: per-peer control version negotiation and an
         optional `OctAddr` depth cap. Signed topology/registry distribution is
         **rejected** (decision 10: the live topology is the source of truth).
         Moved pointers are **rejected, not
        deferred**: a changed topology is a material change in trust dynamics
        (the parent-child relationship), so any in-flight transaction must fail
        with an appropriate message and be re-tried with new source and/or
        destination addresses, discovered **out of band** (no redirects, no
        pointers, no silent re-addressing). Note on "subtree rejoin": a node
        **with or without children can already join any network by invitation** -
        `Join` rewrites the joiner's own address immediately and its descendants
        converge through the periodic healing `RebasePull` (each node is renamed
        only by its own direct parent, and applying a rename re-pushes to its
        children), so the subtree follows within a probe interval (~30 s per
        level) and heals after downtime. Descendants cannot veto; their opt-out is
        to exit and become their own island. The only sharpening left is
        promptness (push `Rebase` downward at `JoinApproved` instead of waiting
        for the pull) plus a persisted per-edge `generation` so repeated renames
        of the same edge can be ordered - neither is needed for the capability.
     - Foster-parent recovery (DECIDED: cut) + stranded-claim evidence bundle
       (DONE): automated recovery was **cut by owner decision**. Rationale: exit
       is already unconditional and works against an unreachable parent, and
       re-attachment already happens through an out-of-band `Invite`; the
       proposed non-response claim is unverifiable and adds no capability, and a
       timeout heuristic misreads the real cases (the parent kicked the node, the
       relationship soured, the parent's services degraded) while inviting a
       "declare my parent dead to dodge a live parent" narrative. Reconnection is
       therefore **leave (if needed) + invitation** - no grace clock, no health
       store, no `Recover` variant. What shipped instead is an out-of-band
       **stranded-claim evidence bundle** for a prospective new parent's
       **discretionary** `prefund`/`fund`: `crates/control/src/claim.rs`
       (`STRANDED_CLAIM_VERSION` 1, domain `cawala-control/stranded-claim/v1`)
       defines a signed dated `StrandedClaim` plus
       `StrandedClaimBundle { version, child, child_operator, child_ledger,
       claim, edge, commitment, parent_balance, parent_proof, chain }` and
       `verify_bundle` (commitment under the child's ledger key; optional
       genesis-anchored or suffix chain continuity; a
       `merkle::verify_state_inclusion` proof of the `Parent` balance against the
       committed `state_root`, verified whenever a proof is present; negative
       balances and a >300 s future `issued_at` rejected). No wire change:
       `CONTROL_FORMAT_VERSION` stays 4. Node CLI `control claim-export
       [--from <node-id>] [--out <file>]` (commits before proving and
       self-verifies before writing), `control claim-review <file>` (1 MiB cap;
       prints an explicit "not proven" block - the amount is self-attested, the
       head may not be the presenter's latest, the edge row is unverified
       context, nothing compels payment), and informational `control
       parent-status` (a one-shot probe: no persistence, no gating); export and
       review are audited. Browser: a passive `cawala.recovery.v1` tracker behind
       `parentStatus()` (instrumented on the existing balance poll, best-effort,
       cannot affect the balance flow) and an informational "Parent unreachable"
       notice with a "re-join via invitation" action; no `LOCAL_STATE_VERSION`
       change. Residual: a re-attached child with a non-zero `Parent` balance
       still shows a hard `MirrorMismatch::UnbackedClaim` until the new parent
       funds it to match or the child writes it off with `ledger edge-close` -
       the bundle is what makes that decision informed (see the M5 `EdgeClose`
       entry below). Verified: `claim.rs` 24 unit tests (frozen field-order
       golden and real Merkle state-inclusion proofs),
       `crates/node/tests/claim_bundle.rs` (11), web `parentLiveness` (12),
       workspace tests, clippy, the wasm32 check, web `npm test` (41) and
       `npm run build`.
     - EdgeClose - clean edge settlement (DONE): `ENTRY_FORMAT_VERSION` 4 adds
       `EntryBody::EdgeClose { amount }`, posting exactly `[{Parent: -amount}]`
       as a **boundary-parent** write-off under a new crate-internal
       `BoundaryParent` rule (`Boundary` stays child-only), authorized by
       `EdgeCloseRequest`/`verify_edge_close` (BLAKE3 domain
       `cawala-ledger/edge-close-request/v1`) and applied by
       `LedgerService::edge_close` - a detached-only guard for a non-zero
       balance (a zero balance is an `Ok(None)` no-op even while attached),
       bailing "run `control exit` first" when still attached, an **exact**
       full-balance close, and an appended `edge-close` audit line - driven by
       the operator-only CLI `cawala-node ledger edge-close [--from <node-id>]`
       (random nonce; writes the whole pooled `Parent` balance off). No new
       wire/control variant: the parent side needs nothing new (`Burn { child }`
       already exists), and the body is deliberately operationally generic. A
       closed edge makes the child's `Parent` 0, so re-attach no longer surfaces
       a hard `UnbackedClaim`. Accepted residuals: (1) an attached unilateral
       write-off hard-dirties the (P,C) mirror
       (`MirrorMismatch::UnmirroredExtension`, suppressing P's nets) - this is
       **pre-existing**, not a new capability: a child could already do it with
       `Issue` + `Ascend` (both paths pinned by
       `attached_unilateral_write_off_is_an_unmirrored_extension`); audit policy
       is unchanged and P's remedies are an honest detach by C, excluding C from
       reconciliation, or a parent-side `Burn { child }` (no service/CLI path
       yet - backlog), and detaching alone does not cure a hostile C that
       ignores the notice; (2) the body is not edge-bound and `Parent` is one
       pooled account, so a close forfeits everything in it (another former
       parent's claim, any extension a new parent already made) - close
       **before** a new parent prefunds, and a node that already re-attached
       with a stranded claim must `control exit` again first; (3) no
       ledger-level exactness and no per-request replay guard: any
       `amount <= balance` is a valid write-off, the service always closes
       fully, and idempotence is the zero no-op plus `InsufficientBalance`;
       (4) hard break: entry format 4 + on-disk ledger meta format 3 invalidate
       all entry hashes/signatures and commitment chains - recreate `node-data`,
       rebuild the wasm bundle, and old browser bundles cannot verify v4 entry
       proofs (the meta bump also replaced the stale-version message with a
       version-generic "unsupported ledger format version {found} (expected
       {expected})" error); (5) the former parent retains the stale `Child(C)`
       liability (conservative for its equity, invisible after severance); no
       supported burn path yet. Verified: `crates/ledger` 239 (golden vector +
       `BoundaryParent` shape + `verify_edge_close` matrix + overdraw),
       `crates/node/tests/edge_close.rs` (exact close/idempotence/attached
       guard), the griefing pin, the pre-close -> post-close re-attach audit,
       clippy and the wasm32 check.
     - Exit-rights follow-ups (DONE): (a) the per-request control-plane refresh
       (record `node.json` + peer `ledger_peers.json`, warn-and-continue) is
       hoisted into a shared `refresh_control_plane` called by **both**
       `receive_at` and `receive_routed_at` before every state-dependent check, so
       a routed request no longer sees a stale record/registry after an external
       CLI write. (b) Parent-side ledger rotation is reconciled on **re-attach**:
       a same-operator/same-role row whose ledger key changed is accepted and
       updated (anchor: the pending `JoinRequest` is self-signed by the child, so
       that child's operator vouches for the new key) with an additive
       `peer-ledger-updated` audit line carrying the actor. `handle_create_child`
       is narrowed to `Authority::SelfOperator` only - a senior child attempting
       the same rotation keeps the pre-batch `Unauthorized` refusal, because that
       request is not signed by the peer whose row would change. Consequences
       documented: after a rotation the old key's historical commitments/carried
       hops no longer resolve against the one-ledger-per-node registry, and a
       rotation is network-wide (peers still holding the old row produce
       conflicting registry rows in a merged netting harness until they update).
       (c) `ledger net` and `ledger verify-cascade` gained
       `--primary-root <node-id>` (default: largest component, ties by root id;
       ignored under `--topology`). (d) The optional `OctAddr` depth cap remains
       deliberately deferred (decision 9: no hard depth cap; frames are already
       bounded by `MAX_CONTROL_FRAME`). No version constants move and there is no
       data-dir or blob impact. Verified: node lib 206, `routed_control` 15,
       `exit_rebase` 8, `netting_harness` 17, workspace tests, clippy and the
       wasm32 check all green.
     - Rebase promptness + generation ordering (DONE): a node that joins with a
       subtree is now rebased **immediately** - `handle_join_approved` pushes a
       `Rebase` to its children right after the record/peers/pending mutations
       have persisted (a no-op when it has none, and no notice is sent for a
       mutation that did not commit) - instead of waiting for the ~30 s healing
       `RebasePull`. `RebaseNotice.generation` is now a real, enforced ordering
       token derived from a node-local monotonic `NodeRecord.address_epoch`
       (bumped exactly once, in the single `RecordStore::set_address_value`, and
       only when the stored asserted address value actually changes) and sent on
       every outgoing notice; the receiver keeps a per-link high-water mark in
       `ParentLink.generation`, and `handle_rebase` ignores `<` (audited
       `rebase-stale-ignored`), treats `==` as idempotent when the address matches
       and `Rejected(BadRequest)` when it disagrees (audited `rebase-conflict`),
       and applies `>` advancing the mark. A deterministically rejected `Rebase`
       notice is now **terminal** (`should_requeue_notice`), so a rolled-back
       parent no longer redials a refusing child every 5 s; `Unreachable`/
       `TimedOut` stay retryable. A parent whose persisted epoch regresses (a
       restored or rolled-back record) can only **degrade push promptness**: the
       generation-agnostic healing pull still applies the parent's current
       address and re-propagates, so any stall is bounded to one probe interval
       (pinned by `rolled_back_parent_stalls_child_until_pull_heals`). A browser
       leaf, which has no healing pull, enforces the same rules with an
       **in-memory** guard - deliberately not persisted, since that would force a
       `LOCAL_STATE_VERSION` bump and discard every existing user blob.
       Compatibility: `node.json` gains only two `#[serde(default)]` fields
       (`address_epoch`, `parent.generation`), so old files load unchanged; no
       `CONTROL_FORMAT_VERSION`, `RebaseNotice`, `NodeSnapshot`/`ControlReply` or
       `LOCAL_STATE_VERSION` change, and no reply/DTO change. Residual: a stale
       browser notice arriving only **after** a reload is theoretically possible and
       is corrected by the parent's next push. Verified: node lib 214,
       `exit_rebase` 11, client 86, workspace tests, clippy and the wasm32 check
        all green.
      - MoveChild re-slot rebase (DONE): a same-parent `MoveChild` (v1: node
        child only) now persists the child's new slot atomically, bumps the
        parent's subtree routing epoch, and queues exactly one targeted `Rebase`
        for the moved child, which re-propagates to its own subtree; the child's
        healing pull adopts the slot named by its entry in the parent's snapshot.
        Both prior healing paths were broken - the push checked `address ==
        parent_address.child(record.parent.slot)` against the child's own stale
        slot, and the pull derived the same stale address - so a re-slot
        stranded the child and its subtree permanently. `handle_rebase`'s rule is
        now the direct-child structural check `address.parent() ==
        Some(parent_address)` and the receiver **adopts** `address.slot()`;
        `RecordStore::move_child_slot`/`apply_rebase` are atomic
        (clone/validate/swap), and a `ChildKind::User` child is refused
        (`BadRequest`) because a browser leaf has no healing pull. No wire/DTO/
        format change: `CONTROL_FORMAT_VERSION` stays 4 and
        `RebaseNotice`/`MoveChild` shapes are unchanged (the pull is deliberately
        generation-agnostic, preserving the rolled-back-parent healing
        guarantee). Verified: node lib 235 (record + control units),
        `exit_rebase` (full suite incl. the new re-slot integration test),
        workspace tests, clippy and the wasm32 check all green.
        Residuals: the stale-address failure surface remains `NoRoute(NoSuchChild)`
        with no dedicated stale-address signal (consistent with the rejected
        moved-pointers decision - retry with fresh addresses discovered out of
        band); and a `User` (browser-leaf) child's re-slot is out of scope in v1
        and refused.
      - Control version negotiation (assessed, deferred) + admin-redelivery
        re-sign (DONE): per-peer `CONTROL_FORMAT_VERSION` negotiation was
        assessed at a design gate and **not built**. Rationale: there is one
        codebase and the wasm bundle is rebuilt in lockstep, so no mixed-version
        fleet exists today; the full design (a per-peer version cache,
        learn-on-inbound, `min()`-version minting at every site, one `BadVersion`
        retry, and a routed intent-version cap) is real but not justified now,
        and full routed negotiation is unsound without a wire change.
        `CONTROL_FORMAT_VERSION` stays 4, so control remains effectively lockstep
        for node->child and routed frames. Accepted residual: **v4-only control
        features** (`Exit`, `DetachNotice`, `Rebase`, `RebasePull`, and
        `MoveChild`, whose healing `Rebase` is v4-only) cannot reach a known-v3
        peer; without a per-peer version record (out of scope) such a child
        cannot be detected or refused, so those operations degrade/fail silently
        across a version boundary. Independently, the present-day
        **admin-redelivery** bug is fixed: `handle_admin_redeliver_join` now
        re-signs the retained inner request with a fresh top-level nonce and
        expiry via `sign_decision` (previously it pushed the stored frame
        verbatim, delivering an **expired** frame after the original TTL - and a
        stale version in a mixed fleet), reproduces the inner request unchanged so
        the applicant still matches the echoed `JoinRequest.nonce`, and stores the
        new frame so later redeliveries build on the latest. No
        `CONTROL_FORMAT_VERSION` bump. Verified: `cawala-node --lib` (the
        redelivery test asserts a differing nonce, a fresh expiry, an identical
        inner request, and a valid signature), workspace tests, clippy, and the
        wasm32 check.

---

**Part 2 - Unified node administration console (P1-P6; superseded).**

# Next Phases - Unified Node Administration (planned 2026-10-02)
  Status: P1-P6 delivered (2026-10-02). Goal: the
  browser console
  looks and functions identically whether the administered node is a leaf or an
  internal node, with a persistent selector showing which node is administered
  and easy switching between administered nodes. Reconciled from the 2026-10-02
  recon (`exp-1` UI branching, `exp-2` admin surface), design proposal
  (`des-4`), and architecture/phasing review (`ora-1`).

## Boundary rule: the browser commands, the node executes
   The browser never holds a node operator key or a ledger key. A delegated
   admin key (`K_admin`) authorizes **intent** only; the node re-signs with its
   own operator key and is the sole holder of the ledger key. This is the
   existing `AdminApproveJoin` pattern extended to topology/value ops. Browser
   operator-key custody is **rejected** (would let XSS forge ledger entries and
   violates "operator keys != ledger keys"). No browser-supplied field may ever
   be used as a ledger signature, operator key, posting, or ledger key.

## Phase plan
   - **P1 - Unified shell + node selector** (client-only, no wire change; uses
     the existing `AdminQuery`). One layout for the selected administered node;
     sticky selector listing "This browser (self)" plus every granted node;
     node kind inferred from `AdminQuery` children (`internal` if any child is a
     node, `leaf` if all are users, `unknown` if empty); target-parameterized
     `getChildren(nodeId)`/`getJoinRequests(nodeId)`; remove the `isLive` layout
     forks; fold the Settings admin-node list into the selector. Deliverable
     parity: shell, children, joins. Accounts/Activity full parity needs P3.
   - **P2 - Scoped grants + signed bundle**. `AdminScope` set
     `{joins, topology, value}`; v1 `admin` grants are interpreted as
     **joins-only** (never silently widened); truthful TTL enforced node-side;
     `cawala://admin?node=<id>&grant=<base64 SignedAdminGrant>` so the browser
     verifies the operator-signed grant instead of inventing its own TTL.
     `ADMIN_GRANT_VERSION` 2; browser `cawala.admin` v1 -> v2 with read-migration.
   - **P3 - Read-only ledger view**. New `AdminLedgerQuery` ->
     `AdminLedgerSnapshot { node_id, height, ledger_id, accounts[], parent_balance,
     equity }`; inject an optional ledger handle into the control path; unified
     Accounts table for both kinds (leaf user accounts; internal child-node
     accounts + parent asset; derived equity `parent - sum(children)`).
     `CONTROL_FORMAT_VERSION` 5, `CONTROL_REPLY_VERSION` 3. Read-only.
   - **P4 - Topology administration**. New `AdminDetachChild`, `AdminMoveChild`
     (same-parent re-slot), reusing the existing record mutations and queuing
     `DetachNotice`/`Rebase` exactly as the senior/self handlers do. Browser
     **create-child is deferred** (needs the child's operator+ledger pubkeys and
     a running process; provisioning stays invite/CLI). `AdminSetAddress`
     deferred (routing identity; not topology scope).
   - **P5 - Value administration** (highest bar). New `AdminIssue`, `AdminBurn`;
     add `LedgerService::burn` (the ledger crate already has `BurnRequest`/
     `verify_burn`; reuse unchanged, no entry-format bump). Stable client
     `request_id` + node-persisted dedupe map returning the prior
     `(seq, hash)`; per-request cap + rolling window budget + per-account
     ceiling configured operator-side; mandatory reason; fail-closed audit.
     This is the only phase with monetary blast radius.
   - **P6 - Polish/optional**. Persisted node `role` (`#[serde(default)]`
     additive), grant-bundle QR, config/credit limits (no config model exists
     yet), non-senior routed topology, quorum/time-lock hardening.

## P1 - delivered 2026-10-02 (client-only, no wire change)
   - Admin key store moved to `cawala.admin.v2` with read-migration from
     `cawala.admin.v1`: the seed survives, v1 grants read as `scopes: ['joins']`
     (never widened), a corrupt v2 payload falls back to the legacy key, and a
     corrupt payload is replaced by the repaired one.
   - Selection is explicit, never "first non-expired grant": the first stored
     grant becomes the selection once; `selectAdminNode()` validates (`self`,
     `mock`, or a stored id) and persists; `activeAdminNode()` returns the
     selected grant only while it is valid; removing the selection falls back to
     another active grant or `self`; clearing everything leaves no envelope, and
     `api._normalizeTarget` maps that to `self`.
   - Probe memory per node (`lastSeenStatus/Kind/Address/At`) written by
     `probeAdminNode`; partial updates never erase better data, and a null
     timestamp stays null instead of collapsing to 0 (1970).
   - One reactive target: `administeredNode` store + `targetEpoch`; a target
     change resets page state and bumps the epoch, and pages reload off the
     epoch so no page data lingers under a new target. `getChildren`,
     `getJoinRequests`, `getAccounts`, `getActivityLog` are target-parameterized.
   - Node kind is derived only from observed children (`nodeKind.inferNodeKind`:
     any child node -> internal, all users -> leaf, empty/unknown -> unknown) and
     only shown after a probe recorded it.
   - Shared surfaces: `components/admin/{AdminNodeRow,NodeSelector,
     GrantStatusBanner,GrantEmptyState}` + `layout/NodeContextBar` under a
     sticky shell header; Settings' admin-node list folds into the same row
     component; `adminView.buildSelectorItems` groups this browser, mock,
     granted, expired for both the selector and Settings.
   - `isLive` layout forks removed from Dashboard, Node, Joins, Accounts,
     Activity and My Account: one layout driven by `adminCapabilities`/mock
     flags, with the Mode chip the only remaining live/mock distinction.
    - Verified: `cd web && npx vite build` (186 modules, no Svelte warnings) and
      `cd web && npm test` (67 tests pass: adminKeys v2/selection/migration,
      nodeKind derivation, adminView selector model, identity bundle, parent
      liveness).

## P2 - delivered 2026-10-02 (scoped grants + signed bundle; control stays v4, reply v2)
   - Control (`cawala-control`): `AdminScope` gained `Joins`/`Topology`/`Value`
     (append-only discriminants) and a fixed three-byte `AdminScopes` set
     (`joins`/`topology`/`value`, >=1 true, cannot represent legacy `Admin`);
     new `AdminGrantV2`/`SignedAdminGrantV2` signed in the
     `cawala-control/admin-grant/v2` domain, `ADMIN_GRANT_VERSION` 2 (mint)
     with `ADMIN_GRANT_V1_VERSION` 1 (read). The v1 `AdminGrant`, context, and
     golden signing hash are unchanged. `MAX_VALUE_ADMIN_TTL_SECS` caps a
     value-scoped grant at 24 h. `ControlRequest::required_scope()` maps
     `AdminQuery -> AnyActive` and the three join mutations -> `Joins`;
     `is_admin()` is exactly `required_scope().is_some()`. New
     `AdminGrantBundleV1` codec + `cawala://admin?node=&grant=` URI (base64url,
     version peek, `MAX_ADMIN_BUNDLE_BYTES`, trailing-byte rejection,
     `node == grant.node`; the codec never verifies the signature).
   - Node (`cawala-node`): `admins.json` dual-accepts v2 and legacy v1 rows
     (`StoredGrant` untagged) with per-type version validation (shape/version
     mismatch is a hard load error) and preserves each row's form on save; a v1
     row means exactly `{ joins }`. `Authority::Delegated(AdminScopes)` and
     scope-checking `authorize_admin`; the routed carried grant stays v1
     evidence-only. `control admin grant --scope <joins|topology|value>`
     (repeatable, default joins) mints/signs/stores v2 and prints the bundle
     URI; `list` shows scopes+version. `ADMIN_STORE_VERSION` stays 1.
   - Browser: wasm `parse_admin_bundle` (container -> `AdminGrantV2::validate`
     -> operator signature derived from `grant.node`; expiry is not judged)
     returns `AdminGrantInfo`. `adminKeys.applyAdminGrant` strictly applies a
     verified grant's scopes/TTL to an existing entry (`grantSource: 'bundle'`;
     provisional/manual and migrated rows default `'manual'`, never widened).
     `api.applyAdminBundle` verifies via wasm, requires the stored entry and a
     matching admin key, then syncs the administered-node view. Settings gains
     a bundle paste/import control, the "Expiry (days)" field is relabeled a
     local **provisional TTL**, and `AdminNodeRow` badges operator-signed vs
     provisional.
   - Hard break (unchanged from the P2 design): after the first v2 grant is
     written, a pre-P2 node binary cannot load `admins.json`. Upgrade the
     binary before minting v2; v1 rows and P1 browsers keep working,
     joins-only.

## P3 - delivered 2026-10-02 (read-only ledger view; control 5, reply 3)
   - Control (`cawala-control`): `ControlRequest::AdminLedgerQuery`
     (discriminant 16, minted at control format 5; `required_scope -> Value`)
     and `ControlReply::AdminLedgerSnapshot` (discriminant 7, reply version 3)
     with `AdminLedgerSnapshot { node_id, ledger_id, height, parent_balance,
     equity, root, truncated, accounts }` and `AdminLedgerAccount { id, kind,
     slot, address, balance }`. `CONTROL_FORMAT_VERSION` 4 -> 5 (mint 5, accept
     4|5; v3 dropped) and `CONTROL_REPLY_VERSION` 2 -> 3. The node-side shape
     gate is now the monotone `min_control_version` (exit-rights -> 4, ledger
     query -> 5, else 3), replacing `carries_v4_variant`; `ROUTED_*` stay 1.
   - Node (`cawala-node`): `LedgerService::admin_ledger_view` takes the shared
     read lock, refreshes from disk, and builds the union of `node.json`
     children (slot order) and remaining ledger `Child` accounts (`NodeId`
     order, `kind: None` for detached), capped at `MAX_ADMIN_LEDGER_ACCOUNTS =
     64` with `truncated`; `equity` is `Balances::equity()` and
     `parent_balance` covers all balances. Read-only: never appends, never takes
     the exclusive lock. Two-phase `Handled`/`PendingLedgerQuery` dispatch: the
     engine lock is captured and dropped before the ledger lock is taken, and
     the engine is only re-locked to audit after the ledger guard is released
     (control -> ledger, never both held). Optional `ledger` handle with
     `attach_ledger`/`ledger_handle` and
     `spawn_control_node_live[_on]_with_ledger`; `main.rs` attaches the running
     ledger before serving.
   - Browser: wasm `ClientNode::admin_ledger_query(node, node_addr)` (direct
     first, routed fallback) returning `AdminLedgerSnapshotDto`/
     `AdminLedgerAccountDto` (explicit `"node"`/`"user"`/`None` kind mapping).
     `api.getAccounts` uses it for a value-scoped administered target, mapping
     the parent asset row + one liability row per account + the canonical equity
     row; it gates on `adminCapabilities.scopes.value` (joins/topology-only ->
     `[]`), keeps the verified-balance path for `self`, and records unreachable
     like the other admin reads. `AccountsPage` renders one table for leaf and
     internal nodes and shows a **Truncated** notice when the node hit its row
     cap.
   - Version matrix: `CONTROL_FORMAT_VERSION` 5, `CONTROL_REPLY_VERSION` 3; no
     ledger/entry/settlement format change (`ENTRY_FORMAT_VERSION` 4,
     `LEDGER_FORMAT_VERSION` 3, settlement/payload unchanged) and **no
     `node-data` recreation**. Pre-existing control traffic is unaffected.
   - Residual (intended): balances are node-asserted (transport-authenticated
     direct, operator-signed routed) with no independent Merkle/commitment
     proof; a `value` admin can see user balances.

## P4 - delivered 2026-10-02 (delegated topology administration; control 6, reply 3)
   - Control (`cawala-control`): `AdminDetachChild { child }` and
     `AdminMoveChild { child, slot }` (no `new_parent`, so a cross-parent move is
     structurally inexpressible) as `ControlRequest` discriminants 17/18, with
     `kind()` `"admin-detach-child"`/`"admin-move-child"`,
     `required_scope -> Topology`, and `validate()` (node-id bound; move slot
     range -> `SlotOutOfRange`). `CONTROL_FORMAT_VERSION` 5 -> 6 (mint 6, accept
     5|6); the exhaustive `min_control_version` grew two -> 6 arms. Reply is
     unchanged: `ControlReply::Accepted`, `CONTROL_REPLY_VERSION` stays 3.
   - Node (`cawala-node`): authority-free `apply_detach_child`/`apply_move_child`
     helpers shared by the senior and admin paths, so validation parity is
     structural (a `User`-child move is `BadRequest`, a non-child `NotFound`,
     occupied slot `SlotTaken`). `handle_admin_detach_child`/
     `handle_admin_move_child` gate on `authorize_admin` (Topology) only, never
     the senior `authorize`, and emit an additive `admin-topology` audit line.
     Notices use the existing outbound path; the routed `dispatch_control_envelope`
     now requeues failed outbound notices (prerequisite bug fix) so a routed
     admin detach/move whose child dial fails is retained by the bounded sweep.
   - Browser: wasm `ClientNode::admin_detach_child`/`admin_move_child`
     (direct-first, routed fallback) matching `Accepted`;
     `api.adminDetachChild`/`adminMoveChild` gated on a non-self target with
     `adminCapabilities.scopes.topology`; NodePage's Children card gains
     row selection and a Move/Detach actions panel with confirmations (a `user`
     child cannot be moved). `createChild` stays stubbed and un-surfaced.
   - Version matrix: `CONTROL_FORMAT_VERSION` 6, `CONTROL_REPLY_VERSION` 3,
     `ROUTED_*` 1; no ledger/entry/settlement change and **no `node-data`
     recreation**. Hard break: a v5 node cannot decode the new discriminants, so
     rebuild the wasm bundle with the node; old browsers simply cannot use
     topology actions.
   - Residual (intended): a topology admin can detach a child with a non-zero
     balance, stranding value without a `value` scope (parity with the senior
     path; the UI warns). Mitigated by audit and revocation.
   - Residual (review-noted): detaching the current senior child changes
     seniority, promoting the next `Node` child (identical to the senior path);
     and a failed `DetachNotice` is not retriable because the child has been
     removed from the record, so it learns of the detach on its next
     interaction (the P2 retry sweep cannot help a detached target).

## P5 - delivered 2026-10-02 (delegated value administration; control 7, reply 4)
   - Control (`cawala-control`): `AdminIssue`/`AdminBurn` (discriminants 19/20)
     carry `AdminValueRequest { request_id: ValueRequestId, account, amount,
     reason }` with `required_scope -> Value`; `ControlReply::AdminValueApplied`
     (8) plus `RejectCode::{LimitExceeded, InsufficientBalance}`.
     `CONTROL_FORMAT_VERSION` 6 -> 7 (mint 7, accept 6|7); `CONTROL_REPLY_VERSION`
     3 -> 4; `min_control_version` arms -> 7.
   - Node (`cawala-node`): `<data-dir>/value_policy.json` (`VALUE_POLICY_VERSION`
     1, deny-by-default) bounds each op; `LedgerService::burn` mirrors `fund`
     (no auto-open, `InsufficientBalance`), and `admin_value_apply` executes
     issue/burn under the exclusive ledger lock with an **end-to-end idempotency**
     guard: a 16-byte `request_id` derives a controller-bound ledger nonce
     (`BLAKE3("cawala-node/admin-value/v1", controller_pub ‖ request_id)`), and a
     ledger-derived `ValueIndex` keyed `(node_operator, nonce)` returns the prior
     `(seq, entry_hash)` without appending on a duplicate (survives reopen; no
     sidecar, never evicted). Caps are enforced in the engine (early per-request)
     and authoritatively in the service (per-request, node-wide Issue window,
     per-account ceiling, burn overdraw). The executor writes a **fail-closed
     intent audit line** before touching the ledger (failure -> `Internal`, no
     append) and a best-effort outcome line. The browser never holds
     operator/ledger keys: the node builds/signs `IssueRequest`/`BurnRequest`
     with its own keys, and no request field is a signature/key/posting.
   - Browser/CLI: wasm `ClientNode::admin_issue`/`admin_burn` +
     `AdminValueAppliedDto`; `api.adminIssue`/`adminBurn` persist a single
     in-flight op (`cawala.value.pending.v1`) before sending and clear it only on
     `AdminValueApplied`, with Retry/Discard on load; AccountsPage liability rows
     gain Issue/Burn confirmations (mandatory reason). CLI
     `control admin value-policy show|set`; `grant --scope value` reminds the
     operator.
   - Version matrix: `CONTROL_FORMAT_VERSION` 7, `CONTROL_REPLY_VERSION` 4,
     `ROUTED_*` 1; no ledger/entry/settlement change and **no `node-data`
     recreation** (the policy file is new and absent-is-deny). Hard break: a v6
     node cannot decode discriminants 19/20, so rebuild the wasm bundle with the
     node.
   - Residual: value ops are node-asserted against its own books; a value-scoped
     K_admin is an XSS-away mint until seed-at-rest hardening (P6). The value
     index is keyed `(node_operator, nonce)`, so rotating the node operator key
     while retaining the ledger makes old delegated records unmatchable - a retry
     after re-granting could re-apply (outside the threat model, but noted).
     `AdminValueApplied.balance_after` is the account's balance **at reply
     time** (post-op for a fresh apply, current for a duplicate), not the
     original application's post-op balance.

## P6 (focused) - delivered 2026-10-02 (web-only seed hardening)
   - Web-only; no Rust/control-format change and no `node-data` recreation.
   - **Required wrap**: a value-scoped key must be passphrase-wrapped before
     **any** value action (not opt-in). A plain value key is refused with a
     distinct `AdminSeedProtectionRequiredError`; the UI opens a Protect dialog
     (passphrase + confirm), wraps the seed, then retries the action once. Only
     value-scoped keys may be wrapped, and joins/topology seeds stay plaintext.
   - `web/src/lib/adminSeedCrypto.js`: passphrase wrap for delegated **value**
     seeds (PBKDF2-SHA-256 600_000 iters + 16-byte salt, AES-256-GCM + 12-byte
     IV, AAD `cawala.admin.seed.v1:<nodeId>`). The identity-bundle format is
     untouched; the iteration count is pinned to the v1 constant so a tampered
     record cannot force unbounded PBKDF2 work. Each wrap uses a fresh salt/IV.
   - `web/src/lib/adminKeys.js` moves to **`cawala.admin.v3`** with read-migration
     from v2/v1 (plaintext rows read as `seedKind:'plain'`). An entry's seed is
     either plaintext or wrapped (`seedWrapped`, `seedKind:'plain'|'pbkdf2-aes-gcm'`,
     `seedProtected`); a wrapped row is never dropped, and seed-free views expose
      only `seedProtected`/`seedKind`. New `adminSeedState`/`unlockAdminSeed`/
      `lockAdminSeed`/`lockAllAdminSeeds`/`protectAdminSeed`/`unprotectAdminSeed`;
      `adminSeedBytes` returns bytes only when plain or session-unlocked.
      `removeAdminNode` clears the session-unlocked cache; `protectAdminSeed`
      throws when the write did not persist (no false "protected").
   - `api.js`: typed `AdminLockedError` and `AdminSeedProtectionRequiredError`;
      `_ensureAdminKey` raises the former for a locked entry and the latter for a
      plain value key; `ensureAdminUnlocked`/`lockAdmin`/`protectValueSeed`
      (value-only, verifies persistence). `adminIssue`/`adminBurn` refuse a
      locked or unprotected seed **before** minting a request id or writing the
      pending record. UI: `UnlockAdminKeyDialog` (passphrase + confirm for
      protect), Settings per-node Protect/Lock shown only for value-scoped keys
      with a `Protected` badge, AccountsPage unlock/protect-and-retry; zero-wire
      limits notice plus actionable `limit_exceeded` copy (no fabricated numbers).
   - Honest residual: the wrap adds an interaction gate and protects at-rest
     dumps and copied browser profiles, but it does **not** stop in-session XSS
     while unlocked (the seed is in JS memory and a copy is in the wasm heap
     after `set_admin_key`); GC zeroization is best-effort, a fake prompt can
     phish the passphrase, and PBKDF2 depends on passphrase strength.
   - Deferrals (with rationale): grant-embedded limits (`ADMIN_GRANT_VERSION` 3)
     needs a grant/format design and cross-version key distribution;
     2-person/time-locks need quorum infrastructure and a recovery story; global
     config/credit limits need a config model (none exists); persisted node
     `role` is a snapshot additive not needed for the UI; bundle QR needs a
     rendering dependency; an anomaly dashboard needs a metrics sink;
     non-senior routed topology needs a routing-trust redesign; the
     operator-key-rotation `ValueIndex` residual is intentional (outside the
     threat model). `AdminValuePolicyQuery`/format 8 was explicitly deferred in
     favour of zero-wire reject copy.

## Authority and value-op requirements (essential)
   - **Scope separation**: each admin request declares its required scope; grant
     management stays self-operator/CLI only (a delegated admin must never
     mutate `admins.json`, self-approve, or touch operator/ledger keys).
   - **End-to-end idempotency** (essential for value): the control replay guard is
     keyed `(origin, controller, nonce)` and retries mint a fresh nonce, so it
     stops replay but not double-execution. A value request must carry a stable
     `request_id` and the node must persist `(controller, request_id) ->
     (seq, hash)`, returning the prior result on retry. Rebuild the map at open.
   - **Value TTL**: <= 24 h recommended; short and explicit. Value scope reached
     only via an explicit `control admin grant --scope value`.
   - **Amount bounds**: the ledger has no global supply anchor and `fund` has no
     ledger-level replay guard, so the control plane is the only cap.
   - **Audit**: additive `control_audit.jsonl` value events with actor pubkey,
     scope, account, amount, `request_id`, entry `seq`/`hash`, outcome.
   - Value-scoped seed at rest should be encrypted (or re-entered per session);
     a value key in plaintext localStorage is an XSS-away mint.

## Administered-node + node-kind model
   - Introduce one browser-side `AdministeredNode { nodeId, address, label,
     kind, scopes, grantExpiresAt, status, lastSeenAt, childrenCount }`; every
     admin page reads from it instead of the implicit first-grant
     `activeAdminNode()`.
   - The wasm admin key stays a **singleton**; the web layer re-installs it on
     switch (`_ensureAdminKey(nodeId)`) rather than adding multi-key wasm state.
   - Node-kind in P1 is inferred from the `AdminQuery` snapshot; an
     authoritative `role` field on `NodeRecord`/`NodeSnapshot` is a P6 additive.
   - Discovery of administered nodes: persisted `cawala.admin` entries (P1) ->
     live `AdminQuery` probe for active/revoked/unreachable + kind (P1/P2) ->
     signed grant bundle (P2).

## Version / format impacts
   - `CONTROL_FORMAT_VERSION` 4 -> 5 (mint 5; accept 4+5; add a
     v5-variant gate mirroring the v4 gate). `CONTROL_REPLY_VERSION` 2 -> 3.
     `ADMIN_GRANT_VERSION` 1 -> 2 (store dual-accepts; v1 = joins-only).
   - **No ledger format changes**: `ENTRY_FORMAT_VERSION` stays 4,
     `LEDGER_FORMAT_VERSION` stays 3, `SETTLE_PAYLOAD_VERSION`/
     `LEDGER_PAYLOAD_V3_VERSION` stay 3, browser `LEDGER_STATE_VERSION` stays 4,
     `LOCAL_STATE_VERSION` stays 1 (selection lives in web localStorage, not
     wasm state). New `ADMIN_BUNDLE_VERSION` 1 if the grant URI is adopted.
   - Hard break: v3 control peers cannot receive v5 variants (lockstep,
     consistent with the existing control-negotiation deferral). Rebuild the
     wasm bundle and recreate `node-data` on the format bump.

## Verification per phase
   - P1: `web npm test` (adminKeys v2 migration, selection, kind derivation) +
     `npx vite build`; manual browser checklist.
   - P3-P5: extend `crates/node/tests/control_admin.rs` (per-scope allow/deny,
     revoke-wins, expiry, replay, routed); new `crates/node/tests/admin_value.rs`
     (issue/burn appended + `verify_issue`/`verify_burn` pass, caps, duplicate
     `request_id` returns the same `(seq, hash)` and appends nothing - including
     after reopen, no ledger handle => refused, audit line present);
     `crates/client-wasm` native tests for new DTO/grant parsing; routed v5;
     `cargo check -p cawala-client --target wasm32-unknown-unknown`;
     `cargo test --workspace` / `clippy -D warnings`; extended
     `web/scripts/smoke-admin.mjs` (grant -> switch -> query -> issue -> burn ->
     revoke -> denied).
   - Not hermetic: N0 relay/address lookup, real wasm glue, Web Locks,
     localStorage quota/private mode, clock skew, XSS resilience.

## Open decisions (defaults chosen; revisit before each phase)
   1. Scope taxonomy: `joins` -> `topology` -> `value`; `value` implies read;
      `joins` grants pending-join read only. (chosen)
   2. v1 admin grant = joins-only, never silently widened. (chosen)
   3. Value TTL <= 24 h, per-request cap, rolling window, per-account ceiling,
      configured operator-side. (chosen)
   4. Retry contract: stable `request_id` + persisted dedupe returning the prior
      result. (chosen)
   5. Browser creates child nodes: no; topology = detach/move only. (chosen)
   6. `AdminSetAddress`: deferred. (chosen)
   7. Value-scoped seed at rest: encrypted / re-entry. (chosen)
   8. Grant delivery: `cawala://admin` bundle (fallback: manual pubkey paste).

---

**Part 3 - Topology-derived administration refactor plan (historical).**


Status: **Draft for review** (no code changes made). Drafted by @oracle and
reconciled by the orchestrator; file:line references are indicative and may
drift.

- Supersedes: the delegated-grant model (P1–P6) and the direct-first admin path.
- Inputs: `REFACTOR.md` R1–R9 plus the resolved decisions for R3/R4/R5/R9.
- Baseline: `main` @ `5cd55b4`, clean.

---

## v2 amendment (2026-10-04) — explicit designation, no priority/failover

The user replaced the R5 priority/TTL-lease model with an explicit designation
set. This **supersedes** §0-R5, §1.3–1.4, and §3.1–3.4/§3.8 as they relate to
ordering, leases, epochs, and automatic failover; everything else (R1 tree-routed
admin, R3 grant removal, R4 replaced by the designation rule, R6–R9) stands.

- A node persists an explicit set of **designated administrator children**
  (child *node* or *leaf/browser*; all equal, full rights). Authority = the
  authenticated last hop is a current child in that set. No priority, TTL,
  lease, epoch, probe loop, or automatic failover.
- Browsers have **no automatic authority**; a leaf child is designated like any
  other child. The old R4 auto-browser-admin rule is removed.
- **Who may change the set:** local operator via CLI (always) and any currently
  designated administrator (routed). Local CLI recovers a lockout.
- Transitive reach remains hop-by-hop; to reach an ancestor each link must have
  designated the next child. Ancestor-chain + discovery walk unchanged (P3).
- Wire impact shrinks: `CONTROL_FORMAT_VERSION` and `CONTROL_REPLY_VERSION`
  revert to baseline (7 and 4); only `ROUTED_CONTROL_VERSION` 1→2 (grant
  dropped) remains. See `.slim/deepwork/admin-refactor-v2-spec.md`.
- `senior.rs`/`senior_child` and `ControlNode::seniority()` are deleted (no
  remaining ordering or authority role).

---

## 0. Resolved decisions this plan is built on

- **R4**: "leaf" = user/browser only. A browser child has **complete** admin over
  its parent. A node with browser children is administered **only** by those
  browsers — no child fallback; local CLI is the fallback when they are offline.
- **R5**: nodes **without** browser children keep a priority-ordered **child-node**
  list, **explicitly seeded** (empty by default; a child gains admin only when the
  operator/current admin authorizes it, first admin via local CLI; join order is
  tie-break only). The current admin may reorder. A configurable TTL (default
  5 min) governs failover: if the node cannot reach the current admin child within
  the TTL, the next child in priority order may administer it. Administration is
  transitive.
- **Ancestor reach (frozen)**: browser upward reach is the strict ancestor chain
  with a node-id discovery walk over the direct parent link (see §1.5); authority
  remains hop-by-hop.
- **R9**: local CLI on the host is the universal fallback (operator key on the
  machine; self-authority, not a grant). It is the only fallback for a node whose
  browser children are offline.
- **R3**: remove the **entire** delegated-admin-grant concept —
  `AdminGrant`/`AdminGrantV2`, `admins.json` + verification, `cawala://admin`
  bundle, `control admin grant|revoke|list`, browser `cawala.admin.*` key store +
  selection/protection, `AdminScope`/scoped grants. Authority derives from
  topology.
- **R1**: all admin is tree-routed; no direct-dial-first admin path.
- **R6–R8**: admin actions live behind a lock + policy acknowledgement on a
  dedicated admin page; up/down target switching; drastically simplified
  UI/sidebar in both modes.

---

## 1. Authority model

### 1.1 Principals and the single authority rule

There are exactly three principals:

| Principal | How identified | Authority |
|---|---|---|
| Browser (`ChildKind::User`) | a direct child of the target, operator key == endpoint id | full admin of its parent |
| Admin child node | a direct child node of the target, selected by the priority list | full admin of its parent |
| Local operator | process on the host with the node's `<data-dir>` + operator key | full admin, always |

The **only** authorization question a node asks is: *is the authenticated direct
neighbor that handed me this request one of my administrators?* This replaces
`admins.active_scopes()` and `AdminScope` entirely. There is no capability token
to present, downgrade, or leak; authority is a property of the target's own
persisted topology state plus the msg-layer-authenticated last hop.

Cross-cutting rule (applies to topology, joins, and value actions alike): a
request is applied only if the **last hop of the routed envelope is a current
administrator** (or the origin is the node's own operator key).
`RoutedForward.hop` strings are never authority (consistent with
`m5-routed-control.md` and `crates/msg/src/route.rs`).

### 1.2 How a node determines its administrator(s)

```
fn administrators(node) -> AdminSet:
    if node.children.any(kind == User):          # R4
        return all User children                  # complete rights, all equal
    else:                                          # R5
        return [priority[current]] if lease valid
```

- **R4 detection is dynamic**: read from `node.json` children each request
  (already reloaded per request by `ControlNode::refresh_control_plane`,
  `crates/node/src/control.rs:711`). A browser child row exists in
  `ledger_peers.json` after `approve_pending`, so `verify_control` can
  authenticate its per-hop forward.
- **R5 list** is persisted (see 1.3); `priority[0]` is the default senior child
  (supersedes `senior_child` as the *authority* selector — `crates/control/src/senior.rs`
  may remain only to compute the initial default).
- The node's own operator key remains self-admin for purely local/self
  operations, but there is **no remote direct path** to exercise it (R1). Local
  CLI does not use control frames.

**Direct vs transitive case, uniformly.** Because the browser's parent is its
direct neighbor, the browser administers its parent with a one-hop routed
envelope whose last hop is the browser itself. When the browser administers an
ancestor, the last hop at the target is the browser's parent (which is the
target's administrator), and the browser's end-to-end intent is carried for
audit. In both cases the target checks the same predicate: the authenticated
predecessor is one of my administrators.

### 1.3 Persisted state and schema

Replace `<data-dir>/admins.json` with `<data-dir>/admin_state.json`:

```jsonc
{
  "version": 1,
  "priority": ["<child_node_id>", ...],  // node children only, <= 8, highest first
  "current": 0,                          // index into priority; -1 when none
  "lease_until": 1730000300,             // unix secs; 0 when no lease
  "epoch": 42,                           // monotonic; bumped on failover/reorder
  "ttl_secs": 300,                        // configurable, default 5 min
  "updated_at": 1729999999,
  "updated_by": "local" | "<admin_node_id>"
}
```

- Default on first open / missing file: `priority = []`, `current = -1`,
  `lease_until = 0`, `epoch = 0`. **Seeding is explicit** (decided 2026-10-03):
  a child enters the list only via explicit operator/current-admin authorization;
  the first admin is bootstrapped by local CLI. Join order only orders
  already-authorized admins. See risk 3.1.
- Loaded/validated per request (mirroring `refresh_control_plane`); a corrupt
  file fails closed to "no remote admin" (local CLI still works).
- Browser children are **not** listed here; R4 is derived from `node.json`.
- `epoch` and `current` must be persisted **before** accepting a request under a
  new epoch (crash-safety / anti-downgrade).

### 1.4 "Cannot connect", failover, proof, rollback

**Definition of "cannot connect."** The current admin child must keep a lease
alive. Recommended concrete definition: the node has received **no valid, fresh
`AdminLease` (renew) and no valid admin request from `priority[current]` for
`ttl_secs`**, and (on expiry) its priority-ordered probe of the next candidate
fails. This is lease semantics (R5 Q3): every successful contact resets
`lease_until = now + ttl`.

**Failover algorithm (recommended, server-side, priority-ordered,
deterministic):**

1. Current admin sends `AdminLease{epoch}` on a cadence `ttl/3`; the node
   validates the sender is `priority[current]` and `epoch == state.epoch`, then
   refreshes `lease_until`. Any valid admin request also refreshes it.
2. When `now > lease_until`, the node walks `priority[current+1 ..]` in order,
   sending a cheap probe (or waiting a bounded window for a renewal from that
   candidate). The first candidate that answers/contacts becomes `current`,
   `epoch += 1`, `lease_until = now + ttl`, persisted **before** the response.
3. If no candidate answers, remote admin is unavailable until a child
   re-establishes contact or local CLI intervenes. Local CLI remains the
   guarantee (R9).

**Proof / anti-replay / anti-downgrade:**

- The node owns the lease clock; a child cannot extend it. Renewals carry
  `epoch`; a former admin's renewal (`epoch < state.epoch`) is rejected.
- `SignedControl` nonce + `SeenStore` replay guard still apply per
  `(origin, controller)`.
- Msg-layer `(src.node, msg_id)` replay guard still applies to the whole
  envelope.
- A delayed request from a former admin arriving after failover is rejected by
  the last-hop check, regardless of nonce freshness.
- **Rollback**: a mistaken failover is corrected by local CLI (reset `current`,
  bump `epoch`, optionally set a cooldown). The network cannot roll an epoch
  back.

**Wire cost.** This wants new control variants (`AdminLease` + a lease state
reply) and therefore a `CONTROL_FORMAT_VERSION` bump (7 → 8). If the team prefers
no new variants, the fallback is parent-initiated dials of `Query`-like probes;
either way a format bump is the clean choice. See §5 R3-Q2.

### 1.5 Transitive scope and the messages it requires

A browser administers its parent directly, and its parent's ancestors
transitively: the browser's request travels `browser → parent → … → target`; each
hop re-signs a `RoutedForward` (existing `prepare_control_forward`,
`crates/node/src/msg.rs:474`); the target applies it because its last hop (the
browser's parent, or deeper) is one of the target's current administrators. No
new routing is needed — the existing ascend/descend and `MSG_CONTROL_V1` per-hop
machinery covers it.

**Reach is bounded by each ancestor's own admin set.** The chain only continues
while every hop's node child is that ancestor's current administrator (R5). If
an intermediate ancestor has its own **browser** children, R4 makes those
browsers its only administrators, so a node child on the path is *not* an
administrator there and the upward chain terminates at that ancestor. Equivalently:
transitive browser reach requires the chain of node children to be explicit
priority admins at every level. This also bounds the §3.5 blast radius. (Correction
recorded from the P1 spec, 2026-10-03.)

**The one unresolved transport gap: identifying an ancestor target.** The browser
knows its own assigned address and its direct parent's node id (from
`JoinApproval`/`ParentLink`), so depth-1 administration is fully authenticated.
For depth ≥ 2 the browser needs the ancestor's **node id** to (a) put it in
`RoutedControlV1.target.node` and (b) verify the routed reply under its operator
key (`verify_routed_reply_bytes`, `crates/client-wasm/src/control.rs`).

Recommended mechanism:
- **Address is derivable** from the browser's own address by repeated
  `.parent()` (the address law: child = `parent.child(slot)`). So `dst`/
  `target.addr` needs no grant and no `nodeAddr` — this answers R1-Q1/R1-Q2.
- **Node id is discovered incrementally**: the browser can prove its parent's
  node id already; to learn the grandparent it uses a signed topology query to
  the (authenticated) parent, and so on. This requires either a small
  `TopologyQuery` reply that includes the parent id, or caching ids learned from
  prior admin replies. This is the single largest design detail to nail down;
  see §5 R1-Q1 and §3.5.

Alternative (simpler but weaker): restrict R7 to the **direct parent only** in
v1; ancestors are addressed by address-only with the reply accepted from the
browser's own parent. That caps the transitive blast radius but does not meet
"administering is transitive so the tree is always coverable" for the browser's
upward reach. Not recommended as the end state.

### 1.6 Local CLI authority semantics

- Authority is the node's own operator key on the host — self-authority, not a
  grant (R9).
- **Online edits**: `control admin priority show|reorder|set-current|reset-epoch`
  and value/topology/join commands run against the live engine; the engine
  already reloads `node.json`/`ledger_peers.json`/policy per request, and the new
  `admin_state.json` must be reloaded the same way.
- **Offline edits**: static config only (priority list, `value_policy.json`,
  detaching a browser/child record). Ledger mutations (issue/burn) and live
  topology mutations require a running node holding the ledger key.
- **Audit**: local actions get a distinct marker (`"via":"local"`,
  `"actor":"operator"`), separate from routed network audit (`"routed":true`,
  `requester`, `forwarder`, `hops`). Answers R9-Q1.
- Local CLI is also the **demotion tool**: because only the current admin may
  reorder (R5), the operator's only way to demote a hostile/rogue admin is local
  CLI.

### 1.7 Fate of value policy and seed protection (R3)

- `value_policy.json` is **kept** but is no longer a grant: it becomes an
  operator-configured, deny-by-default bound on issue/burn (per-request, window,
  per-account, optional per-operator overrides). It is a safety limit, not an
  authority source.
- Browser value-seed passphrase protection (P6, `adminSeedCrypto.js`,
  `protectAdminSeed`) is **deleted**: with no browser-held admin keys there is no
  seed to protect. Local CLI has no analogous passphrase (see risk 3.7).

---

## 2. Delete vs keep (concrete)

### 2.1 `crates/control`

| Action | Item |
|---|---|
| Delete | `src/admin.rs` (`AdminGrant`, `AdminGrantV2`, `AdminScopes`, `AdminScope`, `RequiredScope`, `SignedAdminGrant*`) |
| Delete | `src/admin_bundle.rs` (`AdminGrantBundleV1`) |
| Delete | `src/senior.rs` **or** keep only as the default-ordering helper (no authority role) |
| Edit | `src/request.rs`: remove `required_scope`/`RequiredScope`, `is_admin` scope mapping; keep the admin request **variants** (decision R3-Q2) |
| Edit | `src/routed.rs`: remove `grant: Option<SignedAdminGrant>`; bump `ROUTED_CONTROL_VERSION` **1 → 2** |
| Edit | `src/sign.rs`: `CONTROL_FORMAT_VERSION` 7 → **8** (lease variants); `min_control_version`/`is_supported_control_version` updated |
| Edit | `src/lib.rs`: drop admin/admin_bundle re-exports; add lease types |

### 2.2 `crates/node`

| Action | Item |
|---|---|
| Delete | `src/admin_store.rs` (`admins.json`, `StoredGrant`, `AdminStoreError`) |
| Delete | `src/admin_cli.rs` (`grant`/`revoke`/`list`/bundle) |
| Add | `src/admin_state.rs` (priority/TTL/lease/epoch persistence + validation) |
| Edit | `src/control.rs`: remove `admins` field, `reload_admins`, `Authority::Delegated`, grant branch of `authorize_admin`; rewrite `authorize_admin` to be predecessor-topology-based; rewrite `seniority`; thread or dispatch the intended authority through `receive_routed_at_handled`; lease/failover handling |
| Edit | `src/main.rs`: replace `AdminCommand`/`ScopeArg`/`admin_command` with local `admin priority`/`admin lease`/`admin state` subcommands |
| Edit | `src/lib.rs`: drop `AdminStore`/`admin_store` re-exports |
| Edit | `src/msg.rs`: `prepare_control_forward` drops grant handling; envelope coherence stays |
| Tests | Delete/rewrite `tests/control_admin.rs`, `tests/admin_topology.rs`, `tests/admin_value.rs`, `tests/admin_ledger.rs`; update `tests/control.rs`, `tests/exit_rebase.rs`, `tests/routed_control.rs` (`AdminStore::empty`/grant ctor removal) |

### 2.3 `crates/client-wasm`

| Action | Item |
|---|---|
| Delete | `SharedControl.admin` Mutex, `set_admin`/`admin_key`, `exchange_admin`, `should_try_routed`, `sign_admin_request` as written |
| Edit | `sign_admin_request` → sign with the browser's **own** operator key; origin/controller = this client (not the target) |
| Edit | `admin_exchange` → **always routed**; drop the direct-first attempt; target address derived from own address; keep reply verification |
| Edit | `build_routed_control` drops `grant` field |
| Delete | `set_admin_key`, `clear_admin_key`, `admin_public_key`, `admin_context` |
| Delete | `dto.rs` `parse_admin_bundle`/`AdminGrantInfo` and bundle tests |
| Edit | All `admin_*` methods lose `node_addr` params; they derive ancestor addresses |
| Glue | Rebuild `web/src/wasm/` (`npm run build:wasm`) — arity changes |

### 2.4 Web

| Action | Item |
|---|---|
| Delete | `lib/adminKeys.js`, `lib/adminSeedCrypto.js`; reduce `lib/adminView.js` to ancestor-path helpers |
| Edit | `lib/api.js`: delete `configureAdminNode`, `applyAdminBundle`, `applyAdminGrantInfo`, `removeAdminNode`, `getAdminNodes`, `_ensureAdminKey`, `ensureAdminUnlocked`, `protectValueSeed`, `lockAdmin`, `listAdministeredNodes`; rewrite `setAdministeredNode` to topology-derived targets |
| Edit | `lib/stores.svelte.js`: `administeredNode` becomes "current admin target"; drop `grantExpiresAt`/`scopes`/`grantSource`; add lock state |
| Edit | `lib/constants.js`: `NAV_ITEMS`/`ROUTES` reduced; add `ROUTES.ADMIN` |
| Delete/replace | `components/admin/{AdminNodeRow,GrantEmptyState,GrantStatusBanner}.svelte`; `NodeSelector.svelte` → up/down control |
| Edit | `lib/adminView.js` + `components/layout/{Sidebar,MobileNav,NodeContextBar}.svelte`: drop grant TTL/scope chips, selector dropdown, banner |
| Edit | `components/settings/SettingsPage.svelte`: delete "Node Administration" grant UI; add unlock/policy + admin page |
| Edit | `components/accounts/AccountsPage.svelte`: issue/burn move behind the admin lock (page may stay, actions gated) |
| Tests | Delete/replace admin-key store + bundle tests; add topology-target and lock tests |

### 2.5 Data, wire, and storage migration (hard breaks)

- **On-disk**: `admins.json` deleted/ignored; new `admin_state.json`. Recreate
  `node-data` on upgrade (consistent with the repo's hard-break convention).
- **Control wire**: `CONTROL_FORMAT_VERSION` 7 → **8** (lease variants);
  `ROUTED_CONTROL_VERSION` 1 → **2** (grant field removed). `RoutedReplyV1` may
  bump if it carries lease state. Lockstep repo — rebuild the wasm bundle.
- **Semantic (not shape) break**: an admin `ControlRequest` intent's
  `origin`/`controller` now name the **requester**, not the target; the target no
  longer requires `origin == self`.
- **Browser storage**: `cawala.admin.v1/v2/v3` ignored/deleted; no migration
  (there is no key to carry). Selection is derived from topology.
- **wasm arity**: `set_admin_key`/`clear_admin_key`/`admin_public_key`/`admin_*`
  signatures change → stale glue must never be paired.
- **Field/property removal**: `grant` on `RoutedControlV1`, `Authority::Delegated`,
  `AdminGrantInfo` DTO, `nodeAddr` grant field.

---

## 3. Threat model & risks

### 3.1 Adversarial priority child taking admin — **highest-priority risk**

R5's default "priority = join order" means the **first child ever approved
automatically becomes the parent's administrator**. Under the old model the
operator explicitly issued a grant; here, joining as the earliest child is enough
to gain full admin, including the power to reorder the list and lock out everyone
else. The operator's only demotion path is local CLI.

**Decision (frozen 2026-10-03)**: do **not** auto-seed the priority list from
join order. A child becomes an administrator only when the operator (or the
current admin) explicitly adds it; join order is used only as the tie-break /
stability order among already-authorized admins. The first admin is bootstrapped
via local CLI. This closes the "first joiner is permanent admin" lockout risk.

### 3.2 TTL / replay abuse

Non-admins cannot renew (last-hop + epoch check). A current admin that stalls
renewal loses the lease. Nonce replay is covered by both replay guards. Clock
abuse is bounded because the node owns the clock and `ttl`; a child cannot extend
its own lease. Residual: many distinct `RoutedForward` nonces let a retried
end-to-end intent be re-applied if the guard keys on the hop nonce rather than
the intent nonce (see 3.6) — mitigated by idempotency (`request_id` for value)
and by keeping the intent replay check.

### 3.3 Priority-list manipulation

Only the current admin may reorder (R5). A hostile current admin can pin itself
at `priority[0]`; a newly failed-over admin can reorder immediately (recommended:
yes, audited) to prevent a returning former admin from displacing it. Both are
inherent to "full admin" and recoverable only via local CLI. Mitigation: audit
every reorder with `updated_by`/`epoch`, and document that the host operator is
the root of recovery.

### 3.4 Offline-browser gap (R4)

A node whose only admins are offline browsers has **no** remote admin; local CLI
is the sole path (R4/R9). If the operator lacks host access, the node is
unmanageable until a browser returns. This is by design, but it makes host access
**mandatory** for recovery and should be documented prominently. All browser
children hold equal full rights (R4-Q1 recommendation: yes); one compromised
browser compromises that parent (and, if its parent is a priority child, possibly
ancestors). Recovery: local CLI detaches the browser child.

### 3.5 Transitive escalation

Because each hop trusts the authenticated predecessor-administrator, a
compromised browser can reach every ancestor for which its parent is
(transitively) the current admin child — potentially the root, with full
issue/burn. This is the design's largest blast radius. It is bounded in practice
only by (a) the priority chain from node-with-admin upward, and (b) the local
operator's ability to reorder/detach. **Mitigation options (human decision):**
cap transitive depth; require a per-hop confirmation for value actions; or scope
value actions to the direct parent only. Also note the unresolved ancestor-node-id
discovery problem (§1.5): a v1 that accepts the direct parent's relay without
independent ancestor-key binding lets a malicious parent fabricate ancestor
replies (mislead, not perform). Recommend implementing the discovery walk before
shipping transitive admin.

### 3.6 Wire downgrade

Replaying an old admin intent after losing admin is rejected by the last-hop
check and the target-owned epoch; replay while still current is rejected by the
msg-layer `(src,msg_id)` and control nonce guards; `SignedControl` expiry is
≤ 120 s with a 300 s server cap. **Mitigation**: if we dispatch the last-hop
signed control (instead of the intent), ensure the end-to-end intent's nonce is
*also* observed, or accept idempotency-only semantics — flag as a wire decision.

### 3.7 Local-CLI blast radius

Filesystem access to `<data-dir>` + operator/ledger keys = total,
unauthenticated-node control (arbitrary issue/burn, topology rewrite, epoch
reset), and there is no passphrase gate analogous to P6. Mitigation: OS file
permissions and at-rest disk encryption only; add the `via:"local"` audit marker;
document that host compromise is game-over. This is inherent to R9 and acceptable
if the host is trusted.

### 3.8 Coverage under failover

When a node fails over from child N to sibling M, the browser under N **loses**
the ability to administer that node (the route to the node goes through N, which
is no longer admin; M is off-path). "The tree is always coverable" therefore
means *there exists at least one administrator path* (a browser under the current
admin child, or local CLI), not that every browser retains reach. State this
precisely; the operator can restore N's reach via local CLI reorder. Also: a
mid-tree node with no reachable children cuts off remote admin for its whole
subtree (local CLI per host remains).

### 3.9 Contradiction with existing architecture (must be reconciled)

- README ("one child node (the most senior) is selected to control its parent")
  is superseded — priority list, senior = default #1.
- The current routed admin path dispatches the **intent** and requires
  `origin == self` (`crates/node/src/control.rs:682`, `authorize_admin`); this is
  a direct contradiction to topology authority and must be reworked.
- `PLAN.md` "Trust" + "Next Phases" and `HANDOFF.md` "Current state" describe
  grants as authority; they become wrong and are handled by R2.
- Value policy currently keys on the signing controller; under transitive admin
  the controller may be a relay, not the human — decide (recommend: key on the
  end-to-end requester by dispatching the intent).

---

## 4. Phased plan

Bottom-up, `main` green after every phase. Wire format bumps land in Phase 1;
wasm/web follow in lockstep.

| Phase | Scope | Depends on | Deletes | Verification gate |
|---|---|---|---|---|
| **P0** | Approve this plan; add `ADMIN_POLICY.md` stub; freeze R5 seeding decision (3.1) | — | — | User sign-off; baseline `cargo check --workspace --all-targets` |
| **P1** | Node/control authority core: `admin_state.rs`; topology-authority check; predecessor-bound admin auth; lease + priority failover + epoch; local CLI `admin priority/lease/state`; lease wire variants; `CONTROL_FORMAT_VERSION`→8, `ROUTED_CONTROL_VERSION`→2, drop `grant` | P0 | `seniority` authority role | `cargo test -p cawala-control`, `cargo test -p cawala-node`, rewritten `admin_*` suites, `cargo clippy` |
| **P2** | Delete the grant subsystem (`control/src/admin.rs`, `admin_bundle.rs`; `node/src/admin_store.rs`, `admin_cli.rs`; CLI `grant/revoke/list`; tests) | P1 | all grant types/state/tests | `CARGO_BUILD_JOBS=1 cargo test --workspace`, clippy |
| **P3** | wasm client: always-routed admin; own-operator signing; address derivation + ancestor-id discovery; remove admin key API/store; `dto.rs` bundle removal; rebuild wasm glue | P1 (interface), can parallel P2 | `SharedControl.admin`, `exchange_admin`, bundle parse | host tests + `cargo check -p cawala-client --target wasm32-unknown-unknown`; `npm run build:wasm` |
| **P4** | Web: lock gate + policy ack; admin page (issue/burn, invite, pending joins, topology, leave/join); up/down target switch; simplified `Sidebar`/`MobileNav`/`NodeContextBar`; delete grant UI/store | P3 | `adminKeys.js`, `adminSeedCrypto.js`, grant components, Settings admin section | `cd web && npm test`; `cd web && npm run build` |
| **P5** | Docs consolidation (R2): rewrite `README.md` terminology/features; `PLAN.md` design vs history; shrink `HANDOFF.md`; fix/retire `web/README.md`; fold `REFACTOR.md`/this plan into `PLAN.md` or keep as requirements | P1–P4 | stale doc sections | Manual review; repo link check |

Ordering notes:
- **P1 is the risky phase**: it changes wire formats and the authorization core.
  Land it alone; it does not compile with the old wasm/web, so P1–P4 must ship as
  one lockstep release (develop on a branch, merge together), while each commit
  keeps the workspace compiling.
- **P2 can merge with P1** if the grant deletion is mechanical; keep it separate
  if P1 is already large.
- **P0 policy doc** is a prerequisite for P4's lock acknowledgement.

---

## 5. Open questions — recommendations

Legend: **[REC]** recommended default (implement unless overruled) · **[HUMAN]**
product/security decision required.

### R3 — Remove grants
- **Q1 (drop scopes or keep action classes?)** **[REC]** Drop scopes entirely;
  every administrator has full authority (matches R4 "complete admin rights").
  Keep `value_policy.json` as a separate operator safety bound, not a scope; keep
  `AdminIssue`/`AdminBurn` as value-class requests for policy enforcement.
  **[HUMAN]** whether value actions need a stronger gate than other admin actions.
- **Q2 (keep admin wire variants or replace?)** **[REC]** Keep the existing
  `ControlRequest` admin variants and `RoutedControlV1` shape; change only the
  authorization rule and drop the `grant` field (`ROUTED_CONTROL_VERSION` 2). Add
  lease variants in the same format bump (8). Avoid inventing parallel admin
  variants. **[HUMAN]** accept the format-8 hard break.

### R5 — Priority + TTL
- **Q2 (who may reorder; new admin immediately?)** **[REC]** Only the current
  admin; the newly failed-over admin may reorder immediately, audited. Local CLI
  may always override. **[HUMAN]** freeze window before a new admin can reorder.
- **Q3 (what is "cannot connect"; lease reset?)** **[REC]** Lease semantics: no
  fresh renewal/admin contact for `ttl` (default 300 s), plus a priority-ordered
  probe of candidates on expiry; every successful contact resets the lease.
- **Q4 (relationship to senior child)** **[REC]** Priority replaces seniority for
  authority; default list = `(date_joined, id)` order, so `senior_child` is just
  default `priority[0]`. Keep `senior.rs` only as the ordering helper. **[HUMAN]**
  whether to keep the term "senior" at all.
- **Q5 (automatic vs explicit takeover)** **[REC]** Automatic, server-side, on
  TTL expiry (`epoch += 1`, audited) to avoid races; not a self-claimed takeover.
  **[HUMAN]** whether to require an explicit claim from the candidate.

### R6 — Lock gate
- **Q1 (what/where is the policy doc?)** **[REC]** A versioned `ADMIN_POLICY.md`
  in-repo, rendered in the unlock dialog; acknowledgement stored locally with the
  policy hash/version so edits invalidate it. **[HUMAN]** content and legal
  language.
- **Q2 (on lock, hide or drop authority?)** **[REC]** Hide admin surfaces **and**
  clear in-memory admin target/data caches and reset the page; there is no
  cryptographic key to drop. **[HUMAN]** whether unlock persists across reload
  (recommend: locked by default).
- **Q3 ("leave/join as a non-browser node")** **[REC]** Means administering the
  *administered node's* topology/children (`CreateChild`/`DetachChild`/`MoveChild`)
  and the operator-driven leave of that node; the browser's own join/leave stays
  the normal join flow. **[HUMAN]** whether the browser can trigger a node's exit.

### R7 — Up/down target switching
- **Q1 (what does up/down traverse?)** **[REC]** The ancestor chain derived from
  the browser's own address (own node → parent → … → root): exactly the set it can
  administer, no extra state for addresses. **[HUMAN]** flat list vs strict
  ancestor chain; and whether to invest in ancestor-node-id discovery (§1.5).
- **Q2 (show path/address + current indicator?)** **[REC]** Yes: show target
  address/path and a current-node indicator; disable up/down at the ends.

### R8 — UI simplification
- **Q1 (minimal tab sets)** **[REC]** User mode: `Home`, `Accounts`, `Activity`,
  `Settings` (a single `Join` entry only while unjoined). Admin mode: add one
  `Admin` tab (issue/burn, invite, pending joins, topology, leave) plus the same
  four. Remove `Join Requests` as a top-level tab (it moves into Admin).
  **[HUMAN]** final labels and whether `Admin` is a tab or a mode toggle.

### R9 — Local CLI
- **Q1 (separate audit marker?)** **[REC]** Yes: `via:"local"`, `actor:"operator"`.
- **Q2 (offline vs running process?)** **[REC]** Offline for static config
  (priority list, policy, detach/evict); ledger mutations and live topology
  require a running node. **[HUMAN]** whether to add an offline "plan and apply on
  next start" mode.
- **Q3 (anything unavailable locally?)** **[REC]** No intrinsic gap when the node
  is running (it holds the operator + ledger keys); only ledger/live ops need the
  process. Document the split.

### Answered by this design (not in the original question set)
- **R1-Q1 (nodeAddr required?)** No: derive the target address from the browser's
  own address; node ids for direct-parent are known and ancestors are discovered
  incrementally (see §1.5). **[HUMAN]** approve the discovery mechanism.
- **R1-Q2 (unjoined fail closed?)** Yes — admin fails closed with no
  parent/address.
- **R1-Q3 (keep direct dial to own leaf?)** Yes; `cawala/control/0` remains for
  the join handshake, payments, and `Rebase`/`DetachNotice`/`Query` with the
  direct parent only.
- **R4-Q1 (equal browser rights?)** Yes, all browser children hold equal full
  rights.
- **R4-Q2 (authority above parent?)** Yes, transitively, via the parent relay
  (see 3.5).
- **R2-Q1/Q2/Q3 (docs)** **[REC]** Archive delivered-phase records in
  `PLAN-ARCHIVE.md`/`CHANGELOG.md`; split living design (`PLAN.md`) from history;
  fold `REFACTOR.md` into `PLAN.md` when done. **[HUMAN]** archive vs delete.

---

## 6. Non-goals / explicitly deferred

- Encrypting or passphrase-protecting local CLI authority (host trust is the
  boundary).
- Signed topology/registry distribution (rejected elsewhere; rejected here too).
- Multi-person/time-locked admin, grant-embedded limits, anomaly dashboard — these
  were P5/P6 follow-ups under grants and are dropped with grants (some may be
  reintroduced as local value-policy features if needed).
- Reply confidentiality or a reply-reflection rate limit (unchanged from M5
  residuals).
- Version negotiation for mixed-version fleets (unchanged; lockstep).

---

**Part 4 - Refactor requirements (historical).**


This is a living document that gathers the requirements and ideas for an
upcoming refactor. It is intentionally requirement-first: each entry states what
must be true, why, and what is still open, so it can be reviewed and then turned
into a plan.

Overall intent: **simplify** the architecture where possible — fewer transport
paths, one communication rule, less special-casing.

Status: **Draft — gathering requirements**
Last updated: 2026-10-03
Design + phased plan: **`REFACTOR_PLAN.md`** (draft, derived from R1–R9)

---

## How to use this document

- Requirements get a stable id (`R1`, `R2`, …); append new ones at the end.
- Each requirement captures: statement, rationale, scope/to-confirm, and open
  questions. Keep "grounded facts" (with file references) separate from
  proposals.
- Nothing here is committed until it is reviewed and folded into a plan.

---

## Requirements

### R1 — All administration of nodes is tree-routed

**Statement.** Every administration exchange with a node must be carried over
the routing tree (`MSG_CONTROL_V1` envelopes), hop by hop, from the requester to
the target. There is no direct `cawala/control/0` dial to an admin target.

This covers the whole admin surface:
- `AdminQuery`, `AdminLedgerQuery`;
- `AdminApproveJoin` / `AdminRejectJoin` / `AdminRedeliverJoin`;
- topology admin (`CreateChild` / `DetachChild` / `MoveChild` / `SetAddress`);
- value admin (`AdminIssue` / `AdminBurn`).

**Rationale.** This aligns administration with the network's core
communication rule, which the rest of the system already follows:
- a node only communicates with its parent or up to 8 children
  (`README.md:87`);
- web clients only communicate with leaf nodes (`README.md:88`);
- a web client controls more than one node only **indirectly, through
  intermediate child nodes** (`README.md:91-92`).

Today this is not enforced for administration: `admin_exchange` tries a
**direct dial first** and only retries over the routed tree on a *transport*
failure (`crates/client-wasm/src/lib.rs:1157-1189`, `should_try_routed` in
`crates/client-wasm/src/control.rs:661-670`). That lets a browser open a direct
connection to a non-neighbor / non-leaf ancestor, which contradicts the rule
above. The routed path itself is already neighbor-consistent and can be the
only path.

**Already true / to build on (grounded).**
- Routing only ever forwards to a direct neighbor — the parent or the matching
  child — and refuses to route through a `User` child
  (`crates/msg/src/route.rs:84-111`).
- The receive side enforces that the last hop is the authenticated direct
  neighbor, and that the hop chain is the exact `next_step` path
  (`crates/msg/src/route.rs:155-238`, `crates/node/src/msg.rs` neighbour gate).
- The routed request is already dialed to the requester's parent, with the
  target's asserted octal address as the destination
  (`crates/client-wasm/src/lib.rs:1191-1205`).
- Authority stays per-node: the target verifies the delegated admin key against
  its own `admins.json` and operator key
  (`crates/node/src/admin_store.rs:184-219`); the routed intent is signed to the
  target and each intermediate hop is re-signed by that node
  (`crates/control/src/routed.rs`, `m5-routed-control.md:103-111`).

**Scope (to confirm).**
- [ ] Remove the direct-dial-first path for admin requests; the routed path is
      the only path for the admin surface.
- [ ] The requester dials only its direct parent; each hop forwards to the next
      direct neighbor; the reply follows the same tree path.
- [ ] Keep per-hop authentication and exact-path hop-chain validation.
- [ ] Target address discovery: routed control needs the target's asserted
      octal address (`nodeAddr`). Decide whether it becomes a required field of
      an admin grant entry, or is resolved from the tree/registry.
- [ ] Define the failure mode when the requester is not joined (no parent /
      address).

**Implications / candidate simplifications.**
- One communication rule for data and control; delete the direct admin dial
  path and its fallback logic (`should_try_routed`).
- Revisit what the direct `cawala/control/0` ALPN is still for after this — at
  minimum the join handshake and the browser↔its-own-leaf link (payments/join),
  where the leaf is a direct neighbor.
- Admin targets must be reachable on the tree from the requester (ancestor
  targets work today; non-ancestor targets are already deferred —
  `m5-routed-control.md:230`).

**Open questions.**
- Q1: Must `nodeAddr` become required on an admin grant, or can the target's
  address be derived another way (e.g. from the local topology / parent chain)?
- Q2: For a not-joined requester, fail closed entirely, or is there a
  non-admin exception? (Presumably fail closed for admin.)
- Q3: Does the browser keep a direct dial to its **own leaf** (its direct
  parent) for payments and the join handshake? (Presumably yes — it is a direct
  neighbour link.)

### R2 — Documentation consolidation (simplify and de-duplicate the project docs)

**Statement.** Consolidate the project docs so each has one job and no stale or
duplicated content, and move delivered-phase history out of the operational
entry points.

**Rationale.** Docs are the first thing every session reads, and they have
overlapped and drifted: `HANDOFF.md` claimed to be "deliberately small" while
carrying per-increment prose, stale commit/test references, and a
`cawala.admin.v2` note contradicted elsewhere by v3; `PLAN.md` mixes
architecture, decisions, and long DONE records; `MANUAL_TESTING.md` explicitly
flags `web/README.md` as stale. Simplification is an explicit goal of this
refactor, and clearing doc noise makes the remaining requirements easier to
evaluate.

**Scope (to confirm).**
- [ ] `HANDOFF.md` stays small: current state, open backlog, verify,
      conventions only — no per-increment DONE prose (that is `PLAN.md`'s job).
- [ ] `PLAN.md` separates living design/decisions from historical
      delivered-phase records (collapse or archive the per-increment DONE
      detail); its forward plan is rewritten once R1–Rn are settled.
- [ ] `web/README.md` is fixed or retired (currently stale — it describes a
      ping/debug harness and claims there is no browser admin or issue/burn
      path).
- [ ] Decide where requirement docs live long-term (does this `REFACTOR.md`
      become the plan, or fold into `PLAN.md`, when implemented?).

**Open questions.**
- Q1: Archive delivered-phase records in-repo (e.g. `PLAN-ARCHIVE.md` /
  `CHANGELOG.md`), or delete them (git history retains them)?
- Q2: Keep a single `PLAN.md`, or split "design/decisions" from
  "roadmap/changelog"?
- Q3: When the refactor is done, does `REFACTOR.md` become the new `PLAN.md`, or
  stay a separate requirements doc?

### R3 — Remove delegated admin grants; authority comes from topology

**Statement.** Remove the entire delegated-admin-grant concept: the node-signed
`AdminGrant`/`AdminGrantV2` types, on-node `admins.json` and grant verification,
the `cawala://admin` bundle, the `control admin grant|revoke|list` CLI, the
browser admin-key store (`cawala.admin.v*`) and its selection/protection
machinery, and the `AdminScope`/scoped-grant model. A node's administrator is
determined by its topology (R4/R5), not by an operator-issued key.

**Rationale.** Grants exist to delegate authority to an arbitrary external key.
If authority is inherent in the parent-child relationship, grants add a parallel
trust system plus extra wire formats, a browser key store, passphrase-protection
complexity (P6), and UI surfaces. Removing them deletes a whole subsystem and
simplifies both the control plane and the UI.

**Scope (to confirm).**
- Delete grant storage/verification and the grant wire types; drop the admin-key
  CLI and the browser key store.
- Replace the node's grant check (`authorize_admin` → `admins.active_scope`) with
  a topology-authority check (R4/R5).
- Decide the fate of value-seed passphrase protection (P6) once no admin keys
  live in the browser.
- Wire/hard-break fallout: `admins.json`, admin-grant format 2, and the admin
  variants of `CONTROL_FORMAT_VERSION` must be re-planned.

**Open questions.**
- Q1: Does removing grants also remove the per-request scope set
  (joins/topology/value), or does topology authority still distinguish action
  classes?
- Q2: Keep the existing admin request/reply wire variants with a
  topology-authority check, or replace them?

### R4 — Explicit per-node administrator designation (no priority, no failover)

**Statement.** Every node maintains an explicit, persisted set of **designated
administrator children**. A child of **any** kind — a child *node* or a *leaf*
(browser/user) — may be designated. The node asks exactly one authorization
question: *is the authenticated direct neighbour that handed me this request one
of my designated administrators?* There is **no priority order, no TTL, no
lease, no epoch, and no automatic failover**, and browsers have **no automatic
authority**.

**Rationale.** The delegated-grant model and the priority/lease model both add
parallel machinery (grants, scopes, ordering, clocks, failover races). An
explicit designation set is the minimum needed: authority is a property of the
target's own topology plus the msg-layer-authenticated last hop, and nothing
more. It also removes the R4 "leaf" special case: a browser is just a child that
can be designated.

**Scope (frozen 2026-10-04).**
- Persist the set per node (`<data-dir>/admin_state.json`), empty by default;
  entries must be current children of the node.
- **Who may change it:** the local operator via CLI (R9) **and** any currently
  designated administrator (remotely, routed). A locked-out node is recovered via
  local CLI.
- No ordering, no failover, no lease: a node with no reachable designated
  administrator has only local CLI administration (R9).
- Administration is transitive hop-by-hop: to reach an ancestor, each link on the
  path must have designated the next child. Browser upward reach remains the
  strict ancestor chain with the node-id discovery walk (P3), authority still
  hop-by-hop.
- Supersedes the R4 auto-browser-admin rule and the entire R5 priority/TTL model.

**Open questions.**
- Q1: *Resolved 2026-10-04:* all designated administrators (of either kind) hold
  equal, full rights.
- Q2: *Resolved:* upward reach is transitive but bounded by each ancestor's
  designation set.

### R5 — Superseded: priority list and TTL failover are removed

**Statement.** The priority-ordered child list and the TTL/lease automatic
failover described in the earlier R5 are **removed**. Authority is exactly the
explicit designation set in R4. `senior`/join-order no longer carries any
authority or ordering role; `senior_child` may be deleted. A node whose
designated administrators are all unreachable has no remote administration until
one returns or the local operator (R9) intervenes.

**Rationale.** The user decision of 2026-10-04 dropped automatic failover and
the priority list as unnecessary complexity. The universal local-CLI fallback
(R9) covers the "all admins offline" case without a clock or election.

**Open question.** None outstanding; retained only to record that the earlier R5
requirements are void.

### R6 — Admin mode separated behind a lock gate

**Statement.** Administrative actions — issue, burn, invite creation,
accepting/rejecting pending join requests, and leaving/joining the network as a
non-browser node — move to a dedicated **admin tab/page**. Entering it requires
unlocking admin mode via a lock button, which warns that the user must have read
the policy document and know what they are doing.

**Rationale.** Normal use should be safe and minimal; admin actions are powerful
and should be deliberate. A single explicit unlock establishes intent and
surfaces the policy.

**Scope (to confirm).**
- A dedicated admin page holding the listed actions.
- A lock/unlock control with an explicit policy acknowledgement.
- Locked by default; whether the unlocked state persists across reloads is TBC.
- Regular (non-admin) mode exposes none of these actions.

**Open questions.**
- Q1: What is "the policy document", and where does it live?
- Q2: On lock, do we merely hide actions, or also drop any cached authority?
- Q3: "leaving/joining the network as a non-browser node" — is this about
  provisioning node children, not the browser's own join/leave?

### R7 — Admin target switching via up/down buttons

**Statement.** While admin mode is unlocked, the node being administered is
changed with simple **up/down buttons**, replacing the current node
selector/dropdown.

**Open questions.**
- Q1: What does up/down traverse — the ancestor chain, the priority list, the
  browser's siblings, or a flat list of administrable nodes?
- Q2: Does it show the node's path/address, and is there a "current node"
  indicator?

### R8 — Simplify the UI; minimize sidebar tabs in both modes

**Statement.** Greatly simplify the UI, especially regular (non-admin) mode. In
particular, reduce the number of sidebar tabs as far as possible in **both**
non-admin and admin modes.

**Scope (to confirm).**
- Define a minimal tab set for user mode and for admin mode.
- Move all admin surfaces behind the admin lock (R6).
- Remove the node selector, grant management, and grant-scoped surfaces
  (R3/R7).

**Open questions.**
- Q1: What is the target tab set for user mode (e.g. a single combined page?) and
  for admin mode?

### R9 — Local CLI administration is the universal fallback

**Statement.** The operator, running the CLI on the machine that hosts a node
(with filesystem access to that node's data dir and operator key), can always
administer that node locally. This is the guaranteed fallback for **every**
node — in particular a node whose only administrators are offline leaf
(browser) children (R4/R5).

**Rationale.** It guarantees control without depending on network reachability
or on any child being online, and it is the one authority that cannot be lost to
a disconnect. The operator key already lives on the host, so this is inherent
local authority rather than a delegated grant.

**Scope (to confirm).**
- Local CLI admin covers the same action set as R6 (issue, burn, invite
  creation, pending-join approval, topology, join/leave as a non-browser node).
- Requires local filesystem access to the node's `<data-dir>`; not reachable
  remotely.
- Authority derives from the node's own operator key on the host
  (self-authority, not a grant).

**Open questions.**
- Q1: Does local CLI administration need a separate audit marker to distinguish
  it from network administration?
- Q2: Should it work while the node is stopped (offline local edits), or only
  through a running process against the live node?
- Q3: Is any admin capability intentionally *unavailable* locally (e.g. actions
  that require a peer's signature)?

---

## Further requirements

_To be added. Suggested shape: `### Rn — <title>`, then Statement / Rationale /
Scope / Open questions._

- Rn — _(next)_

---

## Decisions (human)

Rationale and recommended defaults are in `REFACTOR_PLAN.md` §5; **[REC]** marks
the recommended default already proposed.

**Resolved 2026-10-03 (before P1):**
- **R5 seeding** — **explicit operator/current-admin authorization**; first admin
  bootstrapped via local CLI; join order is tie-break only. Auto-seed from join
  order **rejected**. (R5 statement reworded; `REFACTOR_PLAN.md` §3.1.)
- **Transitive scope + ancestor-id discovery** — **strict ancestor chain with a
  node-id discovery walk**; authority stays hop-by-hop. (§1.5/§3.5.)
- **Scope model** — drop scopes entirely; every admin full-power; value bounded
  by `value_policy.json` **[REC]**.
- **Format-8 hard break + lockstep release** — accepted **[REC]**.
- **Value-policy keying** — end-to-end requester **[REC]**.

**Pending before P4 (web UI):**
- **Policy doc** (R6-Q1) — content + location; `ADMIN_POLICY.md` stub exists.
- **Unlock persistence** (R6-Q2) — locked by default **[REC]** vs. persist across reload.
- **Up/down traversal** (R7-Q1) — ancestor chain **[REC]** vs. flat list.
- **Tab sets** (R8-Q1) — see §5 **[REC]**; decide labels and Admin tab vs mode.

**Pending before P5 (docs) / optional:**
- **Docs archive vs delete** (R2-Q1) — archive to `PLAN-ARCHIVE.md`/`CHANGELOG.md`
  **[REC]**.
- **R9 offline "plan and apply on next start" mode** (R9-Q2) — optional.

---

## Cross-cutting open questions

- _(pending)_

## Non-goals

- _(pending)_
