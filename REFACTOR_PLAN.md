# Cawala Refactor Plan — Topology-Derived Node Administration

Status: **Draft for review** (no code changes made). Drafted by @oracle and
reconciled by the orchestrator; file:line references are indicative and may
drift.

- Supersedes: the delegated-grant model (P1–P6) and the direct-first admin path.
- Inputs: `REFACTOR.md` R1–R9 plus the resolved decisions for R3/R4/R5/R9.
- Baseline: `main` @ `5cd55b4`, clean.

---

## 0. Resolved decisions this plan is built on

- **R4**: "leaf" = user/browser only. A browser child has **complete** admin over
  its parent. A node with browser children is administered **only** by those
  browsers — no child fallback; local CLI is the fallback when they are offline.
- **R5**: nodes **without** browser children keep a priority-ordered **child-node**
  list (default = join order, earlier = higher; current admin may reorder). A
  configurable TTL (default 5 min) governs failover: if the node cannot reach the
  current admin child within the TTL, the next child in priority order may
  administer it. Administration is transitive.
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

- Default on first open / missing file: `priority` = node children sorted by
  `(date_joined, id)` (join order), `current = 0` if any, `lease_until = 0`,
  `epoch = 0`. **See risk 3.1 — recommend requiring explicit operator seeding
  instead.**
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
browser's parent, or deeper) is the target's current administrator. No new
routing is needed — the existing ascend/descend and `MSG_CONTROL_V1` per-hop
machinery covers it.

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

**Mitigation (recommended)**: do **not** auto-seed the priority list from join
order. Require the operator (or the current admin) to explicitly add each child
as an administrator; use join order only as the tie-break/stability order among
already-authorized admins. Bootstrap the first admin via local CLI. If the team
insists on auto-default, add a mandatory "provision/auth" step before a child
gains admin. **This may need a requirement change (R5 wording) and is flagged as
a human decision.**

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
