# Cawala Refactor — Requirements

This is a living document that gathers the requirements and ideas for an
upcoming refactor. It is intentionally requirement-first: each entry states what
must be true, why, and what is still open, so it can be reviewed and then turned
into a plan.

Overall intent: **simplify** the architecture where possible — fewer transport
paths, one communication rule, less special-casing.

Status: **Draft — gathering requirements**
Last updated: 2026-10-03

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

### R4 — "Leaf node" means the user/browser; leaf children have full admin over their parent

**Statement.** Disambiguate the term: a **leaf node** is *only* a user/browser
client. Any leaf (browser) that is a child of a node has **complete** admin
rights over that parent node.

**Rationale.** "Leaf" is currently overloaded (a node whose children are all
users vs. a browser user leaf), which is confusing. Making "leaf" == browser
removes the ambiguity and gives each browser a guaranteed, zero-setup path to
administer its own parent — no grant required.

**Scope (to confirm).**
- Update the kind/terminology model so "leaf" is only the browser/user.
- A node with leaf (browser) children is administered **only** by those
  browsers, with full rights. There is **no child-based fallback** for such a
  node — if its browsers are offline, local CLI administration (R9) is the only
  path.
- Supersedes the delegating-grant model and, for such nodes, seniority.

**Open questions.**
- Q1: If a node has several browser children, do all hold equal, full rights?
- Q2: What authority, if any, does a browser have over nodes above its parent
  (ancestors)? See R5 transitivity.

### R5 — Priority-ordered child administration with TTL failover

**Statement.** A node that does **not** have leaf (browser) children keeps a
**priority-ordered list of its child nodes**. Priority defaults to the order the
children joined the network (earlier join = higher priority), and the node's
current admin may reorder it at any time. A configurable TTL (e.g. 5 minutes)
governs failover: if the node cannot connect to the current admin child within
the TTL, the next child in priority order is permitted to administer it. By
transitivity, every node always has an administrator, hop-by-hop.

**Rationale.** Browser leaf nodes are frequently offline, so control must not
depend on them. A priority list plus a liveness TTL guarantees a reachable
administrator among a node's children.

**Applicability.** Only for nodes that do **not** have leaf (browser) children.
A node with leaf children uses R4 (those browsers only) and falls back to local
CLI administration (R9) when they are offline.

**Scope (to confirm).**
- Persist the priority list per node (default = join order); admin-reorderable.
- TTL is configurable (default 5 min) and acts as a liveness/lease window before
  failover to the next child.
- Failover: the next child in priority order becomes admin when the current admin
  child is unreachable past the TTL.
- Administration is transitive so the entire tree is coverable.

**Open questions.**
- Q1: *Resolved:* the priority list is exclusively for nodes **without** leaf
  children. A node with leaf children is administered only by those browsers
  (R4), and falls back to local CLI administration (R9) when they are offline.
- Q2: Who may reorder — only the current admin? Can a newly-failed-over admin
  reorder immediately?
- Q3: What does "cannot connect to the child" mean concretely (control-probe
  timeout? envelope reachability?), and does the TTL reset on each successful
  contact (lease semantics)?
- Q4: How does this relate to the existing "senior child" concept — does
  priority replace seniority, with the senior child simply priority #1?
- Q5: Is failover automatic (authority passes on timeout) or a
  permitted-but-explicit takeover?

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

## Cross-cutting open questions

- _(pending)_

## Non-goals

- _(pending)_
