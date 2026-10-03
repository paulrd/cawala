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

---

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

---

## Further requirements

_To be added. Suggested shape: `### Rn — <title>`, then Statement / Rationale /
Scope / Open questions._

- R3 — _(pending)_
- R4 — _(pending)_

---

## Cross-cutting open questions

- _(pending)_

## Non-goals

- _(pending)_
