# Cawala — handoff index

Short entry point. This file is deliberately small: it carries **current state,
how to verify, and conventions**. Detail lives elsewhere:

- **`PLAN.md`** (tracked) — the design and per-increment DONE records.
- **`REFACTOR.md`** (tracked) — requirements R1–R9 (R4/R5 rewritten 2026-10-04:
  explicit admin designation, no priority/failover).
- **`REFACTOR_PLAN.md`** (tracked) — design + phased plan (see the v2 amendment).
- **`ADMIN_POLICY.md`** (tracked) — the policy shown at the P4 admin-unlock gate
  (stub pending final wording).
- **`.slim/deepwork/*.md`** (gitignored, local-only) — per-effort working notes.
  For this effort: `admin-refactor.md`, `admin-refactor-p1-spec.md`,
  `admin-refactor-v2-spec.md`, `admin-refactor-remediation.md`.

## Next session brief

Continue the administration refactor on branch **`refactor/topology-admin`** (not
pushed, not merged). The **P0+P1+P2 core is DONE and passed the @oracle gate**
(COMMITTABLE, attempt 2 of 3, `eabf749`). Authority is now an explicit per-node
**designation set**: a node lists the children (node *or* leaf) allowed to
administer it; there is **no priority list, TTL, lease, epoch, or automatic
failover**, and browsers have no automatic authority. All admin is tree-routed;
routed `AdminDesignate`/`AdminRevoke` let a current admin change the set.

Next, finish the lockstep release bottom-up.

- **P3 — wasm client** (`crates/client-wasm`): make admin always-routed; sign with
  the client's **own** operator key (origin/controller = the client); derive
  ancestor addresses from the client's own address; implement the **ancestor
  node-id discovery walk**; delete the admin-key API/store (`set_admin_key`,
  `clear_admin_key`, `admin_public_key`, `SharedControl.admin`, `exchange_admin`,
  `should_try_routed`); rebuild `web/src/wasm/` (`npm run build:wasm`).
- **P4 — web**: admin lock gate + policy acknowledgement; dedicated admin page
  (issue/burn, invite, pending joins, topology, leave/join); up/down target
  switching (ancestor chain); simplify `Sidebar`/`MobileNav`/`NodeContextBar`;
  delete the grant UI/store (`adminKeys.js`, `adminSeedCrypto.js`, grant
  components, `cawala.admin.*`).
- **P5 — docs** (R2): fold `REFACTOR.md`/this plan into `PLAN.md`; shrink this
  file; fix `web/README.md`.

P1–P4 ship as **one lockstep release** (format/routed changes do not interoperate
with the old wasm/web). Keep each commit compiling on the branch; merge together.

## Current state

- `main` is clean and pushed; baseline before this branch: `11d7717`.
- **Refactor branch `refactor/topology-admin`** @ `eabf749` (not pushed):
  - Control wire: **control format 8** (mint 8; accept 7|8), **routed control 2**
    (carried grant dropped), reply version 4, new `AdminDesignate`/
    `AdminRevoke` (variants 21/22) gated by the authenticated last hop.
  - Node: explicit designation set in `<data-dir>/admin_state.json`
    (`{version, admins:[child_id...], updated_at, updated_by}`); authority =
    last hop is a current `node.json` child **and** designated; local CLI
    `control admin add|remove|list`; durable one-shot prune.
  - **Deleted:** delegated grants (`AdminGrant*`, `admins.json`, `AdminStore`,
    `cawala://admin` bundle, grant CLI), scopes, priority/TTL/lease/epilogue
    failover, `senior.rs`.
  - Tests: `CARGO_BUILD_JOBS=1 cargo test --workspace` → 950 pass / clippy clean /
    wasm check ok.
- `web/src/wasm/` is gitignored and **stale** until P3 (`npm run build:wasm`).
- M0–M5 and the earlier unified-console P1–P6 remain built on `main`; the branch
  replaces their admin/grant layers.

## Open items (recorded backlog)

- **P3/P4/P5** as in the next-session brief. No human decisions are blocking
  P3/P4 (resolved 2026-10-04: explicit designation, operator + current admins).
- **Gate residuals (accepted):** concurrent local-CLI vs engine `admin_state.json`
  writes are last-writer-wins (single-operator host); a corrupt-file error path
  audits per request but is local-only and CLI-repairable; docs referencing the
  removed priority/lease model are cleaned in P5.
- **Foster-parent recovery — cut by decision** (unchanged).
- **Control version negotiation — deferred** (single lockstep codebase).
- **`OctAddr` depth cap** — deliberately not done.
- **Moved pointers rejected; signed topology distribution rejected** (unchanged).
- **`REFACTOR.md` pending decisions** for P4 (policy doc wording, unlock
  persistence, up/down traversal, tab sets) and P5 (docs archive vs delete).

## Verify

- `CARGO_BUILD_JOBS=1 cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo check -p cawala-client --target wasm32-unknown-unknown`
- `cd web && npm run build`
- `cd web && npm test`
- Targeted node suites: `--test admin_authority`, `--test admin_state`,
  `--test local_admin_cli`, `--test control_admin`, `--test routed_control`,
  `--test settlement_transport`, `--test exit_rebase`, `--test edge_close`,
  `--test netting_harness`.
- Network smoke (N0 relay required): `web/scripts/smoke-*.mjs` (set
  `SMOKE_*_REQUIRE_NETWORK=1` to hard-fail instead of skipping).

## Conventions

- `~/.cargo/config.toml` sets `[build] jobs = 2` (OOM mitigation). Run cargo-heavy
  specialist lanes **serially** — one cargo process at a time. Workspace-wide runs
  need `CARGO_BUILD_JOBS=1`; targeted crate/test suites are fine at 2.
- `.slim/clonedeps/repos/` holds pinned read-only iroh source.
- **Hard breaks** — recreate `node-data` and rebuild the wasm bundle when they
  change: **control format 8** (mint 8; accept 7|8), **routed control 2**,
  ledger (entry/signed) format 4, node on-disk ledger meta format 3, settlement
  payload 3, browser ledger payload 3. `ROUTED_CONTROL_VERSION=2` drops the
  carried grant; there is no `admins.json` (replaced by `admin_state.json`).
- `web/src/wasm/` is gitignored; run `npm run build:wasm` after any
  `crates/client-wasm` change or the JS/wasm arity can desync.
- Control-plane local state under `<data-dir>`: `admin_state.json`,
  `value_policy.json`, `control_seen.json`, `control_audit.jsonl`,
  `pending_joins.json`, `outbound_join.json`, `ledger_peers.json`, `node.json`.
  Record and peers are re-read per control request (direct **and** routed).
- Addresses are network-local and topology-true: an exit rebases the subtree onto
  root `0`; moved pointers are **rejected**. The clean path is `control exit`
  then `ledger edge-close` (detached only); `edge-close` forfeits the entire
  pooled `Parent` balance irreversibly.
- Ledger-key rotation is reconciled on re-attach or by the node operator on
  `CreateChild`.
- **Commit and push as you deem fit.** Prefer small, focused, verified commits;
  match the existing message style (`node:`, `control:`, `docs:`). Never commit
  secrets or unrelated changes.
