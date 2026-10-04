# Cawala — handoff index

Short entry point. This file is deliberately small: it carries **current state,
how to verify, and conventions**. Detail lives elsewhere:

- **`PLAN.md`** (tracked) — living design + roadmap: architecture, the current
  designation authority model, storage/wire facts, the R1–R9 intent, decisions.
- **`PLAN-ARCHIVE.md`** (tracked) — delivered-phase history: the M0–M5 records,
  the superseded unified-console P1–P6, and the administration-refactor plan
  (the former `REFACTOR.md`/`REFACTOR_PLAN.md`, deleted 2026-10-04).
- **`ADMIN_POLICY.md`** (tracked) — the policy shown at the P4 admin-unlock gate
  (stub pending final wording).
- **`.slim/deepwork/*.md`** (gitignored, local-only) — per-effort working notes.
  For this effort: `admin-refactor.md`, `admin-refactor-p1-spec.md`,
  `admin-refactor-v2-spec.md`, `admin-refactor-remediation.md`.

## Next session brief

The **administration refactor P1–P4 is DONE and passed the gate** on branch
**`refactor/topology-admin`** (not pushed, not merged). Authority is an explicit
per-node **designation set**: a node lists the children (node *or* leaf) allowed
to administer it; there is **no priority list, TTL, lease, epoch, or automatic
failover**, and browsers have no automatic authority. All admin is tree-routed;
routed `AdminDesignate`/`AdminRevoke` let a current administrator change the set,
and local CLI `control admin add|remove|list` always works.

**P5 (docs, R2) is this consolidation** — `PLAN.md` slimmed to living
design/roadmap, delivered history moved to `PLAN-ARCHIVE.md`, `REFACTOR.md` and
`REFACTOR_PLAN.md` folded in and deleted, `README.md`/`web/README.md` corrected.

Next: **merge the lockstep release to `main`** (P1–P4 do not interoperate with
the old wasm/web; keep each commit compiling on the branch, merge together).
Then optional backlog in "Open items" below.

## Current state

- `main` is clean and pushed; baseline before this branch: `11d7717`.
- **Refactor branch `refactor/topology-admin`** @ `d4b62e8` + this P5 docs
  commit (not pushed, not merged); P1–P4 done, gated:
  - Control wire: **control format 8** (mint 8; accept 7|8), **routed control 2**
    (carried grant dropped), **reply version 5** (`AdminSnapshot` carries
    `admins`), new `AdminDesignate`/`AdminRevoke` gated by the authenticated
    last hop.
  - Node: explicit designation set in `<data-dir>/admin_state.json`
    (`{version, admins:[child_id...], updated_at, updated_by}`); authority =
    last hop is a current `node.json` child **and** designated; local CLI
    `control admin add|remove|list`; durable one-shot prune.
  - **Deleted:** delegated grants (`AdminGrant*`, `admins.json`, `AdminStore`,
    `cawala://admin` bundle, grant CLI), scopes, priority/TTL/lease/failover,
    `senior.rs`; browser `cawala.admin.*` store + grant/key UI.
  - Web: admin lock gate (policy acknowledgement of `ADMIN_POLICY.md`), dedicated
    Admin page, ancestor-chain up/down target switcher, simplified nav.
  - Tests: `CARGO_BUILD_JOBS=1 cargo test --workspace` passes / clippy clean /
    wasm check ok.
- `web/src/wasm/` is gitignored and generated; run `npm run build:wasm` (or
  `npm run build`) after any `crates/client-wasm` change.
- M0–M5 and the earlier unified-console P1–P6 remain built on `main` (records in
  `PLAN-ARCHIVE.md`); the branch replaces their admin/grant layers.

## Open items (recorded backlog)

- **Merge** the lockstep P1–P5 release to `main` (next task).
- **Gate residuals (accepted):** concurrent local-CLI vs engine `admin_state.json`
  writes are last-writer-wins (single-operator host); a corrupt-file error path
  audits per request but is local-only and CLI-repairable.
- **`ADMIN_POLICY.md` is still a stub** — final policy wording / acknowledgement
  versioning is pending (R6-Q1); the P4 gate depends on the file existing.
- **Foster-parent recovery — cut by decision** (unchanged).
- **Control version negotiation — deferred** (single lockstep codebase).
- **`OctAddr` depth cap** — deliberately not done.
- **Moved pointers rejected; signed topology distribution rejected** (unchanged).

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
  **reply version 5**, ledger (entry/signed) format 4, node on-disk ledger meta
  format 3, settlement payload 3, browser ledger payload 3.
  `ROUTED_CONTROL_VERSION=2` drops the carried grant; there is no `admins.json`
  (replaced by `admin_state.json`).
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
