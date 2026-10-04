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

The **administration refactor (P1–P5) is DONE, gated, merged to `main`, and
pushed** (`ec31535`). Authority is an explicit per-node **designation set**: a
node lists the children (node *or* leaf) allowed to administer it; there is **no
priority list, TTL, lease, epoch, or automatic failover**, and browsers have no
automatic authority. All admin is tree-routed; routed
`AdminDesignate`/`AdminRevoke` let a current administrator change the set, and
local CLI `control admin add|remove|list` always works. Wire: control format 8
(accept 7|8), routed control 2, reply 5. Web admin is behind a
policy-acknowledged lock with ancestor-chain up/down.

Next: the optional backlog in "Open items" below (notably the final
`ADMIN_POLICY.md` wording).

## Current state

- `main` is clean and pushed @ `ec31535` (was `11d7717` before the refactor).
- **Administration refactor** (merged; the `refactor/topology-admin` branch was
  fast-forwarded in and deleted); P1–P5 done, gated:
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
  `control_seen.json`, `control_audit.jsonl`,
  `pending_joins.json`, `outbound_join.json`, `ledger_peers.json`, `node.json`.
  Record and peers are re-read per control request (direct **and** routed).
- Value issue/burn is **uncapped** and authorized solely by the designation set
  (`admin_state.json`) and the local CLI; burn cannot exceed the account balance.
  There is no `value_policy.json`. Ledger idempotency keys on the last-hop admin
  child.
- Addresses are network-local and topology-true: an exit rebases the subtree onto
  root `0`; moved pointers are **rejected**. The clean path is `control exit`
  then `ledger edge-close` (detached only); `edge-close` forfeits the entire
  pooled `Parent` balance irreversibly.
- Ledger-key rotation is reconciled on re-attach or by the node operator on
  `CreateChild`.
- **Commit and push as you deem fit.** Prefer small, focused, verified commits;
  match the existing message style (`node:`, `control:`, `docs:`). Never commit
  secrets or unrelated changes.
