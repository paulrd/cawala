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
- **`CLI.md`** (tracked) — operator guide to the `cawala-node` command surface:
  each command's behavior, intended use, and destructive caveats.
- **`.slim/deepwork/*.md`** (gitignored, local-only) — per-effort working notes.
  For this effort: `admin-refactor.md`, `admin-refactor-p1-spec.md`,
  `admin-refactor-v2-spec.md`, `admin-refactor-remediation.md`.

## Next session brief

The **portable-client refactor base (R1 / R1b types / R2 / R3) is DONE, gated,
merged to `main` (PR #2, `8ccab19`)**. It makes the
web app host-agnostic and identity-portable: localStorage is a best-effort cache
with the node as source of truth (R1); a user-level secp256k1/BIP-39 identity
whose transport Ed25519 key is mnemonic-derived, with a shared EIP-712 `EthIdentity`
carried in a new `LedgerPayloadV4`/`OrderV4` and a write-once, ETH-authorized
`ChildEntry.eth_address` anchor enforced fail-closed at the direct parent (R3);
and dual-target packaging - a self-contained `dist-single/index.html` for
`file://`/zip/email alongside the served multi-asset `dist/` (R2). The frozen
design is `.slim/deepwork/portable-client-refactor-spec.md` (Addenda A/B/C).

The **follow-ups (F1-F6) are DONE, gated, and merged to `main`** (`523cef9`;
the follow-up branch was deleted. Lockstep with the base: control 9, reply 6,
ledger payload v4, browser ledger state 5):

- `eee955c` R1b client capabilities handshake (F1)
- `fcc9116` end-to-end ETH identity node integration tests (F2)
- `127a8bd` identity bundle v2 carries the derived ETH secret/address (F3)
- `2057c3b` incumbent-authorized, idempotent ETH-anchor rotation (F4)
- `1889a3d` optional passkey (WebAuthn PRF) unlock lock (F5)
- `f30f33b` fail-closed leaf-key pinning (F6)

Next: the deferred items in "Open items" below. The phase log is
`.slim/deepwork/portable-client-refactor.md`.

The **administration refactor (P1–P5) is DONE, gated, merged to `main`, and
pushed** (`ec31535`), plus a follow-up **value simplification** (`871e4d5`):
`AdminIssue`/`AdminBurn`/`AdminLedgerQuery` are handled like every other admin
action (authority and ledger idempotency key on the authenticated last-hop admin
child), and the `value_policy.json` cap system is removed — issue is **uncapped**,
burn is bounded by the account balance. Authority is an explicit per-node
**designation set**: a
node lists the children (node *or* leaf) allowed to administer it; there is **no
priority list, TTL, lease, epoch, or automatic failover**, and browsers have no
automatic authority. All admin is tree-routed; routed
`AdminDesignate`/`AdminRevoke` let a current administrator change the set, and
local CLI `control admin add|remove|list` always works. Wire: control format 8
(accept 7|8), routed control 2, reply 5. Web admin is behind a
policy-acknowledged lock with ancestor-chain up/down.

On `main`, next: the optional backlog in "Open items" below (notably the final
`ADMIN_POLICY.md` wording).

## Current state

- **`refactor/portable-client` base (merged to `main` as PR #2, `8ccab19`);**
  `1627114` wasm read getters → `f2fa30b` web best-effort cache → `848b457`
  BIP-39/secp256k1/EIP-712 primitives → `4712e33` shared `cawala-eth` crate +
  control v9 (`Capabilities` 23, `RegisterEthAddress` 24) + `LedgerPayloadV4` →
  `cf448ce` node write-once ETH anchor enforcement → `4a8b746` client ETH wiring
  → `1d79e09` ETH secret export → `204cb94` identity UI → `35c7d08` single-file
  build + `file://`.
  - **R1 delivered:** node is source of truth; `cawala.state.v1`/`cawala.ledger.v1`
    are best-effort cache; identity + TOFU pins authoritative-local; pure wasm
    read getters.
  - **R3 delivered:** mnemonic-derived ETH identity + transport NodeId; EIP-712
    `LedgerPayloadV4`; write-once `RegisterEthAddress` anchor (incumbent-verified
    rotation); fail-closed version-scoped anchor gate at the direct parent;
    derived secret persisted, mnemonic never stored.
  - **R2 delivered:** release wasm; `dist-single/index.html` (bytes-inlined wasm,
    no `file://` fetch); SW + passkey hidden on `file://`.
- **Follow-ups (F1-F6), merged to `main` (`523cef9`):** `eee955c` R1b client
  capabilities handshake → `fcc9116` node ETH identity integration tests →
  `127a8bd` identity bundle v2 → `2057c3b` ETH-anchor rotation (idempotent) →
  `1889a3d` optional passkey (PRF) lock → `f30f33b` fail-closed leaf-key pinning.
  - **F1 (R1b) delivered:** both halves of the `Capabilities` handshake; the
    client sends variant 23 on boot (when joined) and after join, maps reply 9 to
    `NodeCapabilitiesDto`, and the web gates ETH-anchor registration on
    `NODE_FEATURE_ETH_IDENTITY` (graceful "unavailable" on an old node).
  - **F2 delivered:** `crates/node/tests/eth_identity.rs` end-to-end registration
    + rotation tests over the real control transport.
  - **F3 delivered:** portable identity bundle **v2** carries the derived
    secp256k1 secret + EIP-55 address (v1 still imports; crypto unchanged).
  - **F4 delivered:** incumbent-authorized ETH-anchor rotation (client-wasm +
    web), idempotent commit (retained frame, bounded resend, `Replay`
    reconciled as applied); dedicated rotate surface (enter or generate a phrase,
    address-diff confirm); new secret persisted only on success.
  - **F5 delivered:** optional passkey lock (WebAuthn PRF → HKDF-SHA256 →
    AES-256-GCM key-wrap; user-identity record v3; locked boot); passkey panel
    states checking/unsupported/setup/locked/unlocked; passkey is an unlock
    factor, never a signer.
  - **F6 delivered:** fail-closed leaf-key pinning (`PinTrust`
    unconfirmed/confirmed; `LEDGER_STATE_VERSION` 4→5); a different pinned key is
    recorded (never adopted); web trust card confirm action + pin-change warning.
- `main` includes the portable-client refactor (PR #2, `8ccab19`) and the
  follow-ups (`523cef9`); administrative refactor `871e4d5`.
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
  - Value: no `value_policy.json`; `AdminIssue`/`AdminBurn`/`AdminLedgerQuery` are
    uniform admin actions (last-hop authority + ledger idempotency); issue is
    uncapped, burn is bounded by the account balance.
  - Tests: `CARGO_BUILD_JOBS=1 cargo test --workspace` passes / clippy clean /
    wasm check ok.
- `web/src/wasm/` is gitignored and generated; run `npm run build:wasm` (or
  `npm run build`) after any `crates/client-wasm` change.
- Node packaging lives in `packaging/` (systemd template unit + `install.sh`);
  pushing a `v*` tag builds static musl binaries for x86_64/aarch64 via
  `.github/workflows/release.yml` (cargo-zigbuild, no Docker) and attaches them
  plus the unit/installer to the GitHub Release.
- M0–M5 and the earlier unified-console P1–P6 remain built on `main` (records in
  `PLAN-ARCHIVE.md`); the branch replaces their admin/grant layers.

## Open items (recorded backlog)

- **`ADMIN_POLICY.md` is still a stub** — final policy wording / acknowledgement
  versioning is pending (R6-Q1); the P4 gate depends on the file existing.
- **Foster-parent recovery — cut by decision** (unchanged).
- **Control version negotiation — deferred** (single lockstep codebase).
- **`OctAddr` depth cap** — deliberately not done.
- **Moved pointers rejected; signed topology distribution rejected** (unchanged).
- **Passkey lock (F5) is browser-only and manually verified** — no automated test
  (WebAuthn PRF needs a real authenticator); the recovery phrase remains the only
  recovery path.
- **F6 pinning follow-ups — DONE (F7):** receive-URI re-pin is fail-closed (a
  differing `lk` records a `LeafKeyChangeV1` and does not adopt; explicit
  `accept_pin_change` adopts the presented key); an unreadable ledger blob is
  quarantined under `cawala.ledger.backup.v1:<nodeId>` before the first
  overwrite; the Settings trust card lists every pending change with keep/adopt
  actions.
- **`web/scripts/smoke-admin.mjs` is stale — rewrite it against the routed admin
  API.** It predates the administration refactor: it calls the removed wasm
  exports `set_admin_key` / `admin_public_key` and the removed
  `control admin grant|revoke --key` commands, so it fails immediately (it is
  marked "Known-stale" in `MANUAL_TESTING.md` §7). Target shape: bootstrap the
  first administrator with `control admin add <browser-id>`, then drive the wasm
  admin surface directly — `admin_targets()` (the ancestor chain stops at the
  first undesignated hop), `admin_query()` (children, designated set, pending
  joins), `admin_designate` / `admin_revoke`, `admin_approve_join` /
  `admin_reject_join`, `admin_move_child` / `admin_detach_child`, and
  `admin_issue` / `admin_burn` — and assert a non-designated browser is refused
  (`unauthorized`) and that a revoked administrator loses access. Like the other
  smoke scripts it is network-dependent (`SMOKE_ADMIN_REQUIRE_NETWORK=1`,
  `CAWALA_NODE_BIN`) and should print `SKIP:` on a genuinely unreachable N0
  path. Note the web admin **lock gate** is a UI-layer concern (`api.js`), not
  wasm, so it stays in the manual checklist rather than the script.

## Verify

- `CARGO_BUILD_JOBS=1 cargo test --workspace` (includes F2
  `crates/node/tests/eth_identity.rs`)
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo check -p cawala-client --target wasm32-unknown-unknown`
- `cd web && npm run build` (now builds **release** wasm, then `vite build`)
- `cd web && npm run build:singlefile` (-> `web/dist-single/index.html`, self-containment check)
- `cd web && npm test` (covers F1 capabilities, F3 identity bundle v2, F4
  rotation, F6 pin trust); F5 passkey is browser-only and manual.
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
  On current `main` these are **control 9** (accept 7|8|9), **reply 6**, browser
  ledger payload **v4**, and browser ledger state **v5** — a lockstep break
  relative to the pre-refactor `main`.
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
