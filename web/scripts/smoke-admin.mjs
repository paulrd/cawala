#!/usr/bin/env node
// End-to-end delegated-admin smoke test for the browser-admin increment.
//
// This drives the wasm browser client (the same module the PWA loads) from
// Node through the FULL admin flow against a live local Cawala node:
//
//   native parent: init -> set-address 0 -> run -> control invite
//   wasm browser A: spawn_control -> join_via_invite -> immediate "pending"
//   wasm browser B: spawn_control -> set_admin_key -> admin_public_key()
//   native parent: control admin grant --key <B's admin pub> --label smoke
//   wasm browser B: admin_query(parent)        -> lists A's pending join
//   wasm browser B: admin_approve_join(parent, A, null) -> "delivered"
//                   (JSON delivery is not "rejected:*"; "unreachable" is a
//                    tolerated environmental outcome, but not a rejection)
//   wasm browser A: join_status()              -> "joined" at 0.<slot>
//   native parent: control admin revoke --key <B's admin pub>
//   wasm browser B: admin_query(parent)        -> fails "unauthorized"
//
// ---------------------------------------------------------------------------
// NETWORK-DEPENDENT. Both browsers bind the iroh `presets::N0` endpoint: they
// publish pkarr records (https://dns.iroh.link) and connect over the public N0
// relay servers with DNS address lookup, so this needs outbound HTTPS/DNS/UDP
// to N0. If (and only if) the relay/pkarr lookup is genuinely unreachable, the
// script prints `SKIP:` and exits 0. Any handshake/state assertion failure is a
// real bug and exits non-zero.
//
// Note: the local node `run` command exposes no bound SocketAddr, so the invite
// is hint-free and the browser resolves the parent through N0 address lookup,
// exactly as a real browser would.
// ---------------------------------------------------------------------------
//
// Usage (from the repo root or web/):
//   node web/scripts/smoke-admin.mjs
//
// Env:
//   CAWALA_NODE_BIN=/path/to/cawala-node   override the node binary
//   SMOKE_ADMIN_REQUIRE_NETWORK=1          turn an unreachable-relay SKIP into
//                                          a hard failure (for CI)
//
// Exit codes: 0 = success (or a genuine network SKIP), 1 = failure.

import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

import init, {
  ClientNode,
  generate_secret_key,
  parse_invite,
} from "../src/wasm/cawala_client.js";

// ---------------------------------------------------------------------------
// Configuration / paths
// ---------------------------------------------------------------------------

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webDir = path.resolve(__dirname, ".."); // web/
const rootDir = path.resolve(webDir, ".."); // workspace root
const defaultBin = path.join(rootDir, "target", "debug", "cawala-node");
const nodeBin = process.env.CAWALA_NODE_BIN ?? defaultBin;

const PREFIX = "[smoke-admin]";
const requireNetwork = process.env.SMOKE_ADMIN_REQUIRE_NETWORK === "1";

// Deadline for the browser's reverse-dialed JoinApproved to land.
const JOIN_STATE_TIMEOUT_MS = 30_000;
// Time allowed for connection setup + pkarr publication at startup.
const PARENT_READY_TIMEOUT_MS = 90_000;
const CLI_TIMEOUT_MS = 60_000;
// Give the parent's pkarr publisher a moment to land before the first join.
const PKARR_SETTLE_MS = 3_000;

const log = (...args) => console.log(PREFIX, ...args);
const warn = (...args) => console.warn(PREFIX, ...args);
const fail = (...args) => console.error(PREFIX, "ERROR:", ...args);

/** Thrown for a genuinely unreachable relay/pkarr so we can SKIP instead. */
class NetworkUnreachable extends Error {}

// ---------------------------------------------------------------------------
// Small async helpers
// ---------------------------------------------------------------------------

/** Run a one-shot command, capturing stdout/stderr; reject on non-zero exit. */
function runCli(args, { label = args.join(" "), allowFailure = false } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(nodeBin, args, {
      cwd: rootDir,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`command timed out after ${CLI_TIMEOUT_MS}ms: ${label}`));
    }, CLI_TIMEOUT_MS);

    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      const result = { code, stdout, stderr };
      if (code !== 0 && !allowFailure) {
        reject(
          new Error(
            `command failed (exit ${code}): ${label}\n--- stdout ---\n${stdout}\n--- stderr ---\n${stderr}`,
          ),
        );
        return;
      }
      resolve(result);
    });
  });
}

/** A running `cawala-node ... run` process with captured output. */
class AdminNode {
  constructor(dataDir) {
    this.dataDir = dataDir;
    this.stdout = "";
    this.stderr = "";
    this.endpointId = undefined;
    this.child = undefined;
    this.exit = undefined;
  }

  async start() {
    log("starting admin node:", path.relative(rootDir, nodeBin), "run");
    this.child = spawn(nodeBin, ["--data-dir", this.dataDir, "run"], {
      cwd: rootDir,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    this.child.stdout.on("data", (d) => (this.stdout += d));
    this.child.stderr.on("data", (d) => (this.stderr += d));
    this.exit = new Promise((resolve) => {
      this.child.on("close", (code, signal) => resolve({ code, signal }));
    });

    const deadline = Date.now() + PARENT_READY_TIMEOUT_MS;
    while (Date.now() < deadline) {
      const match = this.stdout.match(/^EndpointId:\s*(\S+)\s*$/m);
      if (match && /^Serving /m.test(this.stdout)) {
        this.endpointId = match[1];
        log("admin node endpoint id:", this.endpointId);
        const addr = this.stdout.match(/^Address:\s*(\S+)\s*$/m);
        if (addr) log("admin node asserted address:", addr[1]);
        return this;
      }
      if (this.child.exitCode !== null) {
        throw new Error(
          `admin node exited before becoming ready (code ${this.child.exitCode}).\n` +
            `--- stdout ---\n${this.stdout}\n--- stderr ---\n${this.stderr}`,
        );
      }
      await sleep(200);
    }
    throw new Error(
      `admin node not ready within ${PARENT_READY_TIMEOUT_MS}ms.\n` +
        `--- stdout ---\n${this.stdout}\n--- stderr ---\n${this.stderr}`,
    );
  }

  async stop() {
    if (!this.child || this.child.exitCode !== null) return;
    this.child.kill("SIGKILL");
    await this.exit;
  }
}

/** Plain-object view of the wasm join status DTO. */
function statusView(node) {
  const s = node.join_status();
  return {
    state: s.state,
    parent: s.parent,
    slot: s.slot,
    address: s.address,
    reason: s.reason,
  };
}

/** Plain-object view of an AdminSnapshotDto. */
function adminSnapshotView(snapshot) {
  return {
    nodeId: snapshot.node.node_id,
    address: snapshot.node.address,
    pending: snapshot.pending.map((p) => ({
      childId: p.child_id,
      kind: p.kind,
      operator: p.operator,
      desiredSlot: p.desired_slot,
      expiry: p.expiry,
    })),
  };
}

/** Plain-object view of an AdminActionDto. */
function adminActionView(action) {
  return {
    child: action.child,
    slot: action.slot,
    address: action.address,
    delivery: action.delivery,
  };
}

/** Drain all queued control events, logging them. */
function drainEvents(node) {
  const events = [];
  for (;;) {
    const ev = node.try_recv_control_event();
    if (!ev) break;
    const view = {
      kind: ev.kind,
      parent: ev.parent,
      slot: ev.slot,
      address: ev.address,
      reason: ev.reason,
      dateJoined: ev.date_joined,
    };
    events.push(view);
    log("control event:", JSON.stringify(view));
  }
  return events;
}

/** Poll `join_status()` until `predicate` matches. */
async function waitForStatus(node, predicate, description, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let last = statusView(node);
  while (Date.now() < deadline) {
    drainEvents(node);
    last = statusView(node);
    if (predicate(last)) return last;
    await sleep(300);
  }
  throw new Error(
    `timed out after ${timeoutMs}ms waiting for ${description}; ` +
      `last join_status=${JSON.stringify(last)}`,
  );
}

/**
 * Classify a connect failure as environmental (N0 relay/pkarr) rather than a
 * handshake bug; mirrors smoke-join.mjs.
 */
function isNetworkConnectError(err) {
  const text = String(err?.message ?? err);
  return /connect|connection|timeout|timed out|dns|relay|lookup|pkarr|unreachable|host|addressing|fetch failed/i.test(
    text,
  );
}

// ---------------------------------------------------------------------------
// Phases
// ---------------------------------------------------------------------------

/** Spawn browser A and send the join; retry connect failures until deadline. */
async function browserJoin(label, inviteUri, parentId) {
  const seed = generate_secret_key();
  const node = await ClientNode.spawn_control(seed);
  const browserId = node.endpoint_id();
  log(`${label}: browser endpoint spawned, id = ${browserId}`);

  const info = parse_invite(inviteUri);
  if (info.parent !== parentId) {
    throw new Error(`invite parent ${info.parent} != node endpoint id ${parentId}`);
  }
  log(`${label}: parsed invite`, JSON.stringify({ parent: info.parent, operator: info.operator }));

  const deadline = Date.now() + PARENT_READY_TIMEOUT_MS;
  let attempt = 0;
  for (;;) {
    attempt += 1;
    try {
      log(`${label}: join_via_invite (attempt ${attempt})`);
      const outcome = await node.join_via_invite(inviteUri);
      const view = {
        status: outcome.status,
        rejectCode: outcome.reject_code,
        reason: outcome.reason,
      };
      log(`${label}: immediate join outcome:`, JSON.stringify(view));
      if (view.status === "rejected") {
        throw new Error(
          `${label}: node rejected the join immediately: ${JSON.stringify(view)}`,
        );
      }
      if (view.status !== "pending") {
        throw new Error(`${label}: unexpected immediate status '${view.status}'`);
      }
      const status = statusView(node);
      if (status.state !== "pending") {
        throw new Error(
          `${label}: expected join_status 'pending' after a pending reply, got ` +
            JSON.stringify(status),
        );
      }
      return { node, browserId };
    } catch (err) {
      if (!isNetworkConnectError(err)) throw err;
      if (Date.now() >= deadline) {
        throw new NetworkUnreachable(
          `${label}: could not reach the N0 relay/pkarr node after ${attempt} attempts: ${err.message}`,
        );
      }
      warn(`${label}: join attempt ${attempt} failed to connect (${err.message}); retrying`);
      await sleep(1_000);
    }
  }
}

/**
 * Browser B (the delegated admin). Needs no join of its own: it only holds the
 * admin key and dials the node directly.
 */
async function browserAdmin() {
  const endpointSeed = generate_secret_key();
  const adminSeed = generate_secret_key();
  const node = await ClientNode.spawn_control(endpointSeed);
  node.set_admin_key(adminSeed);
  const adminPub = node.admin_public_key();
  if (typeof adminPub !== "string" || !/^[0-9a-f]{64}$/.test(adminPub)) {
    throw new Error(`unexpected admin_public_key: ${JSON.stringify(adminPub)}`);
  }
  log("admin browser endpoint id:", node.endpoint_id());
  log("admin public key:", adminPub);
  return { node, adminSeed, adminPub };
}

/** Run an admin call, converting a connect failure into a network SKIP. */
async function withNetworkSkip(description, fn) {
  try {
    return await fn();
  } catch (err) {
    if (isNetworkConnectError(err)) {
      throw new NetworkUnreachable(
        `${description}: could not reach the node over N0: ${err.message}`,
      );
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function buildNodeIfNeeded() {
  if (existsSync(nodeBin)) {
    log("using existing node binary:", path.relative(rootDir, nodeBin));
    return;
  }
  log("node binary missing; building with `cargo build -p cawala-node` ...");
  await new Promise((resolve, reject) => {
    const child = spawn("cargo", ["build", "-p", "cawala-node"], {
      cwd: rootDir,
      env: process.env,
      stdio: "inherit",
    });
    child.on("error", reject);
    child.on("close", (code) =>
      code === 0 ? resolve() : reject(new Error(`cargo build exited ${code}`)),
    );
  });
  if (!existsSync(nodeBin)) {
    throw new Error(`build succeeded but ${nodeBin} is still missing`);
  }
}

async function main() {
  await buildNodeIfNeeded();

  const dataDir = await mkdtemp(path.join(tmpdir(), "cawala-smoke-admin-"));
  log("temp data dir:", dataDir);

  const wasmBytes = await readFile(
    new URL("../src/wasm/cawala_client_bg.wasm", import.meta.url),
  );
  await init(wasmBytes);
  log("wasm initialized");

  let node;
  let browserA;
  let browserB;
  try {
    // Bootstrap identity + node record, then assert address `0` so approvals
    // derive child addresses as `0.<slot>`.
    await runCli(["--data-dir", dataDir, "init"]);
    await runCli(["--data-dir", dataDir, "topo", "set-address", "0"]);

    node = await new AdminNode(dataDir).start();

    const inviteOut = await runCli([
      "--data-dir",
      dataDir,
      "control",
      "invite",
      "--label",
      "smoke-admin",
    ]);
    const inviteUri = inviteOut.stdout
      .split(/\r?\n/)
      .map((line) => line.trim())
      .find((line) => line.startsWith("cawala://join?"));
    if (!inviteUri) {
      throw new Error(`no invite URI in 'control invite' output:\n${inviteOut.stdout}`);
    }
    log("invite:", inviteUri);
    await sleep(PKARR_SETTLE_MS);

    // --- Browser A joins (queued for admin approval). -----------------------
    log("=== browser A: join_via_invite -> pending ===");
    browserA = await browserJoin("A", inviteUri, node.endpointId);
    log("A join_status:", JSON.stringify(statusView(browserA.node)));

    // --- Browser B holds a delegated admin key; grant it on the node. -------
    log("=== browser B: set_admin_key + control admin grant ===");
    browserB = await browserAdmin();
    const grant = await runCli([
      "--data-dir",
      dataDir,
      "control",
      "admin",
      "grant",
      "--key",
      browserB.adminPub,
      "--label",
      "smoke",
    ]);
    log("control admin grant:", grant.stdout.trim());
    if (!grant.stdout.includes(`granted admin=${browserB.adminPub}`)) {
      throw new Error(`unexpected 'control admin grant' output:\n${grant.stdout}`);
    }

    // --- Browser B queries and approves A. ----------------------------------
    log("=== browser B: admin_query -> lists A ===");
    const snapshot = await withNetworkSkip("admin_query", () =>
      browserB.node.admin_query(node.endpointId),
    );
    const snapshotView = adminSnapshotView(snapshot);
    log("admin_query:", JSON.stringify(snapshotView));
    if (snapshotView.nodeId !== node.endpointId) {
      throw new Error(
        `admin_query node id ${snapshotView.nodeId} != ${node.endpointId}`,
      );
    }
    if (!snapshotView.pending.some((p) => p.childId === browserA.browserId)) {
      throw new Error(
        `admin_query did not list browser A (${browserA.browserId}): ` +
          JSON.stringify(snapshotView),
      );
    }

    log("=== browser B: admin_approve_join ===");
    const action = await withNetworkSkip("admin_approve_join", () =>
      browserB.node.admin_approve_join(node.endpointId, browserA.browserId, null),
    );
    const actionView = adminActionView(action);
    log("admin_approve_join:", JSON.stringify(actionView));
    if (actionView.child !== browserA.browserId) {
      throw new Error(
        `approve child ${actionView.child} != A ${browserA.browserId}`,
      );
    }
    if (String(actionView.delivery).startsWith("rejected:")) {
      throw new Error(`approval was rejected by the applicant: ${actionView.delivery}`);
    }
    if (actionView.delivery === "unreachable" || actionView.delivery === "timed_out") {
      warn(
        `approval delivery was '${actionView.delivery}' (applicant not dialable); ` +
          `continuing to the state assertions`,
      );
    } else if (actionView.delivery !== "delivered") {
      throw new Error(`unexpected approval delivery '${actionView.delivery}'`);
    }
    if (typeof actionView.address !== "string" || actionView.address.length === 0) {
      throw new Error(`approval did not assign an address: ${JSON.stringify(actionView)}`);
    }

    // --- Browser A observes the assigned address. ---------------------------
    log("=== browser A: join_status -> joined ===");
    const joined = await waitForStatus(
      browserA.node,
      (s) => s.state === "joined",
      "browser A to report 'joined'",
      JOIN_STATE_TIMEOUT_MS,
    );
    log("A join_status after approval:", JSON.stringify(joined));
    if (joined.parent !== node.endpointId) {
      throw new Error(`joined parent ${joined.parent} != ${node.endpointId}`);
    }
    const expectedAddress = `0.${joined.slot}`;
    if (joined.address !== expectedAddress) {
      throw new Error(
        `assigned address ${joined.address} != expected ${expectedAddress} ` +
          `(slot ${joined.slot})`,
      );
    }

    // --- Negative: revoke, then admin_query must be unauthorized. -----------
    log("=== control admin revoke -> admin_query unauthorized ===");
    const revoke = await runCli([
      "--data-dir",
      dataDir,
      "control",
      "admin",
      "revoke",
      "--key",
      browserB.adminPub,
    ]);
    log("control admin revoke:", revoke.stdout.trim());
    if (!revoke.stdout.includes(`revoked admin=${browserB.adminPub}`)) {
      throw new Error(`unexpected 'control admin revoke' output:\n${revoke.stdout}`);
    }

    const revoked = await withNetworkSkip("admin_query after revoke", async () => {
      try {
        const reply = await browserB.node.admin_query(node.endpointId);
        return { ok: true, view: adminSnapshotView(reply) };
      } catch (err) {
        return { ok: false, message: String(err?.message ?? err) };
      }
    });
    if (revoked.ok) {
      throw new Error(
        `admin_query succeeded after revoke: ${JSON.stringify(revoked.view)}`,
      );
    }
    log("admin_query after revoke failed as expected:", revoked.message);
    if (!/unauthorized/i.test(revoked.message)) {
      throw new Error(
        `post-revoke error was not an unauthorized-class failure: ${revoked.message}`,
      );
    }

    log("ALL CHECKS PASSED");
    return 0;
  } finally {
    browserA?.node?.free?.();
    browserB?.node?.free?.();
    if (node) await node.stop().catch(() => {});
    await rm(dataDir, { recursive: true, force: true }).catch(() => {});
  }
}

let exitCode = 0;
try {
  exitCode = await main();
} catch (err) {
  if (err instanceof NetworkUnreachable && !requireNetwork) {
    console.log(`SKIP: ${err.message}`);
    exitCode = 0;
  } else {
    fail(err?.stack ?? String(err));
    exitCode = 1;
  }
}
process.exit(exitCode);
