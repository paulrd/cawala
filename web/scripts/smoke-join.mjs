#!/usr/bin/env node
// End-to-end join handshake smoke test for the "A' user-live" increment.
//
// This drives the wasm browser client (the same module the PWA loads) from
// Node through the FULL user join handshake against a live local Cawala node:
//
//   wasm browser: parse invite -> join_via_invite -> immediate "pending"
//   native parent: control joins (queued) -> control approve --node <browser>
//   native parent: reverse-dials JoinApproved over cawala/control/0
//   wasm browser: join_status() -> "joined", address = parent.child(slot)
//   wasm browser: local_snapshot().parent == parent endpoint id
//
// and, as a second phase, the reject path:
//
//   wasm browser joins -> parent `control reject` -> browser reports "rejected"
//
// ---------------------------------------------------------------------------
// NETWORK-DEPENDENT. Both endpoints bind the iroh `presets::N0` endpoint:
// the browser published a pkarr record (https://dns.iroh.link/pkarr) and
// connects over the public N0 relay servers and DNS address lookup. This test
// therefore needs outbound HTTPS/DNS/UDP to N0. If (and only if) the relay /
// pkarr lookup is genuinely unreachable, the script prints `SKIP:` and exits
// 0. Any handshake/state assertion failure is a real bug and exits non-zero.
//
// The local node `run` command exposes no bound SocketAddr, so it is not
// possible to build an invite with a direct `--ip` transport hint; the invite
// is hint-free and the browser resolves the parent through the N0 address
// lookup (falling back to the relay), exactly as a real browser would.
// ---------------------------------------------------------------------------
//
// Usage (from the repo root or web/):
//   node web/scripts/smoke-join.mjs
//
// Env:
//   CAWALA_NODE_BIN=/path/to/cawala-node   override the node binary
//   SMOKE_JOIN_REQUIRE_NETWORK=1           turn an unreachable-relay SKIP into
//                                          a hard failure (for CI)
//   SMOKE_JOIN_SKIP_REJECT=1               skip the reject-path phase
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

const PREFIX = "[smoke-join]";
const requireNetwork = process.env.SMOKE_JOIN_REQUIRE_NETWORK === "1";
const skipReject = process.env.SMOKE_JOIN_SKIP_REJECT === "1";

// Deadline for the browser's reverse-dialed JoinApproved/JoinRejected to land.
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
class ParentNode {
  constructor(dataDir) {
    this.dataDir = dataDir;
    this.stdout = "";
    this.stderr = "";
    this.endpointId = undefined;
    this.child = undefined;
    this.exit = undefined;
  }

  async start() {
    log("starting parent node:", path.relative(rootDir, nodeBin), "run");
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
        log("parent endpoint id:", this.endpointId);
        const addr = this.stdout.match(/^Address:\s*(\S+)\s*$/m);
        if (addr) log("parent asserted address:", addr[1]);
        if (this.stdout.includes("Serving cawala/ping/0, cawala/msg/0")) {
          log("parent serving ping + msg + control");
        } else {
          log("parent serving ping + control (no asserted address)");
        }
        return this;
      }
      if (this.child.exitCode !== null) {
        throw new Error(
          `parent node exited before becoming ready (code ${this.child.exitCode}).\n` +
            `--- stdout ---\n${this.stdout}\n--- stderr ---\n${this.stderr}`,
        );
      }
      await sleep(200);
    }
    throw new Error(
      `parent node not ready within ${PARENT_READY_TIMEOUT_MS}ms.\n` +
        `--- stdout ---\n${this.stdout}\n--- stderr ---\n${this.stderr}`,
    );
  }

  async stop() {
    if (!this.child || this.child.exitCode !== null) return;
    this.child.kill("SIGKILL");
    await this.exit;
  }
}

/** Plain-object views of the wasm DTOs (wasm-bindgen getters live on the prototype). */
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

function snapshotView(node) {
  const snap = node.local_snapshot();
  const parent = snap.parent
    ? { nodeId: snap.parent.node_id, slot: snap.parent.slot, address: snap.parent.address }
    : undefined;
  return {
    nodeId: snap.node_id,
    address: snap.address,
    parent,
    children: snap.children.map((c) => ({
      childId: c.child_id,
      kind: c.kind,
      slot: c.slot,
      address: c.address,
    })),
  };
}

function outcomeView(outcome) {
  return {
    status: outcome.status,
    rejectCode: outcome.reject_code,
    reason: outcome.reason,
  };
}

/** Drain all queued control events, logging them, and return them as objects. */
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

/**
 * Poll `join_status()` (draining control events) until `predicate` matches.
 * Throws on timeout with the last observed status and any events.
 */
async function waitForStatus(node, predicate, description, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let last = statusView(node);
  const seen = [];
  while (Date.now() < deadline) {
    seen.push(...drainEvents(node));
    last = statusView(node);
    if (predicate(last)) return { status: last, events: seen };
    await sleep(300);
  }
  throw new Error(
    `timed out after ${timeoutMs}ms waiting for ${description}; ` +
      `last join_status=${JSON.stringify(last)}; ` +
      `events=${JSON.stringify(seen)}`,
  );
}

/**
 * Classify a join failure. A failure to *establish* the control connection is
 * purely environmental (N0 relay/pkarr); a failure after the connection is a
 * real handshake bug. iroh surfaces connect failures as JsError strings that
 * mention connect/timeout/dns/relay. An unreachable pkarr/DNS lookup surfaces
 * as "No addressing information available" (the wasm `fetch` to
 * `https://dns.iroh.link` failed), so "addressing"/"fetch failed" are treated
 * as the network-unreachable bucket too.
 */
function isNetworkConnectError(err) {
  const text = String(err?.message ?? err);
  return /connect|connection|timeout|timed out|dns|relay|lookup|pkarr|unreachable|host|addressing|fetch failed/i.test(
    text,
  );
}

// ---------------------------------------------------------------------------
// Handshake phases
// ---------------------------------------------------------------------------

/** Parse an invite in the wasm module and log what the browser sees. */
function inspectInvite(inviteUri, parentId) {
  const info = parse_invite(inviteUri);
  log("parsed invite:", JSON.stringify({
    parent: info.parent,
    operator: info.operator,
    slot: info.slot,
    expiry: info.expiry,
    label: info.label,
    relay: info.relay,
    ip: info.ip,
  }));
  if (info.parent !== parentId) {
    throw new Error(`invite parent ${info.parent} != node endpoint id ${parentId}`);
  }
  return info;
}

/**
 * Spawn a wasm browser client for `inviteUri` and send the join. Retries on a
 * connect failure (pkarr publication can lag) until `deadlineMs`.
 */
async function browserJoin(label, inviteUri, parentId) {
  const seed = generate_secret_key();
  const node = await ClientNode.spawn_control(seed);
  const browserId = node.endpoint_id();
  log(`${label}: browser endpoint spawned, id = ${browserId}`);

  inspectInvite(inviteUri, parentId);

  const deadline = Date.now() + PARENT_READY_TIMEOUT_MS;
  let attempt = 0;
  for (;;) {
    attempt += 1;
    try {
      log(`${label}: join_via_invite (attempt ${attempt})`);
      const outcome = await node.join_via_invite(inviteUri);
      const view = outcomeView(outcome);
      log(`${label}: immediate join outcome:`, JSON.stringify(view));
      if (view.status === "rejected") {
        throw new Error(
          `${label}: parent rejected the join immediately: ${JSON.stringify(view)}`,
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
      log(`${label}: join_status =`, JSON.stringify(status));
      return { node, seed, browserId };
    } catch (err) {
      if (!isNetworkConnectError(err)) throw err;
      if (Date.now() >= deadline) {
        throw new NetworkUnreachable(
          `${label}: could not reach the N0 relay/pkarr parent after ${attempt} attempts: ${err.message}`,
        );
      }
      warn(`${label}: join attempt ${attempt} failed to connect (${err.message}); retrying`);
      await sleep(1_000);
    }
  }
}

/** Phase 1: join -> queue -> approve -> joined, with address/parent assertions. */
async function assertApproveFlow(dataDir, inviteUri, parentId, parentAddress) {
  log("=== phase 1: approve -> joined ===");
  const { node, browserId } = await browserJoin("approve", inviteUri, parentId);

  // The join must have been persisted by the running parent; `control joins`
  // opens the data dir fresh and lists it.
  const joins = await runCli(["--data-dir", dataDir, "control", "joins"]);
  log("control joins:\n" + joins.stdout.trim());
  if (!joins.stdout.includes(browserId)) {
    throw new Error(
      `'control joins' did not list the pending browser ${browserId}.\n${joins.stdout}`,
    );
  }

  const approve = await runCli([
    "--data-dir",
    dataDir,
    "control",
    "approve",
    "--node",
    browserId,
  ]);
  log("control approve:", approve.stdout.trim());
  if (!/accepted/i.test(approve.stdout)) {
    throw new Error(`'control approve' did not report accepted:\n${approve.stdout}\n${approve.stderr}`);
  }

  const { status, events } = await waitForStatus(
    node,
    (s) => s.state === "joined",
    `browser ${browserId} to report 'joined'`,
    JOIN_STATE_TIMEOUT_MS,
  );
  log("join_status after approval:", JSON.stringify(status));

  const snap = snapshotView(node);
  log("local_snapshot:", JSON.stringify(snap));

  if (status.parent !== parentId) {
    throw new Error(`joined parent ${status.parent} != expected ${parentId}`);
  }
  if (!snap.parent || snap.parent.nodeId !== parentId) {
    throw new Error(
      `local_snapshot().parent ${JSON.stringify(snap.parent)} != expected ${parentId}`,
    );
  }
  const expectedAddress = `${parentAddress}.${status.slot}`;
  if (status.address !== expectedAddress) {
    throw new Error(
      `assigned address ${status.address} != expected ${expectedAddress} (parent ${parentAddress} slot ${status.slot})`,
    );
  }
  if (snap.address !== expectedAddress) {
    throw new Error(
      `local_snapshot().address ${snap.address} != expected ${expectedAddress}`,
    );
  }
  if (snap.parent.slot !== status.slot) {
    throw new Error(
      `snapshot parent slot ${snap.parent.slot} != join_status slot ${status.slot}`,
    );
  }
  const accepted = events.find((e) => e.kind === "accepted");
  if (!accepted) {
    warn("no 'accepted' control event was drained (status is authoritative)");
  } else if (accepted.address !== expectedAddress) {
    throw new Error(
      `accepted event address ${accepted.address} != expected ${expectedAddress}`,
    );
  }

  log(`phase 1 OK: browser joined at ${expectedAddress} under ${parentId}`);
  node.free?.();
}

/** Phase 2: join -> queue -> reject -> browser reports rejected. */
async function assertRejectFlow(dataDir, inviteUri, parentId) {
  log("=== phase 2: reject ===");
  const { node, browserId } = await browserJoin("reject", inviteUri, parentId);

  const reject = await runCli([
    "--data-dir",
    dataDir,
    "control",
    "reject",
    "--node",
    browserId,
    "--reason",
    "smoke reject",
  ]);
  log("control reject:", reject.stdout.trim());

  const { status, events } = await waitForStatus(
    node,
    (s) => s.state === "rejected",
    `browser ${browserId} to report 'rejected'`,
    JOIN_STATE_TIMEOUT_MS,
  );
  log("join_status after rejection:", JSON.stringify(status));
  const rejected = events.find((e) => e.kind === "rejected");
  if (!rejected) {
    throw new Error("join_status is 'rejected' but no 'rejected' control event was drained");
  }
  if (status.parent && status.parent !== parentId) {
    throw new Error(`rejected parent ${status.parent} != expected ${parentId}`);
  }
  log("phase 2 OK: browser reported rejected");
  node.free?.();
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

  const dataDir = await mkdtemp(path.join(tmpdir(), "cawala-smoke-join-"));
  log("temp data dir:", dataDir);

  const wasmBytes = await readFile(
    new URL("../src/wasm/cawala_client_bg.wasm", import.meta.url),
  );
  await init(wasmBytes);
  log("wasm initialized");

  let parent;
  try {
    // Bootstrap identity + node record, then assert address `0` so approvals
    // derive child addresses as `0.<slot>`.
    await runCli(["--data-dir", dataDir, "init"]);
    await runCli(["--data-dir", dataDir, "topo", "set-address", "0"]);

    parent = await new ParentNode(dataDir).start();

    // Build the invite (hint-free: the `run` command exposes no SocketAddr).
    const inviteOut = await runCli(["--data-dir", dataDir, "control", "invite", "--label", "smoke-join"]);
    const inviteUri = inviteOut.stdout
      .split(/\r?\n/)
      .map((line) => line.trim())
      .find((line) => line.startsWith("cawala://join?"));
    if (!inviteUri) {
      throw new Error(`no invite URI in 'control invite' output:\n${inviteOut.stdout}`);
    }
    log("invite:", inviteUri);
    log(
      "note: no direct --ip hint is available (node `run` does not print its " +
        "bound SocketAddr); relying on the N0 relay preset (pkarr/DNS + relay)",
    );

    // Let the parent's pkarr record publish before the browser resolves it.
    await sleep(PKARR_SETTLE_MS);

    await assertApproveFlow(dataDir, inviteUri, parent.endpointId, "0");

    if (!skipReject) {
      // The `control approve` CLI binds a short-lived endpoint with the same
      // secret key, which can overwrite the parent's pkarr record. Restart the
      // parent so its address is re-published before the second join.
      log("restarting parent to refresh its pkarr record before the reject phase");
      await parent.stop();
      parent = await new ParentNode(dataDir).start();
      await sleep(PKARR_SETTLE_MS);
      await assertRejectFlow(dataDir, inviteUri, parent.endpointId);
    } else {
      log("SMOKE_JOIN_SKIP_REJECT=1 set; skipping reject phase");
    }

    log("ALL CHECKS PASSED");
    return 0;
  } finally {
    if (parent) await parent.stop().catch(() => {});
    await rm(dataDir, { recursive: true, force: true }).catch(() => {});
  }
}

let exitCode = 0;
try {
  exitCode = await main();
} catch (err) {
  if (err instanceof NetworkUnreachable && !requireNetwork) {
    // The relay/pkarr path is genuinely unreachable: skip with a clear message
    // rather than failing. Any other error (including a connected handshake
    // that never completes) is a real failure.
    console.log(`SKIP: ${err.message}`);
    exitCode = 0;
  } else {
    fail(err?.stack ?? String(err));
    exitCode = 1;
  }
}
process.exit(exitCode);
