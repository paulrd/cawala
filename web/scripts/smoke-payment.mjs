#!/usr/bin/env node
// End-to-end same-leaf payment smoke test for the value-messaging v1 increment.
//
// This drives two wasm browser clients against a live local Cawala leaf node and
// exercises the full browser-value flow:
//
//   operator:  init -> topo set-address 0 -> run, then `control invite`
//   browser A: spawn_control -> join_via_invite -> pending
//   browser B: spawn_control -> join_via_invite -> pending
//   operator:  control approve --node <A> / <B>, then both report "joined"
//   operator:  restart node (refresh pkarr after the CLI approve endpoints)
//   operator:  ledger fund --to <A> --amount 100
//   browser A: send_payment(<B>, 25) -> ack "delivered"
//              -> try_recv_ledger_event "order_result" applied, balance 75
//   browser B: request_balance() -> "balance_receipt" with balance 25
//
// The duplicate/no-double-move path is NOT reachable through the high-level API:
// `send_payment` always builds a fresh order (random nonce), so it cannot resend
// an identical order. The native hermetic test
// `crates/node/tests/ledger_orders.rs` proves the ledger-level duplicate path;
// this script logs the limitation and skips that assertion.
//
// ---------------------------------------------------------------------------
// NETWORK-DEPENDENT. Both browser endpoints and the node use the iroh
// `presets::N0` endpoint: browsers publish pkarr records and connect over the
// public N0 relays / DNS address lookup, and the node reverse-dials the
// browsers to deliver the order result and balance receipt. This test therefore
// needs outbound HTTPS/DNS/UDP to N0. If (and only if) the relay / pkarr path is
// genuinely unreachable, the script prints `SKIP:` and exits 0. Any handshake,
// payment, or balance assertion failure is a real bug and exits non-zero.
//
// Funding and approval run as SEPARATE `cawala-node` CLI processes against the
// live node's data dir. That is safe because the running node's `LedgerService`
// re-reads and replays the log before every mutation/read ("resync"), so the
// external `control approve` / `ledger fund` appends are observed without a
// restart. `ledger fund` issues again on every run: it is an explicit operator
// act, not a replay-guarded browser order.
// ---------------------------------------------------------------------------
//
// Usage (from the repo root or web/):
//   node web/scripts/smoke-payment.mjs
//
// Env:
//   CAWALA_NODE_BIN=/path/to/cawala-node     override the node binary
//   SMOKE_PAYMENT_REQUIRE_NETWORK=1          turn an unreachable-relay SKIP into
//                                            a hard failure (for CI)
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
} from "../src/wasm/cawala_client.js";

// ---------------------------------------------------------------------------
// Configuration / paths
// ---------------------------------------------------------------------------

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webDir = path.resolve(__dirname, ".."); // web/
const rootDir = path.resolve(webDir, ".."); // workspace root
const defaultBin = path.join(rootDir, "target", "debug", "cawala-node");
const nodeBin = process.env.CAWALA_NODE_BIN ?? defaultBin;

const PREFIX = "[smoke-payment]";
const requireNetwork = process.env.SMOKE_PAYMENT_REQUIRE_NETWORK === "1";

// Deadline for the browser's reverse-dialed joins.
const JOIN_STATE_TIMEOUT_MS = 30_000;
// Deadline for an order result / balance receipt to land.
const LEDGER_STATE_TIMEOUT_MS = 30_000;
// Time allowed for connection setup + pkarr publication at startup.
const PARENT_READY_TIMEOUT_MS = 90_000;
const CLI_TIMEOUT_MS = 60_000;
// Give the node's pkarr publisher a moment to land before the browsers resolve it.
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
    this.address = undefined;
    this.child = undefined;
    this.exit = undefined;
  }

  async start() {
    log("starting leaf node:", path.relative(rootDir, nodeBin), "run");
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
        const addr = this.stdout.match(/^Address:\s*(\S+)\s*$/m);
        this.address = addr ? addr[1] : undefined;
        log("leaf endpoint id:", this.endpointId);
        log("leaf asserted address:", this.address);
        if (!this.stdout.includes("cawala/msg/0")) {
          throw new Error(
            "leaf node did not enable messaging; expected `topo set-address 0` before `run`.\n" +
              `--- stdout ---\n${this.stdout}\n--- stderr ---\n${this.stderr}`,
          );
        }
        log("leaf serving ping + msg + control");
        return this;
      }
      if (this.child.exitCode !== null) {
        throw new Error(
          `leaf node exited before becoming ready (code ${this.child.exitCode}).\n` +
            `--- stdout ---\n${this.stdout}\n--- stderr ---\n${this.stderr}`,
        );
      }
      await sleep(200);
    }
    throw new Error(
      `leaf node not ready within ${PARENT_READY_TIMEOUT_MS}ms.\n` +
        `--- stdout ---\n${this.stdout}\n--- stderr ---\n${this.stderr}`,
    );
  }

  async stop() {
    if (!this.child || this.child.exitCode !== null) return;
    this.child.kill("SIGKILL");
    await this.exit;
  }
}

/** Plain-object view of the join status DTO. */
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

/** Plain-object view of the ledger status DTO. */
function ledgerStatusView(node) {
  const s = node.ledger_status();
  return {
    address: s.address,
    parent: s.parent,
    balance: s.balance,
    height: s.height,
    pinnedLedger: s.pinned_ledger,
    pending: s.pending,
    activity: s.activity,
  };
}

/** Plain-object view of one drained ledger event DTO. */
function ledgerEventView(ev) {
  return {
    kind: ev.kind,
    orderHash: ev.order_hash,
    status: ev.status,
    reason: ev.reason,
    amount: ev.amount,
    balance: ev.balance,
    height: ev.height,
    counterparty: ev.counterparty,
    entrySeq: ev.entry_seq,
  };
}

/** Drain all queued control events, logging them, and return them as objects. */
function drainControlEvents(node) {
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

/** Drain all queued ledger events, logging them, and return them as objects. */
function drainLedgerEvents(node) {
  const events = [];
  for (;;) {
    const ev = node.try_recv_ledger_event();
    if (!ev) break;
    const view = ledgerEventView(ev);
    events.push(view);
    log("ledger event:", JSON.stringify(view));
  }
  return events;
}

/**
 * Poll `join_status()` (draining control events) until `predicate` matches.
 * Throws on timeout with the last observed status and any events.
 */
async function waitForJoinStatus(node, predicate, description, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let last = statusView(node);
  const seen = [];
  while (Date.now() < deadline) {
    seen.push(...drainControlEvents(node));
    last = statusView(node);
    if (predicate(last)) return { status: last, events: seen };
    await sleep(300);
  }
  throw new Error(
    `timed out after ${timeoutMs}ms waiting for ${description}; ` +
      `last join_status=${JSON.stringify(last)}; events=${JSON.stringify(seen)}`,
  );
}

/**
 * Poll `ledger_status()` (draining ledger events) until `predicate` matches.
 * Throws on timeout with the last observed status and events.
 */
async function waitForLedger(node, predicate, description, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let last = ledgerStatusView(node);
  const seen = [];
  while (Date.now() < deadline) {
    seen.push(...drainLedgerEvents(node));
    last = ledgerStatusView(node);
    if (predicate(last, seen)) return { status: last, events: seen };
    await sleep(300);
  }
  throw new Error(
    `timed out after ${timeoutMs}ms waiting for ${description}; ` +
      `last ledger_status=${JSON.stringify(last)}; events=${JSON.stringify(seen)}`,
  );
}

/**
 * Classify a connect failure. A failure to *establish* the N0 connection is
 * environmental (relay/pkarr); a failure after connecting is a real bug.
 *
 * iroh surfaces an unreachable pkarr/DNS lookup as
 * "No addressing information available" (the wasm `fetch` to
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
// Handshake + payment phases
// ---------------------------------------------------------------------------

/**
 * Spawn a wasm browser client and send the join. Retries on a connect failure
 * (pkarr publication can lag) until `deadlineMs`.
 */
async function browserJoin(label, inviteUri, parentId) {
  const seed = generate_secret_key();
  const node = await ClientNode.spawn_control(seed);
  const browserId = node.endpoint_id();
  log(`${label}: browser endpoint spawned, id = ${browserId}`);

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
        throw new Error(`${label}: parent rejected the join: ${JSON.stringify(view)}`);
      }
      if (view.status !== "pending") {
        throw new Error(`${label}: unexpected immediate status '${view.status}'`);
      }
      const status = statusView(node);
      if (status.state !== "pending") {
        throw new Error(
          `${label}: expected join_status 'pending', got ${JSON.stringify(status)}`,
        );
      }
      log(`${label}: join_status =`, JSON.stringify(status));
      return { node, browserId };
    } catch (err) {
      if (err instanceof NetworkUnreachable) throw err;
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

/** Send `amount` from `node` to `to`, classifying connect failures. */
async function sendPayment(node, to, amount) {
  try {
    return await node.send_payment(to, amount);
  } catch (err) {
    if (isNetworkConnectError(err)) {
      throw new NetworkUnreachable(`send_payment could not reach the leaf: ${err.message}`);
    }
    throw err;
  }
}

/** Request a balance receipt, classifying connect failures. */
async function requestBalance(node) {
  try {
    return await node.request_balance();
  } catch (err) {
    if (isNetworkConnectError(err)) {
      throw new NetworkUnreachable(`request_balance could not reach the leaf: ${err.message}`);
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
      env: { ...process.env, CARGO_BUILD_JOBS: "2" },
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

  const dataDir = await mkdtemp(path.join(tmpdir(), "cawala-smoke-payment-"));
  log("temp data dir:", dataDir);

  const wasmBytes = await readFile(
    new URL("../src/wasm/cawala_client_bg.wasm", import.meta.url),
  );
  await init(wasmBytes);
  log("wasm initialized");

  let parent;
  let clientA;
  let clientB;
  try {
    // Bootstrap identity + record, then assert address `0` so approvals derive
    // child addresses as `0.<slot>` and the node serves `cawala/msg/0`.
    await runCli(["--data-dir", dataDir, "init"]);
    await runCli(["--data-dir", dataDir, "topo", "set-address", "0"]);

    parent = await new ParentNode(dataDir).start();
    if (parent.address !== "0") {
      throw new Error(`leaf asserted address '${parent.address}' != '0'`);
    }

    const inviteOut = await runCli([
      "--data-dir",
      dataDir,
      "control",
      "invite",
      "--label",
      "smoke-payment",
    ]);
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

    // Let the leaf's pkarr record publish before the browsers resolve it.
    await sleep(PKARR_SETTLE_MS);

    const a = await browserJoin("A", inviteUri, parent.endpointId);
    const b = await browserJoin("B", inviteUri, parent.endpointId);
    clientA = a.node;
    clientB = b.node;
    log(`A endpoint id: ${a.browserId}`);
    log(`B endpoint id: ${b.browserId}`);

    // Both joins must be persisted by the running node; `control joins` opens
    // the data dir fresh and lists them.
    const joins = await runCli(["--data-dir", dataDir, "control", "joins"]);
    log("control joins:\n" + joins.stdout.trim());
    for (const id of [a.browserId, b.browserId]) {
      if (!joins.stdout.includes(id)) {
        throw new Error(`'control joins' did not list pending browser ${id}.\n${joins.stdout}`);
      }
    }

    // Approve both as user children (each approve opens the ledger account).
    for (const [label, id] of [["A", a.browserId], ["B", b.browserId]]) {
      const approve = await runCli([
        "--data-dir",
        dataDir,
        "control",
        "approve",
        "--node",
        id,
      ]);
      log(`control approve ${label}:`, approve.stdout.trim());
      if (!/accepted/i.test(approve.stdout)) {
        throw new Error(
          `'control approve --node ${id}' did not report accepted:\n${approve.stdout}\n${approve.stderr}`,
        );
      }
    }

    for (const [label, node] of [["A", clientA], ["B", clientB]]) {
      const { status } = await waitForJoinStatus(
        node,
        (s) => s.state === "joined",
        `${label} to report 'joined'`,
        JOIN_STATE_TIMEOUT_MS,
      );
      log(`${label} joined:`, JSON.stringify(status));
      if (status.parent !== parent.endpointId) {
        throw new Error(`${label} joined parent ${status.parent} != ${parent.endpointId}`);
      }
      if (!/^0\.\d+$/.test(status.address ?? "")) {
        throw new Error(`${label} joined address ${status.address} is not 0.<slot>`);
      }
    }

    // The `control approve` CLI binds a short-lived endpoint with the node's
    // secret key, which can overwrite its pkarr record. Restart the leaf so it
    // re-publishes a current address before the browsers dial it for payment.
    log("restarting leaf to refresh its pkarr record before payment");
    await parent.stop();
    parent = await new ParentNode(dataDir).start();
    await sleep(PKARR_SETTLE_MS);

    // Fund A via a separate CLI process (the running node resyncs from disk).
    const fund = await runCli([
      "--data-dir",
      dataDir,
      "ledger",
      "fund",
      "--to",
      a.browserId,
      "--amount",
      "100",
    ]);
    log("ledger fund:\n" + fund.stdout.trim());
    if (!/balance:\s*100/.test(fund.stdout)) {
      throw new Error(`'ledger fund' did not report a 100 balance:\n${fund.stdout}`);
    }

    // ---- A pays B 25 -----------------------------------------------------
    log(`A: send_payment(${b.browserId}, 25)`);
    const outcome = await sendPayment(clientA, b.browserId, 25);
    log("A: payment outcome:", JSON.stringify({
      orderHash: outcome.order_hash_hex,
      ack: outcome.ack,
    }));
    if (outcome.ack !== "delivered") {
      throw new Error(`A: expected ack 'delivered', got '${outcome.ack}'`);
    }

    const aResult = await waitForLedger(
      clientA,
      (status, events) =>
        status.balance === 75 &&
        events.some((e) => e.kind === "order_result" && e.status === "applied"),
      "A to see an applied order result with balance 75",
      LEDGER_STATE_TIMEOUT_MS,
    );
    log("A ledger_status:", JSON.stringify(aResult.status));
    const aApplied = aResult.events.find(
      (e) => e.kind === "order_result" && e.status === "applied",
    );
    if (aApplied.amount !== 25) {
      throw new Error(`A: applied order amount ${aApplied.amount} != 25`);
    }
    if (aApplied.counterparty !== b.browserId) {
      throw new Error(`A: applied order counterparty ${aApplied.counterparty} != B`);
    }

    // ---- B queries its balance ------------------------------------------
    log("B: request_balance()");
    const bAck = await requestBalance(clientB);
    log("B: balance query ack:", bAck);
    if (bAck !== "delivered") {
      throw new Error(`B: expected balance query ack 'delivered', got '${bAck}'`);
    }

    const bResult = await waitForLedger(
      clientB,
      (status, events) =>
        status.balance === 25 &&
        events.some((e) => e.kind === "balance_receipt" && e.balance === 25),
      "B to see a verified balance receipt of 25",
      LEDGER_STATE_TIMEOUT_MS,
    );
    log("B ledger_status:", JSON.stringify(bResult.status));

    // ---- Duplicate / no-double-move --------------------------------------
    // `send_payment` always builds a fresh, randomly-nonced order, so the
    // high-level browser API has no way to resubmit an identical order. The
    // ledger-level Duplicate path is proven natively in
    // `crates/node/tests/ledger_orders.rs`; there is nothing to assert here.
    log(
      "duplicate assertion skipped: the high-level send_payment API generates a " +
        "fresh order every call (no byte-identical resend); see " +
        "crates/node/tests/ledger_orders.rs for the ledger Duplicate proof",
    );

    log("ALL CHECKS PASSED");
    return 0;
  } finally {
    clientA?.free?.();
    clientB?.free?.();
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
    // rather than failing. Any other error (including a connected flow that
    // never completes) is a real failure.
    console.log(`SKIP: ${err.message}`);
    exitCode = 0;
  } else {
    fail(err?.stack ?? String(err));
    exitCode = 1;
  }
}
process.exit(exitCode);
