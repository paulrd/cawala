#!/usr/bin/env node
// End-to-end CROSS-SUBTREE settlement smoke test (P4c).
//
// Topology:
//
//            P = 0            (root node; the LCA for the leaves)
//          /       \
//      A = 0.1     B = 0.2    (leaf nodes; hold user children)
//         |            |
//      uA = 0.1.3   uB = 0.2.4  (wasm browser clients)
//
// Flow:
//   operator:  init P/A/B, write their node.json links (P: children A@1, B@2;
//              A/B: parent P), run all three
//   browsers:  uA joins A, uB joins B (control join -> approve)
//   operator:  P funds A (150) and B (1000); A prefunds uA (1000); B prefunds
//              uB (1000)
//   browser uB: receive_uri() -> uA parses it
//   browser uA: send_payment(uB, uB_addr, 100) -> applied (A Ascend/P Lca/B
//              Descend); then a second 100 -> partial at P (the payer leaf's
//              liability is exhausted)
//
// Assertions are on the advisory result status plus the browser's verified
// balance. The cross-subtree result is advisory; the payer's signed receipt is
// ground truth.
//
// ---------------------------------------------------------------------------
// NETWORK-DEPENDENT. All endpoints bind the iroh `presets::N0` endpoint and use
// public pkarr/DNS + relays to resolve and dial each other. If the relay /
// pkarr path is genuinely unreachable, the script prints `SKIP:` and exits 0.
// Any handshake, payment, or settlement assertion failure is a real bug and
// exits non-zero.
// ---------------------------------------------------------------------------
//
// Usage (from the repo root or web/):
//   node web/scripts/smoke-crossleaf.mjs
//
// Env:
//   CAWALA_NODE_BIN=/path/to/cawala-node      override the node binary
//   SMOKE_CROSSLEAF_REQUIRE_NETWORK=1         turn an unreachable-relay SKIP
//                                             into a hard failure (for CI)
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
  parse_receive_uri,
} from "../src/wasm/cawala_client.js";

// ---------------------------------------------------------------------------
// Configuration / paths
// ---------------------------------------------------------------------------

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webDir = path.resolve(__dirname, ".."); // web/
const rootDir = path.resolve(webDir, ".."); // workspace root
const defaultBin = path.join(rootDir, "target", "debug", "cawala-node");
const nodeBin = process.env.CAWALA_NODE_BIN ?? defaultBin;

const PREFIX = "[smoke-crossleaf]";
const requireNetwork = process.env.SMOKE_CROSSLEAF_REQUIRE_NETWORK === "1";

const JOIN_STATE_TIMEOUT_MS = 30_000;
const LEDGER_STATE_TIMEOUT_MS = 45_000;
const PARENT_READY_TIMEOUT_MS = 90_000;
const CLI_TIMEOUT_MS = 60_000;
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

/** Bootstrap identity + record and return the printed endpoint/ledger ids. */
async function initNode(dataDir) {
  const out = await runCli(["--data-dir", dataDir, "init"]);
  const endpointId = out.stdout.match(/^EndpointId:\s*(\S+)\s*$/m)?.[1];
  const ledgerId = out.stdout.match(/^LedgerId:\s*(\S+)\s*$/m)?.[1];
  if (!endpointId || !ledgerId) {
    throw new Error(`could not parse 'init' output:\n${out.stdout}`);
  }
  return { endpointId, ledgerId };
}

/** A running `cawala-node ... run` process with captured output. */
class RunNode {
  constructor(label, dataDir) {
    this.label = label;
    this.dataDir = dataDir;
    this.stdout = "";
    this.stderr = "";
    this.endpointId = undefined;
    this.address = undefined;
    this.child = undefined;
    this.exit = undefined;
  }

  async start() {
    log(`starting ${this.label} node (address ${this.address})`);
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
        if (!this.stdout.includes("cawala/msg/0")) {
          throw new Error(
            `${this.label} did not enable messaging; expected an asserted address.\n` +
              `--- stdout ---\n${this.stdout}\n--- stderr ---\n${this.stderr}`,
          );
        }
        log(`${this.label} ready: endpoint=${this.endpointId} address=${this.address}`);
        return this;
      }
      if (this.child.exitCode !== null) {
        throw new Error(
          `${this.label} exited before becoming ready (code ${this.child.exitCode}).\n` +
            `--- stdout ---\n${this.stdout}\n--- stderr ---\n${this.stderr}`,
        );
      }
      await sleep(200);
    }
    throw new Error(
      `${this.label} not ready within ${PARENT_READY_TIMEOUT_MS}ms.\n` +
        `--- stdout ---\n${this.stdout}\n--- stderr ---\n${this.stderr}`,
    );
  }

  async stop() {
    if (!this.child || this.child.exitCode !== null) return;
    this.child.kill("SIGKILL");
    await this.exit;
  }
}

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
    failedAt: ev.failed_at,
  };
}

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

function isNetworkConnectError(err) {
  const text = String(err?.message ?? err);
  return /connect|connection|timeout|timed out|dns|relay|lookup|pkarr|unreachable|host|addressing|fetch failed/i.test(
    text,
  );
}

/** Spawn a wasm browser client and send the join; retries on connect failures. */
async function browserJoin(label, inviteUri) {
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
      return { node, browserId };
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

async function sendPayment(node, to, toAddress, amount) {
  try {
    return await node.send_payment(to, toAddress, amount);
  } catch (err) {
    if (isNetworkConnectError(err)) {
      throw new NetworkUnreachable(`send_payment could not reach the leaf: ${err.message}`);
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

  const root = await mkdtemp(path.join(tmpdir(), "cawala-smoke-crossleaf-"));
  const dirP = path.join(root, "P");
  const dirA = path.join(root, "A");
  const dirB = path.join(root, "B");
  log("temp data dir:", root);

  const wasmBytes = await readFile(
    new URL("../src/wasm/cawala_client_bg.wasm", import.meta.url),
  );
  await init(wasmBytes);
  log("wasm initialized");

  let p;
  let a;
  let b;
  let clientA;
  let clientB;
  try {
    // ---- identities + records -------------------------------------------
    const idP = await initNode(dirP);
    const idA = await initNode(dirA);
    const idB = await initNode(dirB);

    // P is the root `0` and lists A@1 / B@2 as node children.
    await runCli(["--data-dir", dirP, "topo", "set-address", "0"]);
    await runCli([
      "--data-dir", dirP, "topo", "attach-child",
      "--child", idA.endpointId, "--kind", "node", "--slot", "1",
    ]);
    await runCli([
      "--data-dir", dirP, "topo", "attach-child",
      "--child", idB.endpointId, "--kind", "node", "--slot", "2",
    ]);

    // A/B are non-root leaves at 0.1 / 0.2.
    await runCli(["--data-dir", dirA, "topo", "set-parent", "--parent", idP.endpointId, "--slot", "1"]);
    await runCli(["--data-dir", dirA, "topo", "set-address", "0.1"]);
    await runCli(["--data-dir", dirB, "topo", "set-parent", "--parent", idP.endpointId, "--slot", "2"]);
    await runCli(["--data-dir", dirB, "topo", "set-address", "0.2"]);

    // ---- run all three ---------------------------------------------------
    p = await new RunNode("P", dirP).start();
    a = await new RunNode("A", dirA).start();
    b = await new RunNode("B", dirB).start();
    if (p.address !== "0" || a.address !== "0.1" || b.address !== "0.2") {
      throw new Error(`unexpected addresses P=${p.address} A=${a.address} B=${b.address}`);
    }
    await sleep(PKARR_SETTLE_MS);

    // ---- browsers join under their leaves --------------------------------
    const inviteA = (await runCli(["--data-dir", dirA, "control", "invite", "--label", "crossleaf-A"]))
      .stdout.split(/\r?\n/).map((l) => l.trim()).find((l) => l.startsWith("cawala://join?"));
    const inviteB = (await runCli(["--data-dir", dirB, "control", "invite", "--label", "crossleaf-B"]))
      .stdout.split(/\r?\n/).map((l) => l.trim()).find((l) => l.startsWith("cawala://join?"));
    if (!inviteA || !inviteB) throw new Error("could not build leaf invites");

    const ua = await browserJoin("uA", inviteA);
    const ub = await browserJoin("uB", inviteB);
    clientA = ua.node;
    clientB = ub.node;
    log(`uA endpoint id: ${ua.browserId}`);
    log(`uB endpoint id: ${ub.browserId}`);

    for (const [dataDir, label, browserId] of [
      [dirA, "A", ua.browserId],
      [dirB, "B", ub.browserId],
    ]) {
      const joins = await runCli(["--data-dir", dataDir, "control", "joins"]);
      if (!joins.stdout.includes(browserId)) {
        throw new Error(`${label}: 'control joins' did not list ${browserId}.\n${joins.stdout}`);
      }
      const approve = await runCli(["--data-dir", dataDir, "control", "approve", "--node", browserId]);
      log(`control approve ${label}:`, approve.stdout.trim());
      if (!/accepted/i.test(approve.stdout)) {
        throw new Error(`${label}: 'control approve' was not accepted:\n${approve.stdout}`);
      }
    }

    const joinAddresses = {};
    for (const [label, node, parentId, expected] of [
      ["uA", clientA, a.endpointId, "0.1"],
      ["uB", clientB, b.endpointId, "0.2"],
    ]) {
      const { status } = await waitForJoinStatus(
        node,
        (s) => s.state === "joined",
        `${label} to report 'joined'`,
        JOIN_STATE_TIMEOUT_MS,
      );
      log(`${label} joined:`, JSON.stringify(status));
      if (status.parent !== parentId) {
        throw new Error(`${label} joined parent ${status.parent} != ${parentId}`);
      }
      if (!new RegExp(`^${expected.replace(".", "\\.")}\\.\\d+$`).test(status.address ?? "")) {
        throw new Error(`${label} address ${status.address} is not under ${expected}`);
      }
      joinAddresses[label] = status.address;
    }

    // `control approve` binds a short-lived endpoint with the leaf's secret key,
    // which can overwrite its pkarr record; restart each leaf so it re-publishes.
    log("restarting leaves to refresh their pkarr records before settlement");
    await a.stop();
    await b.stop();
    a = await new RunNode("A", dirA).start();
    b = await new RunNode("B", dirB).start();
    await sleep(PKARR_SETTLE_MS);

    // ---- fund + prefund --------------------------------------------------
    // P holds the children's liabilities: A 150 (exhaustible), B 1000.
    for (const [to, amount] of [[idA.endpointId, "150"], [idB.endpointId, "1000"]]) {
      const fund = await runCli([
        "--data-dir", dirP, "ledger", "fund",
        "--to", to, "--kind", "node", "--amount", amount,
      ]);
      log(`P ledger fund ${to} ${amount}:`, fund.stdout.trim());
    }
    // A/B prefund their user children; A's Parent asset gets its liquidity.
    const prefundA = await runCli([
      "--data-dir", dirA, "ledger", "prefund",
      "--to", ua.browserId, "--kind", "user", "--amount", "1000",
    ]);
    log("A ledger prefund uA 1000:", prefundA.stdout.trim());
    const prefundB = await runCli([
      "--data-dir", dirB, "ledger", "prefund",
      "--to", ub.browserId, "--kind", "user", "--amount", "1000",
    ]);
    log("B ledger prefund uB 1000:", prefundB.stdout.trim());

    // ---- receive URI -----------------------------------------------------
    const receiveUri = clientB.receive_uri();
    log("uB receive uri:", receiveUri);
    const parsed = parse_receive_uri(receiveUri);
    if (parsed.node_id !== ub.browserId || parsed.address !== joinAddresses.uB) {
      throw new Error(
        `uB receive uri parsed to ${parsed.node_id}/${parsed.address}, ` +
          `expected ${ub.browserId}/${joinAddresses.uB}`,
      );
    }

    // ---- cross-subtree payment 1: applied --------------------------------
    log(`uA: send_payment(${parsed.node_id}, ${parsed.address}, 100)`);
    const outcome = await sendPayment(clientA, parsed.node_id, parsed.address, 100);
    log("uA: payment outcome:", JSON.stringify({
      orderHash: outcome.order_hash_hex,
      ack: outcome.ack,
    }));
    if (outcome.ack !== "delivered") {
      throw new Error(`uA: expected ack 'delivered', got '${outcome.ack}'`);
    }

    const aApplied = await waitForLedger(
      clientA,
      (status, events) =>
        status.balance === 900 &&
        events.some((e) => e.kind === "order_result" && e.status === "applied"),
      "uA to see an applied cross-subtree result with balance 900",
      LEDGER_STATE_TIMEOUT_MS,
    );
    log("uA ledger_status:", JSON.stringify(aApplied.status));

    // ---- cross-subtree payment 2: partial at the LCA ---------------------
    // A's Parent asset covers the Ascend, but P's liability for A is exhausted
    // (150 - 100 = 50), so the LCA hop rejects and the result is `partial`.
    log(`uA: send_payment(${parsed.node_id}, ${parsed.address}, 100) [expect partial]`);
    const outcome2 = await sendPayment(clientA, parsed.node_id, parsed.address, 100);
    log("uA: second payment outcome:", JSON.stringify({
      orderHash: outcome2.order_hash_hex,
      ack: outcome2.ack,
    }));

    const aPartial = await waitForLedger(
      clientA,
      (status, events) =>
        status.balance === 800 &&
        events.some((e) => e.kind === "order_result" && e.status === "partial"),
      "uA to see a partial result (debit committed, payee uncredited)",
      LEDGER_STATE_TIMEOUT_MS,
    );
    log("uA ledger_status:", JSON.stringify(aPartial.status));
    const partialEvent = aPartial.events.find(
      (e) => e.kind === "order_result" && e.status === "partial",
    );
    if (partialEvent.failedAt !== p.endpointId) {
      throw new Error(
        `partial failedAt ${partialEvent.failedAt} != LCA ${p.endpointId}`,
      );
    }
    if (partialEvent.reason !== "insufficient_balance") {
      throw new Error(`partial reason ${partialEvent.reason} != insufficient_balance`);
    }

    log("ALL CHECKS PASSED");
    return 0;
  } finally {
    clientA?.free?.();
    clientB?.free?.();
    if (p) await p.stop().catch(() => {});
    if (a) await a.stop().catch(() => {});
    if (b) await b.stop().catch(() => {});
    await rm(root, { recursive: true, force: true }).catch(() => {});
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
