use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use cawala_control::{
    CONTROL_REQUEST_TTL_SECS, ChildKind, ControlReply, ControlRequest, CreateChild, DetachChild,
    Invite, JoinRejection, JoinRequest, MoveChild, NodeId, OperatorPubKey, OperatorSecretKey,
    SetAddress, SignedControl,
};
use cawala_ledger::{AccountRef, Amount, LedgerPubKey, commitment_hash, verify_chain};
use cawala_msg::{MSG_CONTROL_V1, MSG_LEDGER_V1, MSG_SETTLE_V1};
use cawala_node::control::spawn_control_node_live;
use cawala_node::msg::{
    NeighborSource, dispatch_control_envelope, dispatch_ledger_envelope, dispatch_settle_envelope,
    sweep_settlements,
};
use cawala_node::{
    ControlNode, LedgerService, MsgConfig, RoutableSnapshot, SettlementManager, admin_cli,
    build_envelope, identity, ledger_commitments, ledger_keys, ledger_service, ledger_store,
    netting_harness, record, send_envelope, spawn_control_only, spawn_with_secret_key,
};
use cawala_topology::OctAddr;
use clap::{Parser, Subcommand, ValueEnum};
use iroh::EndpointId;
use tokio::sync::Mutex;
use tracing::info;

#[derive(Parser)]
#[command(
    name = "cawala-node",
    version,
    about = "Cawala node: persisted identity, topology links, and the ping/pong protocol"
)]
struct Cli {
    /// Directory for persisted identity and topology links.
    #[arg(long, global = true, default_value = "node-data", value_name = "DIR")]
    data_dir: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the node (the default when no subcommand is given): load identity +
    /// record, bind the endpoint, and serve forever.
    Run,
    /// Create identity + record if absent (idempotent), print the endpoint id.
    Init,
    /// Inspect and mutate this node's topology links.
    Topo {
        #[command(subcommand)]
        command: TopoCommand,
    },
    /// Inspect this node's on-disk ledger.
    Ledger {
        #[command(subcommand)]
        command: LedgerCommand,
    },
    /// Send a `cawala/msg/0` envelope.
    Msg {
        #[command(subcommand)]
        command: MsgCommand,
    },
    /// Direct control-plane commands (M4): join handshake and senior-child
    /// topology control.
    Control {
        #[command(subcommand)]
        command: ControlCommand,
    },
}

/// Direct `cawala/control/0` commands.
///
/// `node`/`parent` are always an iroh `EndpointId` (hex or base32). Commands
/// that mutate a *neighbor's* topology address that neighbor directly: the
/// request is self-signed by this node's operator key and authorized at the
/// target either as self-admin or as its senior child. In v1 control is
/// direct-only (no tree routing).
#[derive(Subcommand)]
enum ControlCommand {
    /// Send a self-signed join request to a prospective parent, either by
    /// endpoint id or by an invite URI (which also pins the parent's operator
    /// key).
    Join {
        /// The prospective parent's `EndpointId` (mutually exclusive with
        /// `--invite`).
        #[arg(long, value_name = "ENDPOINT_ID", conflicts_with = "invite")]
        parent: Option<String>,
        /// A `cawala://join?...` invite carrying the parent and its pinned
        /// operator key (mutually exclusive with `--parent`).
        #[arg(long, value_name = "URI", conflicts_with = "parent")]
        invite: Option<String>,
        /// Whether this node joins as a node or a user.
        #[arg(long, value_name = "KIND", default_value = "node")]
        kind: KindArg,
        /// Requested octal slot 0..=7; omitted asks the parent to pick. When
        /// `--invite` carries a slot it takes precedence.
        #[arg(long, value_name = "SLOT", value_parser = clap::value_parser!(u8).range(0..=7))]
        slot: Option<u8>,
        /// Optional location-service hint (never authoritative).
        #[arg(long, value_name = "HINT")]
        location: Option<String>,
    },
    /// Print a `cawala://join?...` connection invite for this node.
    ///
    /// The invite carries this node's endpoint id and operator public key, so
    /// a joiner can verify the `JoinApproved` signature against the pinned key.
    Invite {
        /// Desired octal slot 0..=7 to offer the joiner; omitted lets this node
        /// pick at approval time.
        #[arg(long, value_name = "SLOT", value_parser = clap::value_parser!(u8).range(0..=7))]
        slot: Option<u8>,
        /// Unix-seconds expiry to offer the joiner; omitted means the joiner
        /// applies its own default TTL.
        #[arg(long, value_name = "EPOCH_SECONDS")]
        expiry: Option<u64>,
        /// Human-readable label (at most 64 bytes).
        #[arg(long, value_name = "LABEL")]
        label: Option<String>,
        /// Optional relay URL transport hint (http/https/ws/wss), so a joiner
        /// can dial this node without an address-lookup service.
        #[arg(long, value_name = "URL")]
        relay: Option<String>,
        /// Optional direct IP transport hint (`HOST:PORT`), e.g. this node's
        /// bound loopback or public `SocketAddr`.
        #[arg(long, value_name = "HOST:PORT")]
        ip: Option<String>,
    },
    /// List join requests awaiting approval at this node.
    Joins,
    /// Approve a pending join request, assigning it a slot and address.
    Approve {
        /// The applicant's `EndpointId`.
        #[arg(long, value_name = "ENDPOINT_ID")]
        node: String,
        /// Octal slot 0..=7; omitted picks the lowest free slot.
        #[arg(long, value_name = "SLOT", value_parser = clap::value_parser!(u8).range(0..=7))]
        slot: Option<u8>,
    },
    /// Reject a pending join request.
    Reject {
        /// The applicant's `EndpointId`.
        #[arg(long, value_name = "ENDPOINT_ID")]
        node: String,
        /// Human-readable reason (defaults to "rejected").
        #[arg(long, value_name = "REASON")]
        reason: Option<String>,
    },
    /// Ask a directly-controlled neighbor to create a child.
    CreateChild {
        /// The controlled neighbor's `EndpointId`.
        #[arg(long, value_name = "ENDPOINT_ID")]
        node: String,
        /// The new child's `EndpointId`.
        #[arg(long, value_name = "ENDPOINT_ID")]
        child: String,
        /// Whether the new child is a node or a user.
        #[arg(long, value_name = "KIND", default_value = "node")]
        kind: KindArg,
        /// The new child's operator public key, hex (64 chars).
        #[arg(long, value_name = "OPERATOR_HEX")]
        operator: String,
        /// The new child's ledger public key, hex (64 chars); required for a
        /// node, omitted for a user.
        #[arg(long, value_name = "LEDGER_HEX")]
        ledger: Option<String>,
        /// Octal slot 0..=7; omitted lets the target pick.
        #[arg(long, value_name = "SLOT", value_parser = clap::value_parser!(u8).range(0..=7))]
        slot: Option<u8>,
    },
    /// Ask a directly-controlled neighbor to detach one of its children.
    DetachChild {
        /// The controlled neighbor's `EndpointId`.
        #[arg(long, value_name = "ENDPOINT_ID")]
        node: String,
        /// The child's `EndpointId`.
        #[arg(long, value_name = "ENDPOINT_ID")]
        child: String,
    },
    /// Ask a directly-controlled neighbor to re-slot one of its direct
    /// children (v1 is downward-only within the same node).
    MoveChild {
        /// The controlled neighbor's `EndpointId`.
        #[arg(long, value_name = "ENDPOINT_ID")]
        node: String,
        /// The child's `EndpointId`.
        #[arg(long, value_name = "ENDPOINT_ID")]
        child: String,
        /// New octal slot 0..=7; omitted picks the lowest free slot.
        #[arg(long, value_name = "SLOT", value_parser = clap::value_parser!(u8).range(0..=7))]
        slot: Option<u8>,
    },
    /// Ask a directly-controlled neighbor to assert or clear its address.
    SetAddress {
        /// The controlled neighbor's `EndpointId`.
        #[arg(long, value_name = "ENDPOINT_ID")]
        node: String,
        /// Octal address to assert; omitted clears the address.
        #[arg(long, value_name = "ADDR")]
        address: Option<String>,
    },
    /// Query a directly-controlled neighbor's snapshot.
    Query {
        /// The controlled neighbor's `EndpointId`.
        #[arg(long, value_name = "ENDPOINT_ID")]
        node: String,
    },
    /// Manage this node's admin grants (operator-signed delegations).
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
}

/// `control admin` subcommands, backed by [`admin_cli`].
///
/// These are **local** operator commands: they edit `<data-dir>/admins.json`
/// directly (no network). Grant/revoke sign with this node's operator key.
#[derive(Subcommand)]
enum AdminCommand {
    /// Grant an operator key administrative authority over this node.
    Grant {
        /// The admin's operator public key, hex (64 chars).
        #[arg(long, value_name = "OPERATOR_HEX")]
        key: String,
        /// Unix-seconds expiry; omitted defaults to 7 days from now.
        #[arg(long, value_name = "EPOCH_SECONDS")]
        expiry: Option<u64>,
        /// Human-readable label (at most 64 bytes).
        #[arg(long, value_name = "LABEL")]
        label: Option<String>,
    },
    /// Revoke an operator key's administrative authority.
    Revoke {
        /// The admin's operator public key, hex (64 chars).
        #[arg(long, value_name = "OPERATOR_HEX")]
        key: String,
    },
    /// List this node's admin grants.
    List,
}

#[derive(Subcommand)]
enum MsgCommand {
    /// Send one envelope to a destination octal address.
    Send {
        /// Destination octal address, e.g. `0.1.2`.
        #[arg(long, value_name = "ADDR")]
        to: String,
        /// Message type discriminator (u16). Defaults to 1 (ledger).
        #[arg(long, default_value_t = 1)]
        r#type: u16,
        /// UTF-8 payload (conflicts with `--payload-hex`).
        #[arg(long, conflicts_with = "payload_hex")]
        payload: Option<String>,
        /// Raw payload given as hex.
        #[arg(long)]
        payload_hex: Option<String>,
        /// Direct next-hop hint, repeatable.
        ///
        /// Format: `ID=ADDR` where `ID` is the neighbor's node id (an iroh
        /// EndpointId, hex or base32) and `ADDR` is a comma-separated transport
        /// list. Each transport is one of `ip:HOST:PORT`, `relay:URL`, or
        /// `custom:<id>_<hex>`. An empty `ADDR` means "id only".
        #[arg(long, value_name = "ID=ENDPOINT_ADDR")]
        hint: Vec<String>,
    },
}

#[derive(Subcommand)]
enum LedgerCommand {
    /// Print node id, ledger id, entry count/height, head hash, and balances.
    Show,
    /// Replay the on-disk log and report chain/conservation validity.
    Verify,
    /// Create the ledger key and an empty log/meta (idempotent).
    Init,
    /// Open a child's ledger account (idempotent).
    OpenAccount {
        /// The child's `EndpointId`.
        #[arg(long, value_name = "ENDPOINT_ID")]
        node: String,
        /// `user` (the default) or `node`.
        #[arg(long, value_name = "KIND")]
        kind: Option<String>,
    },
    /// Issue value into a child's account (an explicit operator act).
    ///
    /// Any node may adjust the accounts it holds for its children, whether or
    /// not it currently has a parent link.
    ///
    /// Each run issues again: the ledger has no per-issue replay guard, so this
    /// is deliberately operator-only and never reachable from a browser order.
    Fund {
        /// The child's `EndpointId`.
        #[arg(long, value_name = "ENDPOINT_ID")]
        to: String,
        /// Amount to issue.
        #[arg(long, value_name = "AMOUNT")]
        amount: u64,
        /// `user` (the default) or `node`.
        #[arg(long, value_name = "KIND")]
        kind: Option<String>,
    },
    /// Extend value from this node's parent account into a child (non-root only).
    ///
    /// Appends a `Descend` transfer that credits both the parent asset account
    /// and the child's liability, establishing the linked-ledger mirror.
    Prefund {
        /// The child's `EndpointId`.
        #[arg(long, value_name = "ENDPOINT_ID")]
        to: String,
        /// Amount to extend.
        #[arg(long, value_name = "AMOUNT")]
        amount: u64,
        /// `user` (the default) or `node`.
        #[arg(long, value_name = "KIND")]
        kind: Option<String>,
    },
    /// Append one chained commitment at the current ledger head.
    Commit,
    /// Print and verify the stored commitment chain.
    Chain {
        /// Emit the raw commitment array plus the verdict as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run the netting reconciliation over peer data dirs.
    ///
    /// Loads each peer's topology, registry, ledger, commitment chain, and
    /// order journal, then runs the ledger crate's `net`. `RouteInvalid`
    /// findings are printed as advisories (topology is live control-plane
    /// state, so route findings need operator adjudication) and do not fail the
    /// command unless `--strict` is given. The ledger crate only collapses
    /// flows (`nets`) when there are **zero** findings, so a route advisory
    /// will suppress nets until resolved; pass `--topology` with a saved
    /// snapshot to remove stale-geography false positives.
    Net {
        /// Peer data dirs (repeatable). Defaults to the global `--data-dir`.
        #[arg(long, value_name = "DATA_DIR")]
        peer: Vec<PathBuf>,
        /// Order source: a JSON array/JSONL file, or `-` for stdin.
        #[arg(long, value_name = "FILE|-")]
        orders: Option<String>,
        /// Use a saved topology snapshot instead of deriving from records.
        #[arg(long, value_name = "FILE")]
        topology: Option<PathBuf>,
        /// Emit the report as JSON.
        #[arg(long)]
        json: bool,
        /// Treat advisories as failures and require an order source.
        #[arg(long)]
        strict: bool,
    },
    /// Reconstruct and verify one order's settlement cascade.
    VerifyCascade {
        /// Peer data dirs (repeatable). Defaults to the global `--data-dir`.
        #[arg(long, value_name = "DATA_DIR")]
        peer: Vec<PathBuf>,
        /// An inline JSON `PaymentOrder`.
        #[arg(long, value_name = "JSON", conflicts_with = "order_hash")]
        order: Option<String>,
        /// Order source: a JSON array/JSONL file, or `-` for stdin.
        #[arg(long, value_name = "FILE|-")]
        orders: Option<String>,
        /// Select an order from `--orders` by its `hash` hex.
        #[arg(long, value_name = "HEX", requires = "orders")]
        order_hash: Option<String>,
        /// Emit the result as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum TopoCommand {
    /// Print the node's id, parent link, and children.
    Show,
    /// Add a child entry (kind: node|user).
    AttachChild {
        #[arg(long, value_name = "ID")]
        child: String,
        #[arg(long, value_name = "KIND")]
        kind: KindArg,
        /// Octal slot 0..=7; omitted picks the lowest free slot.
        #[arg(long, value_name = "SLOT", value_parser = clap::value_parser!(u8).range(0..=7))]
        slot: Option<u8>,
        /// Unix seconds the child first joined; omitted defaults to now.
        /// Pass the child's original value when re-attaching a moved child to
        /// keep its seniority; omit to reset it.
        #[arg(long, value_name = "EPOCH_SECONDS")]
        date_joined: Option<u64>,
    },
    /// Remove a child entry.
    DetachChild {
        #[arg(long, value_name = "ID")]
        child: String,
    },
    /// Set this node's parent link.
    SetParent {
        #[arg(long, value_name = "ID")]
        parent: String,
        /// Octal slot 0..=7 this node occupies under its parent.
        #[arg(long, value_name = "SLOT", value_parser = clap::value_parser!(u8).range(0..=7))]
        slot: u8,
    },
    /// Clear this node's parent link.
    UnsetParent,
    /// Assert this node's octal address (e.g. `0.1.2`).
    SetAddress {
        #[arg(value_name = "ADDR")]
        address: String,
    },
    /// Clear this node's asserted address.
    UnsetAddress,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum KindArg {
    Node,
    User,
}

impl From<KindArg> for cawala_topology::ChildKind {
    fn from(kind: KindArg) -> Self {
        match kind {
            KindArg::Node => cawala_topology::ChildKind::Node,
            KindArg::User => cawala_topology::ChildKind::User,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Run) | None => run(cli.data_dir).await,
        Some(Command::Init) => init(&cli.data_dir),
        Some(Command::Topo { command }) => topo(&cli.data_dir, command),
        Some(Command::Ledger { command }) => ledger(&cli.data_dir, command),
        Some(Command::Msg { command }) => msg_command(&cli.data_dir, command).await,
        Some(Command::Control { command }) => control_command(&cli.data_dir, command).await,
    }
}

/// Load identity + record, bind the endpoint, print the endpoint id, serve
/// forever.
async fn run(data_dir: PathBuf) -> Result<()> {
    // Prevent two node processes on the same data dir. The ledger *write* lock
    // is per-transaction inside `LedgerService`, so operator CLI commands
    // (`ledger fund`, `control approve`, ...) can still run against this node.
    let _instance_lock = ledger_store::LedgerLock::acquire_process_instance(&data_dir)?;
    let secret_key = identity::load_or_create_secret_key(&data_dir)?;
    let node_id = secret_key.public().to_string();
    let store = record::RecordStore::open(&data_dir, &node_id)?;
    store.save()?;

    let operator = OperatorSecretKey::from_bytes(secret_key.to_bytes());
    let control = Arc::new(Mutex::new(ControlNode::open(
        &data_dir, &node_id, operator,
    )?));

    if let Some(address) = store.record().address.clone() {
        let config = MsgConfig::default();
        // Live routing view: re-reads node.json per message so a `control
        // approve` performed in another process is observed without a restart.
        let source = NeighborSource::live(&data_dir, &node_id, std::collections::HashMap::new())?;
        let ledger = Arc::new(Mutex::new(LedgerService::open(&data_dir, &node_id)?));
        let manager = Arc::new(Mutex::new(SettlementManager::new()));

        // Must stay alive for the accept loop; dropped at process exit.
        // Clone the control handle first: `spawn_control_node_live` takes
        // ownership, but the drain loop still needs it for routed control.
        let dispatch_control = Arc::clone(&control);
        let (router, mut received) =
            spawn_control_node_live(secret_key, source.clone(), config.clone(), control).await?;
        let endpoint = router.endpoint().clone();
        info!(endpoint_id = %node_id, %address, "node endpoint bound with messaging + control");
        println!("EndpointId: {node_id}");
        println!("Address: {address}");
        println!("Serving cawala/ping/0, cawala/msg/0, and cawala/control/0");

        // Drain locally delivered envelopes. `Delivered` means "queued": ledger
        // and settlement payloads are dispatched (and applied) here, off the
        // transport path.
        let dispatch_dir = data_dir.clone();
        let dispatch_node = node_id.clone();
        let dispatch_ledger = Arc::clone(&ledger);
        let dispatch_manager = Arc::clone(&manager);
        let dispatch_source = source.clone();
        let dispatch_config = config.clone();
        tokio::spawn(async move {
            while let Some(env) = received.recv().await {
                info!(
                    src = %env.src.node,
                    msg_type = env.msg_type,
                    payload_len = env.payload.len(),
                    msg_id = %env.msg_id.to_hex(),
                    "received message"
                );
                match env.msg_type {
                    MSG_LEDGER_V1 => {
                        dispatch_ledger_envelope(
                            &endpoint,
                            &dispatch_source,
                            &dispatch_config,
                            &dispatch_ledger,
                            &dispatch_manager,
                            &dispatch_dir,
                            &dispatch_node,
                            env,
                        )
                        .await;
                    }
                    MSG_SETTLE_V1 => {
                        dispatch_settle_envelope(
                            &endpoint,
                            &dispatch_source,
                            &dispatch_config,
                            &dispatch_ledger,
                            &dispatch_manager,
                            &dispatch_dir,
                            &dispatch_node,
                            env,
                        )
                        .await;
                    }
                    MSG_CONTROL_V1 => {
                        dispatch_control_envelope(
                            &endpoint,
                            &dispatch_source,
                            &dispatch_config,
                            &dispatch_control,
                            env,
                        )
                        .await;
                    }
                    _ => {}
                }
            }
        });

        // Keep the process alive (dropping `router` would abort the accept
        // loop) and sweep timed-out origin settlements every few seconds.
        let sweep_endpoint = router.endpoint().clone();
        let sweep_source = source.clone();
        let sweep_config = config.clone();
        let sweep_manager = Arc::clone(&manager);
        let sweep_ledger = Arc::clone(&ledger);
        let sweep_dir = data_dir.clone();
        let sweep_node = node_id.clone();
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        loop {
            ticker.tick().await;
            sweep_settlements(
                &sweep_endpoint,
                &sweep_source,
                &sweep_config,
                &sweep_ledger,
                &sweep_dir,
                &sweep_node,
                &sweep_manager,
                now_unix_seconds(),
            )
            .await;
        }
    }

    // No asserted address: routing is impossible, so messaging is disabled, but
    // direct control still works (an address-less applicant must be able to
    // receive `JoinApproved`).
    let _router = spawn_control_only(secret_key, control).await?;
    info!(endpoint_id = %node_id, "node endpoint bound (ping + control; messaging disabled)");
    println!("EndpointId: {node_id}");
    eprintln!(
        "warning: node has no asserted address; messaging disabled. \
         Run `cawala-node topo set-address <ADDR>`."
    );
    println!("Serving cawala/ping/0 and cawala/control/0");

    // Await forever; dropping `router` would abort the accept loop.
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}

/// Create identity + record if absent (idempotent) and print the endpoint id.
fn init(data_dir: &std::path::Path) -> Result<()> {
    let secret_key = identity::load_or_create_secret_key(data_dir)?;
    let node_id = secret_key.public().to_string();
    let store = record::RecordStore::open(data_dir, &node_id)?;
    store.save()?;
    // Also bootstrap the ledger identity at init time.
    let ledger_key = ledger_keys::load_or_create_ledger_key(data_dir)?;
    ledger_store::init_ledger(data_dir, &node_id, &ledger_key.public())?;
    println!("EndpointId: {node_id}");
    println!("LedgerId: {}", ledger_key.public());
    println!(
        "identity, node record, and ledger are ready in {}",
        data_dir.display()
    );
    Ok(())
}

/// Ledger inspection and bootstrap.
fn ledger(data_dir: &std::path::Path, command: LedgerCommand) -> Result<()> {
    let secret_key = identity::load_or_create_secret_key(data_dir)?;
    let node_id = secret_key.public().to_string();
    let ledger_key = ledger_keys::load_or_create_ledger_key(data_dir)?;

    match command {
        LedgerCommand::Init => {
            let meta = ledger_store::init_ledger(data_dir, &node_id, &ledger_key.public())?;
            println!("node_id: {}", meta.node_id);
            println!("ledger_id: {}", meta.ledger_id);
            println!("format_version: {}", meta.format_version);
            println!(
                "ledger layout ready in {}",
                ledger_store::ledger_dir(data_dir).display()
            );
        }
        LedgerCommand::Show => {
            // Shared read lock: a direct log replay must not race a writer.
            let _lock = ledger_store::LedgerLock::acquire_shared(data_dir)?;
            let root = ledger_service::derive_is_root(data_dir, &node_id);
            let ledger = ledger_store::open_ledger(data_dir, &node_id, &ledger_key)?;
            show_ledger(&node_id, &ledger, root);
        }
        LedgerCommand::Verify => {
            let _lock = ledger_store::LedgerLock::acquire_shared(data_dir)?;
            match ledger_store::open_ledger(data_dir, &node_id, &ledger_key) {
                Ok(ledger) => {
                    println!("valid: true");
                    println!("entries: {}", ledger.len());
                    println!("height: {}", ledger.height());
                    println!("head: {}", ledger.head_hash());
                }
                Err(err) => {
                    println!("valid: false");
                    println!("error: {err}");
                    return Err(err);
                }
            }
        }
        LedgerCommand::OpenAccount { node, kind } => {
            let mut service = LedgerService::open(data_dir, &node_id)?;
            let kind = parse_kind(kind.as_deref())?;
            let child = NodeId::from(node.clone());
            if service.ensure_account_open(&child, kind)? {
                println!("opened account for {node}");
            } else {
                println!("account for {node} is already open");
            }
        }
        LedgerCommand::Fund { to, amount, kind } => {
            let mut service = LedgerService::open(data_dir, &node_id)?;
            let operator = OperatorSecretKey::from_bytes(secret_key.to_bytes());
            let nonce = getrandom::u64().map_err(|err| anyhow::anyhow!("getrandom: {err}"))?;
            let now = now_unix_seconds();
            let to_id = NodeId::from(to.clone());
            let (seq, hash) = service.fund(
                &to_id,
                parse_kind(kind.as_deref())?,
                amount,
                &operator,
                nonce,
                now,
            )?;
            println!("issued {amount} to {to}");
            println!("entry_seq: {seq}");
            println!("entry_hash: {hash}");
            println!("balance: {}", service.balance_of(&to_id));
        }
        LedgerCommand::Prefund { to, amount, kind } => {
            let mut service = LedgerService::open(data_dir, &node_id)?;
            let operator = OperatorSecretKey::from_bytes(secret_key.to_bytes());
            let nonce = getrandom::u64().map_err(|err| anyhow::anyhow!("getrandom: {err}"))?;
            let now = now_unix_seconds();
            let to_id = NodeId::from(to.clone());
            let (seq, hash) = service.prefund(
                &to_id,
                parse_kind(kind.as_deref())?,
                amount,
                &operator,
                nonce,
                now,
            )?;
            println!("prefunded {amount} to {to}");
            println!("entry_seq: {seq}");
            println!("entry_hash: {hash}");
            println!("balance: {}", service.balance_of(&to_id));
            println!(
                "parent_balance: {}",
                service
                    .ledger()
                    .balances()
                    .parent_balance()
                    .unwrap_or(Amount::ZERO)
            );
        }
        LedgerCommand::Commit => {
            let mut service = LedgerService::open(data_dir, &node_id)?;
            let (height, hash) = service.commit()?;
            // Read back the commitment just written for its roots/link.
            let commitments = service.commitments()?;
            let signed = commitments
                .chain()
                .last()
                .expect("commit appended a commitment");
            let commitment = &signed.commitment;
            println!(
                "committed height={} entry_count={} entry_root={} state_root={} prev={} hash={}",
                height,
                commitment.entry_count,
                commitment.entry_root,
                commitment.state_root,
                commitment.prev_commitment_hash,
                hash,
            );
        }
        LedgerCommand::Chain { json } => {
            // Shared read lock: a direct replay must not race a running node.
            let _lock = ledger_store::LedgerLock::acquire_shared(data_dir)?;
            let commitments =
                ledger_commitments::CommitmentLog::open(data_dir, ledger_key.public())?;
            let chain = commitments.chain();
            let valid = verify_chain(chain, &ledger_key.public()).is_ok();
            if json {
                let value = serde_json::json!({ "valid": valid, "commitments": chain });
                println!("{}", serde_json::to_string_pretty(&value)?);
            } else if chain.is_empty() {
                println!("no commitments");
                println!("valid: {valid}");
            } else {
                for signed in chain {
                    let commitment = &signed.commitment;
                    println!(
                        "height={} entry_count={} issued_at={} prev={} hash={} entry_root={} state_root={}",
                        commitment.height,
                        commitment.entry_count,
                        commitment.issued_at,
                        commitment.prev_commitment_hash,
                        commitment_hash(commitment),
                        commitment.entry_root,
                        commitment.state_root,
                    );
                }
                println!("valid: {valid}");
            }
        }
        LedgerCommand::Net {
            peer,
            orders,
            topology,
            json,
            strict,
        } => {
            let peers = resolve_peers(data_dir, peer);
            let inputs = match netting_harness::load(&peers, orders.as_deref(), topology.as_deref())
            {
                Ok(inputs) => inputs,
                Err(err) => fail(2, format!("{err:#}")),
            };
            if strict && inputs.orders.is_empty() {
                fail(
                    2,
                    "--strict requires an order source, but none was supplied or found".to_string(),
                );
            }
            let report = netting_harness::report(&inputs);
            if json {
                match serde_json::to_string_pretty(&report) {
                    Ok(text) => println!("{text}"),
                    Err(err) => fail(2, format!("failed to encode report: {err}")),
                }
            } else {
                print_net_report(&report);
            }
            let failed = !report.findings.is_empty() || (strict && !report.advisories.is_empty());
            if failed {
                std::process::exit(1);
            }
        }
        LedgerCommand::VerifyCascade {
            peer,
            order,
            orders,
            order_hash,
            json,
        } => {
            let peers = resolve_peers(data_dir, peer);
            let inputs = match netting_harness::load(&peers, orders.as_deref(), None) {
                Ok(inputs) => inputs,
                Err(err) => fail(2, format!("{err:#}")),
            };
            let order = match resolve_cascade_order(&inputs, order.as_deref(), order_hash.as_deref())
            {
                Ok(order) => order,
                Err(err) => fail(2, err),
            };

            let expected = cawala_ledger::expected_hops(&inputs.topology, &order);
            let result = cawala_ledger::verify_cascade(
                &inputs.topology,
                &order,
                &inputs.ledgers,
                &inputs.registry,
            );
            let valid = result.is_ok();
            let reason = result.as_ref().err().map(|err| err.to_string());

            let hops: Vec<HopReport> = match &expected {
                Ok(expected) => expected
                    .iter()
                    .map(|hop| HopReport {
                        signer: hop.signer.to_string(),
                        role: netting_harness::role_label(hop.role).to_string(),
                        first: netting_harness::account_label(&hop.first),
                        second: netting_harness::account_label(&hop.second),
                        matched: valid,
                    })
                    .collect(),
                Err(_) => Vec::new(),
            };
            let cascade = CascadeReport {
                order_hash: order.hash().to_hex(),
                valid,
                reason: reason.clone(),
                hops,
            };

            if json {
                match serde_json::to_string_pretty(&cascade) {
                    Ok(text) => println!("{text}"),
                    Err(err) => fail(2, format!("failed to encode cascade: {err}")),
                }
            } else {
                println!("order_hash: {}", cascade.order_hash);
                match &expected {
                    Ok(expected) => {
                        for (index, hop) in expected.iter().enumerate() {
                            println!(
                                "hop {index}: signer={} role={} first={} second={} match={}",
                                hop.signer,
                                netting_harness::role_label(hop.role),
                                netting_harness::account_label(&hop.first),
                                netting_harness::account_label(&hop.second),
                                valid,
                            );
                        }
                    }
                    Err(err) => println!("route: unresolvable ({err})"),
                }
                match &reason {
                    Some(reason) => println!("valid: false\nreason: {reason}"),
                    None => println!("valid: true"),
                }
            }
            if !valid {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

/// The peer set for a harness command: explicit `--peer` dirs, else the global
/// `--data-dir`.
fn resolve_peers(data_dir: &std::path::Path, peer: Vec<PathBuf>) -> Vec<PathBuf> {
    if peer.is_empty() {
        vec![data_dir.to_path_buf()]
    } else {
        peer
    }
}

/// Print `message` to stderr and exit with `code` (2 for usage/IO/load errors).
fn fail(code: i32, message: String) -> ! {
    eprintln!("error: {message}");
    std::process::exit(code);
}

/// Resolve the order for `verify-cascade` from either `--order` or
/// `--orders`+`--order-hash`.
fn resolve_cascade_order(
    inputs: &netting_harness::HarnessInputs,
    inline: Option<&str>,
    order_hash: Option<&str>,
) -> Result<cawala_ledger::PaymentOrder, String> {
    if let Some(text) = inline {
        return serde_json::from_str::<cawala_ledger::PaymentOrder>(text)
            .map_err(|err| format!("invalid --order JSON: {err}"));
    }
    let target = order_hash
        .ok_or_else(|| "provide --order <json> or --orders <file> --order-hash <hex>".to_string())?
        .to_lowercase();
    inputs
        .orders
        .iter()
        .find(|order| order.hash().to_hex() == target)
        .cloned()
        .ok_or_else(|| format!("no order with hash {target} in the supplied source"))
}

/// One hop of a cascade verification report.
#[derive(serde::Serialize)]
struct HopReport {
    signer: String,
    role: String,
    first: String,
    second: String,
    matched: bool,
}

/// The `verify-cascade` result, serialized under `--json`.
#[derive(serde::Serialize)]
struct CascadeReport {
    order_hash: String,
    valid: bool,
    reason: Option<String>,
    hops: Vec<HopReport>,
}

fn print_net_report(report: &netting_harness::HarnessReport) {
    println!("peers:");
    for peer in &report.peers {
        println!("  {} ({})", peer.node_id, peer.data_dir);
        println!(
            "    chain: {} ({} commitments)",
            if peer.chain_present { "present" } else { "absent" },
            peer.chain_len
        );
        for note in &peer.notes {
            println!("    note: {note}");
        }
    }
    if !report.chains_present.is_empty() {
        println!("chains_present: {}", report.chains_present.join(", "));
    }
    for note in &report.notes {
        println!("note: {note}");
    }
    println!("advisories: {}", report.advisories.len());
    for finding in &report.advisories {
        println!("  {}", describe_finding(finding));
    }
    println!("findings: {}", report.findings.len());
    for finding in &report.findings {
        println!("  {}", describe_finding(finding));
    }
    println!("nets: {}", report.nets.len());
    for net in &report.nets {
        println!("  {} -> {} via {} : {}", net.from, net.to, net.parent, net.amount);
    }
}

/// Name the culprits carried by each [`cawala_ledger::Finding`].
fn describe_finding(finding: &cawala_ledger::Finding) -> String {
    use cawala_ledger::Finding;
    match finding {
        Finding::Fork {
            ledger_id,
            height,
            heads,
        } => format!(
            "fork ledger={ledger_id} height={height} heads=[{}]",
            heads
                .iter()
                .map(|head| head.to_hex())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Finding::ChainInvalid { node, reason } => {
            format!("chain_invalid node={node} reason={reason}")
        }
        Finding::MirrorMismatch {
            edge,
            parent_view,
            child_view,
            direction,
        } => format!(
            "mirror_mismatch edge={}->{} parent_view={parent_view} child_view={child_view} direction={direction:?}",
            edge.parent, edge.child
        ),
        Finding::RouteInvalid { payment_id, reason } => {
            format!("route_invalid payment={} reason={reason}", payment_id.to_hex())
        }
        Finding::Replay { payment_id, reason } => {
            format!("replay payment={} reason={reason}", payment_id.to_hex())
        }
        Finding::Overdraw {
            node,
            account,
            deficit,
        } => format!(
            "overdraw node={node} account={} deficit={deficit}",
            netting_harness::account_label(account)
        ),
    }
}

/// Parse the optional `--kind user|node` flag (`user` when omitted).
fn parse_kind(kind: Option<&str>) -> Result<cawala_topology::ChildKind> {
    match kind {
        None | Some("user") => Ok(cawala_topology::ChildKind::User),
        Some("node") => Ok(cawala_topology::ChildKind::Node),
        Some(other) => anyhow::bail!("invalid kind '{other}' (expected 'node' or 'user')"),
    }
}

fn show_ledger(
    node_id: &str,
    ledger: &cawala_ledger::Ledger<ledger_store::FileLog>,
    is_root: bool,
) {
    println!("node_id: {node_id}");
    println!("ledger_id: {}", ledger.ledger_id());
    println!("entries: {}", ledger.len());
    println!("height: {}", ledger.height());
    println!("head: {}", ledger.head_hash());
    // Rootness is a control-plane fact (the node record's parent link), not a
    // ledger property: the Parent account is universal.
    println!("root: {is_root}");
    println!(
        "parent_balance: {}",
        ledger.balances().parent_balance().unwrap_or(Amount::ZERO)
    );
    // Equity is derived (`Parent − ΣChild`), never posted; `E < 0` is normal.
    println!("equity: {}", ledger.balances().equity());
    println!("balances:");
    for (account, balance) in ledger.balances().accounts() {
        // The parent asset is surfaced explicitly above.
        if matches!(account, AccountRef::Parent) {
            continue;
        }
        println!("  {}: {balance}", account_name(&account));
    }
}

fn account_name(account: &AccountRef) -> String {
    match account {
        AccountRef::Parent => "parent".to_string(),
        AccountRef::Child(id) => format!("child:{id}"),
    }
}

/// Topology link inspection and mutation.
fn topo(data_dir: &std::path::Path, command: TopoCommand) -> Result<()> {
    let secret_key = identity::load_or_create_secret_key(data_dir)?;
    let node_id = secret_key.public().to_string();
    let mut store = record::RecordStore::open(data_dir, &node_id)?;

    match command {
        TopoCommand::Show => show(&store),
        TopoCommand::AttachChild {
            child,
            kind,
            slot,
            date_joined,
        } => {
            let date_joined = date_joined.unwrap_or_else(now_unix_seconds);
            store.attach_child(&child, kind.into(), slot, date_joined)?;
            store.save()?;
            let entry = store
                .record()
                .children
                .iter()
                .find(|c| c.child_id == child)
                .expect("just attached");
            println!(
                "attached child {child} ({}) at slot {} (date_joined {})",
                kind_name(kind.into()),
                entry.slot,
                entry.date_joined
            );
        }
        TopoCommand::DetachChild { child } => {
            store.detach_child(&child)?;
            store.save()?;
            println!("detached child {child}");
        }
        TopoCommand::SetParent { parent, slot } => {
            store.set_parent(&parent, slot)?;
            store.save()?;
            println!("set parent {parent} at slot {slot}");
        }
        TopoCommand::UnsetParent => {
            store.unset_parent()?;
            store.save()?;
            println!("parent link cleared");
        }
        TopoCommand::SetAddress { address } => {
            let address: OctAddr = address
                .parse()
                .map_err(|err| anyhow::anyhow!("invalid address '{address}': {err}"))?;
            store.set_address(address)?;
            store.save()?;
            let address = store.record().address.as_ref().expect("just set").clone();
            println!("address: {address}");
        }
        TopoCommand::UnsetAddress => {
            store.unset_address()?;
            store.save()?;
            println!("address: none");
        }
    }
    Ok(())
}

fn show(store: &record::RecordStore) {
    let rec = store.record();
    println!("node_id: {}", rec.node_id);
    match &rec.address {
        Some(address) => println!("address: {address}"),
        None => println!("address: none"),
    }
    match &rec.parent {
        Some(parent) => println!(
            "parent: {{ parent_id: {}, slot: {} }}",
            parent.parent_id, parent.slot
        ),
        None => println!("parent: none"),
    }
    if rec.children.is_empty() {
        println!("children: (none)");
    } else {
        println!("children:");
        for child in &rec.children {
            println!(
                "  slot {}: {} {} (joined {})",
                child.slot,
                kind_name(child.kind),
                child.child_id,
                child.date_joined
            );
        }
    }

    // Derived addresses: what the assert address implies for links.
    if let Some(address) = &rec.address {
        match address.parent() {
            Some(parent) => println!("derived parent address: {parent}"),
            None => println!("derived parent address: none"),
        }
        for child in &rec.children {
            println!(
                "derived child slot {} address: {}",
                child.slot,
                address.child(child.slot)
            );
        }
    }
}

fn kind_name(kind: cawala_topology::ChildKind) -> &'static str {
    match kind {
        cawala_topology::ChildKind::Node => "node",
        cawala_topology::ChildKind::User => "user",
    }
}

/// Current time as unix seconds (the default `date_joined` when the admin
/// does not supply one).
fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A fresh control-request nonce from the OS randomness source.
fn fresh_nonce() -> u64 {
    getrandom::u64().unwrap_or_else(|_| now_unix_seconds())
}

/// Send one `cawala/msg/0` envelope.
async fn msg_command(data_dir: &std::path::Path, command: MsgCommand) -> Result<()> {
    match command {
        MsgCommand::Send {
            to,
            r#type,
            payload,
            payload_hex,
            hint,
        } => {
            let secret_key = identity::load_or_create_secret_key(data_dir)?;
            let node_id = secret_key.public().to_string();
            let store = record::RecordStore::open(data_dir, &node_id)?;
            let mut snapshot = RoutableSnapshot::from_record(store.record())?;
            for raw in &hint {
                let (id, addr) = parse_hint(raw)?;
                // `parse_hint` returns the canonical `EndpointId` string, so the
                // hint map is always keyed by the same form `from_record` stores.
                snapshot.hints.insert(id, addr);
            }

            let dst: OctAddr = to
                .parse()
                .map_err(|err| anyhow::anyhow!("invalid --to '{to}': {err}"))?;
            let payload: Vec<u8> = match (payload, payload_hex) {
                (_, Some(hex)) => decode_hex(&hex)?,
                (Some(text), None) => text.into_bytes(),
                (None, None) => Vec::new(),
            };

            let config = MsgConfig::default();
            let env = build_envelope(&snapshot.routable.this, dst, r#type, payload, config.ttl)?;

            // Sending only needs a bound endpoint, not the msg ALPN.
            let router = spawn_with_secret_key(secret_key).await?;
            let ack = send_envelope(router.endpoint(), &snapshot, &env, config.hop_timeout).await?;
            println!("msg_id: {}", ack.msg_id.to_hex());
            println!("status: {}", ack.status_str());
            router
                .shutdown()
                .await
                .map_err(|err| anyhow::anyhow!("router shutdown: {err}"))?;
            Ok(())
        }
    }
}

/// Direct control-plane commands.
async fn control_command(data_dir: &std::path::Path, command: ControlCommand) -> Result<()> {
    let secret_key = identity::load_or_create_secret_key(data_dir)?;
    let node_id = secret_key.public().to_string();
    let operator = OperatorSecretKey::from_bytes(secret_key.to_bytes());
    let me = NodeId::from(node_id.clone());

    match command {
        ControlCommand::Join {
            parent,
            invite,
            kind,
            slot,
            location,
        } => {
            let now = now_unix_seconds();
            // Resolve the parent node and, for an invite, its pinned operator
            // key. `--parent` keeps the old (unpinned) behavior.
            //
            // `target` is `Some` only when an invite carries transport hints
            // (`relay`/`ip`): then we dial the exact `EndpointAddr` rather than
            // relying on an address-lookup service. A hintless invite keeps the
            // id-only `send_direct` path (which uses address lookup).
            let (parent_id, pinned_operator, desired_slot, expiry, target) = match (parent, invite)
            {
                (Some(_), Some(_)) => {
                    anyhow::bail!("--parent and --invite are mutually exclusive")
                }
                (Some(parent), None) => (
                    NodeId::from(parent),
                    None,
                    slot,
                    now.saturating_add(JOIN_TTL_SECONDS),
                    None,
                ),
                (None, Some(uri)) => {
                    let invite = Invite::parse(&uri)
                        .map_err(|err| anyhow::anyhow!("invalid invite: {err}"))?;
                    invite
                        .validate()
                        .map_err(|err| anyhow::anyhow!("invalid invite: {err}"))?;
                    let expiry = invite
                        .expiry
                        .unwrap_or_else(|| now.saturating_add(JOIN_TTL_SECONDS));
                    let target = if invite.relay.is_some() || invite.ip.is_some() {
                        Some(ControlNode::invite_endpoint_addr(&invite).map_err(|err| {
                            anyhow::anyhow!("invalid invite transport hints: {err}")
                        })?)
                    } else {
                        None
                    };
                    (
                        invite.parent.clone(),
                        Some(invite.operator),
                        invite.slot.or(slot),
                        expiry,
                        target,
                    )
                }
                (None, None) => anyhow::bail!("one of --parent or --invite is required"),
            };

            let child_kind: ChildKind = kind.into();
            let ledger = match child_kind {
                ChildKind::Node => Some(ledger_keys::load_or_create_ledger_key(data_dir)?.public()),
                ChildKind::User => None,
            };
            let request = JoinRequest {
                node: me.clone(),
                kind: child_kind,
                operator: operator.public(),
                ledger,
                desired_slot,
                location_hint: location,
                nonce: now,
                expiry,
            };
            let mut engine = ControlNode::open(data_dir, &node_id, operator.clone())?;
            engine.begin_outbound_join(request.clone(), parent_id.clone(), pinned_operator)?;
            let signed = SignedControl::authorize(
                me.clone(),
                &operator,
                fresh_nonce(),
                now.saturating_add(CONTROL_REQUEST_TTL_SECS),
                ControlRequest::Join(request),
            )?;
            let reply = match target {
                Some(target) => send_control_addr(&secret_key, target, &signed).await?,
                None => send_control(&secret_key, &parent_id.to_string(), &signed).await?,
            };
            print_reply(&reply);
        }
        ControlCommand::Invite {
            slot,
            expiry,
            label,
            relay,
            ip,
        } => {
            let relay = relay
                .map(|raw| Invite::parse_relay(&raw))
                .transpose()
                .map_err(|err| anyhow::anyhow!("invalid --relay: {err}"))?;
            let ip = ip
                .map(|raw| Invite::parse_ip(&raw))
                .transpose()
                .map_err(|err| anyhow::anyhow!("invalid --ip: {err}"))?;
            let invite = Invite {
                parent: me.clone(),
                operator: operator.public(),
                slot,
                expiry,
                label,
                relay,
                ip,
            };
            invite
                .validate()
                .map_err(|err| anyhow::anyhow!("invalid invite: {err}"))?;
            println!("{}", invite.encode());
            println!("connection invite: share this with a node joining under {node_id}");
        }
        ControlCommand::Joins => {
            let engine = ControlNode::open(data_dir, &node_id, operator)?;
            let pending = engine.pending().pending();
            if pending.is_empty() {
                println!("no pending join requests");
            } else {
                for request in pending {
                    println!(
                        "{} kind={} operator={} slot={} expiry={}",
                        request.node,
                        kind_name(request.kind),
                        request.operator,
                        request
                            .desired_slot
                            .map_or_else(|| "auto".to_string(), |slot| slot.to_string()),
                        request.expiry,
                    );
                }
            }
        }
        ControlCommand::Approve { node, slot } => {
            let mut engine = ControlNode::open(data_dir, &node_id, operator.clone())?;
            // Open the parent's ledger unconditionally: its public key is
            // distributed to the child in the approval (P5a), and for a user
            // applicant the account must be opened BEFORE `approve_pending`
            // consumes the pending row. Otherwise a transient ledger-lock
            // contention error would leave the join half-approved (control
            // state written, account missing) and a retry would report "no
            // pending join". An account for a not-yet-approved user is harmless
            // and idempotent. A node child has its own ledger, so it gets none.
            let applicant_kind = engine
                .pending()
                .pending_for(&NodeId::from(node.clone()))
                .map(|request| request.kind);
            let mut service = LedgerService::open(data_dir, &node_id)?;
            if applicant_kind == Some(ChildKind::User) {
                service.ensure_account_open(&NodeId::from(node.clone()), ChildKind::User)?;
            }
            let parent_ledger = service.ledger_key_public();
            let now = now_unix_seconds();
            let approval = engine.approve_pending(&node, slot, now, parent_ledger)?;
            let signed = SignedControl::authorize(
                me.clone(),
                &operator,
                fresh_nonce(),
                now.saturating_add(CONTROL_REQUEST_TTL_SECS),
                ControlRequest::JoinApproved(approval),
            )?;
            let reply = send_control(&secret_key, &node, &signed).await?;
            print_reply(&reply);
        }
        ControlCommand::Reject { node, reason } => {
            let mut engine = ControlNode::open(data_dir, &node_id, operator.clone())?;
            let nonce = engine
                .pending()
                .pending_for(&NodeId::from(node.clone()))
                .map(|request| request.nonce)
                .unwrap_or(0);
            engine.reject_pending(&node)?;
            let rejection = JoinRejection {
                child: NodeId::from(node.clone()),
                reason: reason.unwrap_or_else(|| "rejected".to_string()),
                nonce,
            };
            let signed = SignedControl::authorize(
                me.clone(),
                &operator,
                fresh_nonce(),
                now_unix_seconds().saturating_add(CONTROL_REQUEST_TTL_SECS),
                ControlRequest::JoinRejected(rejection),
            )?;
            let reply = send_control(&secret_key, &node, &signed).await?;
            print_reply(&reply);
        }
        ControlCommand::CreateChild {
            node,
            child,
            kind,
            operator: child_operator,
            ledger,
            slot,
        } => {
            let request = ControlRequest::CreateChild(CreateChild {
                child: NodeId::from(child),
                operator: parse_operator_pubkey(&child_operator)?,
                ledger: ledger.map(|hex| parse_ledger_pubkey(&hex)).transpose()?,
                kind: kind.into(),
                slot,
                date_joined: now_unix_seconds(),
            });
            send_control_command(&secret_key, &node, me, &operator, request).await?;
        }
        ControlCommand::DetachChild { node, child } => {
            let request = ControlRequest::DetachChild(DetachChild {
                child: NodeId::from(child),
            });
            send_control_command(&secret_key, &node, me, &operator, request).await?;
        }
        ControlCommand::MoveChild { node, child, slot } => {
            let request = ControlRequest::MoveChild(MoveChild {
                child: NodeId::from(child),
                new_parent: NodeId::from(node.clone()),
                slot,
            });
            send_control_command(&secret_key, &node, me, &operator, request).await?;
        }
        ControlCommand::SetAddress { node, address } => {
            let address = address
                .map(|raw| {
                    raw.parse::<OctAddr>()
                        .map_err(|err| anyhow::anyhow!("invalid address '{raw}': {err}"))
                })
                .transpose()?;
            let request = ControlRequest::SetAddress(SetAddress { address });
            send_control_command(&secret_key, &node, me, &operator, request).await?;
        }
        ControlCommand::Query { node } => {
            send_control_command(&secret_key, &node, me, &operator, ControlRequest::Query).await?;
        }
        ControlCommand::Admin { command } => {
            admin_command(data_dir, &node_id, &operator, command)?;
        }
    }
    Ok(())
}

/// Local `control admin grant|revoke|list`, delegating to [`admin_cli`].
fn admin_command(
    data_dir: &std::path::Path,
    node_id: &str,
    operator: &OperatorSecretKey,
    command: AdminCommand,
) -> Result<()> {
    match command {
        AdminCommand::Grant { key, expiry, label } => {
            let admin = parse_operator_pubkey(&key)?;
            let now = now_unix_seconds();
            let outcome = admin_cli::grant(data_dir, node_id, operator, admin, expiry, label, now)
                .map_err(|err| anyhow::anyhow!("{err}"))?;
            println!(
                "granted admin={} scope=admin expires={}",
                outcome.admin, outcome.expiry
            );
            println!("node {node_id}: add this admin key in Settings -> Node administration.");
        }
        AdminCommand::Revoke { key } => {
            let admin = parse_operator_pubkey(&key)?;
            admin_cli::revoke(data_dir, node_id, operator, &admin)
                .map_err(|err| anyhow::anyhow!("{err}"))?;
            println!("revoked admin={admin}");
        }
        AdminCommand::List => {
            let entries = admin_cli::list(data_dir, node_id, operator)
                .map_err(|err| anyhow::anyhow!("{err}"))?;
            if entries.is_empty() {
                println!("no admins");
            } else {
                let now = now_unix_seconds();
                for entry in &entries {
                    println!("{}", entry.render(now));
                }
            }
        }
    }
    Ok(())
}

/// Build, sign, send, and print one control request to `target`.
async fn send_control_command(
    secret_key: &iroh::SecretKey,
    target: &str,
    origin: NodeId,
    operator: &OperatorSecretKey,
    request: ControlRequest,
) -> Result<()> {
    let signed = SignedControl::authorize(
        origin,
        operator,
        fresh_nonce(),
        now_unix_seconds().saturating_add(CONTROL_REQUEST_TTL_SECS),
        request,
    )?;
    let reply = send_control(secret_key, target, &signed).await?;
    print_reply(&reply);
    Ok(())
}

/// Bind a short-lived endpoint, dial `target`, and exchange one control frame.
async fn send_control(
    secret_key: &iroh::SecretKey,
    target: &str,
    signed: &SignedControl,
) -> Result<ControlReply> {
    let target: EndpointId = target
        .parse()
        .map_err(|err| anyhow::anyhow!("invalid endpoint id '{target}': {err}"))?;
    // Sending only needs a bound endpoint; the control ALPN is negotiated with
    // the remote, not registered locally.
    let router = spawn_with_secret_key(secret_key.clone()).await?;
    let reply = ControlNode::send_direct(
        router.endpoint(),
        target,
        signed,
        Duration::from_secs(CONTROL_TIMEOUT_SECONDS),
    )
    .await?;
    router
        .shutdown()
        .await
        .map_err(|err| anyhow::anyhow!("router shutdown: {err}"))?;
    Ok(reply)
}

/// Like [`send_control`], but dials an explicit [`iroh::EndpointAddr`] carrying
/// transport hints (from an invite's `relay`/`ip`), bypassing address lookup.
async fn send_control_addr(
    secret_key: &iroh::SecretKey,
    target: iroh::EndpointAddr,
    signed: &SignedControl,
) -> Result<ControlReply> {
    let router = spawn_with_secret_key(secret_key.clone()).await?;
    let reply = ControlNode::send_direct_addr(
        router.endpoint(),
        target,
        signed,
        Duration::from_secs(CONTROL_TIMEOUT_SECONDS),
    )
    .await
    .map_err(|err| anyhow::anyhow!("direct control to invite hints failed: {err}"))?;
    router
        .shutdown()
        .await
        .map_err(|err| anyhow::anyhow!("router shutdown: {err}"))?;
    Ok(reply)
}

fn print_reply(reply: &ControlReply) {
    match reply {
        ControlReply::Accepted => println!("accepted"),
        ControlReply::Pending => println!("pending"),
        ControlReply::Rejected(code) => println!("rejected: {code:?}"),
        ControlReply::Snapshot(snapshot) => print_snapshot(snapshot),
        ControlReply::AdminSnapshot(snapshot) => print_admin_snapshot(snapshot),
        ControlReply::AdminApproved(approved) => println!(
            "admin-approved: child={} slot={} address={} delivery={:?}",
            approved.child, approved.slot, approved.address, approved.delivery
        ),
        ControlReply::AdminRejected(rejected) => {
            println!(
                "admin-rejected: child={} delivery={:?}",
                rejected.child, rejected.delivery
            )
        }
    }
}

fn print_admin_snapshot(snapshot: &cawala_control::AdminSnapshot) {
    print_snapshot(&snapshot.node);
    if snapshot.pending.is_empty() {
        println!("pending: (none)");
    } else {
        for pending in &snapshot.pending {
            println!(
                "pending: {} kind={} operator={} slot={} expiry={}",
                pending.child,
                kind_name(pending.kind),
                pending.operator,
                pending
                    .desired_slot
                    .map_or_else(|| "auto".to_string(), |slot| slot.to_string()),
                pending.expiry,
            );
        }
    }
}

fn print_snapshot(snapshot: &cawala_control::NodeSnapshot) {
    println!("node_id: {}", snapshot.node_id);
    match &snapshot.address {
        Some(address) => println!("address: {address}"),
        None => println!("address: none"),
    }
    match &snapshot.parent {
        Some(parent) => println!(
            "parent: {} slot {} address {}",
            parent.node_id, parent.slot, parent.address
        ),
        None => println!("parent: none"),
    }
    if snapshot.children.is_empty() {
        println!("children: (none)");
    } else {
        for child in &snapshot.children {
            println!(
                "child: {} kind={} slot={} address={} joined={}",
                child.child_id,
                kind_name(child.kind),
                child.slot,
                child
                    .address
                    .as_ref()
                    .map_or_else(|| "none".to_string(), |address| address.to_string()),
                child.date_joined,
            );
        }
    }
}

fn parse_operator_pubkey(raw: &str) -> Result<OperatorPubKey> {
    let bytes = parse_hex32(raw, "operator")?;
    OperatorPubKey::from_bytes(&bytes).map_err(|err| anyhow::anyhow!("invalid operator key: {err}"))
}

fn parse_ledger_pubkey(raw: &str) -> Result<LedgerPubKey> {
    let bytes = parse_hex32(raw, "ledger")?;
    LedgerPubKey::from_bytes(&bytes).map_err(|err| anyhow::anyhow!("invalid ledger key: {err}"))
}

fn parse_hex32(raw: &str, label: &str) -> Result<[u8; 32]> {
    let bytes = decode_hex(raw)?;
    bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "{label} key must be exactly 32 bytes (64 hex digits), found {}",
            bytes.len()
        )
    })
}

/// Join requests expire this long after creation.
const JOIN_TTL_SECONDS: u64 = 3600;

/// Per-request direct-control deadline.
const CONTROL_TIMEOUT_SECONDS: u64 = 15;

/// Parse a `ID=ADDR` next-hop hint.
///
/// `ID` is the neighbor's node id (an iroh `EndpointId`, hex or base32) and is
/// returned in canonical `Display` form so hint keys match the canonical ids
/// stored by [`RoutableSnapshot::from_record`]. `ADDR` is a comma-separated
/// transport list where each entry is one of `ip:HOST:PORT`, `relay:URL`, or
/// `custom:<id>_<hex>`; an empty `ADDR` means "id only" (rely on address
/// lookup).
fn parse_hint(raw: &str) -> Result<(String, iroh::EndpointAddr)> {
    let (id_str, addr_str) = raw
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("hint '{raw}' must be ID=ADDR"))?;
    let id: iroh::EndpointId = id_str
        .parse()
        .map_err(|err| anyhow::anyhow!("hint id '{id_str}' is not an EndpointId: {err}"))?;

    let mut addrs: Vec<iroh::TransportAddr> = Vec::new();
    if !addr_str.trim().is_empty() {
        for part in addr_str.split(',') {
            let part = part.trim();
            let transport = if let Some(rest) = part.strip_prefix("ip:") {
                iroh::TransportAddr::Ip(
                    rest.parse()
                        .map_err(|err| anyhow::anyhow!("invalid ip transport '{rest}': {err}"))?,
                )
            } else if let Some(rest) = part.strip_prefix("relay:") {
                iroh::TransportAddr::Relay(
                    rest.parse().map_err(|err| {
                        anyhow::anyhow!("invalid relay transport '{rest}': {err}")
                    })?,
                )
            } else if let Some(rest) = part.strip_prefix("custom:") {
                iroh::TransportAddr::Custom(
                    rest.parse().map_err(|err| {
                        anyhow::anyhow!("invalid custom transport '{rest}': {err}")
                    })?,
                )
            } else {
                anyhow::bail!("hint transport '{part}' must start with ip:, relay:, or custom:");
            };
            addrs.push(transport);
        }
    }

    let addr = iroh::EndpointAddr::from_parts(id, addrs);
    Ok((id.to_string(), addr))
}

/// Decode a hex string (whitespace ignored) into bytes.
fn decode_hex(input: &str) -> Result<Vec<u8>> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if !cleaned.len().is_multiple_of(2) {
        anyhow::bail!("hex payload must have an even number of digits");
    }
    if !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("hex payload contains a non-hex character");
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16)
                .map_err(|err| anyhow::anyhow!("invalid hex byte at offset {i}: {err}"))
        })
        .collect()
}
