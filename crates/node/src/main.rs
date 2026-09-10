use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use cawala_control::{
    ChildKind, ControlReply, ControlRequest, CreateChild, DetachChild, Invite, JoinRejection,
    JoinRequest, MoveChild, NodeId, OperatorPubKey, OperatorSecretKey, SetAddress, SignedControl,
};
use cawala_ledger::{AccountRef, LedgerPubKey};
use cawala_node::{
    ControlNode, MsgConfig, RoutableSnapshot, build_envelope, identity, ledger_keys, ledger_store,
    record, send_envelope, spawn_control_node, spawn_control_only, spawn_with_secret_key,
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
    let secret_key = identity::load_or_create_secret_key(&data_dir)?;
    let node_id = secret_key.public().to_string();
    let store = record::RecordStore::open(&data_dir, &node_id)?;
    store.save()?;

    let operator = OperatorSecretKey::from_bytes(secret_key.to_bytes());
    let control = Arc::new(Mutex::new(ControlNode::open(
        &data_dir, &node_id, operator,
    )?));

    if let Some(address) = store.record().address.clone() {
        let snapshot = RoutableSnapshot::from_record(store.record())?;

        // Must stay alive for the accept loop; dropped at process exit.
        let (_router, mut received) =
            spawn_control_node(secret_key, snapshot, MsgConfig::default(), control).await?;
        info!(endpoint_id = %node_id, %address, "node endpoint bound with messaging + control");
        println!("EndpointId: {node_id}");
        println!("Address: {address}");
        println!("Serving cawala/ping/0, cawala/msg/0, and cawala/control/0");

        // Log envelopes delivered locally at this node.
        tokio::spawn(async move {
            while let Some(env) = received.recv().await {
                info!(
                    src = %env.src.node,
                    msg_type = env.msg_type,
                    payload_len = env.payload.len(),
                    msg_id = %env.msg_id.to_hex(),
                    "received message"
                );
            }
        });

        // Await forever; dropping `router` would abort the accept loop.
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
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
            let ledger = ledger_store::open_ledger(data_dir, &node_id, &ledger_key)?;
            show_ledger(&node_id, &ledger);
        }
        LedgerCommand::Verify => match ledger_store::open_ledger(data_dir, &node_id, &ledger_key) {
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
        },
    }
    Ok(())
}

fn show_ledger(node_id: &str, ledger: &cawala_ledger::Ledger<ledger_store::FileLog>) {
    println!("node_id: {node_id}");
    println!("ledger_id: {}", ledger.ledger_id());
    println!("entries: {}", ledger.len());
    println!("height: {}", ledger.height());
    println!("head: {}", ledger.head_hash());
    println!("balances:");
    for (account, balance) in ledger.balances().accounts() {
        println!("  {}: {balance}", account_name(&account));
    }
}

fn account_name(account: &AccountRef) -> String {
    match account {
        AccountRef::Parent => "parent".to_string(),
        AccountRef::Child(id) => format!("child:{id}"),
        AccountRef::Equity => "equity".to_string(),
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
            let signed =
                SignedControl::authorize(me.clone(), &operator, ControlRequest::Join(request))?;
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
            let approval = engine.approve_pending(&node, slot, now_unix_seconds())?;
            let signed = SignedControl::authorize(
                me.clone(),
                &operator,
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
    let signed = SignedControl::authorize(origin, operator, request)?;
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
