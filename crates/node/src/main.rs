use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use cawala_ledger::AccountRef;
use cawala_node::{
    MsgConfig, RoutableSnapshot, build_envelope, identity, ledger_keys, ledger_store, record,
    send_envelope, spawn_msg_node, spawn_with_secret_key,
};
use cawala_topology::OctAddr;
use clap::{Parser, Subcommand, ValueEnum};
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
    }
}

/// Load identity + record, bind the endpoint, print the endpoint id, serve
/// forever.
async fn run(data_dir: PathBuf) -> Result<()> {
    let secret_key = identity::load_or_create_secret_key(&data_dir)?;
    let node_id = secret_key.public().to_string();
    let store = record::RecordStore::open(&data_dir, &node_id)?;
    store.save()?;

    if let Some(address) = store.record().address.clone() {
        let snapshot = RoutableSnapshot::from_record(store.record())?;

        // Must stay alive for the accept loop; dropped at process exit.
        let (_router, mut received) =
            spawn_msg_node(secret_key, snapshot, MsgConfig::default()).await?;
        info!(endpoint_id = %node_id, %address, "node endpoint bound with messaging");
        println!("EndpointId: {node_id}");
        println!("Address: {address}");
        println!("Serving cawala/ping/0 and cawala/msg/0");

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

    // No asserted address: routing is impossible, so serve ping only.
    let _router = spawn_with_secret_key(secret_key).await?;
    info!(endpoint_id = %node_id, "node endpoint bound (ping only)");
    println!("EndpointId: {node_id}");
    eprintln!(
        "warning: node has no asserted address; messaging disabled. \
         Run `cawala-node topo set-address <ADDR>`."
    );
    println!(
        "Run the web client to ping this node, or check the round-trip with: cargo test -p cawala-node"
    );

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
