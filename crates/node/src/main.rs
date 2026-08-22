use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use cawala_node::{identity, record, spawn_with_secret_key};
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
    }
}

/// Load identity + record, bind the endpoint, print the endpoint id, serve
/// forever.
async fn run(data_dir: PathBuf) -> Result<()> {
    let secret_key = identity::load_or_create_secret_key(&data_dir)?;
    let node_id = secret_key.public().to_string();
    let store = record::RecordStore::open(&data_dir, &node_id)?;
    store.save()?;

    // Must stay alive for the accept loop; dropped at process exit.
    let _router = spawn_with_secret_key(secret_key).await?;
    info!(endpoint_id = %node_id, "node endpoint bound");
    println!("EndpointId: {node_id}");
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
    println!("EndpointId: {node_id}");
    println!("identity and node record are ready in {}", data_dir.display());
    Ok(())
}

/// Topology link inspection and mutation.
fn topo(data_dir: &std::path::Path, command: TopoCommand) -> Result<()> {
    let secret_key = identity::load_or_create_secret_key(data_dir)?;
    let node_id = secret_key.public().to_string();
    let mut store = record::RecordStore::open(data_dir, &node_id)?;

    match command {
        TopoCommand::Show => show(&store),
        TopoCommand::AttachChild { child, kind, slot, date_joined } => {
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
    }
    Ok(())
}

fn show(store: &record::RecordStore) {
    let rec = store.record();
    println!("node_id: {}", rec.node_id);
    match &rec.parent {
        Some(parent) => println!("parent: {{ parent_id: {}, slot: {} }}", parent.parent_id, parent.slot),
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
