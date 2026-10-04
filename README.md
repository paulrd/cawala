# Project Overview
  **Cawala** is a modernized Hawala alternative. Value is transmitted, created and
   destroyed by sending messages to other sovereign nodes that are organized
   into a hierarchical network based primarily on geographical region.

# Terminology
  Cawala separates a node's **identity** from its **location**. "Address" is
  overloaded across the stack, so it is always qualified when it matters.
  - **Node**: a running `cawala-node` process with its own data directory,
    identity key, topology links, and ledger.
  - **Leaf node**: a node whose children are users - the only node kind a
    browser talks to. A node with node children is *internal*.
  - **User**: a leaf account holder (a browser client); a `ChildKind::User`
    with an operator key but no ledger of its own.
  - **Designated administrator**: a current child of a node (of **any** kind -
    child node or browser user) listed in that node's persisted designation set
    (see `admin_state.json` below). Designation is the only source of
    administration rights; there is no grant, scope, priority, or seniority.
  - **EndpointId** (Iroh): the node's Ed25519 public identity key rendered as a
    string. Stable and immutable; used to authenticate the peer.
  - **NodeId**: Cawala/ledger name for that same identity string (an
    EndpointId). The key in the peer registry (`PeerKeys.node_id`).
  - **EndpointAddr** (Iroh): how to dial a peer **now** - an EndpointId plus
    transport addresses (relay URL and/or direct IP:port). Changes over time;
    it is not an identity.
  - **Octal address** (`OctAddr`): the node's position in the tree - dotted
    octal digits, e.g. `0.3.5.2`; root is `0`; one digit per level. Used for
    routing, and changes when a node is moved or re-slotted.
  - **Slot**: the last octal digit of an address; a node's position among its
    parent's children (`0..=7`).
  - **Depth**: number of digits (tree levels). The root has depth 1; there is no
    hard depth cap.
  - **Parent / child**: topology links. A node holds one parent link and up to 8
    child links; users are always leaves.
  - **LCA**: least common ancestor - the longest shared address prefix, and the
    settlement point for cross-subtree payments.
  - **Envelope**: the M3 wire message - `src: PeerRef { node, addr }`,
    `dst: OctAddr`, `msg_id`, `msg_type`, `nonce`, `ttl`, `payload`,
    `hop_chain`.
  - **Operator key**: Ed25519 key that authorises control and intent; distinct
    from the ledger key.
  - **Ledger key**: Ed25519 key that signs ledger entries and commitments; it
    never leaves the node.
  - **Control message**: an operator-signed request (join, topology edit,
    query, designation, value). The direct `cawala/control/0` ALPN carries the
    join handshake and a browser's exchanges with its own leaf; all
    administration of a node other than that direct link is **tree-routed**
    hop by hop (`MSG_CONTROL_V1`).
  - **Address lookup** (Iroh discovery): given only an EndpointId, Iroh
    resolves it to an EndpointAddr through the configured lookup service
    (pkarr/DNS under the N0 preset). An invite's optional `relay`/`ip`
    transport hints supply the address directly, so no lookup service is
    needed.
  - **Invite**: out-of-band onboarding code -
    `cawala://join?parent=<EndpointId>&op=<operator>[&slot&exp&label][&relay&ip]`.
    `relay`/`ip` are transport hints that let the joiner dial the parent
    without an address-lookup service.
  - **Location service**: optional, non-authoritative hint service (lat/lon or
    map click -> suggested octal address). Out of scope for M4; it never
    issues the final address.

  Protocol ALPNs: `cawala/ping/0` (M0 health check), `cawala/msg/0` (M3
  envelope routing), `cawala/control/0` (direct signed control - join handshake
  and a browser's own leaf). Administration is routed inside `cawala/msg/0`.

  Key rule: **identity is immutable; address is mutable.** Both travel together
  in an M3 envelope (`node` = EndpointId, `addr` = octal address).

# Goals and Non-Goals
## Goals
  - Use decentralized technology (Iroh) to allow users to easily deploy their
    own nodes and to allow web clients and nodes to communicate securely.
  - Mitigate risks by only communicating with a small number of connected nodes
    and make it easy for nodes to join, leave or move based on trust and
    reliability.
  - Re-use the hierarchical nature of the network and communal control of nodes
    to encourage communication and coordination between communities at varying
    population and geographical scales.
  - Provide some level of anonymity via restricting the kind of data that gets
    transmitted between nodes.
  - Users will interact with node primarily through web clients that has Iroh
    WASM modules.
  - Nodes will be regular Iroh nodes written in the rust language.
## Non-Goals
  - Cawala nodes do not provide Zero Trust computing and as such each node can
    see data that it holds.
  - Cawala doesn't support running nodes on phones.
# Target Users
  Cawala lets you transfer, create and destroy liabilities (IOU's). It creates a
  network of communities based on trust whose tangible and intangible assets
  back the creation of all liabilities.
# Features / Functional Requirements
  - deploy a web client with WASM Iroh module as a static PWA on github pages
  - nodes are built using the Rust language and Iroh.
  - project is open-source MIT License.
  - each node is small and light-weight instance of an Iroh node
  - each node only communicates with its parent node or up to 8 child nodes.
  - web clients only communicate with leaf nodes (their direct parent).
  - leaf nodes can have up to 8 users
  - each node keeps an explicit set of **designated administrator children** in
    `<data-dir>/admin_state.json`; a designated child of any kind (child node
    or browser user) may administer the node, and all designated administrators
    have equal, full rights. There is no senior child, priority, grant, or scope.
  - all administration is **tree-routed** hop by hop; a browser reaches an
    ancestor only while each link on the path designates the next child. The
    local CLI (`control admin add|remove|list`) is the universal fallback.
  - the web client administers its leaf node and the ancestors reachable from
    it; the Admin page is locked by default behind a policy acknowledgement
    (`ADMIN_POLICY.md`) and switches target with up/down over the ancestor
    chain.
  - more than one node can be deployed to the same server
  - nodes can be deployed on almost any device
  - each node and user will have an octal address that will allow their position
    in the tree to be known so that payments or messages can be routed.
  - a separate SQLITE database can be queried that can suggest the appropriate
    octal address for a given user's location.
  - Accounts are double-entry: the account a node holds for a child is a
    **liability** of that node and simultaneously an **asset** of the child - one
    signed obligation with two viewpoints, mirrored on both ledgers.
  - An internal node holds up to 8 accounts, one for each of its child nodes; a
    leaf node holds up to 8 accounts for its users. Every non-root node also
    holds exactly one asset account with its parent.
  - Per-node accounting equation: Assets (the account with the parent) minus
    Liabilities (accounts held for children/users) equals Equity. Transfers post
    to two accounts and conserve value; only signed issue/burn entries change a
    node's equity.
  - A designated administrator (or the local operator) can issue/burn value on
    an account (posted against the node's equity), bounded by the operator-side
    `value_policy.json`; the browser never holds the node's operator or ledger
    key.
# Constraints
  - tech stack is Iroh, Rust, Typescript, Virtual Private Servers
# Open Questions
  - How do we allow nodes to split so that an already full node can get a new
    user or child node?
  - What other out-of-band services might be required? Some of these might be:
    - How do people learn about Cawala?
    - How does a Cawala user introduce a new user to the network so they can
      receive or send a payment?
