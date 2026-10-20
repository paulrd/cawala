# HOTCP-0: Routed Octal Tree Substrate

**Version:** 0.2
**Status:** Draft Specification

---

## 1. Overview

HOTCP-0 is a peer-to-peer message routing substrate operating over a rooted tree topology. Nodes are addressed by octal strings using digits `0`–`7`. The substrate provides hop-by-hop forwarding of opaque payloads between any two addresses in the tree.

HOTCP-0 knows nothing about the meaning of the payloads it routes. It provides:
- A deterministic addressing scheme
- A routing rule for computing the next hop from `origin` and `destination`
- A message envelope format with a `content_type` field for application dispatch
- A signature chain for tamper-evidence
- Optional privacy extensions (truncation, onion wrapping)

Applications built on HOTCP-0 (such as HOTCP-1, the hierarchical clearing protocol) declare a `content_type` and register a handler for it.

### 1.1 Design Goals
- **Local knowledge**: each node knows only its parent, its children, and its own address.
- **Local routing**: the next hop is a pure function of the node's own address, the `origin`, and the `destination`.
- **Minimal state**: peer addresses are derivable from the node's own address; only peer handles and application state need storage.
- **Extensibility**: multiple applications can coexist on the same substrate, dispatched by `content_type`.

### 1.2 Non-Goals
- Reliable end-to-end delivery (only best-effort hop-by-hop)
- Ordered delivery across hops
- Confidentiality of payloads (see optional privacy extensions)
- Application-level atomicity (an application-layer concern)

---

## 2. Topology and Addressing

### 2.1 Tree Structure
- The tree has a single **root** node.
- Every non-root node has exactly one **parent**.
- Every node has at most **B** children, where `B` is the branching factor.
- For HOTCP-0, the default branching factor is **8**, and child indices are the octal digits `0`–`7`.
- Leaf nodes have zero children.

### 2.2 Octal Addressing
Each node is identified by an octal string using digits `0`–`7`, representing its path from the root.

| Node | Address |
|------|---------|
| Root | `0` |
| Root's first child | `00` |
| Root's second child | `01` |
| Root's eighth child | `07` |
| First child of node `01` | `010` |
| Eighth child of node `01` | `017` |

**Derived properties:**
- **Parent address**: the address with the last digit removed. `parent("012") = "01"`.
- **Depth**: the length of the address. `depth("012") = 3`.
- **Root**: the unique address with `depth(A) == 1`, i.e. `0`. It has no parent.
- **LCA(A, B)**: the longest common prefix of A and B. `LCA("012", "014") = "01"`.
- **Ancestor test**: A is an ancestor of B iff A is a prefix of B.
- **Child address**: `child_address(A, d) = A + d` where `d` is an octal digit `0`–`7`.
- **Child lookup on path**: the child of address `A` on the path to `D` is the prefix of `D` of length `depth(A) + 1`. The child index is the last digit of that prefix.

### 2.3 Child Index
Each child is indexed by a single octal digit `0`–`7`. A parent stores a peer handle for each existing child in its `connections` map. The set of keys in `connections` defines which children exist.

---

## 3. Routing

### 3.1 Routing Decision
Every node that receives a message computes its routing decision from `origin` and `destination` alone. Let `A` be the receiving node's address.

Let `L = LCA(origin, destination)`.

| Condition | Role | Action |
|-----------|------|--------|
| `A == destination` | Destination | Dispatch payload to the handler registered for `content_type` |
| `A == L` | Turning point | Forward to child on path to `destination` |
| `A` is a proper prefix of `origin` and `A != L` | Intermediate upward | Forward to parent |
| `A` is a proper prefix of `destination` and `A != L` | Intermediate downward | Forward to child on path to `destination` |
| `A == origin` | Origin | Forward toward turning point (upward if `A != L`, downward if `A == L`) |
| otherwise | Unreachable | Drop the message and emit a `ROUTING_ERROR` event |

### 3.2 Next Hop Computation
- **Upward**: the next hop is `parent(A)`, obtained by dropping the last octal digit of `A`.
- **Downward**: the next hop is the child of `A` on the path to `destination`, obtained as the prefix of `destination` of length `depth(A) + 1`. The child index is the last digit of that prefix.

Both computations are O(1).

### 3.3 Why This Works
In a tree with octal addressing, the unique path between any two nodes is fully determined by their addresses. The LCA is the longest common prefix. Every node on the path can determine, from its own address alone, whether it is above, at, or below the LCA, and in which direction the message must travel. No path information needs to be carried in the message.

### 3.4 Delivery Semantics
- **Best-effort**: the substrate makes no guarantee that a message will reach its destination.
- **At-most-once per hop**: a node forwards a message at most once per receipt. Duplicate `envelope_id`s are dropped.
- **No global ordering**: messages may arrive out of order at the destination. Applications that require ordering must impose it themselves.

### 3.5 Content-Type Dispatch
When an envelope reaches its destination, HOTCP-0 dispatches the `payload` to the handler registered for the envelope's `content_type`. If no handler is registered, HOTCP-0 emits an `UNHANDLED_CONTENT_TYPE` event and drops the payload. Intermediate nodes do not inspect `content_type`; they forward the envelope unchanged.

---

## 4. Message Envelope

### 4.1 Envelope Format
All messages are JSON objects. The envelope is:

```json
{
  "type": "ENVELOPE",
  "envelope_id": "uuid-v4-string",
  "origin": "012",
  "destination": "014",
  "content_type": "application/hotcp-1+json",
  "ttl": 64,
  "payload": "base64-encoded-opaque-bytes",
  "created_at": 1699999999,
  "signatures": [
    {
      "node": "012",
      "sig": "hex-encoded-signature"
    }
  ]
}
```

**Fields:**
- `envelope_id`: unique identifier for idempotency and deduplication.
- `origin`, `destination`: octal addresses using digits `0`–`7`.
- `content_type`: a MIME-like string identifying the application that should handle the payload at the destination. Intermediate nodes do not interpret this field.
- `ttl`: time-to-live in hops. Decremented by 1 at each hop. If it reaches 0, the message is dropped.
- `payload`: opaque bytes. The substrate does not interpret this field.
- `created_at`: Unix timestamp (advisory).
- `signatures`: accumulated per-hop signatures, one entry per hop that has forwarded the envelope.

### 4.2 Content-Type Registration
Applications register handlers with HOTCP-0:

```
register_handler(content_type, handler) -> void
unregister_handler(content_type) -> void
```

A handler is a function that receives an envelope when the local node is its destination. Multiple applications may be registered simultaneously. The `content_type` string is the dispatch key.

### 4.3 Signature Chain
Each hop that forwards an envelope:
1. Verifies the previous hop's signature.
2. Appends its own signature, covering `envelope_id`, `origin`, `destination`, `content_type`, `ttl`, a hash of `payload`, and the previous hop's signature.

The signature chain does not protect the payload from being read by intermediate nodes — only from being modified. For payload confidentiality, see Section 7.

### 4.4 Deduplication
Each node maintains a bounded set of recently seen `envelope_id`s. An envelope whose `envelope_id` is already in the set is dropped silently.

---

## 5. State

Each node maintains the following state:

### 5.1 Persistent State
```
address: string                       // octal address using digits 0-7
connections: map<octal_digit, peer>   // up to 8 entries, keys 0-7
handlers: map<content_type, handler>  // registered application handlers
recent_envelopes: set<envelope_id>    // bounded, for deduplication
```

The parent address and child addresses are not stored. They are computed:
- `parent(A) = A` with the last digit removed, if `depth(A) > 1`
- `child_address(A, d) = A + d`
- The root is the unique address with `depth(A) == 1`

The `connections` map stores, for each existing child index, whatever peer information is needed to communicate with that child (public key, network address, or connection handle). The set of keys in `connections` defines which children exist.

### 5.2 Transient State
```
pending_forwards: map<envelope_id, ForwardState>
```

Used for timeout handling and retry if the application layer requests it.

---

## 6. Interface to the Application Layer

HOTCP-0 exposes the following to applications built on top of it:

### 6.1 Topology Queries (Pure Functions)
```
parent(A) -> address | null
child_address(A, d) -> address
depth(A) -> integer
lca(A, B) -> address
is_ancestor(A, B) -> boolean
next_hop_up(A) -> address
next_hop_down(A, destination) -> address
```

These are pure functions of the address algebra. They require no I/O and no state.

### 6.2 Routing Primitives
```
send(destination, content_type, payload) -> envelope_id
on_receive(envelope) -> event
```

`send` constructs an envelope with `origin` set to the local address, signs it, and forwards it toward `destination`. `on_receive` is called by the substrate when the local node is the destination of an envelope whose `content_type` matches a registered handler.

### 6.3 Peer Management
```
add_child(digit, peer) -> void
remove_child(digit) -> void
```

### 6.4 Handler Registration
```
register_handler(content_type, handler) -> void
unregister_handler(content_type) -> void
```

### 6.5 Events
```
on_delivery(envelope) -> void        // envelope reached its destination
on_forward(envelope, next_hop) -> void  // envelope was forwarded
on_drop(envelope, reason) -> void    // envelope was dropped (TTL, unreachable, unhandled content type)
on_peer_change(digit, event) -> void // child added or removed
```

Applications subscribe to these events to implement their own semantics.

---

## 7. Optional Privacy Extensions

### 7.1 Truncated Addressing
Implementations MAY support truncated addressing. When enabled, the `origin` and `destination` fields are omitted from the envelope, and the envelope carries only hop counts and downward child-index information. Each hop learns only its local role and next hop.

The envelope in truncated mode:
```json
{
  "type": "ENVELOPE",
  "envelope_id": "uuid-v4-string",
  "content_type": "application/hotcp-1+json",
  "upward_hops": 2,
  "downward_hops": 3,
  "downward_digits": ["0", "1", "4"],
  "ttl": 64,
  "payload": "base64-encoded-opaque-bytes",
  "signatures": [...]
}
```

Note that `content_type` is still visible to intermediate nodes in this mode. If content-type privacy is required, it must be carried inside the encrypted payload instead, with a generic content type (e.g., `application/octet-stream`) at the envelope level.

### 7.2 Onion Wrapping
Implementations MAY support onion wrapping, where each layer of the envelope is encrypted to the next hop's public key. This hides `origin`, `destination`, `content_type`, and the payload from intermediate nodes. The cost is public-key operations per hop and a key-discovery mechanism.

### 7.3 Threat Model
Truncation hides absolute addresses but not content type or relative position. Onion wrapping hides both. Neither hides timing.

---

## 8. Performance Characteristics

| Metric | Value |
|--------|-------|
| Message complexity | `O(depth(origin) + depth(destination))` |
| State per node | `O(children)` for connections, `O(handlers)` for content types, `O(recent)` for deduplication |
| Path length (balanced tree, N nodes, branching B) | `O(log_B N)` |
| Routing decision cost | O(1) per hop |
| Message size | O(1) addresses + O(1) content type + O(signatures) |

For a tree of depth 10 with branching factor 8 (8^10 ≈ 1 billion nodes), a message crosses at most 20 hops.

---

## 9. Security Considerations

### 9.1 Signatures
Every hop signs the envelope with its private key. The signature covers `envelope_id`, `origin`, `destination`, `content_type`, `ttl`, a hash of `payload`, and the previous hop's signature.

### 9.2 Routing Integrity
Because `origin`, `destination`, and `content_type` are signed and the routing decision is a deterministic function of the addresses, a malicious intermediate node cannot misroute a message without detection.

### 9.3 Replay Protection
- `envelope_id` is unique per message.
- Each node tracks recently seen `envelope_id`s and rejects duplicates.
- Timestamps are advisory; the signature chain is authoritative.

### 9.4 Content-Type Integrity
Because `content_type` is included in the signature chain, a malicious intermediate node cannot change the content type without detection. The destination dispatches only to the registered handler for the signed content type.

### 9.5 Denial of Service
- Rate-limit incoming envelopes per peer.
- Enforce TTL to bound forwarding.
- Prune `recent_envelopes` and `pending_forwards` after timeout.
- Cap the number of registered handlers per node.

### 9.6 Privacy
By default, every hop on the path learns `origin`, `destination`, and `content_type`. Optional extensions (Section 7) mitigate this.

---

## 10. Open Questions and Future Work

1. **Peer discovery**: how does a node learn the peer handle for a child index?
2. **Churn handling**: what happens when a child disconnects? How are in-flight messages handled?
3. **Branching factor configurability**: should `B` be a parameter or fixed at 8?
4. **Message ordering**: should the substrate offer per-hop ordering guarantees?
5. **Cross-tree routing**: what if `origin` and `destination` are in different trees?
6. **Key discovery for onion wrapping**: how does the origin learn the public keys of path nodes?
7. **Content-type versioning**: should content types carry version suffixes (e.g., `application/hotcp-1+json;v=1`)?

---

## 11. Summary

HOTCP-0 is a minimal routed-tree substrate that:
- Uses **octal addressing with digits 0–7** for O(1) parent/LCA computation.
- Routes messages **locally at each hop** from `origin` and `destination` alone.
- Stores only **peer connections and handler registrations**, deriving all addresses from the node's own address.
- Carries **opaque payloads** with a `content_type` field for application dispatch.
- Maintains a **tamper-evident signature chain** covering routing and content type.
- Offers **optional privacy extensions** for truncated addressing and onion wrapping.
- Exposes a **clean interface** to application layers.

Applications such as HOTCP-1 (Hierarchical Octal Tree Clearing Protocol) build their semantics on top of this substrate without modifying it.