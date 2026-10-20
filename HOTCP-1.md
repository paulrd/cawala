# HOTCP-1: Hierarchical Clearing Application

**Version:** 0.3
**Status:** Draft Specification
**Depends on:** HOTCP-0 (Routed Octal Tree Substrate)

---

## 1. Overview

HOTCP-1 is an application layer built on HOTCP-0. It defines a peer-to-peer payment protocol operating over a rooted tree topology. Payments are routed hop-by-hop along the unique tree path between source and destination, settling through the Least Common Ancestor (LCA). Liability is defined as **what a parent owes its child**, and is tracked per child by each parent.

HOTCP-1 registers a handler for the content type `application/hotcp-1+json` with HOTCP-0 and uses the substrate for addressing, routing, and message delivery. It does not modify the substrate.

### 1.1 Design Goals
- **Atomicity**: a payment either completes fully or is rolled back completely.
- **Non-negativity**: no liability value may become negative.
- **Local knowledge**: each node knows only its parent, its children, and its own liability table.
- **Application-level signatures**: HOTCP-1 signs payment intent independently of HOTCP-0's forwarding signatures.

### 1.2 Dependencies on HOTCP-0
HOTCP-1 relies on the following from HOTCP-0:
- The address algebra: `parent(A)`, `child_address(A, d)`, `depth(A)`, `lca(A, B)`, `is_ancestor(A, B)`, `next_hop_up(A)`, `next_hop_down(A, destination)`
- Routing primitives: `send(destination, content_type, payload)`, `on_receive(envelope)`
- Peer management: `add_child(digit, peer)`, `remove_child(digit)`
- Handler registration: `register_handler(content_type, handler)`
- Events: `on_delivery`, `on_forward`, `on_drop`, `on_peer_change`
- The envelope format and signature chain

HOTCP-1 does **not** rely on:
- Any guarantee of end-to-end atomicity
- Any guarantee of ordering across hops
- Any interpretation of the `payload` field by the substrate

---

## 2. Content Type

HOTCP-1 registers the content type:

```
application/hotcp-1+json
```

All HOTCP-1 messages are JSON objects carried as the `payload` of HOTCP-0 envelopes. The `content_type` field of the envelope is set to this string. Intermediate nodes forward the envelope without interpreting the payload.

---

## 3. Liability Model

### 3.1 Definition
For a parent `P` and child `C`, the **liability** `L(P, C)` is the amount that `P` owes to `C`. It is a non-negative integer.

### 3.2 Invariants
1. `L(P, C) >= 0` for all parent-child pairs.
2. A parent's liability table contains exactly one entry per existing child.
3. When a child is added, its liability starts at 0.
4. When a child is removed, its liability must be 0 (settled).

### 3.3 Settlement
Liability represents an unsettled obligation. Out-of-band settlement reduces liability to zero. HOTCP-1 only tracks liability; it does not perform the underlying value transfer.

---

## 4. Payment Semantics

### 4.1 Definitions
- **Source** `S`: the node initiating the payment.
- **Destination** `D`: the node receiving the payment.
- **Amount** `X`: a positive integer.
- **LCA** `L = LCA(S, D)`.

### 4.2 Effect of a Payment
A payment of `X` from `S` to `D`:

**Upward phase (from S up to, but not including, L):**
For each node `U` on the path from `S` upward to (but not including) `L`:
- `L(parent(U), U) -= X`

**Downward phase (from L down to, but not including, D):**
For each node `W` on the path from `L` downward to (but not including) `D`:
- `L(parent(W), W) += X`

### 4.3 Net Effect
- The chain of obligations from S up to L is reduced by X.
- A new chain of obligations from L down to D is increased by X.
- The total liability along the full path S→L→D changes consistently.

### 4.4 Validity Conditions
A payment is valid only if:
1. `X > 0`.
2. Both `S` and `D` exist in the tree.
3. For every node `U` on the upward path (excluding L), `L(parent(U), U) >= X`.

---

## 5. Message Types

HOTCP-1 messages are carried as the `payload` of HOTCP-0 envelopes with `content_type = application/hotcp-1+json`. Each message is a JSON object.

### 5.1 PAYMENT
```json
{
  "type": "PAYMENT",
  "payment_id": "uuid-v4-string",
  "source": "012",
  "destination": "010",
  "amount": 100,
  "created_at": 1699999999,
  "app_signatures": [
    {
      "node": "012",
      "phase": "upward",
      "sig": "hex-encoded-signature"
    }
  ]
}
```

### 5.2 ACK
```json
{
  "type": "ACK",
  "payment_id": "uuid-v4-string",
  "node": "01",
  "phase": "upward",
  "sig": "hex-encoded-signature"
}
```

### 5.3 COMMIT
```json
{
  "type": "COMMIT",
  "payment_id": "uuid-v4-string",
  "app_signatures": []
}
```

### 5.4 ROLLBACK
```json
{
  "type": "ROLLBACK",
  "payment_id": "uuid-v4-string",
  "reason": "insufficient_liability",
  "failed_at": "01",
  "applied_hops": ["012"],
  "app_signatures": []
}
```

### 5.5 ERROR
```json
{
  "type": "ERROR",
  "payment_id": "uuid-v4-string",
  "code": "INSUFFICIENT_LIABILITY",
  "node": "01",
  "detail": "required 100, available 40"
}
```

**Error codes:**
- `INSUFFICIENT_LIABILITY`
- `INVALID_AMOUNT`
- `UNKNOWN_DESTINATION`
- `MALFORMED_MESSAGE`
- `SIGNATURE_INVALID`
- `TIMEOUT`

---

## 6. State Machine

### 6.1 Persistent State
```
liability: map<octal_digit, integer>  // liability owed to each child
```

This is the only additional persistent state HOTCP-1 introduces.

### 6.2 Transient State
```
pending_payments: map<payment_id, PendingPayment>
```

Where `PendingPayment` is:
```
{
  payment_id: string,
  direction: "upward" | "downward",
  role: "initiator" | "intermediate" | "lca" | "destination",
  message: PaymentMessage,
  applied: boolean,
  rollback_received: boolean,
  timeout_at: timestamp
}
```

### 6.3 Roles

| Condition | Role |
|-----------|------|
| `A == source` | Initiator |
| `A == destination` | Destination |
| `A == L` and `A != source` and `A != destination` | LCA |
| `A` is a proper prefix of `source` and `A != L` | Intermediate upward |
| `A` is a proper prefix of `destination` and `A != L` | Intermediate downward |

### 6.4 Node Transitions

**Initiator (S)**
- State: `IDLE` → `SENT` → `COMMITTED` or `ROLLED_BACK`
- Action: validate amount, compute LCA, construct PAYMENT payload, call `send(destination, "application/hotcp-1+json", payload)`.

**Intermediate Upward (U, U != L)**
- State: `IDLE` → `RECEIVED` → `APPLIED` → `FORWARDED`
- Action: verify application signature, check `L(parent(U), U) >= X`, apply `L -= X`, sign, forward the PAYMENT payload to parent via HOTCP-0.

**LCA (L)**
- State: `IDLE` → `RECEIVED` → `TRANSITIONED` → `FORWARDED`
- Action: verify application signature, switch to downward phase, forward the PAYMENT payload to the child on the path to `D`.

**Intermediate Downward (W, W != D)**
- State: `IDLE` → `RECEIVED` → `APPLIED` → `FORWARDED`
- Action: verify application signature, apply `L += X` on the parent's side, sign, forward to child on path to `D`.

**Destination (D)**
- State: `IDLE` → `RECEIVED` → `COMMITTED`
- Action: verify application signature, apply final `L += X`, send COMMIT back toward the initiator.

### 6.5 State Transition Table

| Current State | Event | Next State | Action |
|---------------|-------|------------|--------|
| IDLE | initiate(payment) | SENT | compute LCA, sign, send PAYMENT |
| IDLE | receive(PAYMENT) | RECEIVED | verify sig, compute role |
| RECEIVED | role=upward, liability ok | APPLIED | `L -= X`, sign, forward |
| RECEIVED | role=upward, liability insufficient | ROLLED_BACK | send ROLLBACK |
| RECEIVED | role=lca | TRANSITIONED | switch phase, forward downward |
| RECEIVED | role=downward | APPLIED | `L += X`, sign, forward |
| RECEIVED | role=destination | COMMITTED | `L += X`, send COMMIT |
| APPLIED | receive(ROLLBACK) | ROLLED_BACK | reverse `L`, forward ROLLBACK |
| APPLIED | receive(COMMIT) | COMMITTED | finalize, clear pending |
| SENT | receive(COMMIT) | COMMITTED | finalize, clear pending |
| SENT | receive(ROLLBACK) | ROLLED_BACK | clear pending |

### 6.6 Rollback Procedure
If any node on the path fails:
1. The failing node sends a ROLLBACK payload toward the initiator via HOTCP-0.
2. Each node receiving ROLLBACK reverses its applied change:
   - Upward nodes: `L += X` (restore)
   - Downward nodes: `L -= X` (restore)
3. The ROLLBACK propagates back to the initiator.
4. The initiator marks the payment as `ROLLED_BACK`.

### 6.7 Timeout Handling
Each hop sets a timeout (e.g., 30 seconds). If no ACK or COMMIT is received:
1. The node initiates rollback locally.
2. Sends ROLLBACK toward the initiator.
3. Retries are idempotent due to `payment_id` deduplication.

---

## 7. Protocol Walkthrough

### 7.1 Example
Tree:
```
          0
        /   \
      00     01
            /|\
           / | \
        010 012 013
```

- `01` has children `010`, `011`, `012`, `013`, ..., `017`.
- `00` is a separate subtree.
- `012` and `013` are siblings, both children of `01`.
- `010` is also a child of `01`.

Note that in octal addressing, a node's children are always `A0`, `A1`, ..., `A7`, where `A` is the node's own address. Thus `012` and `013` are children of `01`, not of `010`.

Payment: 100 from `012` to `010`.

- **LCA(012, 010)** = `01`

### 7.2 Sequence
1. **012** computes LCA = `01`, constructs a PAYMENT payload, and calls `send("010", "application/hotcp-1+json", payload)`. HOTCP-0 routes the envelope upward to `01`.
2. **01** receives the envelope. HOTCP-0 delivers the payload to the HOTCP-1 handler. HOTCP-1 computes LCA = `01`, sees that `01 == L`, switches to downward phase, and forwards the PAYMENT payload to child `010` via HOTCP-0.
3. **010** receives. HOTCP-1 sees `010 == destination`, applies `L(01,010) += 100`, and sends a COMMIT payload back toward `012`.
4. **01** forwards COMMIT to **012**.
5. **012** finalizes. Payment complete.

### 7.3 Rollback Example
If **01** had insufficient liability:
1. **01** sends a ROLLBACK payload toward **012**.
2. **012** marks payment as `ROLLED_BACK`.
3. No liability changes persist.

### 7.4 A Deeper Example
Tree:
```
          0
        /   \
      00     01
            /|\
           / | \
        010 012 013
        /|\
       / | \
    0100 0101 0102
```

Payment: 50 from `0100` to `013`.

- **LCA(0100, 013)** = `01`
- Upward phase: `0100 → 010 → 01`
- Downward phase: `01 → 013`

Sequence:
1. **0100** sends PAYMENT to `013`. HOTCP-0 routes it upward.
2. **010** receives. It is a proper prefix of `0100` and `010 != 01`, so it is an intermediate upward node. It checks `L(010, 0100) >= 50`, applies `L(010, 0100) -= 50`, signs, forwards to parent `01`.
3. **01** receives. `01 == L`, so it is the LCA. It switches to downward phase and forwards to child `013`.
4. **013** receives. `013 == destination`, so it applies `L(01, 013) += 50` and sends COMMIT back toward `0100`.
5. **01** forwards COMMIT to `010`, `010` forwards to `0100`.
6. **0100** finalizes. Payment complete.

---

## 8. Application Signatures

HOTCP-1 signatures are distinct from HOTCP-0 envelope signatures.

- **HOTCP-0 signatures** attest to forwarding: "I received this envelope and forwarded it."
- **HOTCP-1 signatures** attest to application intent: "I authorize this liability change."

A HOTCP-1 signature covers:
- `payment_id`
- `source`, `destination`, `amount`
- The node's own address and phase
- The previous HOTCP-1 signature (hash-chained)

This creates an application-level tamper-evident chain that is independent of the substrate's forwarding signatures. If a node misbehaves at the application layer, the HOTCP-1 chain detects it even if the HOTCP-0 chain is valid.

---

## 9. Security Considerations

### 9.1 Routing Integrity
HOTCP-0 guarantees that the envelope reaches its destination with a tamper-evident chain covering `origin`, `destination`, and `content_type`.

### 9.2 Replay Protection
`payment_id` is unique per payment. Each node tracks recently seen `payment_id`s and rejects duplicates. Timestamps are advisory; the application signature chain is authoritative.

### 9.3 Byzantine Behavior
If a node applies a change but does not forward, the timeout triggers rollback. If a node applies a change and forwards a forged message, the application signature chain detects it. Dispute resolution requires an out-of-band mechanism.

### 9.4 Privacy
A parent necessarily knows the liability it owes each of its children. A node that inspects the PAYMENT payload can see `source` and `destination`. HOTCP-0's optional privacy extensions (truncated addressing, onion wrapping) can hide routing information, but liability changes remain visible to the parent whose liability changes.

### 9.5 Denial of Service
- Rate-limit incoming PAYMENT messages per peer.
- Require a small proof-of-work or staking deposit for payment initiation.
- Prune `pending_payments` after timeout.

---

## 10. Performance Characteristics

| Metric | Value |
|--------|-------|
| Message complexity | `O(depth(S) + depth(D))` |
| State per node | `O(children)` for liability, `O(pending)` for in-flight |
| Path length (balanced tree, N nodes) | `O(log_8 N)` |
| Signatures per payment | `O(path length)` at both layers |
| Routing decision cost | O(1) per hop |

For a tree of depth 10 (8^10 ≈ 1 billion nodes), a payment crosses at most 20 hops.

---

## 11. Open Questions and Future Work

1. **Netting**: can liabilities be netted across sibling subtrees to reduce settlement frequency?
2. **Dynamic rebalancing**: when a node reaches 8 children, how is a new child inserted? Does the tree split?
3. **Cross-tree payments**: what if the source and destination are in different trees?
4. **Settlement layer**: how are liabilities actually cleared?
5. **Node departure**: if a node with non-zero liability leaves, who assumes its obligations?
6. **Amount commitments**: can liability values be hidden from parents with Pedersen commitments while preserving the non-negativity check?
7. **Multi-application substrate**: HOTCP-0 now supports content-type dispatch; other applications can register their own handlers.

---

## 12. Summary

HOTCP-1 is a clearing application built on HOTCP-0 that:
- Registers the content type **`application/hotcp-1+json`** with the substrate.
- Tracks **parent-owes-child liability** per edge.
- Routes payments through the **LCA** with an upward and downward phase.
- Uses HOTCP-0 for **addressing, routing, and delivery**.
- Adds only **one persistent state field** (liability) beyond the substrate.
- Guarantees **atomicity** through optimistic application with rollback.
- Enforces **non-negativity** at each hop before applying changes.
- Maintains an **application-level signature chain** independent of the substrate.

The protocol is simple enough to implement in a few hundred lines per node, and its properties are amenable to formal verification.