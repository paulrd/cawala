# Cawala Node Administration Policy

> **Status: STUB.** Content is pending (R6-Q1 open decision). This file will be
> rendered in the admin-unlock dialog, and acknowledgement will be stored
> locally against a hash/version so edits invalidate it. Do not remove this
> file: the P4 unlock gate depends on it existing.

## Who may administer a node

- Each node keeps an explicit set of **designated administrator children**. A
  designated child of **any** kind — a child *node* or a *leaf* (browser/user) —
  has full administrative authority over that node, and — transitively, hop by
  hop — over the node's ancestors along paths where each link designates the next
  child. Nothing is automatic: a child must be designated.
- The set may be changed by the **local operator** (via CLI, always) and by any
  **currently designated administrator** (remotely, routed). A locked-out node is
  recovered with local CLI administration.
- The **local operator** on the host that holds the node's `<data-dir>` and
  operator key may always administer the node locally (the universal fallback).
  There is no priority order, TTL, lease, or automatic failover.

## Responsibilities of an administrator

- Treat topology changes as material changes in trust.
- Keep the designation set accurate (and the account balances in view).
- Understand that issuing and burning value is irreversible.

## TODO (pending human wording)

- [ ] Fill in the policy prose and legal/risk language (R6-Q1).
- [ ] Decide the versioning/hash scheme used to invalidate acknowledgement.
