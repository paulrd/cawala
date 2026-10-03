# Cawala Node Administration Policy

> **Status: STUB.** Content is pending (R6-Q1 open decision). This file will be
> rendered in the admin-unlock dialog, and acknowledgement will be stored
> locally against a hash/version so edits invalidate it. Do not remove this
> file: the P4 unlock gate depends on it existing.

## Who may administer a node

- A **browser** (user/leaf client) that is a direct child of a node has full
  administrative authority over that node, and — transitively, hop by hop —
  over the node's ancestors.
- A node **without** browser children is administered by the administrator
  selected from its priority-ordered child list (a TTL lease governs
  failover); see `REFACTOR.md` R5.
- The **local operator** on the host that holds the node's `<data-dir>` and
  operator key may always administer the node locally (the universal fallback).

## Responsibilities of an administrator

- Treat topology changes as material changes in trust.
- Keep the priority list and value policy accurate.
- Understand that issuing and burning value is irreversible.

## TODO (pending human wording)

- [ ] Fill in the policy prose and legal/risk language (R6-Q1).
- [ ] Decide the versioning/hash scheme used to invalidate acknowledgement.
