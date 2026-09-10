//! Operator authorisation: binding signed orders to ledger entries.
//!
//! An operator signs an off-ledger *order* ([`PaymentOrder`] or
//! [`IssueRequest`]). The resulting [`AuthRef`] is embedded in the ledger
//! [`Entry`] (and therefore covered by the ledger signature). These functions
//! re-verify that binding against a [`PeerRegistry`] before a consumer trusts
//! an entry.
//!
//! The operator signature is over the domain-separated request **hash** (not
//! the raw bytes), and the transfer/issue/burn contexts differ, so an
//! authorisation produced for one kind can never validate another.
//!
//! # Replay
//!
//! None of the `verify_*` functions enforce replay protection. The replay unit
//! is the per-cascade `payment_id`/order: every hop of a cascade shares one
//! [`PaymentOrder::nonce`], and Phase D consumes that order once. Per-entry
//! `(from, nonce)` uniqueness is **not** the model here.

use serde::{Deserialize, Serialize};

use crate::account::{AccountRef, NodeId, Posting, aggregate_deltas};
use crate::amount::Amount;
use crate::entry::{AuthRef, EntryBody, HopRole, SignedEntry};
use crate::error::LedgerError;
use crate::hash::Hash;
use crate::keys::OperatorSecretKey;
use crate::registry::PeerRegistry;

/// BLAKE3 derive-key context for [`PaymentOrder::hash`].
pub const ORDER_CONTEXT: &str = "cawala-ledger/order/v1";
/// BLAKE3 derive-key context for [`IssueRequest::hash`].
pub const ISSUE_CONTEXT: &str = "cawala-ledger/issue-request/v1";
/// BLAKE3 derive-key context for [`BurnRequest::hash`].
pub const BURN_CONTEXT: &str = "cawala-ledger/burn-request/v1";

fn encode_node_id(out: &mut Vec<u8>, id: &NodeId) {
    let bytes = id.as_str().as_bytes();
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn derive_order_hash(context: &str, bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn require_no_expiry(expiry: u64, now: u64) -> Result<(), LedgerError> {
    if now > expiry {
        Err(LedgerError::OrderExpired)
    } else {
        Ok(())
    }
}

/// An operator-signed payment order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentOrder {
    /// Payer node.
    pub from: NodeId,
    /// Payee node.
    pub to: NodeId,
    /// Amount to move.
    pub amount: Amount,
    /// Per-cascade replay nonce: every hop shares it; Phase D consumes the
    /// order (keyed on the cascade `payment_id`) once.
    pub nonce: u64,
    /// Unix-style expiry; valid while `now <= expiry`.
    pub expiry: u64,
}

impl PaymentOrder {
    fn encode_into(&self, out: &mut Vec<u8>) {
        encode_node_id(out, &self.from);
        encode_node_id(out, &self.to);
        out.extend_from_slice(&self.amount.get().to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&self.expiry.to_le_bytes());
    }

    /// The canonical order bytes (the preimage of [`Self::hash`]).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LedgerError> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        Ok(out)
    }

    /// The domain-separated order hash (`cawala-ledger/order/v1`).
    pub fn hash(&self) -> Hash {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        derive_order_hash(ORDER_CONTEXT, &out)
    }

    /// Authorise this order with an operator key, producing an [`AuthRef`].
    ///
    /// The signature is over [`Self::hash`]'s bytes, so it cannot be replayed
    /// as a different order kind.
    pub fn authorize(&self, operator: &OperatorSecretKey) -> Result<AuthRef, LedgerError> {
        let order_hash = self.hash();
        Ok(AuthRef {
            operator: operator.public(),
            nonce: self.nonce,
            order_hash,
            signature: operator.sign(order_hash.as_bytes()),
        })
    }
}

/// An operator-signed request to issue value into an account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueRequest {
    /// The node whose operator authorises the issue.
    pub node: NodeId,
    /// The account to credit.
    pub account: NodeId,
    /// Amount to issue.
    pub amount: Amount,
    /// Per-cascade replay nonce (consumed once by Phase D).
    pub nonce: u64,
    /// Unix-style expiry; valid while `now <= expiry`.
    pub expiry: u64,
}

impl IssueRequest {
    fn encode_into(&self, out: &mut Vec<u8>) {
        encode_node_id(out, &self.node);
        encode_node_id(out, &self.account);
        out.extend_from_slice(&self.amount.get().to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&self.expiry.to_le_bytes());
    }

    /// The canonical request bytes (the preimage of [`Self::hash`]).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LedgerError> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        Ok(out)
    }

    /// The domain-separated request hash
    /// (`cawala-ledger/issue-request/v1`).
    pub fn hash(&self) -> Hash {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        derive_order_hash(ISSUE_CONTEXT, &out)
    }

    /// Authorise this request with an operator key, producing an [`AuthRef`].
    ///
    /// The signature is over [`Self::hash`]'s bytes, so it cannot be replayed
    /// as a different order kind.
    pub fn authorize(&self, operator: &OperatorSecretKey) -> Result<AuthRef, LedgerError> {
        let request_hash = self.hash();
        Ok(AuthRef {
            operator: operator.public(),
            nonce: self.nonce,
            order_hash: request_hash,
            signature: operator.sign(request_hash.as_bytes()),
        })
    }
}

/// An operator-signed request to burn value from an account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnRequest {
    /// The node whose operator authorises the burn.
    pub node: NodeId,
    /// The account to debit.
    pub account: NodeId,
    /// Amount to burn.
    pub amount: Amount,
    /// Per-cascade replay nonce (consumed once by Phase D).
    pub nonce: u64,
    /// Unix-style expiry; valid while `now <= expiry`.
    pub expiry: u64,
}

impl BurnRequest {
    fn encode_into(&self, out: &mut Vec<u8>) {
        encode_node_id(out, &self.node);
        encode_node_id(out, &self.account);
        out.extend_from_slice(&self.amount.get().to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&self.expiry.to_le_bytes());
    }

    /// The canonical request bytes (the preimage of [`Self::hash`]).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LedgerError> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        Ok(out)
    }

    /// The domain-separated request hash (`cawala-ledger/burn-request/v1`).
    pub fn hash(&self) -> Hash {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        derive_order_hash(BURN_CONTEXT, &out)
    }

    /// Authorise this request with an operator key, producing an [`AuthRef`].
    ///
    /// The signature is over [`Self::hash`]'s bytes, so it cannot be replayed
    /// as a different order kind.
    pub fn authorize(&self, operator: &OperatorSecretKey) -> Result<AuthRef, LedgerError> {
        let request_hash = self.hash();
        Ok(AuthRef {
            operator: operator.public(),
            nonce: self.nonce,
            order_hash: request_hash,
            signature: operator.sign(request_hash.as_bytes()),
        })
    }
}

/// For `Direct` transfers, the debited child must be `order.from` and the
/// credited child must be `order.to`.
///
/// For `Ascend`/`Descend`/`Lca*` hops the full route/recipient binding is
/// reconstructed by Phase D netting; this function only binds direct moves.
fn verify_direct_endpoints(postings: &[Posting], order: &PaymentOrder) -> Result<(), LedgerError> {
    let deltas = aggregate_deltas(postings)?;
    let mut debited = None;
    let mut credited = None;
    for (account, delta) in &deltas {
        if let AccountRef::Child(id) = account {
            if *delta < 0 {
                // Exactly one debited child, not last-one-wins.
                if debited.is_some() {
                    return Err(LedgerError::InvalidEntryShape);
                }
                debited = Some(id);
            } else if *delta > 0 {
                // Exactly one credited child, not last-one-wins.
                if credited.is_some() {
                    return Err(LedgerError::InvalidEntryShape);
                }
                credited = Some(id);
            }
        }
    }
    if debited != Some(&order.from) || credited != Some(&order.to) {
        return Err(LedgerError::InvalidEntryShape);
    }
    Ok(())
}

/// Verify that a signed transfer hop carries a valid authorisation for
/// `order`.
///
/// # Not a standalone acceptance path
///
/// This only proves that the payer authorised `order` and that the hop is
/// signed by *some* registered node ledger. It does **not** prove the hop
/// routes the payment correctly. Neither the edge-mirror relation nor the
/// conservation check detects transfer misrouting, and a registered rogue hop
/// can mutate its own accounts and still satisfy this function. Route/recipient
/// binding is unenforced until Phase D `netting` performs full route
/// reconstruction: the unique topology path `order.from -> order.to`, the
/// expected signer/role/edge for each hop, and the terminal credit
/// `Child(order.to)`.
///
/// Checks performed here: [`Entry::check_conservation`] passes; the entry
/// verifies under a registered ledger key ([`PeerRegistry::verify_entry`], not
/// necessarily the payer's); `auth` is present and its operator matches
/// `operator_of(order.from)`; `order_hash`/`nonce` match the order; the order
/// is unexpired; `payment_id`/`amount` match; `Direct` hops debit `order.from`
/// and credit `order.to`; and the operator signature verifies over
/// `order.hash()`'s bytes under `auth.operator`.
///
/// # Replay
///
/// No replay enforcement; the replay unit is the per-cascade `payment_id`
/// (one shared `nonce`), consumed once by Phase D.
pub fn verify_transfer(
    signed: &SignedEntry,
    order: &PaymentOrder,
    registry: &PeerRegistry,
    now: u64,
) -> Result<(), LedgerError> {
    // Reject a malformed entry before trusting any operator material.
    signed.entry.check_conservation()?;
    // The hop must be signed by *some* registered node ledger.
    registry.verify_entry(signed)?;

    let EntryBody::Transfer {
        payment_id,
        amount,
        role,
    } = &signed.entry.body
    else {
        return Err(LedgerError::InvalidEntryShape);
    };
    let auth = signed
        .entry
        .auth
        .as_ref()
        .ok_or(LedgerError::MissingAuthorization)?;
    let payer_operator = registry
        .operator_of(&order.from)
        .ok_or(LedgerError::Unauthorized)?;
    if auth.operator != *payer_operator {
        return Err(LedgerError::Unauthorized);
    }

    let order_hash = order.hash();
    if auth.order_hash != order_hash || auth.nonce != order.nonce {
        return Err(LedgerError::OrderMismatch);
    }
    require_no_expiry(order.expiry, now)?;

    if *payment_id != order_hash || *amount != order.amount {
        return Err(LedgerError::InvalidEntryShape);
    }

    if *role == HopRole::Direct {
        verify_direct_endpoints(&signed.entry.postings, order)?;
    }

    auth.operator.verify(order_hash.as_bytes(), &auth.signature)
}

/// Verify that a signed issue entry carries a valid authorisation for
/// `request`.
///
/// Issues keep the strict binding: the entry must be signed by the ledger of
/// `request.node`. Requires: [`Entry::check_conservation`] passes; the entry
/// verifies under a registered ledger key and that signer is `request.node`
/// (else [`LedgerError::LedgerMismatch`]); `auth` is present and its operator
/// matches `operator_of(request.node)`; `order_hash`/`nonce` match the request;
/// the request is unexpired; the body credits `Child(request.account)` for the
/// requested amount; and the operator signature verifies over
/// `request.hash()`'s bytes under `auth.operator`.
///
/// # Replay
///
/// No replay enforcement; Phase D consumes the request once.
pub fn verify_issue(
    signed: &SignedEntry,
    request: &IssueRequest,
    registry: &PeerRegistry,
    now: u64,
) -> Result<(), LedgerError> {
    // Reject a malformed entry before trusting any operator material.
    signed.entry.check_conservation()?;
    let signer = registry.verify_entry(signed)?;
    if signer.node_id != request.node {
        return Err(LedgerError::LedgerMismatch);
    }

    let EntryBody::Issue { account, amount } = &signed.entry.body else {
        return Err(LedgerError::InvalidEntryShape);
    };
    let auth = signed
        .entry
        .auth
        .as_ref()
        .ok_or(LedgerError::MissingAuthorization)?;
    if auth.operator != signer.operator {
        return Err(LedgerError::Unauthorized);
    }

    let order_hash = request.hash();
    if auth.order_hash != order_hash || auth.nonce != request.nonce {
        return Err(LedgerError::OrderMismatch);
    }
    require_no_expiry(request.expiry, now)?;

    match account {
        AccountRef::Child(id) if id == &request.account => {}
        _ => return Err(LedgerError::InvalidEntryShape),
    }
    if *amount != request.amount {
        return Err(LedgerError::InvalidEntryShape);
    }

    auth.operator.verify(order_hash.as_bytes(), &auth.signature)
}

/// Verify that a signed burn entry carries a valid authorisation for
/// `request`.
///
/// Burns keep the strict binding: the entry must be signed by the ledger of
/// `request.node`. Requires: [`Entry::check_conservation`] passes; the entry
/// verifies under a registered ledger key and that signer is `request.node`
/// (else [`LedgerError::LedgerMismatch`]); `auth` is present and its operator
/// matches the signer's; `order_hash`/`nonce` match the request; the request is
/// unexpired; the body debits `Child(request.account)` for the requested
/// amount; and the operator signature verifies over `request.hash()`'s bytes
/// under `auth.operator`.
///
/// # Replay
///
/// No replay enforcement; Phase D consumes the request once.
pub fn verify_burn(
    signed: &SignedEntry,
    request: &BurnRequest,
    registry: &PeerRegistry,
    now: u64,
) -> Result<(), LedgerError> {
    // Reject a malformed entry before trusting any operator material.
    signed.entry.check_conservation()?;
    let signer = registry.verify_entry(signed)?;
    if signer.node_id != request.node {
        return Err(LedgerError::LedgerMismatch);
    }

    let EntryBody::Burn { account, amount } = &signed.entry.body else {
        return Err(LedgerError::InvalidEntryShape);
    };
    let auth = signed
        .entry
        .auth
        .as_ref()
        .ok_or(LedgerError::MissingAuthorization)?;
    if auth.operator != signer.operator {
        return Err(LedgerError::Unauthorized);
    }

    let order_hash = request.hash();
    if auth.order_hash != order_hash || auth.nonce != request.nonce {
        return Err(LedgerError::OrderMismatch);
    }
    require_no_expiry(request.expiry, now)?;

    match account {
        AccountRef::Child(id) if id == &request.account => {}
        _ => return Err(LedgerError::InvalidEntryShape),
    }
    if *amount != request.amount {
        return Err(LedgerError::InvalidEntryShape);
    }

    auth.operator.verify(order_hash.as_bytes(), &auth.signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{Entry, EntryBody, HopRole, SignedEntry};
    use crate::keys::{LedgerSecretKey, OperatorPubKey, Signature};
    use crate::registry::{PeerKeys, PeerRole};

    fn child(id: &str) -> NodeId {
        NodeId::from(id)
    }

    fn operator(seed: u8) -> OperatorSecretKey {
        OperatorSecretKey::from_bytes([seed; 32])
    }

    fn ledger(seed: u8) -> LedgerSecretKey {
        LedgerSecretKey::from_bytes([seed; 32])
    }

    fn peer(id: &str, op: &OperatorSecretKey, ledger_key: &LedgerSecretKey) -> PeerKeys {
        PeerKeys {
            node_id: NodeId::from(id),
            operator: op.public(),
            ledger: Some(ledger_key.public()),
            role: PeerRole::Node,
        }
    }

    fn registry_with(peers: &[(&str, &OperatorSecretKey, &LedgerSecretKey)]) -> PeerRegistry {
        let mut registry = PeerRegistry::new();
        for (id, op, ledger_key) in peers {
            registry.insert(peer(id, op, ledger_key)).unwrap();
        }
        registry
    }

    fn transfer_entry(
        ledger_key: &LedgerSecretKey,
        payment_id: Hash,
        amount: Amount,
        role: HopRole,
        postings: Vec<Posting>,
        auth: Option<AuthRef>,
    ) -> SignedEntry {
        let entry = Entry {
            ledger_id: ledger_key.public(),
            seq: 0,
            height: 0,
            prev_hash: Hash::ZERO,
            issued_at: 0,
            body: EntryBody::Transfer {
                payment_id,
                amount,
                role,
            },
            postings,
            auth,
        };
        SignedEntry::sign(entry, ledger_key).unwrap()
    }

    fn posting(account: AccountRef, delta: i64) -> Posting {
        Posting {
            account,
            delta: crate::amount::SignedAmount::new(delta),
        }
    }

    fn child_posting(id: &str, delta: i64) -> Posting {
        posting(AccountRef::Child(child(id)), delta)
    }

    fn issue_entry(
        ledger_key: &LedgerSecretKey,
        account: &str,
        amount: Amount,
        auth: Option<AuthRef>,
    ) -> SignedEntry {
        let postings = vec![
            child_posting(account, amount.get() as i64),
            posting(AccountRef::Equity, -(amount.get() as i64)),
        ];
        let entry = Entry {
            ledger_id: ledger_key.public(),
            seq: 0,
            height: 0,
            prev_hash: Hash::ZERO,
            issued_at: 0,
            body: EntryBody::Issue {
                account: AccountRef::Child(child(account)),
                amount,
            },
            postings,
            auth,
        };
        SignedEntry::sign(entry, ledger_key).unwrap()
    }

    fn order() -> PaymentOrder {
        PaymentOrder {
            from: child("alice"),
            to: child("bob"),
            amount: Amount::new(10),
            nonce: 1,
            expiry: 100,
        }
    }

    fn request() -> IssueRequest {
        IssueRequest {
            node: child("alice"),
            account: child("a"),
            amount: Amount::new(25),
            nonce: 7,
            expiry: 200,
        }
    }

    #[test]
    fn authorize_round_trips_over_the_hash() {
        let op = operator(1);
        let order = order();
        let auth = order.authorize(&op).unwrap();

        assert_eq!(auth.operator, op.public());
        assert_eq!(auth.nonce, order.nonce);
        assert_eq!(auth.order_hash, order.hash());
        assert_eq!(
            auth.operator
                .verify(order.hash().as_bytes(), &auth.signature),
            Ok(())
        );
        // The raw order bytes are not what was signed.
        assert_ne!(
            auth.operator
                .verify(&order.canonical_bytes().unwrap(), &auth.signature),
            Ok(())
        );
    }

    #[test]
    fn valid_transfer_is_accepted() {
        let op = operator(1);
        let ledger_key = ledger(11);
        let registry = registry_with(&[("alice", &op, &ledger_key)]);
        let order = order();
        let auth = order.authorize(&op).unwrap();
        let signed = transfer_entry(
            &ledger_key,
            order.hash(),
            order.amount,
            HopRole::Direct,
            vec![child_posting("alice", -10), child_posting("bob", 10)],
            Some(auth),
        );
        assert_eq!(verify_transfer(&signed, &order, &registry, 50), Ok(()));
    }

    #[test]
    fn transfer_rejects_wrong_or_missing_operator() {
        let op = operator(1);
        let other = operator(2);
        let ledger_key = ledger(11);
        let order = order();
        let auth = order.authorize(&op).unwrap();
        let signed = transfer_entry(
            &ledger_key,
            order.hash(),
            order.amount,
            HopRole::Direct,
            vec![child_posting("alice", -10), child_posting("bob", 10)],
            Some(auth),
        );

        // Registered operator for alice is a different key.
        let registry = registry_with(&[("alice", &other, &ledger_key)]);
        assert_eq!(
            verify_transfer(&signed, &order, &registry, 50),
            Err(LedgerError::Unauthorized)
        );

        // Unregistered payer.
        let empty = PeerRegistry::new();
        assert_eq!(
            verify_transfer(&signed, &order, &empty, 50),
            Err(LedgerError::Unauthorized)
        );
    }

    #[test]
    fn transfer_rejects_unregistered_ledger_key() {
        // Alice is registered with ledger K1, but the entry is signed by an
        // unregistered K2.
        let op = operator(1);
        let registry = registry_with(&[("alice", &op, &ledger(11))]);
        let order = order();
        let auth = order.authorize(&op).unwrap();
        let signed = transfer_entry(
            &ledger(22),
            order.hash(),
            order.amount,
            HopRole::Direct,
            vec![child_posting("alice", -10), child_posting("bob", 10)],
            Some(auth),
        );
        assert_eq!(
            verify_transfer(&signed, &order, &registry, 50),
            Err(LedgerError::Unauthorized)
        );
    }

    #[test]
    fn transfer_accepts_registered_non_payer_signer() {
        // The payer (alice) authorises the intent; the hop is signed by a
        // different registered node (bob). This is the per-hop model.
        let alice = operator(1);
        let bob = operator(2);
        let registry = registry_with(&[("alice", &alice, &ledger(11)), ("bob", &bob, &ledger(22))]);
        let order = order();
        let auth = order.authorize(&alice).unwrap();
        let signed = transfer_entry(
            &ledger(22), // signed by bob's ledger, not the payer's
            order.hash(),
            order.amount,
            HopRole::Direct,
            vec![child_posting("alice", -10), child_posting("bob", 10)],
            Some(auth),
        );
        assert_eq!(verify_transfer(&signed, &order, &registry, 50), Ok(()));
    }

    #[test]
    fn transfer_accepts_ascending_hop_signed_by_non_payer() {
        // Ascend/Descend/Lca hops are not endpoint-bound here; route binding is
        // Phase D netting's job. A registered non-payer signer is accepted.
        let payer = operator(1);
        let hop = operator(2);
        let registry = registry_with(&[("alice", &payer, &ledger(11)), ("hop", &hop, &ledger(22))]);
        let order = order();
        let auth = order.authorize(&payer).unwrap();
        let signed = transfer_entry(
            &ledger(22),
            order.hash(),
            order.amount,
            HopRole::Ascend,
            vec![posting(AccountRef::Parent, -10), child_posting("down", -10)],
            Some(auth),
        );
        assert_eq!(verify_transfer(&signed, &order, &registry, 50), Ok(()));
    }

    #[test]
    fn transfer_rejects_bad_signature() {
        let op = operator(1);
        let ledger_key = ledger(11);
        let registry = registry_with(&[("alice", &op, &ledger_key)]);
        let order = order();
        let mut auth = order.authorize(&op).unwrap();
        let mut bytes = auth.signature.to_bytes();
        bytes[0] ^= 0x01;
        auth.signature = Signature::from_bytes(&bytes);
        let signed = transfer_entry(
            &ledger_key,
            order.hash(),
            order.amount,
            HopRole::Direct,
            vec![child_posting("alice", -10), child_posting("bob", 10)],
            Some(auth),
        );
        assert_eq!(
            verify_transfer(&signed, &order, &registry, 50),
            Err(LedgerError::InvalidSignature)
        );
    }

    #[test]
    fn transfer_rejects_order_and_nonce_mismatch() {
        let op = operator(1);
        let ledger_key = ledger(11);
        let registry = registry_with(&[("alice", &op, &ledger_key)]);
        let order = order();
        let postings = || vec![child_posting("alice", -10), child_posting("bob", 10)];

        // A body `payment_id` that disagrees with `auth.order_hash` is caught
        // by the transfer invariant; to reach the order-binding check, keep
        // them consistent but stale.
        let stale = Hash::from_bytes([9u8; 32]);
        let mut auth = order.authorize(&op).unwrap();
        auth.order_hash = stale;
        let signed = transfer_entry(
            &ledger_key,
            stale,
            order.amount,
            HopRole::Direct,
            postings(),
            Some(auth),
        );
        assert_eq!(
            verify_transfer(&signed, &order, &registry, 50),
            Err(LedgerError::OrderMismatch)
        );

        let mut auth = order.authorize(&op).unwrap();
        auth.nonce += 1;
        let signed = transfer_entry(
            &ledger_key,
            order.hash(),
            order.amount,
            HopRole::Direct,
            postings(),
            Some(auth),
        );
        assert_eq!(
            verify_transfer(&signed, &order, &registry, 50),
            Err(LedgerError::OrderMismatch)
        );
    }

    #[test]
    fn transfer_rejects_expired_order() {
        let op = operator(1);
        let ledger_key = ledger(11);
        let registry = registry_with(&[("alice", &op, &ledger_key)]);
        let order = order();
        let auth = order.authorize(&op).unwrap();
        let signed = transfer_entry(
            &ledger_key,
            order.hash(),
            order.amount,
            HopRole::Direct,
            vec![child_posting("alice", -10), child_posting("bob", 10)],
            Some(auth),
        );
        assert_eq!(
            verify_transfer(&signed, &order, &registry, order.expiry + 1),
            Err(LedgerError::OrderExpired)
        );
    }

    #[test]
    fn transfer_rejects_body_mismatch() {
        let op = operator(1);
        let ledger_key = ledger(11);
        let registry = registry_with(&[("alice", &op, &ledger_key)]);
        let order = order();
        let postings = || vec![child_posting("alice", -10), child_posting("bob", 10)];

        // payment_id mismatch
        let auth = order.authorize(&op).unwrap();
        let signed = transfer_entry(
            &ledger_key,
            Hash::ZERO,
            order.amount,
            HopRole::Direct,
            postings(),
            Some(auth),
        );
        assert_eq!(
            verify_transfer(&signed, &order, &registry, 50),
            Err(LedgerError::InvalidEntryShape)
        );

        // amount mismatch
        let auth = order.authorize(&op).unwrap();
        let signed = transfer_entry(
            &ledger_key,
            order.hash(),
            Amount::new(11),
            HopRole::Direct,
            postings(),
            Some(auth),
        );
        assert_eq!(
            verify_transfer(&signed, &order, &registry, 50),
            Err(LedgerError::InvalidEntryShape)
        );
    }

    #[test]
    fn direct_transfer_binds_debit_and_credit_endpoints() {
        let op = operator(1);
        let ledger_key = ledger(11);
        let registry = registry_with(&[("alice", &op, &ledger_key)]);
        let order = order();
        let auth = order.authorize(&op).unwrap();

        // Wrong debit child.
        let signed = transfer_entry(
            &ledger_key,
            order.hash(),
            order.amount,
            HopRole::Direct,
            vec![child_posting("carol", -10), child_posting("bob", 10)],
            Some(auth.clone()),
        );
        assert_eq!(
            verify_transfer(&signed, &order, &registry, 50),
            Err(LedgerError::InvalidEntryShape)
        );

        // Wrong credit child.
        let signed = transfer_entry(
            &ledger_key,
            order.hash(),
            order.amount,
            HopRole::Direct,
            vec![child_posting("alice", -10), child_posting("carol", 10)],
            Some(auth),
        );
        assert_eq!(
            verify_transfer(&signed, &order, &registry, 50),
            Err(LedgerError::InvalidEntryShape)
        );
    }

    #[test]
    fn direct_endpoints_requires_exactly_one_debit_and_one_credit() {
        let order = order();

        // Canonical.
        let postings = vec![child_posting("alice", -10), child_posting("bob", 10)];
        assert_eq!(verify_direct_endpoints(&postings, &order), Ok(()));

        // Two debits: the old last-one-wins logic would have accepted this.
        let postings = vec![
            child_posting("alice", -10),
            child_posting("carol", -10),
            child_posting("bob", 20),
        ];
        assert_eq!(
            verify_direct_endpoints(&postings, &order),
            Err(LedgerError::InvalidEntryShape)
        );

        // Two credits.
        let postings = vec![
            child_posting("alice", -20),
            child_posting("bob", 10),
            child_posting("carol", 10),
        ];
        assert_eq!(
            verify_direct_endpoints(&postings, &order),
            Err(LedgerError::InvalidEntryShape)
        );
    }

    #[test]
    fn verify_transfer_rejects_malformed_entry() {
        let op = operator(1);
        let ledger_key = ledger(11);
        let registry = registry_with(&[("alice", &op, &ledger_key)]);
        let order = order();
        let auth = order.authorize(&op).unwrap();

        // Empty postings fail canonical shape validation before auth is used.
        let signed = transfer_entry(
            &ledger_key,
            order.hash(),
            order.amount,
            HopRole::Direct,
            vec![],
            Some(auth),
        );
        assert_eq!(
            verify_transfer(&signed, &order, &registry, 50),
            Err(LedgerError::InvalidEntryShape)
        );
    }

    #[test]
    fn transfer_rejects_wrong_body_and_missing_auth() {
        let op = operator(1);
        let ledger_key = ledger(11);
        let registry = registry_with(&[("alice", &op, &ledger_key)]);
        let order = order();
        let auth = order.authorize(&op).unwrap();

        // Missing auth.
        let signed = transfer_entry(
            &ledger_key,
            order.hash(),
            order.amount,
            HopRole::Direct,
            vec![child_posting("alice", -10), child_posting("bob", 10)],
            None,
        );
        assert_eq!(
            verify_transfer(&signed, &order, &registry, 50),
            Err(LedgerError::MissingAuthorization)
        );

        // Wrong body kind.
        let signed = issue_entry(&ledger_key, "a", order.amount, Some(auth));
        assert_eq!(
            verify_transfer(&signed, &order, &registry, 50),
            Err(LedgerError::InvalidEntryShape)
        );
    }

    #[test]
    fn valid_issue_is_accepted() {
        let op = operator(1);
        let ledger_key = ledger(11);
        let registry = registry_with(&[("alice", &op, &ledger_key)]);
        let request = request();
        let auth = request.authorize(&op).unwrap();
        let signed = issue_entry(&ledger_key, "a", request.amount, Some(auth));
        assert_eq!(verify_issue(&signed, &request, &registry, 50), Ok(()));
    }

    #[test]
    fn issue_rejects_wrong_operator_expiry_and_account() {
        let op = operator(1);
        let other = operator(2);
        let ledger_key = ledger(11);
        let request = request();
        let auth = request.authorize(&op).unwrap();

        // Wrong registered operator.
        let registry = registry_with(&[("alice", &other, &ledger_key)]);
        let signed = issue_entry(&ledger_key, "a", request.amount, Some(auth.clone()));
        assert_eq!(
            verify_issue(&signed, &request, &registry, 50),
            Err(LedgerError::Unauthorized)
        );

        // Expired.
        let registry = registry_with(&[("alice", &op, &ledger_key)]);
        assert_eq!(
            verify_issue(&signed, &request, &registry, request.expiry + 1),
            Err(LedgerError::OrderExpired)
        );

        // Account mismatch.
        let wrong_account = issue_entry(&ledger_key, "b", request.amount, Some(auth));
        assert_eq!(
            verify_issue(&wrong_account, &request, &registry, 50),
            Err(LedgerError::InvalidEntryShape)
        );
    }

    #[test]
    fn issue_rejects_unregistered_and_mismatched_ledger() {
        let op = operator(1);
        let request = request();
        let auth = request.authorize(&op).unwrap();

        // Unregistered signer.
        let registry = registry_with(&[("alice", &op, &ledger(11))]);
        let signed = issue_entry(&ledger(22), "a", request.amount, Some(auth.clone()));
        assert_eq!(
            verify_issue(&signed, &request, &registry, 50),
            Err(LedgerError::Unauthorized)
        );

        // Signed by bob's ledger while alice authorises.
        let bob = operator(2);
        let registry = registry_with(&[("alice", &op, &ledger(11)), ("bob", &bob, &ledger(22))]);
        let signed = issue_entry(&ledger(22), "a", request.amount, Some(auth));
        assert_eq!(
            verify_issue(&signed, &request, &registry, 50),
            Err(LedgerError::LedgerMismatch)
        );
    }

    #[test]
    fn issue_rejects_amount_mismatch_and_missing_auth() {
        let op = operator(1);
        let ledger_key = ledger(11);
        let registry = registry_with(&[("alice", &op, &ledger_key)]);
        let request = request();

        let auth = request.authorize(&op).unwrap();
        let signed = issue_entry(&ledger_key, "a", Amount::new(26), Some(auth));
        assert_eq!(
            verify_issue(&signed, &request, &registry, 50),
            Err(LedgerError::InvalidEntryShape)
        );

        let signed = issue_entry(&ledger_key, "a", request.amount, None);
        assert_eq!(
            verify_issue(&signed, &request, &registry, 50),
            Err(LedgerError::MissingAuthorization)
        );
    }

    #[test]
    fn issue_rejects_nonce_and_order_hash_mismatch() {
        let op = operator(1);
        let ledger_key = ledger(11);
        let registry = registry_with(&[("alice", &op, &ledger_key)]);
        let request = request();

        let mut auth = request.authorize(&op).unwrap();
        auth.nonce += 1;
        let signed = issue_entry(&ledger_key, "a", request.amount, Some(auth));
        assert_eq!(
            verify_issue(&signed, &request, &registry, 50),
            Err(LedgerError::OrderMismatch)
        );

        let mut auth = request.authorize(&op).unwrap();
        auth.order_hash = Hash::from_bytes([1u8; 32]);
        let signed = issue_entry(&ledger_key, "a", request.amount, Some(auth));
        assert_eq!(
            verify_issue(&signed, &request, &registry, 50),
            Err(LedgerError::OrderMismatch)
        );
    }

    #[test]
    fn verify_issue_rejects_malformed_entry() {
        let op = operator(1);
        let ledger_key = ledger(11);
        let registry = registry_with(&[("alice", &op, &ledger_key)]);
        let request = request();
        let auth = request.authorize(&op).unwrap();

        // Empty postings fail canonical shape validation before auth is used.
        let entry = Entry {
            ledger_id: ledger_key.public(),
            seq: 0,
            height: 0,
            prev_hash: Hash::ZERO,
            issued_at: 0,
            body: EntryBody::Issue {
                account: AccountRef::Child(child("a")),
                amount: request.amount,
            },
            postings: vec![],
            auth: Some(auth),
        };
        let signed = SignedEntry::sign(entry, &ledger_key).unwrap();
        assert_eq!(
            verify_issue(&signed, &request, &registry, 50),
            Err(LedgerError::InvalidEntryShape)
        );
    }

    fn burn_request() -> BurnRequest {
        BurnRequest {
            node: child("alice"),
            account: child("a"),
            amount: Amount::new(25),
            nonce: 9,
            expiry: 200,
        }
    }

    fn burn_entry(
        ledger_key: &LedgerSecretKey,
        account: &str,
        amount: Amount,
        auth: Option<AuthRef>,
    ) -> SignedEntry {
        let postings = vec![
            child_posting(account, -(amount.get() as i64)),
            posting(AccountRef::Equity, amount.get() as i64),
        ];
        let entry = Entry {
            ledger_id: ledger_key.public(),
            seq: 0,
            height: 0,
            prev_hash: Hash::ZERO,
            issued_at: 0,
            body: EntryBody::Burn {
                account: AccountRef::Child(child(account)),
                amount,
            },
            postings,
            auth,
        };
        SignedEntry::sign(entry, ledger_key).unwrap()
    }

    #[test]
    fn authorize_burn_round_trips() {
        let op = operator(1);
        let request = burn_request();
        let auth = request.authorize(&op).unwrap();
        assert_eq!(auth.operator, op.public());
        assert_eq!(auth.nonce, request.nonce);
        assert_eq!(auth.order_hash, request.hash());
        assert_eq!(
            auth.operator
                .verify(request.hash().as_bytes(), &auth.signature),
            Ok(())
        );
    }

    #[test]
    fn valid_burn_is_accepted() {
        let op = operator(1);
        let ledger_key = ledger(11);
        let registry = registry_with(&[("alice", &op, &ledger_key)]);
        let request = burn_request();
        let auth = request.authorize(&op).unwrap();
        let signed = burn_entry(&ledger_key, "a", request.amount, Some(auth));
        assert_eq!(verify_burn(&signed, &request, &registry, 50), Ok(()));
    }

    #[test]
    fn burn_rejects_wrong_operator_and_account() {
        let op = operator(1);
        let other = operator(2);
        let ledger_key = ledger(11);
        let request = burn_request();
        let auth = request.authorize(&op).unwrap();

        // Wrong registered operator.
        let registry = registry_with(&[("alice", &other, &ledger_key)]);
        let signed = burn_entry(&ledger_key, "a", request.amount, Some(auth.clone()));
        assert_eq!(
            verify_burn(&signed, &request, &registry, 50),
            Err(LedgerError::Unauthorized)
        );

        // Account mismatch.
        let registry = registry_with(&[("alice", &op, &ledger_key)]);
        let wrong_account = burn_entry(&ledger_key, "b", request.amount, Some(auth));
        assert_eq!(
            verify_burn(&wrong_account, &request, &registry, 50),
            Err(LedgerError::InvalidEntryShape)
        );
    }

    #[test]
    fn burn_rejects_amount_nonce_and_missing_auth() {
        let op = operator(1);
        let ledger_key = ledger(11);
        let registry = registry_with(&[("alice", &op, &ledger_key)]);
        let request = burn_request();

        let auth = request.authorize(&op).unwrap();
        let signed = burn_entry(&ledger_key, "a", Amount::new(26), Some(auth));
        assert_eq!(
            verify_burn(&signed, &request, &registry, 50),
            Err(LedgerError::InvalidEntryShape)
        );

        let mut auth = request.authorize(&op).unwrap();
        auth.nonce += 1;
        let signed = burn_entry(&ledger_key, "a", request.amount, Some(auth));
        assert_eq!(
            verify_burn(&signed, &request, &registry, 50),
            Err(LedgerError::OrderMismatch)
        );

        let signed = burn_entry(&ledger_key, "a", request.amount, None);
        assert_eq!(
            verify_burn(&signed, &request, &registry, 50),
            Err(LedgerError::MissingAuthorization)
        );
    }

    #[test]
    fn burn_rejects_unregistered_and_mismatched_ledger() {
        let op = operator(1);
        let request = burn_request();
        let auth = request.authorize(&op).unwrap();

        // Unregistered signer.
        let registry = registry_with(&[("alice", &op, &ledger(11))]);
        let signed = burn_entry(&ledger(22), "a", request.amount, Some(auth.clone()));
        assert_eq!(
            verify_burn(&signed, &request, &registry, 50),
            Err(LedgerError::Unauthorized)
        );

        // Signed by bob's ledger while alice authorises.
        let bob = operator(2);
        let registry = registry_with(&[("alice", &op, &ledger(11)), ("bob", &bob, &ledger(22))]);
        let signed = burn_entry(&ledger(22), "a", request.amount, Some(auth));
        assert_eq!(
            verify_burn(&signed, &request, &registry, 50),
            Err(LedgerError::LedgerMismatch)
        );
    }

    #[test]
    fn cross_kind_authorization_is_rejected() {
        // A PaymentOrder and an IssueRequest with identical field values hash
        // to different values, so a transfer authorisation cannot validate an
        // issue (and vice versa).
        let op = operator(1);
        let ledger_key = ledger(11);
        let registry = registry_with(&[("alice", &op, &ledger_key)]);

        let order = PaymentOrder {
            from: child("alice"),
            to: child("a"),
            amount: Amount::new(25),
            nonce: 7,
            expiry: 200,
        };
        let request = IssueRequest {
            node: child("alice"),
            account: child("a"),
            amount: Amount::new(25),
            nonce: 7,
            expiry: 200,
        };
        assert_ne!(order.hash(), request.hash());

        // Auth built from the payment order, placed on an issue entry.
        let transfer_auth = order.authorize(&op).unwrap();
        let signed = issue_entry(&ledger_key, "a", request.amount, Some(transfer_auth));
        assert_eq!(
            verify_issue(&signed, &request, &registry, 50),
            Err(LedgerError::OrderMismatch)
        );

        // Auth built from the issue request, placed on a transfer entry.
        // The transfer invariant `payment_id == auth.order_hash` now rejects
        // this before the order-mismatch check is reached.
        let issue_auth = request.authorize(&op).unwrap();
        let signed = transfer_entry(
            &ledger_key,
            order.hash(),
            order.amount,
            HopRole::Direct,
            vec![child_posting("alice", -25), child_posting("a", 25)],
            Some(issue_auth),
        );
        assert_eq!(
            verify_transfer(&signed, &order, &registry, 50),
            Err(LedgerError::InvalidEntryShape)
        );
    }

    #[test]
    fn operator_pub_key_types_remain_distinct() {
        // Compile-time reminder that auth uses `OperatorPubKey`.
        let op: OperatorPubKey = operator(3).public();
        let auth = PaymentOrder {
            from: child("x"),
            to: child("y"),
            amount: Amount::new(1),
            nonce: 0,
            expiry: 1,
        }
        .authorize(&operator(3))
        .unwrap();
        assert_eq!(auth.operator, op);
    }
}
