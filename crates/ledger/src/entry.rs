//! Ledger entries: the signed, conserved units of the append-only log.
//!
//! # Signed format
//!
//! [`Entry`]'s field order and [`EntryBody`]'s variant/payload order **are**
//! the signed format. Do not reorder fields or variants: doing so silently
//! changes every signature and hash. The format is versioned by
//! [`ENTRY_FORMAT_VERSION`], prefixed to [`Entry::canonical_bytes`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::account::{
    AccountRef, NodeId, Posting, aggregate_deltas, class_sums, postings_conserve,
};
use crate::amount::Amount;
use crate::error::LedgerError;
use crate::hash::Hash;
use crate::keys::{LedgerId, LedgerPubKey, LedgerSecretKey, OperatorPubKey, Signature};

/// Version prefix of [`Entry::canonical_bytes`]. Bump on any format change.
pub const ENTRY_FORMAT_VERSION: u8 = 2;

/// The position of a transfer hop within the LCA settlement cascade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum HopRole {
    /// Value moving up: `Parent−`/`Child−`.
    Ascend,
    /// The reallocation hop at the least common ancestor:
    /// `Child(branch_from)−`/`Child(branch_to)+`.
    Lca,
    /// Value moving down: `Parent+`/`Child+`.
    Descend,
    /// A same-parent (sibling) move: `Child−`/`Child+`.
    Direct,
}

/// Operator authorisation attached to an entry.
///
/// `auth` is covered by the ledger signature over the whole entry. The `auth`
/// module verifies [`AuthRef::operator`]/[`AuthRef::signature`] against the
/// operator-signed order preimage ([`AuthRef::order_hash`] commits to
/// from/to/amount/expiry). Replay is **not** enforced per entry: all hops of a
/// cascade share one order and `nonce`, so the replay unit is the per-cascade
/// `payment_id`, consumed once by netting (Phase D).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthRef {
    /// The operator public key authorising the entry.
    pub operator: OperatorPubKey,
    /// Order nonce, shared by all hops of a cascade; not an entry-level replay key.
    pub nonce: u64,
    /// Commitment to the operator-signed order (from/to/amount/expiry).
    pub order_hash: Hash,
    /// The operator's signature over the order preimage.
    pub signature: Signature,
}

/// The semantic body of an entry.
///
/// Variant and payload order is part of the signed format.
// `LedgerPubKey` embeds the full decompressed Edwards point, so the
// `RotateLedgerKey` variant is intentionally the largest. Box it only with a
// format-version bump: the signed layout is frozen here.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryBody {
    /// Open (or re-assert) an account for a child. Postings must be empty;
    /// `auth` is optional.
    OpenAccount {
        /// The child whose account is being opened.
        child: NodeId,
        /// Whether the child is a node or a user.
        kind: cawala_topology::ChildKind,
    },
    /// A value transfer that conserves equity. The exact accounts moved are
    /// fixed by [`HopRole`] and validated by [`Entry::check_conservation`].
    Transfer {
        /// Correlates the hops of one payment.
        payment_id: Hash,
        /// The transferred quantity (must be `> 0`).
        amount: Amount,
        /// The hop's position in the settlement cascade.
        role: HopRole,
    },
    /// Create value into a child account against equity:
    /// `[account:+amount, Equity:−amount]`.
    Issue {
        /// The credited account (must be `Child(_)`).
        account: AccountRef,
        /// The amount created (must be `> 0`).
        amount: Amount,
    },
    /// Destroy value from a child account against equity:
    /// `[account:−amount, Equity:+amount]`.
    Burn {
        /// The debited account (must be `Child(_)`).
        account: AccountRef,
        /// The amount destroyed (must be `> 0`).
        amount: Amount,
    },
    /// Rotate the ledger key, authorised by the operator key.
    ///
    /// Rejected with [`LedgerError::Unsupported`] in Phase A. Phase B
    /// implements verification and the actual key swap.
    RotateLedgerKey {
        /// The new ledger public key.
        new_key: LedgerPubKey,
        /// The operator's authorisation signature.
        operator_sig: Signature,
    },
}

/// One ledger entry.
///
/// # Signed format
///
/// **Field order is the signed format — do not reorder.** `payment_id` lives
/// in [`EntryBody::Transfer`], not here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// The ledger this entry belongs to.
    pub ledger_id: LedgerId,
    /// Strictly increasing position in the chain, starting at 0.
    pub seq: u64,
    /// Height; for now must equal `seq` (Phase A), possibly redefined later.
    pub height: u64,
    /// Hash of the previous entry ([`Hash::ZERO`] at genesis).
    pub prev_hash: Hash,
    /// Coarse issuance timestamp.
    pub issued_at: u64,
    /// The semantic body.
    pub body: EntryBody,
    /// The balance movements this entry applies.
    pub postings: Vec<Posting>,
    /// Operator authorisation (required for transfer/issue/burn).
    pub auth: Option<AuthRef>,
}

impl Entry {
    /// Whether the body requires an [`AuthRef`].
    pub fn requires_auth(&self) -> bool {
        matches!(
            &self.body,
            EntryBody::Transfer { .. } | EntryBody::Issue { .. } | EntryBody::Burn { .. }
        )
    }

    /// Validate the posting set against the double-entry rules **and** the
    /// canonical shape declared by the body.
    ///
    /// First checks the raw posting sum
    /// `Σdelta(Parent) − Σdelta(Child) − Σdelta(Equity) == 0` (in `i128`),
    /// then binds the body to the postings:
    ///
    /// - `Transfer { amount, role }`: `amount > 0`, `Δequity == 0`, and,
    ///   per role:
    ///   - `Ascend`: exactly `[Parent:−amount, Child(_):−amount]`;
    ///   - `Descend`: exactly `[Parent:+amount, Child(_):+amount]`;
    ///   - `Direct`/`Lca`: exactly two distinct `Child(_)` postings, one
    ///     `+amount` and one `−amount`, with no `Parent`/`Equity` leg.
    /// - `Issue { account, amount }`: `account` is `Child(_)`, `amount > 0`,
    ///   exactly `[account:+amount, Equity:−amount]`.
    /// - `Burn { account, amount }`: `account` is `Child(_)`, `amount > 0`,
    ///   exactly `[account:−amount, Equity:+amount]`.
    /// - `OpenAccount`: postings must be empty (opening is a pure account
    ///   creation; the zero balance is materialized by [`crate::log::Ledger::append`]).
    /// - `RotateLedgerKey`: [`LedgerError::Unsupported`] in Phase A.
    ///
    /// A `Transfer` additionally requires `payment_id == auth.order_hash`: the
    /// body is bound to the same authorisation hash the operator signed. This
    /// stops a hop from carrying a valid [`Entry::auth`] while claiming a
    /// different payment id; `netting` selects by `auth.order_hash`, so the two
    /// must agree.
    ///
    /// Transfer/issue/burn require [`Entry::auth`] to be `Some`.
    pub fn check_conservation(&self) -> Result<(), LedgerError> {
        if matches!(&self.body, EntryBody::RotateLedgerKey { .. }) {
            return Err(LedgerError::Unsupported);
        }
        if self.requires_auth() && self.auth.is_none() {
            return Err(LedgerError::MissingAuthorization);
        }
        // A transfer's body `payment_id` must be the same hash the operator
        // authorised. Without this, a hop could carry a valid `auth` while
        // claiming a different payment id, so netting selects by
        // `auth.order_hash` (see `crate::netting`) and this is the matching
        // append-time invariant.
        if let EntryBody::Transfer { payment_id, .. } = &self.body {
            let auth = self
                .auth
                .as_ref()
                .ok_or(LedgerError::MissingAuthorization)?;
            if *payment_id != auth.order_hash {
                return Err(LedgerError::InvalidEntryShape);
            }
        }

        let deltas = aggregate_deltas(&self.postings)?;
        let (delta_parent, delta_child, delta_equity) = class_sums(&deltas)?;
        postings_conserve(delta_parent, delta_child, delta_equity)?;
        self.validate_shape(&deltas, delta_equity)
    }

    /// Enforce the canonical posting shape for the declared body.
    fn validate_shape(
        &self,
        deltas: &BTreeMap<AccountRef, i128>,
        delta_equity: i128,
    ) -> Result<(), LedgerError> {
        match &self.body {
            EntryBody::OpenAccount { .. } => {
                if !self.postings.is_empty() || delta_equity != 0 {
                    return Err(LedgerError::InvalidEntryShape);
                }
                Ok(())
            }
            EntryBody::Transfer { amount, role, .. } => {
                let amount = amount.get() as i128;
                if amount == 0 || delta_equity != 0 {
                    return Err(LedgerError::InvalidEntryShape);
                }
                let parent = deltas.get(&AccountRef::Parent).copied().unwrap_or(0);
                let children: Vec<i128> = deltas
                    .iter()
                    .filter_map(|(account, delta)| match account {
                        AccountRef::Child(_) => Some(*delta),
                        _ => None,
                    })
                    .collect();

                let canonical = match role {
                    HopRole::Ascend => {
                        deltas.len() == 2
                            && parent == -amount
                            && children.len() == 1
                            && children[0] == -amount
                    }
                    HopRole::Descend => {
                        deltas.len() == 2
                            && parent == amount
                            && children.len() == 1
                            && children[0] == amount
                    }
                    HopRole::Direct | HopRole::Lca => {
                        deltas.len() == 2
                            && children.len() == 2
                            && deltas.keys().all(|a| matches!(a, AccountRef::Child(_)))
                            && children.iter().filter(|d| **d == amount).count() == 1
                            && children.iter().filter(|d| **d == -amount).count() == 1
                    }
                };
                if canonical {
                    Ok(())
                } else {
                    Err(LedgerError::InvalidEntryShape)
                }
            }
            EntryBody::Issue { account, amount } => {
                let amount = amount.get() as i128;
                if amount == 0 {
                    return Err(LedgerError::InvalidEntryShape);
                }
                if !matches!(account, AccountRef::Child(_)) {
                    return Err(LedgerError::InvalidEntryShape);
                }
                if deltas.len() == 2
                    && deltas.get(account).copied() == Some(amount)
                    && deltas.get(&AccountRef::Equity).copied() == Some(-amount)
                {
                    Ok(())
                } else {
                    Err(LedgerError::InvalidEntryShape)
                }
            }
            EntryBody::Burn { account, amount } => {
                let amount = amount.get() as i128;
                if amount == 0 {
                    return Err(LedgerError::InvalidEntryShape);
                }
                if !matches!(account, AccountRef::Child(_)) {
                    return Err(LedgerError::InvalidEntryShape);
                }
                if deltas.len() == 2
                    && deltas.get(account).copied() == Some(-amount)
                    && deltas.get(&AccountRef::Equity).copied() == Some(amount)
                {
                    Ok(())
                } else {
                    Err(LedgerError::InvalidEntryShape)
                }
            }
            EntryBody::RotateLedgerKey { .. } => Err(LedgerError::Unsupported),
        }
    }

    /// The canonical signed bytes: [`ENTRY_FORMAT_VERSION`] followed by the
    /// postcard encoding of this entry in fixed field order.
    ///
    /// This is the message that is signed, hashed, and chained.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LedgerError> {
        let body =
            postcard::to_allocvec(self).map_err(|err| LedgerError::Encode(err.to_string()))?;
        let mut bytes = Vec::with_capacity(body.len() + 1);
        bytes.push(ENTRY_FORMAT_VERSION);
        bytes.extend_from_slice(&body);
        Ok(bytes)
    }
}

/// An [`Entry`] together with its ledger signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEntry {
    /// The signed entry.
    pub entry: Entry,
    /// The signature over `entry.canonical_bytes()`.
    pub signature: Signature,
}

impl SignedEntry {
    /// Sign `entry` with `key`, producing a [`SignedEntry`].
    pub fn sign(entry: Entry, key: &LedgerSecretKey) -> Result<Self, LedgerError> {
        let bytes = entry.canonical_bytes()?;
        let signature = key.sign(&bytes);
        Ok(SignedEntry { entry, signature })
    }

    /// Verify this entry's signature under `key`.
    ///
    /// Returns [`LedgerError::LedgerMismatch`] if the entry was created for a
    /// different ledger (i.e. `entry.ledger_id != *key`) before attempting any
    /// signature check.
    pub fn verify(&self, key: &LedgerPubKey) -> Result<(), LedgerError> {
        if self.entry.ledger_id != *key {
            return Err(LedgerError::LedgerMismatch);
        }
        let bytes = self.entry.canonical_bytes()?;
        key.verify(&bytes, &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amount::SignedAmount;
    use crate::keys::OperatorSecretKey;

    fn child(id: &str) -> NodeId {
        NodeId::from(id)
    }

    fn posting(account: AccountRef, delta: i64) -> Posting {
        Posting {
            account,
            delta: SignedAmount::new(delta),
        }
    }

    fn child_posting(id: &str, delta: i64) -> Posting {
        posting(AccountRef::Child(child(id)), delta)
    }

    fn ledger_key() -> LedgerSecretKey {
        LedgerSecretKey::from_bytes([4u8; 32])
    }

    fn auth() -> AuthRef {
        let operator = OperatorSecretKey::from_bytes([6u8; 32]);
        AuthRef {
            operator: operator.public(),
            nonce: 0,
            order_hash: Hash::ZERO,
            signature: operator.sign(b"order"),
        }
    }

    fn base(body: EntryBody, postings: Vec<Posting>) -> Entry {
        Entry {
            ledger_id: ledger_key().public(),
            seq: 0,
            height: 0,
            prev_hash: Hash::ZERO,
            issued_at: 0,
            body,
            postings,
            auth: None,
        }
    }

    #[test]
    fn transfer_shapes_conserve() {
        let cases = [
            // sibling transfer: Child−/Child+
            (
                HopRole::Direct,
                vec![child_posting("a", -5), child_posting("b", 5)],
            ),
            // ascend: Parent−/Child−
            (
                HopRole::Ascend,
                vec![posting(AccountRef::Parent, -5), child_posting("a", -5)],
            ),
            // descend: Parent+/Child+
            (
                HopRole::Descend,
                vec![posting(AccountRef::Parent, 5), child_posting("a", 5)],
            ),
            // LCA reallocation is child-to-child as well
            (
                HopRole::Lca,
                vec![child_posting("a", -5), child_posting("b", 5)],
            ),
        ];
        for (role, postings) in cases {
            let entry = Entry {
                auth: Some(auth()),
                ..base(
                    EntryBody::Transfer {
                        payment_id: Hash::ZERO,
                        amount: Amount::new(5),
                        role,
                    },
                    postings,
                )
            };
            assert_eq!(entry.check_conservation(), Ok(()), "role {role:?}");
        }
    }

    #[test]
    fn non_canonical_transfer_shapes_are_rejected() {
        // These conserve value but do not match the role's canonical shape.
        let bad_shape = [
            // wrong magnitude
            (
                HopRole::Direct,
                vec![child_posting("a", -4), child_posting("b", 4)],
            ),
            // three legs
            (
                HopRole::Direct,
                vec![
                    child_posting("a", -5),
                    child_posting("b", 3),
                    child_posting("c", 2),
                ],
            ),
            // same account twice (nets to zero but not two distinct children)
            (
                HopRole::Direct,
                vec![child_posting("a", -5), child_posting("a", 5)],
            ),
            // ascend with the right signs but the wrong declared amount
            (
                HopRole::Ascend,
                vec![posting(AccountRef::Parent, -4), child_posting("a", -4)],
            ),
        ];
        for (role, postings) in bad_shape {
            let entry = Entry {
                auth: Some(auth()),
                ..base(
                    EntryBody::Transfer {
                        payment_id: Hash::ZERO,
                        amount: Amount::new(5),
                        role,
                    },
                    postings,
                )
            };
            assert_eq!(
                entry.check_conservation(),
                Err(LedgerError::InvalidEntryShape),
                "role {role:?}"
            );
        }

        // These do not conserve value at all.
        let bad_value = [
            (
                HopRole::Ascend,
                vec![posting(AccountRef::Parent, -5), child_posting("a", 5)],
            ),
            (
                HopRole::Direct,
                vec![posting(AccountRef::Parent, -5), child_posting("a", 5)],
            ),
        ];
        for (role, postings) in bad_value {
            let entry = Entry {
                auth: Some(auth()),
                ..base(
                    EntryBody::Transfer {
                        payment_id: Hash::ZERO,
                        amount: Amount::new(5),
                        role,
                    },
                    postings,
                )
            };
            assert_eq!(
                entry.check_conservation(),
                Err(LedgerError::ConservationViolation),
                "role {role:?}"
            );
        }
    }

    #[test]
    fn zero_amount_is_rejected() {
        for body in [
            EntryBody::Transfer {
                payment_id: Hash::ZERO,
                amount: Amount::ZERO,
                role: HopRole::Direct,
            },
            EntryBody::Issue {
                account: AccountRef::Child(child("a")),
                amount: Amount::ZERO,
            },
            EntryBody::Burn {
                account: AccountRef::Child(child("a")),
                amount: Amount::ZERO,
            },
        ] {
            let entry = Entry {
                auth: Some(auth()),
                ..base(body, vec![])
            };
            assert_eq!(
                entry.check_conservation(),
                Err(LedgerError::InvalidEntryShape)
            );
        }
    }

    #[test]
    fn issue_and_burn_canonical_shapes() {
        let issue = Entry {
            auth: Some(auth()),
            ..base(
                EntryBody::Issue {
                    account: AccountRef::Child(child("a")),
                    amount: Amount::new(100),
                },
                vec![child_posting("a", 100), posting(AccountRef::Equity, -100)],
            )
        };
        assert_eq!(issue.check_conservation(), Ok(()));

        let burn = Entry {
            auth: Some(auth()),
            ..base(
                EntryBody::Burn {
                    account: AccountRef::Child(child("a")),
                    amount: Amount::new(40),
                },
                vec![child_posting("a", -40), posting(AccountRef::Equity, 40)],
            )
        };
        assert_eq!(burn.check_conservation(), Ok(()));
    }

    #[test]
    fn issue_to_non_child_account_is_rejected() {
        // This posting set conserves, so only the account-kind rule rejects it.
        let entry = Entry {
            auth: Some(auth()),
            ..base(
                EntryBody::Issue {
                    account: AccountRef::Parent,
                    amount: Amount::new(100),
                },
                vec![posting(AccountRef::Parent, 100), child_posting("a", 100)],
            )
        };
        assert_eq!(
            entry.check_conservation(),
            Err(LedgerError::InvalidEntryShape)
        );
    }

    #[test]
    fn wrong_issue_shape_is_rejected() {
        let entry = Entry {
            auth: Some(auth()),
            ..base(
                EntryBody::Issue {
                    account: AccountRef::Child(child("a")),
                    amount: Amount::new(100),
                },
                vec![child_posting("a", 99), posting(AccountRef::Equity, -99)],
            )
        };
        assert_eq!(
            entry.check_conservation(),
            Err(LedgerError::InvalidEntryShape)
        );
    }

    #[test]
    fn missing_auth_is_rejected() {
        let issue = base(
            EntryBody::Issue {
                account: AccountRef::Child(child("a")),
                amount: Amount::new(10),
            },
            vec![child_posting("a", 10), posting(AccountRef::Equity, -10)],
        );
        assert_eq!(
            issue.check_conservation(),
            Err(LedgerError::MissingAuthorization)
        );

        let transfer = base(
            EntryBody::Transfer {
                payment_id: Hash::ZERO,
                amount: Amount::new(5),
                role: HopRole::Direct,
            },
            vec![child_posting("a", -5), child_posting("b", 5)],
        );
        assert_eq!(
            transfer.check_conservation(),
            Err(LedgerError::MissingAuthorization)
        );
    }

    #[test]
    fn open_account_allows_empty_postings_without_auth() {
        let entry = base(
            EntryBody::OpenAccount {
                child: child("a"),
                kind: cawala_topology::ChildKind::User,
            },
            vec![],
        );
        assert_eq!(entry.check_conservation(), Ok(()));
    }

    #[test]
    fn open_account_rejects_any_postings() {
        // Non-zero postings.
        let nonzero = base(
            EntryBody::OpenAccount {
                child: child("a"),
                kind: cawala_topology::ChildKind::User,
            },
            vec![child_posting("a", 1), posting(AccountRef::Equity, -1)],
        );
        assert_eq!(
            nonzero.check_conservation(),
            Err(LedgerError::InvalidEntryShape)
        );

        // All-zero postings are also rejected: openings must be empty.
        let zero = base(
            EntryBody::OpenAccount {
                child: child("a"),
                kind: cawala_topology::ChildKind::User,
            },
            vec![child_posting("a", 0)],
        );
        assert_eq!(
            zero.check_conservation(),
            Err(LedgerError::InvalidEntryShape)
        );
    }

    #[test]
    fn rotate_ledger_key_is_unsupported() {
        let entry = base(
            EntryBody::RotateLedgerKey {
                new_key: LedgerSecretKey::from_bytes([9u8; 32]).public(),
                operator_sig: OperatorSecretKey::from_bytes([6u8; 32]).sign(b"rotate"),
            },
            vec![],
        );
        assert_eq!(entry.check_conservation(), Err(LedgerError::Unsupported));
    }

    #[test]
    fn canonical_bytes_round_trip() {
        let entry = base(
            EntryBody::OpenAccount {
                child: child("a"),
                kind: cawala_topology::ChildKind::Node,
            },
            vec![],
        );
        let bytes = entry.canonical_bytes().unwrap();
        assert_eq!(bytes[0], ENTRY_FORMAT_VERSION);
        assert_eq!(bytes, entry.canonical_bytes().unwrap());
    }

    #[test]
    fn golden_vectors() {
        // Frozen signed-format vectors. If these fail after an intentional
        // format change, bump ENTRY_FORMAT_VERSION and update the constants.
        for (name, entry) in golden_entries() {
            let bytes = entry.canonical_bytes().unwrap();
            assert_eq!(bytes[0], ENTRY_FORMAT_VERSION, "{name}: version prefix");
            let hex = to_hex(&bytes);
            assert_eq!(hex, golden_hex(name), "{name}: canonical bytes changed");
        }

        let auth_hex = to_hex(&postcard::to_allocvec(&golden_auth()).unwrap());
        assert_eq!(auth_hex, AUTH_REF_GOLDEN, "AuthRef bytes changed");
    }

    fn golden_ledger() -> LedgerSecretKey {
        LedgerSecretKey::from_bytes([0x11; 32])
    }

    fn golden_auth() -> AuthRef {
        let operator = OperatorSecretKey::from_bytes([0x33; 32]);
        AuthRef {
            operator: operator.public(),
            nonce: 5,
            order_hash: Hash::from_bytes([0x44; 32]),
            signature: operator.sign(b"order"),
        }
    }

    fn golden_entry(body: EntryBody, postings: Vec<Posting>, auth: Option<AuthRef>) -> Entry {
        Entry {
            ledger_id: golden_ledger().public(),
            seq: 1,
            height: 1,
            prev_hash: Hash::from_bytes([0x22; 32]),
            issued_at: 1234,
            body,
            postings,
            auth,
        }
    }

    fn golden_entries() -> Vec<(&'static str, Entry)> {
        let payment_id = Hash::from_bytes([0x22; 32]);
        let amount = Amount::new(7);
        let transfer = |role| EntryBody::Transfer {
            payment_id,
            amount,
            role,
        };
        vec![
            (
                "open_account",
                golden_entry(
                    EntryBody::OpenAccount {
                        child: child("a"),
                        kind: cawala_topology::ChildKind::Node,
                    },
                    vec![],
                    None,
                ),
            ),
            (
                "transfer_ascend",
                golden_entry(
                    transfer(HopRole::Ascend),
                    vec![posting(AccountRef::Parent, -7), child_posting("a", -7)],
                    Some(golden_auth()),
                ),
            ),
            (
                "transfer_lca",
                golden_entry(
                    transfer(HopRole::Lca),
                    vec![child_posting("a", -7), child_posting("b", 7)],
                    Some(golden_auth()),
                ),
            ),
            (
                "transfer_descend",
                golden_entry(
                    transfer(HopRole::Descend),
                    vec![posting(AccountRef::Parent, 7), child_posting("a", 7)],
                    Some(golden_auth()),
                ),
            ),
            (
                "transfer_direct",
                golden_entry(
                    transfer(HopRole::Direct),
                    vec![child_posting("a", -7), child_posting("b", 7)],
                    Some(golden_auth()),
                ),
            ),
            (
                "issue",
                golden_entry(
                    EntryBody::Issue {
                        account: AccountRef::Child(child("a")),
                        amount,
                    },
                    vec![child_posting("a", 7), posting(AccountRef::Equity, -7)],
                    Some(golden_auth()),
                ),
            ),
            (
                "burn",
                golden_entry(
                    EntryBody::Burn {
                        account: AccountRef::Child(child("a")),
                        amount,
                    },
                    vec![child_posting("a", -7), posting(AccountRef::Equity, 7)],
                    Some(golden_auth()),
                ),
            ),
            (
                "rotate_ledger_key",
                golden_entry(
                    EntryBody::RotateLedgerKey {
                        new_key: LedgerSecretKey::from_bytes([0x55; 32]).public(),
                        operator_sig: OperatorSecretKey::from_bytes([0x33; 32]).sign(b"rotate"),
                    },
                    vec![],
                    None,
                ),
            ),
        ]
    }

    fn golden_hex(name: &str) -> &'static str {
        match name {
            "open_account" => GOLDEN_OPEN_ACCOUNT,
            "transfer_ascend" => GOLDEN_TRANSFER_ASCEND,
            "transfer_lca" => GOLDEN_TRANSFER_LCA,
            "transfer_descend" => GOLDEN_TRANSFER_DESCEND,
            "transfer_direct" => GOLDEN_TRANSFER_DIRECT,
            "issue" => GOLDEN_ISSUE,
            "burn" => GOLDEN_BURN,
            "rotate_ledger_key" => GOLDEN_ROTATE,
            other => panic!("unknown golden case {other}"),
        }
    }

    const GOLDEN_OPEN_ACCOUNT: &str = "02d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873701012222222222222222222222222222222222222222222222222222222222222222d209000161000000";
    const GOLDEN_TRANSFER_ASCEND: &str = "02d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873701012222222222222222222222222222222222222222222222222222222222222222d209012222222222222222222222222222222222222222222222222222222222222222070002000d0101610d0117cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce0544444444444444444444444444444444444444444444444444444444444444444ef0de24d928dfa8740dcc7e9f7012b52d0d51026858a05447c7ce0bcdfa47f072cdfd611cd4eb96dbdf103aa3cad2a3c9f259810b5705501518f6bebf739101";
    const GOLDEN_TRANSFER_LCA: &str = "02d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873701012222222222222222222222222222222222222222222222222222222222222222d2090122222222222222222222222222222222222222222222222222222222222222220701020101610d0101620e0117cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce0544444444444444444444444444444444444444444444444444444444444444444ef0de24d928dfa8740dcc7e9f7012b52d0d51026858a05447c7ce0bcdfa47f072cdfd611cd4eb96dbdf103aa3cad2a3c9f259810b5705501518f6bebf739101";
    const GOLDEN_TRANSFER_DESCEND: &str = "02d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873701012222222222222222222222222222222222222222222222222222222222222222d209012222222222222222222222222222222222222222222222222222222222222222070202000e0101610e0117cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce0544444444444444444444444444444444444444444444444444444444444444444ef0de24d928dfa8740dcc7e9f7012b52d0d51026858a05447c7ce0bcdfa47f072cdfd611cd4eb96dbdf103aa3cad2a3c9f259810b5705501518f6bebf739101";
    const GOLDEN_TRANSFER_DIRECT: &str = "02d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873701012222222222222222222222222222222222222222222222222222222222222222d2090122222222222222222222222222222222222222222222222222222222222222220703020101610d0101620e0117cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce0544444444444444444444444444444444444444444444444444444444444444444ef0de24d928dfa8740dcc7e9f7012b52d0d51026858a05447c7ce0bcdfa47f072cdfd611cd4eb96dbdf103aa3cad2a3c9f259810b5705501518f6bebf739101";
    const GOLDEN_ISSUE: &str = "02d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873701012222222222222222222222222222222222222222222222222222222222222222d2090201016107020101610e020d0117cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce0544444444444444444444444444444444444444444444444444444444444444444ef0de24d928dfa8740dcc7e9f7012b52d0d51026858a05447c7ce0bcdfa47f072cdfd611cd4eb96dbdf103aa3cad2a3c9f259810b5705501518f6bebf739101";
    const GOLDEN_BURN: &str = "02d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873701012222222222222222222222222222222222222222222222222222222222222222d2090301016107020101610d020e0117cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce0544444444444444444444444444444444444444444444444444444444444444444ef0de24d928dfa8740dcc7e9f7012b52d0d51026858a05447c7ce0bcdfa47f072cdfd611cd4eb96dbdf103aa3cad2a3c9f259810b5705501518f6bebf739101";
    const GOLDEN_ROTATE: &str = "02d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873701012222222222222222222222222222222222222222222222222222222222222222d20904c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242647ee6334067ec8141217bfe87e83ea3a89dbc91b2f615c993275bae5eeab0557e12f5f62257a1eef97ba76f68d2cf83379ebc7c2f0071998f9539d523cd1a090000";
    const AUTH_REF_GOLDEN: &str = "17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce0544444444444444444444444444444444444444444444444444444444444444444ef0de24d928dfa8740dcc7e9f7012b52d0d51026858a05447c7ce0bcdfa47f072cdfd611cd4eb96dbdf103aa3cad2a3c9f259810b5705501518f6bebf739101";

    fn to_hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let key = LedgerSecretKey::from_bytes([5u8; 32]);
        let entry = Entry {
            ledger_id: key.public(),
            auth: Some(auth()),
            ..base(
                EntryBody::OpenAccount {
                    child: child("a"),
                    kind: cawala_topology::ChildKind::Node,
                },
                vec![],
            )
        };
        let signed = SignedEntry::sign(entry, &key).unwrap();
        assert_eq!(signed.verify(&key.public()), Ok(()));
    }

    #[test]
    fn verify_rejects_wrong_ledger_key_with_mismatch() {
        let key = LedgerSecretKey::from_bytes([5u8; 32]);
        let other = LedgerSecretKey::from_bytes([8u8; 32]);
        let entry = Entry {
            ledger_id: key.public(),
            ..base(
                EntryBody::OpenAccount {
                    child: child("a"),
                    kind: cawala_topology::ChildKind::Node,
                },
                vec![],
            )
        };
        let signed = SignedEntry::sign(entry, &key).unwrap();
        assert_eq!(
            signed.verify(&other.public()),
            Err(LedgerError::LedgerMismatch)
        );
    }

    #[test]
    fn tampered_entry_fails_verification() {
        let key = LedgerSecretKey::from_bytes([5u8; 32]);
        let entry = Entry {
            ledger_id: key.public(),
            ..base(
                EntryBody::OpenAccount {
                    child: child("a"),
                    kind: cawala_topology::ChildKind::Node,
                },
                vec![],
            )
        };
        let mut signed = SignedEntry::sign(entry, &key).unwrap();
        signed.entry.seq = 99;
        assert_eq!(
            signed.verify(&key.public()),
            Err(LedgerError::InvalidSignature)
        );
    }

    #[test]
    fn tampered_auth_breaks_signature() {
        let key = LedgerSecretKey::from_bytes([5u8; 32]);
        let entry = Entry {
            ledger_id: key.public(),
            auth: Some(auth()),
            ..base(
                EntryBody::Issue {
                    account: AccountRef::Child(child("a")),
                    amount: Amount::new(10),
                },
                vec![child_posting("a", 10), posting(AccountRef::Equity, -10)],
            )
        };
        let mut signed = SignedEntry::sign(entry, &key).unwrap();
        signed.entry.auth.as_mut().unwrap().nonce += 1;
        assert_eq!(
            signed.verify(&key.public()),
            Err(LedgerError::InvalidSignature)
        );
    }
}
