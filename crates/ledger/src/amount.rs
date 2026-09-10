//! Unsigned and signed ledger amounts.
//!
//! All fallible arithmetic returns [`LedgerError`] rather than silently
//! wrapping: balances are money, and an overflow must never be observable as
//! a plausible-looking value.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::error::LedgerError;

/// A non-negative quantity of the single Cawala nominal unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Amount(u64);

impl Amount {
    /// The additive identity.
    pub const ZERO: Amount = Amount(0);

    /// Wrap a raw `u64`.
    pub const fn new(value: u64) -> Self {
        Amount(value)
    }

    /// The raw value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Checked addition.
    pub fn checked_add(self, other: Self) -> Result<Self, LedgerError> {
        self.0
            .checked_add(other.0)
            .map(Amount)
            .ok_or(LedgerError::Overflow)
    }

    /// Checked subtraction; a negative result is an error.
    pub fn checked_sub(self, other: Self) -> Result<Self, LedgerError> {
        self.0
            .checked_sub(other.0)
            .map(Amount)
            .ok_or(LedgerError::Overflow)
    }

    /// Checked multiplication.
    pub fn checked_mul(self, other: Self) -> Result<Self, LedgerError> {
        self.0
            .checked_mul(other.0)
            .map(Amount)
            .ok_or(LedgerError::Overflow)
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for Amount {
    fn from(value: u64) -> Self {
        Amount(value)
    }
}

/// A signed quantity: a posting delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SignedAmount(i64);

impl SignedAmount {
    /// The additive identity.
    pub const ZERO: SignedAmount = SignedAmount(0);

    /// Wrap a raw `i64`.
    pub const fn new(value: i64) -> Self {
        SignedAmount(value)
    }

    /// The raw value.
    pub const fn get(self) -> i64 {
        self.0
    }

    /// Convert a non-negative [`Amount`] into a `SignedAmount`.
    ///
    /// Fails with [`LedgerError::Overflow`] when the amount exceeds
    /// [`i64::MAX`].
    pub fn from_amount(amount: Amount) -> Result<Self, LedgerError> {
        i64::try_from(amount.get())
            .map(SignedAmount)
            .map_err(|_| LedgerError::Overflow)
    }

    /// Checked absolute value.
    ///
    /// Fails with [`LedgerError::Overflow`] for [`i64::MIN`], whose magnitude
    /// is not representable.
    pub fn abs(self) -> Result<Self, LedgerError> {
        self.0
            .checked_abs()
            .map(SignedAmount)
            .ok_or(LedgerError::Overflow)
    }

    /// Checked negation.
    ///
    /// Fails with [`LedgerError::Overflow`] for [`i64::MIN`].
    // Named `neg` by the frozen ledger API; it is fallible, so it cannot be
    // the infallible `std::ops::Neg::neg`.
    #[allow(clippy::should_implement_trait)]
    pub fn neg(self) -> Result<Self, LedgerError> {
        self.0
            .checked_neg()
            .map(SignedAmount)
            .ok_or(LedgerError::Overflow)
    }

    /// Checked addition.
    pub fn checked_add(self, other: Self) -> Result<Self, LedgerError> {
        self.0
            .checked_add(other.0)
            .map(SignedAmount)
            .ok_or(LedgerError::Overflow)
    }

    /// Checked subtraction.
    pub fn checked_sub(self, other: Self) -> Result<Self, LedgerError> {
        self.0
            .checked_sub(other.0)
            .map(SignedAmount)
            .ok_or(LedgerError::Overflow)
    }

    /// Checked multiplication.
    pub fn checked_mul(self, other: Self) -> Result<Self, LedgerError> {
        self.0
            .checked_mul(other.0)
            .map(SignedAmount)
            .ok_or(LedgerError::Overflow)
    }
}

impl fmt::Display for SignedAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<i64> for SignedAmount {
    fn from(value: i64) -> Self {
        SignedAmount(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amount_basics() {
        assert_eq!(Amount::ZERO.get(), 0);
        assert_eq!(Amount::new(7).get(), 7);
        assert_eq!(Amount::new(7).to_string(), "7");
        assert_eq!(Amount::new(3).checked_add(Amount::new(4)).unwrap().get(), 7);
        assert_eq!(
            Amount::new(3).checked_sub(Amount::new(4)),
            Err(LedgerError::Overflow)
        );
        assert_eq!(
            Amount::new(3).checked_mul(Amount::new(4)).unwrap().get(),
            12
        );
    }

    #[test]
    fn amount_overflow_is_an_error() {
        let max = Amount::new(u64::MAX);
        assert_eq!(max.checked_add(Amount::new(1)), Err(LedgerError::Overflow));
        assert_eq!(max.checked_mul(Amount::new(2)), Err(LedgerError::Overflow));
    }

    #[test]
    fn signed_amount_basics() {
        assert_eq!(SignedAmount::new(-5).get(), -5);
        assert_eq!(SignedAmount::ZERO.get(), 0);
        assert_eq!(SignedAmount::from_amount(Amount::new(9)).unwrap().get(), 9);
        assert_eq!(SignedAmount::new(-9).abs().unwrap().get(), 9);
        assert_eq!(SignedAmount::new(9).neg().unwrap().get(), -9);
        assert_eq!(SignedAmount::new(-9).to_string(), "-9");
        assert_eq!(
            SignedAmount::new(2)
                .checked_add(SignedAmount::new(3))
                .unwrap()
                .get(),
            5
        );
    }

    #[test]
    fn signed_amount_overflow_is_an_error() {
        let over = Amount::new(i64::MAX as u64 + 1);
        assert_eq!(SignedAmount::from_amount(over), Err(LedgerError::Overflow));

        assert_eq!(
            SignedAmount::new(i64::MAX).checked_add(SignedAmount::new(1)),
            Err(LedgerError::Overflow)
        );
        assert_eq!(
            SignedAmount::new(i64::MIN).checked_sub(SignedAmount::new(1)),
            Err(LedgerError::Overflow)
        );
        assert_eq!(
            SignedAmount::new(i64::MAX).checked_mul(SignedAmount::new(2)),
            Err(LedgerError::Overflow)
        );
        assert_eq!(
            SignedAmount::new(i64::MIN).neg(),
            Err(LedgerError::Overflow)
        );
        assert_eq!(
            SignedAmount::new(i64::MIN).abs(),
            Err(LedgerError::Overflow)
        );
    }

    #[test]
    fn serde_round_trip() {
        let a = Amount::new(42);
        let back: Amount = postcard::from_bytes(&postcard::to_allocvec(&a).unwrap()).unwrap();
        assert_eq!(a, back);

        let s = SignedAmount::new(-42);
        let back: SignedAmount = postcard::from_bytes(&postcard::to_allocvec(&s).unwrap()).unwrap();
        assert_eq!(s, back);
    }
}
