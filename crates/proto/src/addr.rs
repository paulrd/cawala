//! Octal hierarchical addresses (`OctAddr`).
//!
//! An address is a dotted string of one octal digit per tree level, e.g.
//! `"0.3.5.2"`. The root is `"0"` and every address descends from it, so the
//! first component is always `0`. Geographic containment is automatic: a
//! descendant's address is a strict prefix extension of its ancestors'.
//!
//! This module is WASM-safe: `std` + `serde` only (no tokio, no iroh).

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Largest valid octal slot digit (7, i.e. at most 8 children per node).
pub const MAX_SLOT: u8 = 7;

/// An octal hierarchical address.
///
/// One byte per level, each in `0..=MAX_SLOT`. Invariants enforced by every
/// constructor: non-empty, first digit `0` (every address descends from the
/// root `"0"`), all digits `0..=MAX_SLOT`. There is no depth limit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OctAddr(Vec<u8>);

impl OctAddr {
    /// Build an address from digits. Returns `None` if the digits are empty,
    /// the first digit is not `0`, or any digit exceeds [`MAX_SLOT`].
    pub fn from_digits(digits: impl Into<Vec<u8>>) -> Option<OctAddr> {
        let digits = digits.into();
        if digits.is_empty() || digits[0] != 0 || digits.iter().any(|&d| d > MAX_SLOT) {
            return None;
        }
        Some(OctAddr(digits))
    }

    /// Number of levels (digits). The root has depth 1.
    pub fn depth(&self) -> usize {
        self.0.len()
    }

    /// Whether this is the root address `"0"`.
    pub fn is_root(&self) -> bool {
        self.depth() == 1 // the first digit is always 0
    }

    /// The deepest digit: this node's slot within its parent.
    /// `None` for the root, which has no parent slot.
    pub fn slot(&self) -> Option<u8> {
        if self.is_root() {
            None
        } else {
            Some(self.0[self.0.len() - 1])
        }
    }

    /// Parent address (the deepest digit removed). `None` for the root.
    pub fn parent(&self) -> Option<OctAddr> {
        if self.is_root() {
            return None;
        }
        let mut v = self.0.clone();
        v.pop();
        Some(OctAddr(v))
    }

    /// The address of a child in the given octal slot. The caller must pass
    /// `slot <= MAX_SLOT` (debug builds panic otherwise).
    pub fn child(&self, slot: u8) -> OctAddr {
        debug_assert!(slot <= MAX_SLOT, "octal slot {slot} out of range");
        let mut v = self.0.clone();
        v.push(slot);
        OctAddr(v)
    }

    /// Strict prefix test: `self` is a strict ancestor of `other`.
    pub fn is_ancestor_of(&self, other: &OctAddr) -> bool {
        self.depth() < other.depth() && other.0.starts_with(&self.0)
    }

    /// Strict prefix test: `self` is a strict descendant of `other`.
    pub fn is_descendant_of(&self, other: &OctAddr) -> bool {
        other.is_ancestor_of(self)
    }

    /// Least common ancestor: the longest common prefix. Never empty because
    /// every address starts with `0`.
    pub fn lca(&self, other: &OctAddr) -> OctAddr {
        let n = self
            .0
            .iter()
            .zip(&other.0)
            .take_while(|(a, b)| a == b)
            .count();
        // n >= 1: both addresses start with the root digit 0.
        OctAddr(self.0[..n].to_vec())
    }

    /// The raw digits, one byte per level (each `0..=MAX_SLOT`, first is `0`).
    pub fn digits(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for OctAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, d) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            write!(f, "{d}")?;
        }
        Ok(())
    }
}

/// Error returned when parsing an invalid [`OctAddr`] string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseOctAddrError;

impl fmt::Display for ParseOctAddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "invalid octal address: expected a dotted string of octal digits (0-7), \
             starting with the root \"0\", at most 255 digits",
        )
    }
}

impl std::error::Error for ParseOctAddrError {}

impl FromStr for OctAddr {
    type Err = ParseOctAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ParseOctAddrError);
        }
        let mut digits = Vec::with_capacity(s.len().div_ceil(2));
        for (i, comp) in s.split('.').enumerate() {
            if comp.len() != 1 {
                return Err(ParseOctAddrError);
            }
            let c = comp.as_bytes()[0];
            if !(b'0'..=b'7').contains(&c) {
                return Err(ParseOctAddrError);
            }
            if i == 0 && c != b'0' {
                return Err(ParseOctAddrError);
            }
            digits.push(c - b'0');
        }
        Ok(OctAddr(digits))
    }
}

impl Serialize for OctAddr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for OctAddr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl Ord for OctAddr {
    /// Component-wise comparison, then by depth: shallower addresses sort
    /// first, e.g. `"0" < "0.3" < "0.3.5" < "0.3.5.2"`.
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for OctAddr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> OctAddr {
        s.parse().unwrap_or_else(|e| panic!("parse of {s:?} failed: {e}"))
    }

    #[test]
    fn display_round_trips() {
        for s in [
            "0",
            "0.7",
            "0.0.0.0",
            "0.3.5.2",
            "0.3.5.7.1.2.3.4.5.6.7",
        ] {
            assert_eq!(addr(s).to_string(), s);
        }
    }

    #[test]
    fn zero_components_are_legal() {
        assert_eq!(addr("0").depth(), 1);
        assert_eq!(addr("0.0").depth(), 2);
        assert_eq!(addr("0.0.0.7").to_string(), "0.0.0.7");
    }

    #[test]
    fn invalid_inputs_rejected() {
        for s in [
            "", "0.8", "0.3.5.", ".0", "0x", "0.12", "3", "3.1", "0.00", "0..1",
            "0.-1", "0. 1", "0.10", "0..", "00", "0.3.5..2",
        ] {
            assert!(
                s.parse::<OctAddr>().is_err(),
                "expected {s:?} to be rejected"
            );
        }
    }

    #[test]
    fn from_digits_validation() {
        assert_eq!(OctAddr::from_digits(vec![0]), Some(addr("0")));
        assert_eq!(
            OctAddr::from_digits(vec![0, 3, 5, 2]),
            Some(addr("0.3.5.2"))
        );
        assert_eq!(OctAddr::from_digits(Vec::<u8>::new()), None); // empty
        assert_eq!(OctAddr::from_digits(vec![3]), None); // must descend from root 0
        assert_eq!(OctAddr::from_digits(vec![0, 8]), None); // digit out of range
        assert!(OctAddr::from_digits(vec![0; 400]).is_some()); // no depth limit
    }

    #[test]
    fn root_edge_cases() {
        let root = addr("0");
        assert!(root.is_root());
        assert_eq!(root.depth(), 1);
        assert_eq!(root.slot(), None);
        assert_eq!(root.parent(), None);
        let child0 = addr("0.0");
        assert!(!child0.is_root());
        assert_eq!(child0.slot(), Some(0));
        assert_eq!(child0.parent(), Some(root));
    }

    #[test]
    fn parent_child_slot() {
        let a = addr("0.3.5.2");
        assert_eq!(a.slot(), Some(2));
        assert_eq!(a.parent(), Some(addr("0.3.5")));
        assert_eq!(a.parent().unwrap().parent(), Some(addr("0.3")));
        assert_eq!(
            a.parent().unwrap().parent().unwrap().parent(),
            Some(addr("0"))
        );
        assert_eq!(addr("0").child(3).child(5).child(2), a);
        assert_eq!(addr("0").child(7), addr("0.7"));
        assert_eq!(addr("0.3.5").child(2), a);
    }

    #[test]
    fn ancestor_descendant() {
        let p = addr("0.3");
        assert!(p.is_ancestor_of(&addr("0.3.5")));
        assert!(p.is_ancestor_of(&addr("0.3.0.1")));
        assert!(!p.is_ancestor_of(&p)); // strict
        assert!(!p.is_ancestor_of(&addr("0.4.1")));
        assert!(!p.is_ancestor_of(&addr("0")));
        assert!(p.is_descendant_of(&addr("0")));
        assert!(addr("0.3.5").is_descendant_of(&p));
        assert!(!p.is_descendant_of(&p));
        assert!(!addr("0.3.5").is_descendant_of(&addr("0.3.5.2")));
        // the root is an ancestor of every non-root address
        let root = addr("0");
        for s in ["0.0", "0.1", "0.7", "0.3.5.2"] {
            assert!(root.is_ancestor_of(&addr(s)));
        }
    }

    #[test]
    fn lca() {
        assert_eq!(addr("0.3.5.2").lca(&addr("0.3.5.7")), addr("0.3.5"));
        assert_eq!(addr("0.3.5").lca(&addr("0.3")), addr("0.3"));
        assert_eq!(addr("0.1.2").lca(&addr("0.3.4")), addr("0"));
        assert_eq!(addr("0.3.5").lca(&addr("0.3.5")), addr("0.3.5"));
        assert_eq!(addr("0").lca(&addr("0.7")), addr("0"));
        // commutative
        assert_eq!(
            addr("0.3.5").lca(&addr("0.3.7")),
            addr("0.3.7").lca(&addr("0.3.5"))
        );
    }

    #[test]
    fn ordering() {
        let mut xs = [
            addr("0.1.7"),
            addr("0.0"),
            addr("0.0.1"),
            addr("0"),
            addr("0.7"),
            addr("0.1"),
        ];
        xs.sort();
        assert_eq!(
            xs.to_vec(),
            vec![
                addr("0"),
                addr("0.0"),
                addr("0.0.1"),
                addr("0.1"),
                addr("0.1.7"),
                addr("0.7"),
            ]
        );
        // component-wise then depth
        assert!(addr("0") < addr("0.0"));
        assert!(addr("0.3") < addr("0.3.5"));
        assert!(addr("0.3.5.2") < addr("0.4"));
        assert_eq!(addr("0.1").cmp(&addr("0.1")), Ordering::Equal);
    }

    #[test]
    fn serde_wire_form_is_the_dotted_string() {
        let a = addr("0.3.5.2");
        let bytes = postcard::to_allocvec(&a).unwrap();
        // postcard serializes the address exactly like the plain string.
        assert_eq!(bytes, postcard::to_allocvec(&a.to_string()).unwrap());
        let back: OctAddr = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, a);
        // root round-trips too
        let root_bytes = postcard::to_allocvec(&addr("0")).unwrap();
        assert_eq!(root_bytes, postcard::to_allocvec(&"0".to_string()).unwrap());
    }

    #[test]
    fn serde_rejects_invalid_string() {
        let mut buf = vec![3u8]; // postcard length prefix
        buf.extend_from_slice(b"0.8");
        assert!(postcard::from_bytes::<OctAddr>(&buf).is_err());
    }
}
