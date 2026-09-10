//! Bounded, in-memory replay defense.
//!
//! [`SeenSet`] remembers recently observed `(origin, msg_id)` pairs and answers
//! [`Seen::Fresh`] or [`Seen::Duplicate`]. It is deliberately simple and
//! wasm-safe: no clocks, no persistence, no background eviction. Ordering is
//! count-based (a monotonic counter stands in for time), so behavior is fully
//! reproducible.
//!
//! This is best-effort only. It forgets under memory pressure, and a malicious
//! relay can bypass it entirely by re-originating a frame. It must never be
//! used as a security boundary — see the crate docs.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::envelope::MsgId;

/// Bounds for a [`SeenSet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeenConfig {
    /// Maximum remembered ids per origin (FIFO eviction).
    pub max_per_origin: usize,
    /// Maximum tracked origins (least-recently-touched eviction).
    pub max_origins: usize,
}

impl Default for SeenConfig {
    fn default() -> Self {
        SeenConfig {
            max_per_origin: 1024,
            max_origins: 256,
        }
    }
}

/// The result of observing a message id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seen {
    /// Not seen before; it has now been recorded.
    Fresh,
    /// Already recorded for this origin.
    Duplicate,
}

/// Per-origin window: a membership set plus FIFO insertion order and the last
/// time the origin was touched (for cross-origin eviction).
#[derive(Debug)]
struct OriginWindow {
    set: HashSet<MsgId>,
    order: VecDeque<MsgId>,
    last_touch: u64,
}

/// Bounded replay-detection set.
#[derive(Debug)]
pub struct SeenSet {
    config: SeenConfig,
    origins: HashMap<String, OriginWindow>,
    tick: u64,
}

impl SeenSet {
    /// Create an empty set with the given bounds.
    pub fn new(config: SeenConfig) -> Self {
        SeenSet {
            config,
            origins: HashMap::new(),
            tick: 0,
        }
    }

    /// Observe `(origin, msg_id)`.
    ///
    /// Returns [`Seen::Fresh`] the first time a pair is seen (recording it)
    /// and [`Seen::Duplicate`] thereafter. A zero bound (`max_origins == 0` or
    /// `max_per_origin == 0`) means "track nothing": every observation is
    /// [`Seen::Fresh`] and nothing is stored. Per-origin ids are evicted FIFO
    /// once `max_per_origin` is reached; when a new origin would exceed
    /// `max_origins`, the least-recently-touched origin is dropped.
    pub fn observe(&mut self, origin: &str, msg_id: MsgId) -> Seen {
        // Zero bounds mean "track nothing": never store, always report Fresh.
        if self.config.max_origins == 0 || self.config.max_per_origin == 0 {
            return Seen::Fresh;
        }
        self.tick = self.tick.wrapping_add(1);
        let now = self.tick;

        if let Some(window) = self.origins.get_mut(origin) {
            window.last_touch = now;
            if window.set.contains(&msg_id) {
                return Seen::Duplicate;
            }
            window.set.insert(msg_id);
            window.order.push_back(msg_id);
            if window.order.len() > self.config.max_per_origin
                && let Some(old) = window.order.pop_front()
            {
                window.set.remove(&old);
            }
            return Seen::Fresh;
        }

        // A new origin: make room first if we are at capacity.
        if self.origins.len() >= self.config.max_origins {
            let lru = self
                .origins
                .iter()
                .min_by_key(|(_, w)| w.last_touch)
                .map(|(k, _)| k.clone());
            if let Some(key) = lru {
                self.origins.remove(&key);
            }
        }

        // `max_per_origin >= 1` here, so the single id always fits.
        let mut set = HashSet::new();
        set.insert(msg_id);
        let mut order = VecDeque::new();
        order.push_back(msg_id);
        self.origins.insert(
            origin.to_string(),
            OriginWindow {
                set,
                order,
                last_touch: now,
            },
        );
        Seen::Fresh
    }

    /// Remove `(origin, msg_id)` if present.
    ///
    /// Used to roll back a mark when processing failed transiently, so a retry
    /// is not spuriously reported as [`Seen::Duplicate`]. If the origin's
    /// window becomes empty it is dropped entirely (reducing
    /// [`SeenSet::origin_count`]).
    pub fn unobserve(&mut self, origin: &str, msg_id: MsgId) {
        let Some(window) = self.origins.get_mut(origin) else {
            return;
        };
        if window.set.remove(&msg_id) {
            window.order.retain(|id| *id != msg_id);
        }
        let empty = window.set.is_empty();
        if empty {
            self.origins.remove(origin);
        }
    }

    /// Number of origins currently tracked.
    pub fn origin_count(&self) -> usize {
        self.origins.len()
    }

    /// Number of ids remembered for `origin` (0 if unknown).
    pub fn origin_len(&self, origin: &str) -> usize {
        self.origins.get(origin).map_or(0, |w| w.set.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seen_fresh_then_duplicate() {
        let mut set = SeenSet::new(SeenConfig::default());
        let id = MsgId([1; 16]);
        assert_eq!(set.observe("n1", id), Seen::Fresh);
        assert_eq!(set.observe("n1", id), Seen::Duplicate);
        assert_eq!(set.observe("n1", id), Seen::Duplicate);
        assert_eq!(set.origin_count(), 1);
        assert_eq!(set.origin_len("n1"), 1);
    }

    #[test]
    fn seen_per_origin_independent() {
        let mut set = SeenSet::new(SeenConfig::default());
        let id = MsgId([2; 16]);
        assert_eq!(set.observe("a", id), Seen::Fresh);
        assert_eq!(set.observe("b", id), Seen::Fresh);
        assert_eq!(set.observe("a", id), Seen::Duplicate);
        assert_eq!(set.observe("b", id), Seen::Duplicate);
        assert_eq!(set.origin_count(), 2);
        assert_eq!(set.origin_len("a"), 1);
        assert_eq!(set.origin_len("b"), 1);
    }

    #[test]
    fn seen_evicts_oldest_entry_per_origin() {
        let mut set = SeenSet::new(SeenConfig {
            max_per_origin: 2,
            max_origins: 8,
        });
        let a = MsgId([1; 16]);
        let b = MsgId([2; 16]);
        let c = MsgId([3; 16]);
        assert_eq!(set.observe("o", a), Seen::Fresh);
        assert_eq!(set.observe("o", b), Seen::Fresh);
        assert_eq!(set.observe("o", c), Seen::Fresh); // evicts a
        assert_eq!(set.origin_len("o"), 2);
        // a was the oldest and is forgotten, so it is Fresh again.
        assert_eq!(set.observe("o", a), Seen::Fresh); // evicts b
        assert_eq!(set.origin_len("o"), 2);
        assert_eq!(set.observe("o", c), Seen::Duplicate);
    }

    #[test]
    fn seen_evicts_least_recent_origin() {
        let mut set = SeenSet::new(SeenConfig {
            max_per_origin: 8,
            max_origins: 2,
        });
        let id = MsgId([1; 16]);
        assert_eq!(set.observe("a", id), Seen::Fresh);
        assert_eq!(set.observe("b", id), Seen::Fresh);
        assert_eq!(set.observe("a", id), Seen::Duplicate); // refreshes a
        assert_eq!(set.observe("c", id), Seen::Fresh); // evicts b (older touch)
        assert_eq!(set.origin_count(), 2);
        // a survived; b was the least recently touched and is forgotten.
        assert_eq!(set.observe("a", id), Seen::Duplicate);
        assert_eq!(set.observe("b", id), Seen::Fresh);
    }

    #[test]
    fn unobserve_allows_retry() {
        let mut set = SeenSet::new(SeenConfig::default());
        let id = MsgId([7; 16]);
        assert_eq!(set.observe("o", id), Seen::Fresh);
        assert_eq!(set.observe("o", id), Seen::Duplicate);

        set.unobserve("o", id);
        // The window became empty and was dropped.
        assert_eq!(set.origin_count(), 0);

        // A retry after rollback is Fresh again.
        assert_eq!(set.observe("o", id), Seen::Fresh);
        assert_eq!(set.origin_len("o"), 1);
    }

    #[test]
    fn unobserve_unknown_is_noop() {
        let mut set = SeenSet::new(SeenConfig::default());
        // Unknown origin is a no-op.
        set.unobserve("never", MsgId([8; 16]));
        assert_eq!(set.origin_count(), 0);

        // Unknown id under a known origin is a no-op.
        let known = MsgId([9; 16]);
        assert_eq!(set.observe("known", known), Seen::Fresh);
        set.unobserve("known", MsgId([10; 16]));
        assert_eq!(set.origin_len("known"), 1);
        assert_eq!(set.origin_count(), 1);
        assert_eq!(set.observe("known", known), Seen::Duplicate);
    }

    #[test]
    fn seen_max_origins_zero_tracks_nothing() {
        let mut set = SeenSet::new(SeenConfig {
            max_per_origin: 4,
            max_origins: 0,
        });
        let id = MsgId([1; 16]);
        assert_eq!(set.observe("o", id), Seen::Fresh);
        assert_eq!(set.observe("o", id), Seen::Fresh);
        assert_eq!(set.origin_count(), 0);
        assert_eq!(set.origin_len("o"), 0);
    }

    #[test]
    fn seen_max_per_origin_zero_tracks_nothing() {
        let mut set = SeenSet::new(SeenConfig {
            max_per_origin: 0,
            max_origins: 4,
        });
        let id = MsgId([1; 16]);
        assert_eq!(set.observe("o", id), Seen::Fresh);
        assert_eq!(set.observe("o", id), Seen::Fresh);
        assert_eq!(set.origin_count(), 0);
        assert_eq!(set.origin_len("o"), 0);
    }
}
