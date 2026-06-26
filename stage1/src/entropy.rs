// =============================================================================
// entropy.rs — Shannon Source-IP Entropy Calculator
// =============================================================================
//
// PURPOSE
// -------
// Computes the Shannon Entropy of the source IP distribution inside one
// 50-packet window.  The resulting scalar `h` is the "diversity score" that
// flows into the Welford accumulator (Layer 2 → Layer 3) after every window.
//
// WHY ENTROPY, NOT UNIQUE IP COUNT?
// ------------------------------------
// Two windows can have identical unique IP counts yet completely different
// threat profiles:
//
//   Window A: 10 unique IPs, one appears 41 times → concentration → DDoS
//   Window B: 10 unique IPs, each appears 5 times  → even spread → normal
//
// Shannon Entropy H(X) = −Σ p(x)·log₂p(x) captures the full *shape* of the
// probability distribution, not just its cardinality.  It returns a single
// scalar between 0.0 (total concentration) and log₂(n) ≈ 5.64 bits (50
// perfectly distinct IPs), giving Layer 3 a meaningful quantity to compare.
//
// RESET BEHAVIOUR
// ----------------
// Unlike EWMA (which carries memory across windows), entropy is computed fresh
// from a HashMap that is **cleared after every window close**.  This is correct:
// entropy measures the diversity of the *current* window, not a long-run trend.
// The long-run trend is tracked by the Welford accumulator upstream.
//
// IMPLEMENTATION NOTES
// ----------------------
// • Uses `std::collections::HashMap<IpAddr, u32>` for frequency counting.
// • Recomputes from scratch each window — this is O(n) in window size (50
//   packets), which is negligible. No incremental update needed.
// • Uses only standard library: `HashMap`, `f64::log2()`.  No external crates.
// • BPF filter (`dst host <victim_ip>`) is applied at the `pcap` level before
//   this module ever sees a packet, so all IPs counted here are *source* IPs
//   of inbound traffic only.
//
// RANGE REFERENCE
// ----------------
//   Window size = 50 packets (WINDOW_SIZE constant)
//   Minimum entropy = 0.0   (all 50 packets from one IP)
//   Maximum entropy ≈ 5.64  (50 packets from 50 unique IPs, log₂(50))
// =============================================================================

use std::{collections::HashMap, net::IpAddr};

/// Number of packets per analysis window.
///
/// This constant is the single source of truth for window sizing across the
/// entire Stage 1 codebase. Both the entropy calculator and the main capture
/// loop use it to decide when a window has closed.
pub const WINDOW_SIZE: usize = 50;

// -----------------------------------------------------------------------------
// EntropyAccumulator
// -----------------------------------------------------------------------------

/// Accumulates source IPs over one window and computes Shannon Entropy on close.
///
/// Lifecycle per window:
///   1. Call `add_packet(src_ip)` for each of the 50 arriving packets.
///   2. When `is_window_full()` returns `true`, call `compute_and_reset()`.
///   3. The returned `f64` is the entropy scalar `h` to pass to Welford.
///   4. The HashMap and counter are cleared internally by `compute_and_reset()`.
#[derive(Debug, Default)]
pub struct EntropyAccumulator {
    /// Frequency count of each unique source IP seen in the current window.
    /// Cleared after every `compute_and_reset()` call.
    counts: HashMap<IpAddr, u32>,
    /// Number of packets accumulated in the current window (0..=WINDOW_SIZE).
    packet_count: usize,
}

impl EntropyAccumulator {
    /// Create a new, empty accumulator (window not started yet).
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one packet's source IP in the current window.
    ///
    /// Must be called per-packet from the analysis thread's main loop.
    /// Silently ignores calls once `WINDOW_SIZE` is reached — the caller
    /// should check `is_window_full()` first and call `compute_and_reset()`
    /// before ingesting the next packet.
    pub fn add_packet(&mut self, src_ip: IpAddr) {
        if self.packet_count < WINDOW_SIZE {
            // Increment the count for this IP (or insert 1 if first time seen).
            *self.counts.entry(src_ip).or_insert(0) += 1;
            self.packet_count += 1;
        }
    }

    /// Returns `true` when exactly `WINDOW_SIZE` packets have been recorded.
    pub fn is_window_full(&self) -> bool {
        self.packet_count >= WINDOW_SIZE
    }

    /// Compute Shannon Entropy over the current window, then reset state.
    ///
    /// # Returns
    /// The entropy scalar `h` in bits (range `[0.0, log₂(WINDOW_SIZE)]`).
    /// Returns `0.0` if the window is empty (should not happen in normal use).
    ///
    /// # Side Effect
    /// Clears `self.counts` and resets `self.packet_count` to zero so the
    /// accumulator is ready for the next 50-packet window immediately.
    pub fn compute_and_reset(&mut self) -> f64 {
        let h = compute_entropy(&self.counts, self.packet_count);
        // Reset for next window — O(capacity) clear keeps the HashMap allocation
        // alive to avoid repeated heap allocations across windows.
        self.counts.clear();
        self.packet_count = 0;
        h
    }

    /// Peek at the current packet count without consuming the window.
    /// Useful for the analysis thread's progress logging.
    pub fn packet_count(&self) -> usize {
        self.packet_count
    }
}

// -----------------------------------------------------------------------------
// Core entropy computation (pure function — testable without network traffic)
// -----------------------------------------------------------------------------

/// Compute Shannon Entropy from a frequency map and total packet count.
///
/// H(X) = −Σ p(xᵢ) · log₂(p(xᵢ))
///
/// where p(xᵢ) = count(xᵢ) / total_packets
///
/// This is a standalone pure function so unit tests can drive it directly
/// with crafted frequency maps without needing an `EntropyAccumulator`.
///
/// # Arguments
/// * `counts`       — HashMap mapping each unique IP to its frequency.
/// * `total_packets`— Total number of packets in the window (= Σ counts).
///
/// # Returns
/// Entropy in bits.  Returns `0.0` if `total_packets` is 0.
pub fn compute_entropy(counts: &HashMap<IpAddr, u32>, total_packets: usize) -> f64 {
    if total_packets == 0 {
        return 0.0;
    }

    let n = total_packets as f64;

    counts
        .values()
        .filter(|&&c| c > 0) // defensive: skip zero-count entries
        .map(|&c| {
            // Probability of this IP class in the current window.
            let p = c as f64 / n;
            // Each term of the Shannon sum: −p · log₂(p).
            // log₂(0) would be −∞, but p > 0 is guaranteed by the filter above.
            -p * p.log2()
        })
        .sum()
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// Helper to build an IpAddr::V4 quickly in tests.
    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    // -------------------------------------------------------------------------
    // compute_entropy pure function tests
    // -------------------------------------------------------------------------

    /// All packets from a single IP → entropy must be exactly 0.0.
    #[test]
    fn single_source_zero_entropy() {
        let mut counts = HashMap::new();
        counts.insert(ip(1, 0, 0, 1), 50);
        let h = compute_entropy(&counts, 50);
        assert!(
            h.abs() < 1e-10,
            "single-source entropy should be 0.0, got {h}"
        );
    }

    /// All 50 packets from 50 unique IPs → maximum entropy ≈ log₂(50) ≈ 5.644.
    #[test]
    fn uniform_distribution_maximum_entropy() {
        let mut counts = HashMap::new();
        for i in 0..50_u8 {
            counts.insert(ip(10, 0, 0, i), 1);
        }
        let h        = compute_entropy(&counts, 50);
        let expected = (50_f64).log2(); // ≈ 5.6439
        assert!(
            (h - expected).abs() < 1e-6,
            "uniform entropy mismatch: expected {expected:.6}, got {h:.6}"
        );
    }

    /// Two equally likely IPs → entropy = log₂(2) = 1.0 exactly.
    #[test]
    fn two_equal_sources_one_bit() {
        let mut counts = HashMap::new();
        counts.insert(ip(192, 168, 1, 1), 25);
        counts.insert(ip(192, 168, 1, 2), 25);
        let h = compute_entropy(&counts, 50);
        assert!(
            (h - 1.0).abs() < 1e-10,
            "expected exactly 1.0 bit, got {h}"
        );
    }

    /// Empty map → 0.0 (no divide-by-zero).
    #[test]
    fn empty_window_returns_zero() {
        let counts = HashMap::new();
        let h = compute_entropy(&counts, 0);
        assert_eq!(h, 0.0);
    }

    // -------------------------------------------------------------------------
    // EntropyAccumulator integration tests
    // -------------------------------------------------------------------------

    /// Window fills correctly and compute_and_reset returns expected scalar.
    #[test]
    fn accumulator_fills_and_resets() {
        let mut acc = EntropyAccumulator::new();

        // Feed 50 packets from 2 IPs (25 each) → should return 1.0 bit.
        for i in 0..50 {
            let src = if i < 25 { ip(10, 0, 0, 1) } else { ip(10, 0, 0, 2) };
            acc.add_packet(src);
        }

        assert!(acc.is_window_full());
        let h = acc.compute_and_reset();
        assert!((h - 1.0).abs() < 1e-10, "expected 1.0 bit, got {h}");

        // After reset: window must be empty and ready for next window.
        assert_eq!(acc.packet_count(), 0);
        assert!(!acc.is_window_full());
    }

    /// Calls beyond WINDOW_SIZE are silently dropped (no panic, no over-count).
    #[test]
    fn extra_packets_are_dropped() {
        let mut acc = EntropyAccumulator::new();
        let src = ip(172, 16, 0, 1);
        for _ in 0..60 {
            // Feed 10 extra packets beyond the window
            acc.add_packet(src);
        }
        // Packet count must not exceed WINDOW_SIZE.
        assert_eq!(acc.packet_count(), WINDOW_SIZE);
    }

    /// Back-to-back windows work correctly (reset clears state fully).
    #[test]
    fn two_consecutive_windows() {
        let mut acc = EntropyAccumulator::new();

        // Window 1: all from one IP → entropy = 0.
        for _ in 0..WINDOW_SIZE {
            acc.add_packet(ip(1, 1, 1, 1));
        }
        let h1 = acc.compute_and_reset();
        assert!(h1.abs() < 1e-10, "window 1 entropy should be 0.0, got {h1}");

        // Window 2: uniform 50 unique IPs → entropy ≈ 5.644.
        for i in 0..50_u8 {
            acc.add_packet(ip(2, 0, 0, i));
        }
        let h2 = acc.compute_and_reset();
        assert!(
            h2 > 5.0,
            "window 2 entropy should be near 5.644, got {h2}"
        );
    }
}
