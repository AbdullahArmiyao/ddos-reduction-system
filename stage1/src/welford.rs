// =============================================================================
// welford.rs — Welford Online Variance Accumulator
// =============================================================================
//
// PURPOSE
// -------
// Tracks a running mean (μ) and variance (σ²) for a stream of scalar samples
// using Welford's numerically stable one-pass algorithm.
//
// WHY WELFORD, NOT NAIVE VARIANCE?
// ---------------------------------
// Naïve running variance accumulates `sum` and `sum_of_squares`, then computes
// `variance = (sum_sq - sum²/n) / n`. On large streams this causes catastrophic
// cancellation — two huge numbers almost cancelling, leaving a near-zero
// (or even negative) result. Welford avoids this by working only with small
// deltas relative to the running mean.
//
// THE TWO-DELTA TRICK (why delta and delta2 both exist)
// -------------------------------------------------------
//   delta  = x - mean_OLD   ← surprise relative to where we *were*
//   mean  += delta / n       ← centre shifts toward x
//   delta2 = x - mean_NEW   ← surprise relative to where we *are now*
//   M2    += delta * delta2  ← geometric cross-product keeps M2 exact
//
// Multiplying delta×delta2 algebraically transitions the sum-of-squares from
// the old mean to the new mean in a single step with no stored history.
//
// RECENCY (CAPPED n)
// -------------------
// A gateway running for days would accumulate n → ∞. When n is huge the nudge
// factor (delta/n) approaches zero and the mean becomes frozen — the algorithm
// can't react to a new DDoS pattern quickly enough. To preserve recency memory
// the accumulator caps `n` at `max_n`. Once capped every new sample still runs
// the full Welford update but the denominator stays ≤ max_n so the mean keeps
// tracking recent drift.
//
// GOLDEN TEST VECTOR (must reproduce exactly)
// --------------------------------------------
//   Input: [4.0, 7.0, 13.0, 16.0] → mean = 10.0, variance ≈ 30.0
// =============================================================================

/// How many Welford windows to accumulate before the running stats are
/// considered "warm" enough to trust for anomaly decisions.
/// During warm-up Layer 3 will not fire even if thresholds are breached.
pub const WARMUP_WINDOWS: u64 = 200;

/// Maximum `n` the accumulator will count to before capping.  
/// This limits how "frozen" the mean can become over a long-running session
/// (the "recency memory" cap described in the architecture notes).
pub const MAX_N: u64 = 500;

// -----------------------------------------------------------------------------
// WelfordAccumulator
// -----------------------------------------------------------------------------

/// Incrementally tracks mean and variance for a stream of `f64` samples.
///
/// Fields are `pub` so the IPC serialisation layer can read them directly
/// without going through a getter each packet cycle.
#[derive(Debug, Clone)]
pub struct WelfordAccumulator {
    /// Number of samples seen so far (capped at `max_n` for recency).
    pub n: u64,
    /// Running mean (μ).
    pub mean: f64,
    /// Running sum-of-squared-deviations (M2 in Welford notation).
    /// `variance = M2 / (n - 1)` once n ≥ 2.
    pub m2: f64,
    /// Upper cap on `n` to preserve recency sensitivity.
    max_n: u64,
}

impl WelfordAccumulator {
    /// Create a new accumulator with a custom recency cap.
    /// For most gateway uses, prefer `WelfordAccumulator::default()`.
    pub fn new(max_n: u64) -> Self {
        Self {
            n: 0,
            mean: 0.0,
            m2: 0.0,
            max_n,
        }
    }

    /// Ingest one new scalar sample and update mean + M2.
    ///
    /// This is the *only* operation the rest of the code calls on this struct.
    /// Everything else (variance, std_dev, threshold) is a derived read.
    pub fn update(&mut self, x: f64) {
        // Increment sample counter, but never exceed the recency cap.
        // When we hit the cap we still run the full Welford update — the only
        // difference is the nudge factor (delta/n) stays at 1/max_n, which
        // keeps the mean responsive to recent traffic rather than frozen at a
        // historical average built up over millions of windows.
        let at_cap = self.n >= self.max_n;
        self.n = (self.n + 1).min(self.max_n);

        // Step 1 — First deviation: how surprised are we *before* the mean moves?
        let delta = x - self.mean;

        // Step 2 — Shift the centre toward x.
        self.mean += delta / self.n as f64;

        // Step 3 — Second deviation: how far is x from the *new* centre?
        let delta2 = x - self.mean;

        // Step 4 — Accumulate the cross-product into M2.
        // The product delta×delta2 is the exact correction needed to transition
        // the sum of squares from the old mean to the new mean without storing
        // any past data. A perfectly average sample contributes 0×0 = 0.
        if at_cap {
            // Apply exponential decay to M2 to match the recency cap of the mean.
            // This prevents M2 (and thus variance/std_dev) from growing to infinity
            // over a long-running session.
            self.m2 = self.m2 * (1.0 - 1.0 / self.max_n as f64) + delta * delta2;
        } else {
            self.m2 += delta * delta2;
        }
    }

    /// Population variance (σ²) using Bessel's correction (n−1).
    ///
    /// Returns `None` if fewer than 2 samples have been seen (division by zero
    /// risk) or if M2 has gone negative due to floating-point noise near zero.
    pub fn variance(&self) -> Option<f64> {
        if self.n < 2 {
            return None;
        }
        let v = self.m2 / (self.n - 1) as f64;
        if v < 0.0 { None } else { Some(v) }
    }

    /// Standard deviation (σ = √variance).
    ///
    /// Returns `0.0` if variance is not yet available (warm-up period).
    pub fn std_dev(&self) -> f64 {
        self.variance().map(|v| v.sqrt()).unwrap_or(0.0)
    }

    /// Upper anomaly boundary: μ + k·σ
    ///
    /// Used by the EWMA rate accumulator — a spike *above* this boundary
    /// means the packet rate has surged beyond normal levels.
    pub fn upper_boundary(&self, k: f64) -> f64 {
        self.mean + k * self.std_dev()
    }

    /// Lower anomaly boundary: μ − k·σ
    ///
    /// Used by the entropy accumulator — a drop *below* this boundary
    /// means traffic sources have become abnormally concentrated (DDoS pattern).
    pub fn lower_boundary(&self, k: f64) -> f64 {
        self.mean - k * self.std_dev()
    }

    /// Returns `true` once the accumulator has seen enough windows to be
    /// trusted for anomaly decisions (see `WARMUP_WINDOWS`).
    pub fn is_warm(&self) -> bool {
        self.n >= WARMUP_WINDOWS
    }

    /// Reset all state (used in unit tests and optional periodic re-baseline).
    pub fn reset(&mut self) {
        self.n    = 0;
        self.mean = 0.0;
        self.m2   = 0.0;
    }
}

impl Default for WelfordAccumulator {
    fn default() -> Self {
        Self::new(MAX_N)
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden test vector from the architecture spec.
    /// Input  : [4, 7, 13, 16]
    /// Expected: mean = 10.0,  variance = 30.0  (population Bessel-corrected)
    #[test]
    fn golden_test_vector() {
        let mut acc = WelfordAccumulator::default();
        for &x in &[4.0_f64, 7.0, 13.0, 16.0] {
            acc.update(x);
        }
        // Mean must be exactly 10.0 (no floating-point excuse here)
        assert!((acc.mean - 10.0).abs() < 1e-10, "mean mismatch: {}", acc.mean);

        // Variance must be 30.0 ± tiny epsilon
        let var = acc.variance().expect("variance should be Some after 4 samples");
        assert!((var - 30.0).abs() < 1e-10, "variance mismatch: {var}");
    }

    /// A single perfectly average sample contributes zero variance.
    #[test]
    fn single_sample_no_variance() {
        let mut acc = WelfordAccumulator::default();
        acc.update(42.0);
        assert_eq!(acc.n, 1);
        assert_eq!(acc.variance(), None); // need at least 2 samples
    }

    /// Two identical values → zero variance.
    #[test]
    fn identical_samples_zero_variance() {
        let mut acc = WelfordAccumulator::default();
        acc.update(5.0);
        acc.update(5.0);
        let var = acc.variance().unwrap();
        assert!(var.abs() < 1e-12, "expected ~0 variance, got {var}");
    }

    /// Recency cap: n must never exceed max_n.
    #[test]
    fn recency_cap_respected() {
        let max = 10_u64;
        let mut acc = WelfordAccumulator::new(max);
        for i in 0..100 {
            acc.update(i as f64);
        }
        assert_eq!(acc.n, max, "n exceeded the recency cap");
    }

    /// Upper / lower boundary helpers are symmetric around mean.
    #[test]
    fn boundary_helpers() {
        let mut acc = WelfordAccumulator::default();
        for &x in &[4.0_f64, 7.0, 13.0, 16.0] {
            acc.update(x);
        }
        let k = 2.0;
        let sd = acc.std_dev();
        assert!((acc.upper_boundary(k) - (10.0 + k * sd)).abs() < 1e-10);
        assert!((acc.lower_boundary(k) - (10.0 - k * sd)).abs() < 1e-10);
    }

    /// Warmup flag is false until WARMUP_WINDOWS samples have been fed.
    #[test]
    fn warmup_flag() {
        let mut acc = WelfordAccumulator::new(1000);
        for i in 0..(WARMUP_WINDOWS - 1) {
            acc.update(i as f64);
            assert!(!acc.is_warm(), "should not be warm at n={}", i + 1);
        }
        acc.update(99.0);
        assert!(acc.is_warm(), "should be warm after {} samples", WARMUP_WINDOWS);
    }
}
