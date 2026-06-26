// =============================================================================
// ewma.rs — Exponentially Weighted Moving Average (EWMA) Rate Estimator
// =============================================================================
//
// PURPOSE
// -------
// Tracks the current packet arrival *rate* (packets per second) as a smoothed
// scalar that weights recent observations more heavily than old ones.
//
// WHY EWMA, NOT A SIMPLE MOVING AVERAGE?
// ----------------------------------------
// A Simple Moving Average (SMA) weights every sample equally.  During a DDoS
// ramp-up, the SMA lags badly — it averages the flood's spike against dozens of
// calm prior windows, masking the surge. EWMA instead applies a decay factor α
// so the *most recent* inter-packet gaps dominate the estimate. The result is a
// speedometer that reacts within seconds of a flood onset.
//
// MEMORY FOOTPRINT
// ----------------
// The EWMA state is exactly one `f64` — the current smoothed estimate.  No
// ring buffer, no heap allocation, no growing history. Constant O(1) space
// regardless of how long the gateway has been running.
//
// THE FORMULA
// -----------
//   ewma_new = α · instant_rate + (1 − α) · ewma_old
//
//   where  instant_rate  = 1.0 / inter_arrival_seconds
//          α (alpha)     = smoothing factor ∈ (0, 1)
//
//   High α → fast reaction, noisier estimate.
//   Low  α → slow reaction, smoother estimate.
//
// RECOMMENDED ALPHA VALUES
// -------------------------
//   α = 0.125  (1/8)  — same constant used in TCP RTT estimators (RFC 6298)
//   α = 0.25          — more responsive; good for short-burst detection
//   α = 0.05          — very smooth; suitable for long-trend monitoring
//
// This implementation defaults to α = 0.125.
//
// IMPORTANT — EWMA NEVER RESETS
// --------------------------------
// Unlike Shannon Entropy (which is computed fresh each window from a cleared
// HashMap), the EWMA carries memory *across* windows by design.  Resetting it
// would discard the very smoothing that makes it useful for detecting flood
// ramp-ups that build across multiple windows.
//
// The analysis thread reads the current EWMA snapshot once per window close
// (Layer 2) and passes that scalar to the Welford accumulator (Layer 3).
// =============================================================================

use std::time::Instant;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default smoothing factor.  Matches the TCP RTT estimator (RFC 6298, §2).
/// Tunable via `EwmaState::with_alpha()`.
pub const DEFAULT_ALPHA: f64 = 0.125;

// -----------------------------------------------------------------------------
// EwmaState
// -----------------------------------------------------------------------------

/// Maintains the running EWMA packet-rate estimate.
///
/// Instantiate once per analysis session and call `update()` on every packet.
/// Read `snapshot()` at window close to obtain the scalar for Welford.
#[derive(Debug, Clone)]
pub struct EwmaState {
    /// Current smoothed rate estimate in packets per second.
    value: f64,
    /// Smoothing factor α ∈ (0, 1).
    alpha: f64,
    /// Timestamp of the most recently seen packet (for inter-arrival calculation).
    last_arrival: Option<Instant>,
}

impl EwmaState {
    /// Create a new EWMA state with the default alpha (`DEFAULT_ALPHA`).
    pub fn new() -> Self {
        Self {
            value:        0.0,
            alpha:        DEFAULT_ALPHA,
            last_arrival: None,
        }
    }

    /// Create a new EWMA state with a custom smoothing factor.
    ///
    /// # Panics
    /// Panics if `alpha` is not in the open interval (0, 1).
    pub fn with_alpha(alpha: f64) -> Self {
        assert!(
            alpha > 0.0 && alpha < 1.0,
            "alpha must be in (0, 1), got {alpha}"
        );
        Self {
            value:        0.0,
            alpha,
            last_arrival: None,
        }
    }

    /// Update the EWMA with the arrival of one new packet.
    ///
    /// Must be called on **every** packet — not just at window boundaries.
    /// The per-packet inter-arrival interval drives the rate estimate.
    ///
    /// # Arguments
    /// * `now` — the timestamp of the arriving packet (usually `Instant::now()`
    ///   captured immediately after `pcap` delivers the frame).
    pub fn update(&mut self, now: Instant) {
        if let Some(prev) = self.last_arrival {
            let dt_secs = now.duration_since(prev).as_secs_f64();

            // Guard against zero or negative intervals (clock hiccup or burst
            // of packets arriving in the same nanosecond). If dt is zero we
            // would attempt 1/0 = +inf, which would corrupt the running EWMA.
            if dt_secs > 0.0 {
                // Instantaneous packet rate for this single inter-arrival gap.
                let instant_rate = 1.0 / dt_secs;

                // Core EWMA formula:
                //   new = α · current_sample + (1−α) · previous_smoothed
                self.value = self.alpha * instant_rate + (1.0 - self.alpha) * self.value;
            }
            // If dt == 0 we silently skip the update — the EWMA retains its
            // previous value, which is the safest no-op for a burst edge case.
        }
        // Record this packet's arrival time for the next inter-arrival calculation.
        self.last_arrival = Some(now);
    }

    /// Return the current smoothed rate estimate (packets per second).
    ///
    /// Called once per window close by the analysis thread to produce the
    /// scalar `x_rate` that feeds `WelfordAccumulator::update()`.
    ///
    /// The EWMA itself is NOT reset after this read — it retains its memory
    /// across windows so that flood ramp-ups spanning multiple windows are
    /// still detected.
    pub fn snapshot(&self) -> f64 {
        self.value
    }

    /// Expose the current alpha for logging / debugging.
    pub fn alpha(&self) -> f64 {
        self.alpha
    }
}

impl Default for EwmaState {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // Helper: simulate `n` packets arriving with a fixed inter-arrival gap.
    fn simulate_fixed_rate(alpha: f64, gap_ms: u64, n: usize) -> EwmaState {
        let mut ewma = EwmaState::with_alpha(alpha);
        // Start at an arbitrary point; only relative gaps matter.
        let mut now = Instant::now();
        for _ in 0..n {
            ewma.update(now);
            now += Duration::from_millis(gap_ms);
        }
        ewma
    }

    /// After many packets at a fixed rate, the EWMA should converge
    /// close to that true rate.
    ///
    /// At 10 ms gaps → 100 pps.  After 200 packets the EWMA should be
    /// within 5% of 100 pps.
    #[test]
    fn convergence_to_steady_state() {
        let ewma = simulate_fixed_rate(DEFAULT_ALPHA, 10, 200);
        let expected = 100.0; // packets per second
        let got      = ewma.snapshot();
        let err_pct  = ((got - expected) / expected).abs() * 100.0;
        assert!(
            err_pct < 5.0,
            "EWMA did not converge: expected ~{expected} pps, got {got:.2} pps ({err_pct:.1}% error)"
        );
    }

    /// A fresh EWMA starts at 0.0 with no last_arrival set.
    #[test]
    fn initial_value_is_zero() {
        let ewma = EwmaState::new();
        assert_eq!(ewma.snapshot(), 0.0);
    }

    /// The EWMA reacts upward when the packet rate doubles.
    #[test]
    fn rate_spike_increases_ewma() {
        // First 100 packets at 10 ms gaps (100 pps).
        let mut ewma = simulate_fixed_rate(DEFAULT_ALPHA, 10, 100);
        let before = ewma.snapshot();

        // Next 20 packets at 1 ms gaps (1000 pps — a 10× spike).
        let mut now = Instant::now();
        for _ in 0..20 {
            ewma.update(now);
            now += Duration::from_millis(1);
        }
        let after = ewma.snapshot();

        assert!(
            after > before,
            "EWMA should increase during a rate spike (before={before:.2}, after={after:.2})"
        );
    }

    /// alpha = 0.5 should converge faster than alpha = 0.125.
    #[test]
    fn higher_alpha_converges_faster() {
        let slow = simulate_fixed_rate(0.125, 10, 50).snapshot();
        let fast = simulate_fixed_rate(0.500, 10, 50).snapshot();
        let target = 100.0;

        // Both should be heading toward 100 pps; fast alpha should be closer.
        let slow_err = (slow - target).abs();
        let fast_err = (fast - target).abs();
        assert!(
            fast_err <= slow_err,
            "higher alpha should converge faster (slow_err={slow_err:.2}, fast_err={fast_err:.2})"
        );
    }

    /// Zero inter-arrival gap must not corrupt the EWMA (no +inf).
    #[test]
    fn zero_dt_is_a_no_op() {
        let mut ewma = EwmaState::new();
        let t = Instant::now();
        ewma.update(t);
        ewma.update(t); // same timestamp → dt = 0
        assert!(
            ewma.snapshot().is_finite(),
            "EWMA became non-finite after zero-dt update"
        );
    }
}
