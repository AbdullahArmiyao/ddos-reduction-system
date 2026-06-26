// =============================================================================
// analysis.rs — Stage 1: Three-Layer Analysis Thread
// =============================================================================
//
// PURPOSE
// -------
// This module owns the *analysis thread* — the brain of Stage 1. It receives
// `PacketMeta` records from the capture thread via a crossbeam channel and
// runs the complete three-layer pipeline:
//
//   Layer 1 (per packet)
//   ---------------------
//   • EWMA rate: update exponential smoothing with the new inter-arrival gap.
//   • Entropy accumulator: record the source IP in the current window's HashMap.
//
//   Layer 2 (per 50th packet — window close)
//   -----------------------------------------
//   • Shannon entropy: compute the diversity scalar `h` from the IP HashMap,
//     then clear the HashMap and reset the packet counter.
//   • EWMA snapshot: read the current EWMA value as the rate scalar `r`.
//     (The EWMA is NOT reset — it carries memory across windows by design.)
//
//   Layer 3 (per window, immediately after Layer 2)
//   -------------------------------------------------
//   • Feed `r` into the EWMA Welford accumulator (Welford_rate).
//   • Feed `h` into the Entropy Welford accumulator (Welford_entropy).
//   • Evaluate thresholds:
//       rate anomaly    → `r > Welford_rate.mean + k·σ_rate`
//       entropy anomaly → `h < Welford_entropy.mean − k·σ_entropy`
//   • If either fires AND the accumulators are past warm-up:
//       build a `FeatureVector` and send it to Stage 2 via `IpcSocket`.
//
// ANOMALY THRESHOLD MULTIPLIER (k)
// ----------------------------------
// The specification uses k = 2.0 (two standard deviations) as the default.
// This constant is exposed so you can tune it without recompiling — pass it
// through `AnalysisConfig`. A higher k reduces false positives at the cost
// of slower detection; a lower k is more sensitive but may fire on flash crowds
// before Stage 2 can distinguish them.
//
// WARM-UP PERIOD
// ---------------
// Welford's mean and variance are meaningless until enough windows have been
// seen to build a real baseline (see `welford::WARMUP_WINDOWS`). During warm-up
// Layer 3 will *not* fire even if a threshold is technically breached. The
// gateway logs a "warm-up" message to console so you know when it goes live.
//
// DOMINANT IP RATIO
// ------------------
// On every window close the analysis thread also computes the fraction of
// packets belonging to the single most-frequent source IP. This is included
// in the `FeatureVector` sent to Stage 2 as an additional feature — useful for
// the Random Forest classifier and for operator-level logging.
// =============================================================================

use crate::{
    capture::PacketMeta,
    entropy::EntropyAccumulator,
    ewma::EwmaState,
    ipc::{FeatureVector, IpcSocket, FLAG_ENTROPY_ANOMALY, FLAG_RATE_ANOMALY},
    welford::WelfordAccumulator,
};
use crossbeam_channel::Receiver;
use log::{info, warn};
use std::collections::HashMap;
use std::net::IpAddr;

// -----------------------------------------------------------------------------
// AnalysisConfig
// -----------------------------------------------------------------------------

/// Runtime parameters for the analysis thread.
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    /// Anomaly detection multiplier (k in `μ ± k·σ`).
    /// Default: 2.0 (two standard deviations, as per the project specification).
    pub k: f64,
    /// EWMA smoothing factor α. Default: 0.125 (RFC 6298 TCP RTT constant).
    pub ewma_alpha: f64,
    /// Socket path for IPC to Stage 2. Default: `/tmp/ddos_stage1.sock`.
    pub socket_path: String,
    /// Victim IP string — logged at startup for operator confirmation.
    pub victim_ip: String,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            k:           2.0,
            ewma_alpha:  crate::ewma::DEFAULT_ALPHA,
            socket_path: crate::ipc::SOCKET_PATH.to_string(),
            victim_ip:   String::from("(not set)"),
        }
    }
}

// -----------------------------------------------------------------------------
// run_analysis_thread — the analysis thread entry point
// -----------------------------------------------------------------------------

/// Receive `PacketMeta` records from the capture thread and run the three-layer
/// pipeline indefinitely.
///
/// Intended to be called from within `std::thread::spawn()`. Returns when the
/// `rx` channel closes (capture thread exited or an unrecoverable error occurred).
///
/// # Arguments
/// * `cfg` — analysis configuration (k, alpha, socket path).
/// * `rx`  — the receiving end of the crossbeam channel from the capture thread.
pub fn run_analysis_thread(cfg: AnalysisConfig, rx: Receiver<PacketMeta>) {
    info!(
        "Analysis: thread started | interface victim={} | k={} | α={}",
        cfg.victim_ip, cfg.k, cfg.ewma_alpha
    );

    // -------------------------------------------------------------------------
    // Initialise all per-session state objects.
    // -------------------------------------------------------------------------

    // Layer 1 state — updated on every incoming packet.
    let mut ewma    = EwmaState::with_alpha(cfg.ewma_alpha);
    let mut entropy = EntropyAccumulator::new();

    // Layer 3 state — two independent Welford accumulators (never shared).
    let mut welford_rate    = WelfordAccumulator::default(); // tracks r (pps)
    let mut welford_entropy = WelfordAccumulator::default(); // tracks h (bits)

    // IPC socket to Stage 2 (Python). Connected lazily on first anomaly.
    let mut ipc = IpcSocket::with_path(&cfg.socket_path);

    // Monotonically increasing counter of closed windows (not just anomalous ones).
    // Sent in every FeatureVector so Python can detect missed windows.
    let mut window_id: u64 = 0;

    // Temporary HashMap for computing the dominant-IP ratio per window.
    // Maintained separately from EntropyAccumulator so we can inspect it
    // *after* entropy is computed (before the accumulator resets it).
    let mut ip_counts: HashMap<IpAddr, u32> = HashMap::new();
    let mut window_packet_count: usize = 0;

    // -------------------------------------------------------------------------
    // Main loop — one iteration per packet received from the capture thread.
    // -------------------------------------------------------------------------
    for meta in rx {
        // =====================================================================
        // LAYER 1 — Per-Packet Updates
        // =====================================================================

        // Update the EWMA rate estimator with this packet's arrival timestamp.
        // This call is on the hot path and must stay O(1).
        ewma.update(meta.arrived_at);

        // Increment this IP's frequency count for the current window.
        // EntropyAccumulator maintains its own internal counts; ip_counts is
        // our separate copy for the dominant-IP ratio calculation.
        entropy.add_packet(meta.src_ip);
        *ip_counts.entry(meta.src_ip).or_insert(0) += 1;
        window_packet_count += 1;

        // =====================================================================
        // LAYER 2 — Window Close (every WINDOW_SIZE packets)
        // =====================================================================
        if !entropy.is_window_full() {
            // Window not yet closed — continue to next packet.
            continue;
        }

        window_id += 1;

        // Compute Shannon Entropy scalar h from the current window's IP distribution.
        // This call clears the internal HashMap and resets the packet counter.
        let h = entropy.compute_and_reset();

        // Read the current EWMA rate as a snapshot scalar r.
        // The EWMA itself is NOT reset — it retains cross-window memory.
        let r = ewma.snapshot();

        // Compute the dominant-IP ratio: fraction of packets from the busiest IP.
        let dominant_count = ip_counts.values().copied().max().unwrap_or(0);
        let dominant_ip_ratio = dominant_count as f64 / window_packet_count as f64;

        // Reset the temporary per-window IP map for the next window.
        ip_counts.clear();
        window_packet_count = 0;

        // =====================================================================
        // LAYER 3 — Welford Update and Anomaly Evaluation
        // =====================================================================

        // Feed both scalars into their respective Welford accumulators.
        welford_rate.update(r);
        welford_entropy.update(h);

        // Log the current window summary at debug level.
        log::debug!(
            "Window #{window_id}: r={r:.2} pps | h={h:.4} bits | \
             μ_r={:.2} σ_r={:.2} | μ_h={:.4} σ_h={:.4}",
            welford_rate.mean, welford_rate.std_dev(),
            welford_entropy.mean, welford_entropy.std_dev()
        );

        // Do not evaluate thresholds during the warm-up period — the Welford
        // mean and variance are too noisy on a small sample to be trustworthy.
        if !welford_rate.is_warm() || !welford_entropy.is_warm() {
            info!(
                "Analysis: warm-up window {}/{} | r={r:.1} pps | h={h:.3} bits",
                welford_rate.n, crate::welford::WARMUP_WINDOWS
            );
            continue;
        }

        // Evaluate the two anomaly thresholds.
        //
        // Rate breach  : current rate r is above the upper boundary (flood).
        // Entropy breach: current entropy h is below the lower boundary (concentrated source).
        let rate_boundary    = welford_rate.upper_boundary(cfg.k);
        let entropy_boundary = welford_entropy.lower_boundary(cfg.k);

        let rate_breach    = r < rate_boundary;    // No anomaly (normal case).
        let entropy_breach = h > entropy_boundary; // No anomaly (normal case).

        // Build anomaly flags bitmask.
        let mut anomaly_flags: u8 = 0;
        if r > rate_boundary {
            anomaly_flags |= FLAG_RATE_ANOMALY;
        }
        if h < entropy_boundary {
            anomaly_flags |= FLAG_ENTROPY_ANOMALY;
        }

        // =====================================================================
        // Signal Stage 2 if any anomaly was detected.
        // =====================================================================
        if anomaly_flags != 0 {
            warn!(
                "ANOMALY window {} | flags={:#04x} | r={:.1} (boundary={:.1}) | \
                 h={:.4} (boundary={:.4}) | dom_ratio={:.3}",
                window_id, anomaly_flags, r, rate_boundary, h, entropy_boundary, dominant_ip_ratio
            );

            let fv = FeatureVector {
                ewma_rate: r,
                entropy: h,
                dominant_ip_ratio,
                anomaly_flags,
                window_id,
            };

            // Attempt to send to Stage 2. If the socket is not connected yet
            // (Python not yet ready) IpcSocket will log and return false.
            // We do NOT block the analysis loop waiting for IPC — the gateway
            // must keep capturing even if Stage 2 is temporarily unavailable.
            if !ipc.send(&fv) {
                warn!("Analysis: IPC send failed for window #{window_id}; Stage 2 may be offline");
            }
        } else {
            // Normal window — no anomaly. Log at debug level only.
            let _ = (rate_breach, entropy_breach); // suppress unused warnings
            log::debug!("Window #{window_id}: NORMAL | r={r:.1} | h={h:.4}");
        }
    }

    // -------------------------------------------------------------------------
    // The rx channel has closed — the capture thread has exited.
    // -------------------------------------------------------------------------
    info!("Analysis: channel closed; processed {window_id} windows total. Exiting.");
}
