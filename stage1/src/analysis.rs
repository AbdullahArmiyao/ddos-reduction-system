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
    capture::{PacketMeta, Protocol},
    entropy::{EntropyAccumulator, WINDOW_SIZE},
    ewma::EwmaState,
    ipc::{FeatureVector, IpcSocket, FLAG_ENTROPY_ANOMALY, FLAG_RATE_ANOMALY},
    welford::WelfordAccumulator,
};
use crossbeam_channel::Receiver;
use log::{info, warn};
use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH, Instant};

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
    /// If Some, write every post-warmup feature vector to this CSV file.
    /// The file is created (or appended) at thread start.
    pub train_csv: Option<String>,
    /// Integer class label written into every CSV row.
    /// 0 = normal, 1 = flash_crowd, 2 = ddos
    pub train_label: u8,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            k:           2.0,
            ewma_alpha:  crate::ewma::DEFAULT_ALPHA,
            socket_path: crate::ipc::SOCKET_PATH.to_string(),
            victim_ip:   String::from("(not set)"),
            train_csv:   None,
            train_label: 0,
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
    // Open the CSV training file if --train-csv was passed.
    // -------------------------------------------------------------------------
    let mut csv_writer: Option<std::fs::File> = if let Some(ref path) = cfg.train_csv {
        let file_exists = std::path::Path::new(path).exists();
        match std::fs::OpenOptions::new().create(true).append(true).open(path) {
            Ok(mut f) => {
                if !file_exists {
                    // Write CSV header only if the file is new.
                    let _ = writeln!(
                        f,
                        "entropy,ewma_rate,mean_h,mean_r,sigma_h,sigma_r,\
                         proto_ratio,dominant_ip_ratio,timestamp,label"
                    );
                }
                info!("Analysis: training mode ON — writing CSV to '{}' with label={}", path, cfg.train_label);
                Some(f)
            }
            Err(e) => {
                warn!("Analysis: failed to open train-csv '{}': {e} — training disabled", path);
                None
            }
        }
    } else {
        None
    };

    // Layer 1 state — updated on every incoming packet.
    let mut ewma    = EwmaState::with_alpha(cfg.ewma_alpha);
    let mut entropy = EntropyAccumulator::new();

    // Layer 1 protocol counters — cleared on every window boundary.
    let mut tcp_count:  u32 = 0;
    let mut udp_count:  u32 = 0;
    let mut icmp_count: u32 = 0;

    // Layer 3 state — two independent Welford accumulators (never shared).
    let mut welford_rate    = WelfordAccumulator::default(); // tracks r (pps)
    let mut welford_entropy = WelfordAccumulator::default(); // tracks h (bits)

    // Long-term peacetime references (ultra-slow EWMA references)
    let mut peacetime_rate_ref: Option<f64> = None;
    let mut peacetime_entropy_ref: Option<f64> = None;

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
    let mut last_window_close = Instant::now();
    let mut cooldown_counter: usize = 0;

    // Active IP and port flow counters for Web UI telemetry.
    let mut flow_counts: HashMap<(IpAddr, u16, u8), u32> = HashMap::new();
    let mut last_flow_write = Instant::now();
    let mut last_sent_time = 0.0;

    // -------------------------------------------------------------------------
    // Main loop — one iteration per packet received from the capture thread.
    // -------------------------------------------------------------------------
    for meta in rx {
        // =====================================================================
        // LAYER 1 — Per-Packet Updates
        // =====================================================================

        // Increment this IP's frequency count for the current window.
        // EntropyAccumulator maintains its own internal counts; ip_counts is
        // our separate copy for the dominant-IP ratio calculation.
        entropy.add_packet(meta.src_ip);
        *ip_counts.entry(meta.src_ip).or_insert(0) += 1;
        window_packet_count += 1;

        // Track specific flow for web telemetry
        let proto_num = match meta.protocol {
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
            Protocol::Icmp => 1,
            Protocol::Other => 0,
        };
        *flow_counts.entry((meta.src_ip, meta.dst_port, proto_num)).or_insert(0) += 1;

        // Increment the Layer 4 protocol counter for the current window.
        match meta.protocol {
            Protocol::Tcp  => tcp_count  += 1,
            Protocol::Udp  => udp_count  += 1,
            Protocol::Icmp => icmp_count += 1,
            Protocol::Other => {} // not tracked in the ratio
        }

        // =====================================================================
        // LAYER 2 — Window Close (every WINDOW_SIZE packets)
        // =====================================================================
        if !entropy.is_window_full() {
            // Window not yet closed — continue to next packet.
            continue;
        }

        window_id += 1;

        // Calculate window duration and update the EWMA rate once per window.
        // This eliminates timing jitter spikes from microsecond packet spacing.
        let now_instant = Instant::now();
        let window_duration = now_instant.duration_since(last_window_close).as_secs_f64();
        last_window_close = now_instant;

        let window_rate = if window_duration > 0.0 {
            WINDOW_SIZE as f64 / window_duration
        } else {
            0.0
        };
        
        // Asymmetric decay: 
        // 1. Cliff-drop decay: If we detect a precipitous drop in raw rate (<10% of EWMA)
        //    AND we are not in active cooldown (cooldown_counter == 0), use alpha = 0.8
        //    to instantly flush the rate history (e.g. after a firewall block).
        // 2. Otherwise, if the raw rate is decreasing or we are in a cooldown recovery window,
        //    use a moderately fast alpha (0.5).
        // 3. Otherwise, use the standard configured alpha to avoid reacting to single transient spikes.
        let active_alpha = if window_rate < 0.1 * ewma.snapshot() && cooldown_counter == 0 {
            0.8f64.max(cfg.ewma_alpha)
        } else if window_rate < ewma.snapshot() || cooldown_counter > 0 {
            0.5f64.max(cfg.ewma_alpha)
        } else {
            cfg.ewma_alpha
        };
        ewma.update_rate_with_alpha(window_rate, active_alpha);

        // Compute Shannon Entropy scalar h from the current window's IP distribution.
        // This call clears the internal HashMap and resets the packet counter.
        let h = entropy.compute_and_reset();

        // Read the current EWMA rate as a snapshot scalar r.
        // The EWMA itself is NOT reset — it retains cross-window memory.
        let r = ewma.snapshot();

        // Compute the dominant-IP ratio: fraction of packets from the busiest IP, and retrieve that IP.
        let (dominant_ip, dominant_count) = ip_counts.iter()
            .map(|(ip, count)| (*ip, *count))
            .max_by_key(|(_, count)| *count)
            .unwrap_or((std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0));
        let dominant_ip_ratio = dominant_count as f64 / window_packet_count as f64;

        // Compute proto_ratio: fraction of window packets that were TCP.
        // Range [0.0, 1.0] — a UDP/ICMP flood will push this toward 0.0.
        let total_tracked = (tcp_count + udp_count + icmp_count) as f64;
        let proto_ratio = if total_tracked > 0.0 {
            tcp_count as f64 / total_tracked
        } else {
            0.0
        };

        // Wall-clock timestamp of this window close (seconds since UNIX epoch).
        // Used by Stage 2 for time-based analysis and logging.
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        // Write active flows periodically to JSON for dashboard (every 10s)
        if now_instant.duration_since(last_flow_write).as_secs_f64() >= 10.0 {
            write_active_flows(&flow_counts, timestamp);
            flow_counts.clear();
            last_flow_write = now_instant;
        }

        // Reset all per-window accumulators for the next window.
        ip_counts.clear();
        window_packet_count = 0;
        tcp_count  = 0;
        udp_count  = 0;
        icmp_count = 0;

        // =====================================================================
        // LAYER 3 — Anomaly Evaluation and Welford Update
        // =====================================================================

        // Do not evaluate thresholds during the warm-up period — the Welford
        // mean and variance are too noisy on a small sample to be trustworthy.
        if !welford_rate.is_warm() || !welford_entropy.is_warm() {
            // During warm-up, always update the Welford trackers.
            welford_rate.update(r);
            welford_entropy.update(h);

            info!(
                "Analysis: warm-up window {}/{} | r={r:.1} pps | h={h:.3} bits",
                welford_rate.n, crate::welford::WARMUP_WINDOWS
            );

            // Send warmup telemetry updates so that the dashboard updates immediately!
            let fv = FeatureVector {
                entropy:     h,
                ewma_rate:   r,
                mean_h:      welford_entropy.mean,
                mean_r:      welford_rate.mean,
                sigma_h:     welford_entropy.std_dev(),
                sigma_r:     welford_rate.std_dev(),
                proto_ratio,
                dominant_ip_ratio,
                timestamp,
                dominant_ip: IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), // No dominant IP during warmup
            };
            if !ipc.send(&fv) {
                warn!("Analysis: IPC send failed during warm-up; Stage 2 may be offline");
            }

            continue;
        }

        // Get raw standard deviations
        let raw_sigma_r = welford_rate.std_dev();
        let raw_sigma_h = welford_entropy.std_dev();

        // 1. Sigma Ceiling & Floor: Cap the standard deviation to prevent the boundaries from drifting too wide,
        // but also enforce a floor to prevent zero-baseline lockout.
        // Cap rate standard deviation at 10000.0 pps or 20% of the mean (whichever is larger), floor at 50.0.
        let ceiling_r = (0.2 * welford_rate.mean).max(10000.0);
        let sigma_r = raw_sigma_r.max(50.0).min(ceiling_r);

        // Cap entropy standard deviation at 0.5 bits, floor at 0.05 bits.
        let sigma_h = raw_sigma_h.max(0.05).min(0.5);

        // 2. High-Sensitivity Cooldown Mode & Entropy-Guided Scaling:
        // - If we are within the cooldown recovery window, reduce the baseline multiplier to increase sensitivity.
        // - Scale the rate multiplier up if the entropy is high (indicating high diversity/flash crowd)
        //   to avoid false rate alarms.
        let base_k = if cooldown_counter > 0 {
            (cfg.k * 0.5).max(1.0)
        } else {
            cfg.k
        };

        // Dynamic k-Scaling: Scale k relative to the running mean of entropy (mean_h)
        // instead of a hardcoded 4.0 divisor. Use 4.0 as a fallback if mean_h is 0.0 (warmup).
        // Also enforce an Emergency Volume Cap: if raw rate exceeds 10 standard deviations above the mean,
        // override entropy scaling to prevent high-entropy botnet floods from evading detection.
        let mean_h = welford_entropy.mean;
        let rate_k = if r > (welford_rate.mean + 10.0 * sigma_r) {
            base_k
        } else {
            let divisor = if mean_h > 0.0 { mean_h } else { 4.0 };
            base_k * (h / divisor).max(1.0)
        };
        let entropy_k = base_k;

        // Evaluate the two anomaly thresholds.
        let rate_boundary    = welford_rate.mean + rate_k * sigma_r;
        let entropy_boundary = welford_entropy.mean - entropy_k * sigma_h;

        // Build anomaly flags bitmask.
        let mut anomaly_flags: u8 = 0;
        if r > rate_boundary {
            anomaly_flags |= FLAG_RATE_ANOMALY;
        }
        if h < entropy_boundary {
            anomaly_flags |= FLAG_ENTROPY_ANOMALY;
        }

        // Determine if this window breached the original configuration-level threshold (real anomaly).
        // This prevents the system from getting trapped in an infinite cooldown loop due to minor
        // normal fluctuations breaching the tighter active_k.
        let real_rate_k = if r > (welford_rate.mean + 10.0 * sigma_r) {
            cfg.k
        } else {
            let divisor = if mean_h > 0.0 { mean_h } else { 4.0 };
            cfg.k * (h / divisor).max(1.0)
        };
        let real_rate_boundary = welford_rate.mean + real_rate_k * sigma_r;
        let real_entropy_boundary = welford_entropy.mean - cfg.k * sigma_h;
        let is_real_anomaly = r > real_rate_boundary || h < real_entropy_boundary;

        // 3. Conditional Updates: Feed scalars into Welford accumulators ONLY if the window is clean
        // and we are not in cooldown. This keeps the baseline stable and prevents statistical explosion.
        if anomaly_flags == 0 && cooldown_counter == 0 {
            // Outlier Rejection: Reject updates if the sample is > 5 standard deviations away.
            // Baseline Capping: Impose a hard ceiling of 10000.0 pps on the Welford mean rate.
            let is_rate_outlier = sigma_r > 0.0 && (r - welford_rate.mean).abs() > 5.0 * sigma_r;
            if !is_rate_outlier && welford_rate.mean < 10000.0 {
                welford_rate.update(r);
            }

            let is_entropy_outlier = sigma_h > 0.0 && (h - welford_entropy.mean).abs() > 5.0 * sigma_h;
            if !is_entropy_outlier {
                welford_entropy.update(h);
            }

            // Peacetime Reference (Long-Term Drift Detection):
            // Update peacetime references with alpha = 0.001
            let rate_ref = peacetime_rate_ref.get_or_insert(r);
            *rate_ref = 0.001 * r + 0.999 * (*rate_ref);

            let entropy_ref = peacetime_entropy_ref.get_or_insert(h);
            *entropy_ref = 0.001 * h + 0.999 * (*entropy_ref);
            
            // Baseline Poisoning Check:
            // Revert running mean if it drifts > 50% from peacetime reference.
            if (*rate_ref) > 0.0 && (welford_rate.mean - *rate_ref).abs() / (*rate_ref) > 0.50 {
                warn!(
                    "[!!!] Baseline Poisoning Detected! Welford mean rate ({:.2}) deviated >50% from peacetime reference ({:.2}). Reverting mean.",
                    welford_rate.mean, *rate_ref
                );
                welford_rate.mean = *rate_ref;
            }
        }

        // Manage cooldown counter: if a real anomaly is detected, set to 10. Otherwise decrement.
        if is_real_anomaly {
            cooldown_counter = 10;
        } else if cooldown_counter > 0 {
            cooldown_counter -= 1;
        }

        // Log the current window summary at debug level.
        log::debug!(
            "Window #{window_id}: r={r:.2} pps | h={h:.4} bits | \
             μ_r={:.2} σ_r={:.2} (active={:.2}) | μ_h={:.4} σ_h={:.4} (active={:.4}) | cooldown={}",
            welford_rate.mean, raw_sigma_r, sigma_r,
            welford_entropy.mean, raw_sigma_h, sigma_h,
            cooldown_counter
        );

        // Signal Stage 2 if an anomaly was detected OR if 10 seconds elapsed (heartbeat telemetry)
        let is_heartbeat = (timestamp - last_sent_time) >= 10.0;
        if anomaly_flags != 0 || is_heartbeat {
            if anomaly_flags != 0 {
                warn!(
                    "ANOMALY window {} | flags={:#04x} | r={:.1} (boundary={:.1}) | \
                     h={:.4} (boundary={:.4}) | proto_ratio={:.3} | dom_ratio={:.3} | dominant_ip={}",
                    window_id, anomaly_flags, r, rate_boundary, h, entropy_boundary,
                    proto_ratio, dominant_ip_ratio, dominant_ip
                );
            } else {
                log::debug!("Window #{window_id}: HEARTBEAT | r={r:.1} | h={h:.4}");
            }

            let fv = FeatureVector {
                entropy:     h,
                ewma_rate:   r,
                mean_h:      welford_entropy.mean,
                mean_r:      welford_rate.mean,
                sigma_h,
                sigma_r,
                proto_ratio,
                dominant_ip_ratio,
                timestamp,
                dominant_ip,
            };

            if ipc.send(&fv) {
                last_sent_time = timestamp;
            } else {
                warn!("Analysis: IPC send failed for window #{window_id}; Stage 2 may be offline");
            }
        } else {
            // Normal window — no anomaly, no heartbeat. Log at debug level only.
            log::debug!("Window #{window_id}: NORMAL | r={r:.1} | h={h:.4}");
        }

        // =====================================================================
        // Training mode: append this window to the CSV regardless of anomaly.
        // =====================================================================
        if let Some(ref mut f) = csv_writer {
            let _ = writeln!(
                f,
                "{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},{:.3},{}",
                h, r,
                welford_entropy.mean, welford_rate.mean,
                sigma_h, sigma_r,
                proto_ratio, dominant_ip_ratio,
                timestamp,
                cfg.train_label
            );
        }
    }

    // -------------------------------------------------------------------------
    // The rx channel has closed — the capture thread has exited.
    // -------------------------------------------------------------------------
    info!("Analysis: channel closed; processed {window_id} windows total. Exiting.");
}

/// Helper function to write top 20 active network flows atomically to /tmp/ddos_active_flows.json
fn write_active_flows(flow_counts: &HashMap<(IpAddr, u16, u8), u32>, timestamp: f64) {
    // Sort flows by packet count descending
    let mut flows: Vec<_> = flow_counts.iter().collect();
    flows.sort_by(|a, b| b.1.cmp(a.1));
    
    // Take top 20 active flows to prevent massive files
    let top_flows = flows.into_iter().take(20);
    
    let mut json = String::new();
    json.push_str("{\n  \"timestamp\": ");
    json.push_str(&timestamp.to_string());
    json.push_str(",\n  \"active_ips\": [\n");
    
    let mut first = true;
    for (key, count_ref) in top_flows {
        let (ip, port, proto) = *key;
        let count = *count_ref;
        if !first {
            json.push_str(",\n");
        }
        first = false;
        
        let proto_str = match proto {
            6 => "TCP",
            17 => "UDP",
            1 => "ICMP",
            _ => "OTHER",
        };
        
        // Calculate rate over 10 seconds (count / 10.0)
        let rate = count as f64 / 10.0;
        
        json.push_str(&format!(
            "    {{\"ip\": \"{}\", \"port\": {}, \"proto\": \"{}\", \"rate\": {:.1}}}",
            ip, port, proto_str, rate
        ));
    }
    json.push_str("\n  ]\n}");
    
    // Write atomically
    let tmp_path = "/tmp/ddos_active_flows.tmp";
    let final_path = "/tmp/ddos_active_flows.json";
    if let Ok(mut file) = std::fs::File::create(tmp_path) {
        use std::io::Write;
        if file.write_all(json.as_bytes()).is_ok() {
            let _ = std::fs::rename(tmp_path, final_path);
        }
    }
}
