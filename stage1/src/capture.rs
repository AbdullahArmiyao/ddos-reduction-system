// =============================================================================
// capture.rs — Stage 0: Raw Packet Capture from the Network Bridge
// =============================================================================
//
// PURPOSE
// -------
// This module owns the *capture thread* — the ingress edge of the pipeline.
// It opens a pcap handle on the specified network interface (typically `br0`),
// applies a BPF filter to restrict capture to **inbound traffic to the victim**
// only, then forwards raw parsed packet metadata into a bounded crossbeam
// channel consumed by the analysis thread.
//
// ARCHITECTURE — WHY A SEPARATE THREAD AND A CHANNEL?
// -----------------------------------------------------
// A single-threaded design where capture and analysis share the same loop
// would stall packet capture every time a 50-packet window triggers entropy
// computation + Welford update. Under a flood (100k+ pps) even microseconds
// of stall cause the kernel ring buffer to overflow and packets to be silently
// dropped — defeating the very thing we are measuring.
//
// Using crossbeam's bounded channel decouples the two concerns:
//   • Capture thread: calls pcap::next_packet() in a tight loop, parses headers,
//     sends `PacketMeta` into the channel. Never blocks on analysis.
//   • Analysis thread: receives `PacketMeta` from the channel, runs Layers 1–3.
//
// The channel is bounded (see `CHANNEL_CAPACITY`) to apply *backpressure*: if
// the analysis thread falls badly behind (e.g., system overloaded), the bounded
// channel will fill. Capture then *blocks* rather than allocating unbounded
// memory. This is intentional — a stalled capture is detectable and safe;
// unbounded memory growth is not.
//
// BPF FILTER
// -----------
// `dst host <victim_ip>` is applied at the pcap level — in the kernel — before
// any Rust code processes a byte. This means:
//   • Outbound replies from the victim are excluded (their source IPs would
//     pollute the entropy metric with legitimate server addresses).
//   • ARP/ICMP/broadcast not addressed to the victim is excluded.
//   • The analysis thread sees *only* inbound unicast frames targeting the
//     victim's IP.
//
// WHAT `PacketMeta` CONTAINS
// ---------------------------
// The analysis thread only needs metadata — the full payload is never copied
// into user space beyond what etherparse parses from the header bytes.
//   • `src_ip`    — source IP address (IPv4 or IPv6), used for entropy.
//   • `arrived_at`— high-resolution monotonic timestamp, used for EWMA rate.
//
// All other header fields (dst_ip, TCP flags, port, payload length, etc.) are
// discarded at this stage. Stage 2 feature vectors add more fields offline.
// =============================================================================

use crossbeam_channel::Sender;
use etherparse::{SlicedPacket, InternetSlice};
use log::{debug, error, info, warn};
use pcap::{Capture, Device};
use std::{net::IpAddr, time::Instant};

// -----------------------------------------------------------------------------
// Channel capacity
// -----------------------------------------------------------------------------

/// Depth of the bounded channel between the capture and analysis threads.
///
/// At WINDOW_SIZE=50 packets per window, a capacity of 1024 means the analysis
/// thread can fall up to ~20 windows behind before backpressure kicks in.
/// Tune this value based on observed queue depth at your gateway's peak pps.
pub const CHANNEL_CAPACITY: usize = 1024;

// -----------------------------------------------------------------------------
// PacketMeta — the minimal per-packet record passed across the channel
// -----------------------------------------------------------------------------

/// Lightweight per-packet metadata record sent from the capture thread to
/// the analysis thread via the crossbeam channel.
///
/// Only fields actually consumed by Layers 1–3 are included.
/// Keeping this struct small reduces copy overhead across the channel.
#[derive(Debug, Clone)]
pub struct PacketMeta {
    /// Source IP address extracted from the IP header.
    /// IPv4 addresses are stored as `IpAddr::V4`; IPv6 as `IpAddr::V6`.
    pub src_ip: IpAddr,
    /// High-resolution monotonic timestamp recorded *immediately* after pcap
    /// delivers the frame to user space. Used by EWMA for inter-arrival timing.
    pub arrived_at: Instant,
}

// -----------------------------------------------------------------------------
// CaptureConfig — runtime parameters for the capture thread
// -----------------------------------------------------------------------------

/// Configuration passed into `run_capture_thread()`.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// Network interface to capture on (e.g., `"br0"`, `"eth0"`, `"ens3"`).
    pub interface: String,
    /// BPF filter string applied at the kernel level.
    /// Should be `"dst host <victim_ip>"` in production.
    /// Set to `""` (empty string) to disable filtering (dev/test only).
    pub bpf_filter: String,
    /// pcap snapshot length in bytes — only this many bytes of each frame are
    /// copied to user space. 96 bytes is enough for Ethernet + IPv6 + TCP headers.
    pub snaplen: i32,
    /// pcap buffer flush timeout in milliseconds.
    /// Lower values reduce latency between packet arrival and delivery to Rust.
    /// Higher values allow the kernel to batch more packets per wakeup.
    pub timeout_ms: i32,
    /// Set to `true` to enable pcap promiscuous mode (capture all frames,
    /// not just those addressed to this interface's MAC).
    /// Required when running on a bridge (`br0`) that sees others' traffic.
    pub promiscuous: bool,
}

impl CaptureConfig {
    /// Production-ready defaults for a bridge interface.
    ///
    /// # Arguments
    /// * `interface`  — the name of the network bridge (e.g., `"br0"`).
    /// * `victim_ip`  — victim's IP address as a string (e.g., `"10.0.0.3"`).
    pub fn for_bridge(interface: &str, victim_ip: &str) -> Self {
        Self {
            interface:   interface.to_string(),
            // Support both standard and VLAN-tagged frames matching the victim IP
            bpf_filter:  format!("dst host {victim_ip} or (vlan and dst host {victim_ip})"),
            snaplen:     256,   // Capture only header bytes (optimizes memory copy speed under flood)
            timeout_ms:  100,   // 100 ms flush window (prevents Linux TPACKET ring buffer packet drops)
            promiscuous: true,  // bridge must see all passing frames
        }
    }

    /// Minimal config for local testing without a BPF filter.
    pub fn for_test(interface: &str) -> Self {
        Self {
            interface:   interface.to_string(),
            bpf_filter:  String::new(),
            snaplen:     256,   // Capture only header bytes (optimizes memory copy speed under flood)
            timeout_ms:  100,
            promiscuous: true,  // Enable promiscuous mode to capture bridged transit traffic
        }
    }
}

// -----------------------------------------------------------------------------
// run_capture_thread — the capture thread entry point
// -----------------------------------------------------------------------------

/// Open a pcap capture on `cfg.interface`, apply the BPF filter, and forward
/// parsed `PacketMeta` records into `tx` indefinitely.
///
/// This function *blocks forever* and is intended to be called from within a
/// dedicated `std::thread::spawn()` closure. It returns only if:
///   • A fatal pcap error occurs (logged at ERROR level).
///   • The `tx` sender is dropped (analysis thread exited).
///
/// # Arguments
/// * `cfg` — capture configuration (interface, BPF filter, pcap parameters).
/// * `tx`  — the sending end of the crossbeam channel to the analysis thread.
///
/// # Errors
/// Logs via the `log` crate and returns early on pcap open/filter failure.
/// Individual malformed packets are logged at WARN and skipped.
pub fn run_capture_thread(cfg: CaptureConfig, tx: Sender<PacketMeta>) {
    // -------------------------------------------------------------------------
    // Step 1: Open the pcap capture handle on the specified interface.
    // -------------------------------------------------------------------------
    info!("Capture: opening interface '{}' (promiscuous={})", cfg.interface, cfg.promiscuous);

    let mut cap = match Capture::from_device(cfg.interface.as_str()) {
        Ok(inactive) => {
            // Configure before activating.
            let inactive = inactive
                .snaplen(cfg.snaplen)
                .timeout(cfg.timeout_ms)
                .promisc(cfg.promiscuous)
                .immediate_mode(true) // Deliver packets immediately instead of batching to prevent delay
                .buffer_size(128 * 1024 * 1024); // 128MB buffer to prevent OS packet drops under flood

            match inactive.open() {
                Ok(c) => c,
                Err(e) => {
                    error!("Capture: failed to open device '{}': {e}", cfg.interface);
                    return;
                }
            }
        }
        Err(e) => {
            error!("Capture: device '{}' not found: {e}", cfg.interface);
            // List available devices to help with diagnostics.
            if let Ok(devices) = Device::list() {
                let names: Vec<_> = devices.iter().map(|d| d.name.as_str()).collect();
                error!("Capture: available interfaces: {}", names.join(", "));
            }
            return;
        }
    };

    // -------------------------------------------------------------------------
    // Step 2: Apply the BPF filter (kernel-level, before Rust sees anything).
    // -------------------------------------------------------------------------
    if !cfg.bpf_filter.is_empty() {
        info!("Capture: applying BPF filter: '{}'", cfg.bpf_filter);
        if let Err(e) = cap.filter(&cfg.bpf_filter, true) {
            error!("Capture: BPF filter '{}' failed: {e}", cfg.bpf_filter);
            return;
        }
    } else {
        warn!("Capture: no BPF filter applied — all traffic will be processed (dev mode)");
    }

    // Log the datalink type (e.g. ETHERNET, LINUX_SLL) to detect parsing issues
    let linktype = cap.get_datalink();
    info!("Capture: interface '{}' datalink type is {:?}", cfg.interface, linktype);
    if linktype != pcap::Linktype::ETHERNET {
        warn!("Capture: interface linktype is NOT Ethernet. Packet parsing will fail unless standard Ethernet headers are present.");
    }

    info!("Capture: capture loop started on '{}'", cfg.interface);

    // -------------------------------------------------------------------------
    // Step 3: Main capture loop — runs until the channel closes or pcap errors.
    // -------------------------------------------------------------------------
    let mut packet_count: u64 = 0;
    let mut total_raw_packets: u64 = 0;
    let mut total_timeouts: u64 = 0;
    let mut last_status_time = Instant::now();

    loop {
        // Periodic progress status update (every 5 seconds)
        let now = Instant::now();
        if now.duration_since(last_status_time).as_secs() >= 5 {
            info!(
                "Capture: status | interface={} | raw_captured={} | timeouts={} | forwarded={}",
                cfg.interface, total_raw_packets, total_timeouts, packet_count
            );
            last_status_time = now;
        }

        // Retrieve the next raw frame from the pcap ring buffer.
        let raw = match cap.next_packet() {
            Ok(p) => {
                total_raw_packets += 1;
                p
            }
            Err(pcap::Error::TimeoutExpired) => {
                total_timeouts += 1;
                // No packets arrived within the flush window — normal during
                // quiet periods. Loop immediately to poll again.
                continue;
            }
            Err(e) => {
                error!("Capture: pcap read error: {e}");
                break;
            }
        };

        // Record arrival time as early as possible after the kernel hands us
        // the frame — before etherparse parsing adds any latency.
        let arrived_at = Instant::now();

        // -------------------------------------------------------------------------
        // Step 4: Parse Ethernet frame headers with etherparse (zero-copy).
        // -------------------------------------------------------------------------
        let sliced = match SlicedPacket::from_ethernet(raw.data) {
            Ok(s)  => s,
            Err(_) => {
                // Malformed or truncated frame (can happen on noisy links).
                // Skip silently at debug level to avoid flooding logs under attack.
                debug!("Capture: etherparse failed on packet #{packet_count}; skipping");
                continue;
            }
        };

        // -------------------------------------------------------------------------
        // Step 5: Extract source IP from the IP header.
        // -------------------------------------------------------------------------
        let src_ip = match sliced.net {
            Some(InternetSlice::Ipv4(ref ipv4)) => {
                IpAddr::from(ipv4.header().source_addr())
            }
            Some(InternetSlice::Ipv6(ref ipv6)) => {
                IpAddr::from(ipv6.header().source_addr())
            }
            // Non-IP frame (ARP, etc.) — ignore.
            _ => continue,
        };

        packet_count += 1;

        // -------------------------------------------------------------------------
        // Step 6: Forward metadata to the analysis thread via the bounded channel.
        // -------------------------------------------------------------------------
        let meta = PacketMeta { src_ip, arrived_at };

        // `send()` blocks if the channel is full (backpressure).  This is the
        // correct behaviour — it prevents unbounded memory growth under flood.
        // `send_timeout` with a short deadline prevents a deadlock if the
        // analysis thread has crashed; we log and break instead.
        if tx.send(meta).is_err() {
            // The receiver (analysis thread) has been dropped — time to exit.
            info!("Capture: analysis channel closed; capture thread exiting after {packet_count} packets");
            break;
        }

        // Periodic progress log (every 10,000 packets) — visible in dev mode.
        if packet_count % 10_000 == 0 {
            debug!("Capture: {} packets forwarded to analysis thread", packet_count);
        }
    }
}
