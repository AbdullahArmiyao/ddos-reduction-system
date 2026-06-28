// =============================================================================
// main.rs — Stage 1 Entry Point and Thread Orchestrator
// =============================================================================
//
// PURPOSE
// -------
// Parses CLI arguments, wires the crossbeam channel between the capture thread
// and the analysis thread, then spawns both and waits for them to exit.
//
// THREAD ARCHITECTURE (recap)
// ----------------------------
//
//   ┌─────────────────────────────────────────────────────────────┐
//   │  Stage 0 / Stage 1 — Rust Binary (this binary)             │
//   │                                                             │
//   │  ┌────────────────┐  PacketMeta  ┌───────────────────────┐ │
//   │  │ Capture Thread │──────────────► Analysis Thread        │ │
//   │  │ (pcap + BPF)   │  crossbeam   │ Layer 1: EWMA + Cnt   │ │
//   │  │                │  bounded     │ Layer 2: entropy + r  │ │
//   │  └────────────────┘  channel     │ Layer 3: Welford + μ2σ│ │
//   │                                  │         ↓ anomaly      │ │
//   │                                  │   FeatureVector IPC    │ │
//   │                                  └──────────┬────────────┘ │
//   └─────────────────────────────────────────────┼──────────────┘
//                                                 │ Unix Domain Socket
//                                                 ▼
//   ┌─────────────────────────────────────────────────────────────┐
//   │  Stage 2 — Python (separate process)                        │
//   │  Random Forest classifier → ipset block or k-decay widen   │
//   └─────────────────────────────────────────────────────────────┘
//
// CLI USAGE
// ----------
//   sudo ./ddos_stage1 --interface br0 --victim-ip 10.0.0.3
//
// Full options:
//   --interface  <IFACE>   Network interface to capture on (required)
//   --victim-ip  <IP>      BPF filter target IP (required in production)
//   --k          <FLOAT>   Anomaly multiplier μ ± k·σ (default: 2.0)
//   --alpha      <FLOAT>   EWMA smoothing α (default: 0.125)
//   --socket     <PATH>    Unix socket path for Stage 2 IPC (default: /tmp/ddos_stage1.sock)
//   --no-filter            Disable BPF filter (dev/test mode only)
//
// LOG LEVEL
// ----------
// Controlled via the RUST_LOG environment variable (uses env_logger):
//   RUST_LOG=info   — operational, startup messages and anomaly alerts (default)
//   RUST_LOG=debug  — per-window statistics
//   RUST_LOG=warn   — anomalies and errors only
//
// PRIVILEGES
// -----------
// Raw pcap capture requires either:
//   • Running as root (sudo), OR
//   • The binary having the CAP_NET_RAW Linux capability set:
//       sudo setcap cap_net_raw+ep ./ddos_stage1
// =============================================================================

// Declare submodules — Rust loads them from their respective files.
mod analysis;
mod capture;
mod entropy;
mod ewma;
mod ipc;
mod welford;

use analysis::AnalysisConfig;
use capture::CaptureConfig;
use crossbeam_channel::bounded;
use log::info;
use std::{env, process};

// ── Simple CLI parser ─────────────────────────────────────────────────────────
// We intentionally avoid `clap` / `structopt` to keep the dependency tree lean.
// This parser handles `--flag value` style arguments only.

/// Parse CLI arguments from `std::env::args()` into a plain struct.
struct CliArgs {
    interface: String,
    victim_ip: Option<String>,
    k:         f64,
    alpha:     f64,
    socket:    String,
    no_filter: bool,
    log_file:  Option<String>,
    /// If set, write every post-warmup feature vector to this CSV file.
    train_csv: Option<String>,
    /// Integer class label written into the CSV (0=normal, 1=flash_crowd, 2=ddos).
    train_label: u8,
}

impl CliArgs {
    /// Parse arguments and exit the process with a usage message on error.
    fn parse() -> Self {
        let args: Vec<String> = env::args().collect();
        let mut interface = String::new();
        let mut victim_ip: Option<String> = None;
        let mut k         = 2.0_f64;
        let mut alpha     = ewma::DEFAULT_ALPHA;
        let mut socket      = ipc::SOCKET_PATH.to_string();
        let mut no_filter   = false;
        let mut log_file:   Option<String> = None;
        let mut train_csv:  Option<String> = None;
        let mut train_label: u8 = 0;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--interface" => {
                    i += 1;
                    interface = args.get(i).cloned().unwrap_or_default();
                }
                "--victim-ip" => {
                    i += 1;
                    victim_ip = args.get(i).cloned();
                }
                "--k" => {
                    i += 1;
                    k = args.get(i)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(2.0);
                }
                "--alpha" => {
                    i += 1;
                    alpha = args.get(i)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(ewma::DEFAULT_ALPHA);
                }
                "--socket" => {
                    i += 1;
                    socket = args.get(i).cloned().unwrap_or(ipc::SOCKET_PATH.to_string());
                }
                "--no-filter" => {
                    no_filter = true;
                }
                "--log-file" => {
                    i += 1;
                    log_file = args.get(i).cloned();
                }
                "--train-csv" => {
                    i += 1;
                    train_csv = args.get(i).cloned();
                }
                "--label" => {
                    i += 1;
                    train_label = args.get(i)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                }
                "--help" | "-h" => {
                    print_usage(&args[0]);
                    process::exit(0);
                }
                other => {
                    eprintln!("Unknown argument: {other}");
                    print_usage(&args[0]);
                    process::exit(1);
                }
            }
            i += 1;
        }

        // Validate required arguments.
        if interface.is_empty() {
            eprintln!("Error: --interface is required.");
            print_usage(&args[0]);
            process::exit(1);
        }

        Self { interface, victim_ip, k, alpha, socket, no_filter, log_file, train_csv, train_label }
    }
}

fn print_usage(bin: &str) {
    eprintln!(
        r"\nUsage: {bin} --interface <IFACE> [--victim-ip <IP>] [OPTIONS]\n"
    );
    eprintln!("Options:");
    eprintln!("  --interface  <IFACE>   Network interface to sniff (e.g., br0)");
    eprintln!("  --victim-ip  <IP>      BPF filter IP. Omit with --no-filter.");
    eprintln!("  --k          <FLOAT>   Anomaly multiplier k  [default: 2.0]");
    eprintln!("  --alpha      <FLOAT>   EWMA smoothing alpha  [default: 0.125]");
    eprintln!("  --socket     <PATH>    IPC socket path       [default: /tmp/ddos_stage1.sock]");
    eprintln!("  --no-filter            Disable BPF filter (dev/test only)");
    eprintln!("  --log-file   <PATH>    Path to write logs to in addition to terminal");
    eprintln!("  --train-csv  <PATH>    Write ALL post-warmup feature vectors to CSV (training mode)");
    eprintln!("  --label      <INT>     Class label for training CSV rows (0=normal, 1=flash_crowd, 2=ddos)");
    eprintln!("  --help, -h             Show this message");
    eprintln!();
    eprintln!("Environment:");
    eprintln!("  RUST_LOG=info|debug|warn   Log verbosity (default: info)");
    eprintln!();
    eprintln!("Requires root or CAP_NET_RAW capability for raw pcap capture.");
}

// =============================================================================
// main()
// =============================================================================
fn main() {
    // Parse CLI arguments first so we know if a log file is requested.
    let args = CliArgs::parse();

    // Setup logging target
    let log_file = if let Some(ref path) = args.log_file {
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            Ok(file) => Some(file),
            Err(e) => {
                eprintln!("[ERROR] Failed to open log file '{}': {}", path, e);
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    struct LogSplitter {
        file: Option<std::fs::File>,
    }

    impl std::io::Write for LogSplitter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let stderr = std::io::stderr();
            let mut handle = stderr.lock();
            let _ = handle.write_all(buf);

            if let Some(ref mut f) = self.file {
                let _ = f.write_all(buf);
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            let _ = std::io::stderr().flush();
            if let Some(ref mut f) = self.file {
                let _ = f.flush();
            }
            Ok(())
        }
    }

    // Initialise the env_logger — reads RUST_LOG env var for level.
    // Defaults to INFO if RUST_LOG is not set.
    let mut builder = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    );
    builder.format_timestamp_millis();
    builder.target(env_logger::Target::Pipe(Box::new(LogSplitter { file: log_file })));
    builder.init();

    info!("╔══════════════════════════════════════════════════════════╗");
    info!("║  Adaptive DDoS Pre-Filter — Stage 1 (Rust)              ║");
    info!("║  Abdullah Armiyao | ***REMOVED*** | ***REMOVED*** ***REMOVED***      ║");
    info!("╚══════════════════════════════════════════════════════════╝");

    // -------------------------------------------------------------------------
    // Build the capture and analysis configurations.
    // -------------------------------------------------------------------------

    // Capture config: BPF filter applied only when --no-filter is not set
    // and a victim IP was provided.
    let cap_cfg = if args.no_filter || args.victim_ip.is_none() {
        log::warn!("main: BPF filter DISABLED — all traffic will be processed (dev mode only)");
        CaptureConfig::for_test(&args.interface)
    } else {
        let victim = args.victim_ip.as_deref().unwrap();
        info!("main: BPF filter target victim IP = {victim}");
        CaptureConfig::for_bridge(&args.interface, victim)
    };

    let analysis_cfg = AnalysisConfig {
        k:           args.k,
        ewma_alpha:  args.alpha,
        socket_path: args.socket.clone(),
        victim_ip:   args.victim_ip.clone().unwrap_or_default(),
        train_csv:   args.train_csv.clone(),
        train_label: args.train_label,
    };

    // -------------------------------------------------------------------------
    // Privilege pre-check: attempt to open the interface NOW, on the main
    // thread, before spawning anything. If pcap fails here it almost always
    // means missing CAP_NET_RAW (not running as root).
    //
    // Doing this early gives us a loud, synchronous error message instead of
    // the silent exit that happens when the capture thread dies and drops the
    // crossbeam channel before the analysis thread ever processes a packet.
    // -------------------------------------------------------------------------
    {
        use pcap::Capture;
        let test_open = Capture::from_device(cap_cfg.interface.as_str())
            .and_then(|inactive| inactive.snaplen(64).timeout(1).open());

        if let Err(e) = test_open {
            let msg = e.to_string().to_lowercase();
            if msg.contains("permission denied") || msg.contains("operation not permitted") {
                eprintln!();
                eprintln!("[ERROR] Permission denied opening '{}'", cap_cfg.interface);
                eprintln!("        pcap requires raw socket access. Fix with one of:");
                eprintln!("          1. Run as root:              sudo ./ddos_stage1 ...");
                eprintln!("          2. Grant capability (once):  sudo setcap cap_net_raw+ep ./ddos_stage1");
                eprintln!();
            } else {
                eprintln!("[ERROR] Cannot open interface '{}': {}", cap_cfg.interface, e);
                eprintln!("        Check that the interface name is correct.");
                if let Ok(devices) = pcap::Device::list() {
                    let names: Vec<_> = devices.iter().map(|d| d.name.as_str()).collect();
                    eprintln!("        Available interfaces: {}", names.join(", "));
                }
            }
            process::exit(1);
        }
        // The test handle is dropped here — the real capture thread opens a
        // fresh handle. Opening twice is fine; pcap handles are independent.
    }

    info!(
        "main: config | interface={} | k={} | α={} | socket={}",
        cap_cfg.interface, analysis_cfg.k, analysis_cfg.ewma_alpha, analysis_cfg.socket_path
    );

    // -------------------------------------------------------------------------
    // Create the bounded crossbeam channel connecting capture → analysis.
    // -------------------------------------------------------------------------
    let (tx, rx) = bounded(capture::CHANNEL_CAPACITY);

    info!(
        "main: channel capacity = {} packets",
        capture::CHANNEL_CAPACITY
    );

    // -------------------------------------------------------------------------
    // Spawn the analysis thread first so it is ready to consume from the
    // channel before the capture thread starts flooding it.
    // -------------------------------------------------------------------------
    let analysis_handle = std::thread::Builder::new()
        .name("analysis".to_string())
        .spawn(move || {
            analysis::run_analysis_thread(analysis_cfg, rx);
        })
        .expect("failed to spawn analysis thread");

    // -------------------------------------------------------------------------
    // Run the capture thread on the *current* thread (main thread).
    // This blocks indefinitely.  The analysis thread runs in the background.
    //
    // Rationale: running capture on main keeps it easy to handle SIGINT/SIGTERM
    // from the OS — when the process is killed, main unblocks and the `tx`
    // Sender is dropped, which closes the channel and causes the analysis
    // thread to exit cleanly.
    // -------------------------------------------------------------------------
    capture::run_capture_thread(cap_cfg, tx);

    // -------------------------------------------------------------------------
    // Capture thread exited (channel closed or pcap error).
    // Wait for the analysis thread to drain and exit cleanly.
    // -------------------------------------------------------------------------
    info!("main: capture thread exited; waiting for analysis thread to finish...");
    if let Err(e) = analysis_handle.join() {
        log::error!("main: analysis thread panicked: {e:?}");
        process::exit(1);
    }

    info!("main: clean shutdown complete.");
}
