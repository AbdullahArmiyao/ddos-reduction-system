# Adaptive Two-Stage DDoS Mitigation Gateway

**Author:** Abdullah Armiyao

**Project:** Adaptive Two-Stage Framework for Near Real-Time DDoS Mitigation Using Behavioral Traffic Analysis


## What This Project Is

Most DDoS mitigation systems use **static thresholds** — hard-coded numbers like "block any IP sending more than 1000 packets/sec." The problem is that your legitimate traffic might naturally spike to 1000 pps during a registration rush, so those systems either miss real attacks or block real users.

This project solves that by building a gateway that **learns what your normal traffic looks like** and adapts its detection boundaries accordingly. It can tell the difference between a DDoS flood and a flash crowd (a legitimate traffic surge) without a human adjusting thresholds.

The system is split into two stages:

- **Stage 1 (Rust):** Sits inline on the network bridge, watches every packet, runs lightweight statistics, and raises an anomaly flag when something looks wrong.
- **Stage 2 (Python, not yet built):** Wakes up only when Stage 1 flags something, runs a Random Forest classifier to confirm whether it's a real attack or a flash crowd, then issues kernel-level blocks via `ipset`.


## Network Topology and Virtualization Gotchas

In virtualized hypervisor environments (like Proxmox VE), the layout of your network bridges directly controls what traffic the Sensor VM can inspect.

### The Virtual Switch Subnet Bypass Gotcha
If the **Attacker VM** and **Victim VM** are placed on the same Proxmox bridge (e.g., `vmbr1`) and share the same IP subnet (e.g., `192.168.1.0/24`):
1. They communicate directly host-to-host at Layer 2. The Proxmox host switch learns their MAC addresses and forwards packets directly between their virtual ports.
2. Even if the Sensor VM is configured as their default gateway, **local subnet traffic bypasses the gateway**. 
3. The Sensor VM's NIC (`ens19`) receives 0% of the unicast flood traffic. It will only capture broadcast packets (like ARP requests) or traffic sent directly to the Sensor's IP.

---

### The Routed Subnet Setup (192.168.1.0/24 -> 10.0.0.0/24)

To ensure the Sensor VM can inspect and filter all traffic, the Attacker and Victim are separated into two distinct subnets connected by the Sensor VM acting as an IP Router:

```
[ Attacker / Flash Crowd ]             [ Sensor VM / Gateway ]                 [ Victim VM ]
  (Subnet: 192.168.1.0/24)             (Router/Firewall Gateway)          (Subnet: 10.0.0.0/24)
  (IP: 192.168.1.4)                                │                      (IP: 10.0.0.3)
         │                                         │                            │
     [ vmbr1 ] <───────────────────────────────> [ens19]                        │
   (LAN Segment 1)                       (IP: 192.168.1.2)                      │
                                                 [ens20] <──────────────────> [ vmbr2 ]
                                         (IP: 10.0.0.2)                     (LAN Segment 2)
```

*   **How it works:** The Attacker VM (`192.168.1.4`) wants to target the Victim VM (`10.0.0.3`). Because they are on different subnets, the Attacker is forced to route the traffic through its default gateway (`192.168.1.2` - the Sensor VM's ingress interface).
*   **Where to capture:** Run `ddos_stage1` on the **ingress interface (`ens19`)** where the flood traffic first enters the gateway.

---

## The Three-Layer Pipeline (Stage 1)

Every packet that enters the ingress interface addressed to the victim goes through this pipeline:

```
[ Packet arrives on ingress interface ]
         │
         │  BPF filter: dst host <victim_ip>  (kernel drops everything else)
         ▼
[ Stage 0: Capture Thread ]
   pcap reads raw frame → etherparse extracts src_ip + timestamp
   → sends PacketMeta over crossbeam channel →
         │
         ▼
[ LAYER 1: per-packet — Analysis Thread ]
   └── EntropyAccumulator::add(src_ip)   increments IP frequency counter
         │
         │  (every 50th packet — window closes)
         ▼
[ LAYER 2: per-window ]
   ├── h = entropy.compute_and_reset()   → diversity scalar  [0.0 .. 5.64 bits]
   └── r = ewma.update(window_duration)  → rate scalar       [0.0 .. ∞ pps]
         │
         ▼
[ LAYER 3: per-window ]
   ├── welford_rate.update(r)
   ├── welford_entropy.update(h)
   ├── if r  >  μ_rate    + k·σ_rate    → FLAG_RATE_ANOMALY    (flood)
   └── if h  <  μ_entropy − k·σ_entropy → FLAG_ENTROPY_ANOMALY (concentrated source)
         │
         │  (only fires after warm-up AND at least one flag is set)
         ▼
[ IPC: FeatureVector → Unix Domain Socket → Stage 2 Python ]
```

---

## Key Building Blocks Explained

### 1. Welford's Online Variance Algorithm

**File:** `stage1/src/welford.rs`

**The problem it solves:** You need to track the running mean and standard deviation of a stream of numbers (packet rates, entropy scores) without storing every past value. The naïve approach — accumulate `sum` and `sum_of_squares`, then compute variance — causes **catastrophic cancellation**: two huge numbers almost cancel each other, leaving a near-zero or even *negative* result due to floating-point errors.

**How Welford works:**

Each time a new sample `x` arrives, run exactly these five steps:

```
n     += 1
delta  = x - mean          ← surprise vs the OLD mean
mean  += delta / n         ← shift the centre toward x
delta2 = x - mean          ← surprise vs the NEW mean
M2    += delta * delta2    ← accumulate the cross-product
```

Then: `variance = M2 / (n - 1)`

**Why two deltas?** `delta` measures how surprising `x` was *before* the mean moved. `delta2` measures how far `x` still is *after* the mean stepped toward it. Their product is the exact algebraic correction that transitions the sum-of-squares from the old mean to the new mean in one step, with no stored history and no cancellation.

**Recency cap:** After weeks of running, `n` becomes enormous and `delta/n ≈ 0`, freezing the mean. The implementation caps `n` at 500 so the algorithm stays sensitive to recent traffic patterns.

**Warm-up:** The first 30 windows are discarded from anomaly evaluation. Welford's variance is meaningless on 2–3 samples.

**Golden test:** `[4, 7, 13, 16]` → mean = 10.0, variance = 30.0 exactly.

---

### 2. Exponentially Weighted Moving Average (EWMA)

**File:** `stage1/src/ewma.rs`

**The problem it solves:** You need a *rate* (packets per second) that reacts quickly to floods but isn't thrown off by a single bursty packet interval or scheduling delays.

**How it works (Jitter-Resistant design):**
Instead of updating the EWMA rate per packet (which suffers from massive timing jitter spikes due to OS interrupt coalescing or virtualization scheduling), Stage 1 calculates the rate **once per 50-packet window** using the window's exact elapsed time:
```
window_rate = WINDOW_SIZE / window_duration_seconds
ewma_new    = α · window_rate + (1 − α) · ewma_old
```

`α` (alpha) controls responsiveness:
- High α → reacts fast, noisier
- Low α → smooth, slower reaction
- Default: `α = 0.125` (same constant used in TCP's RTT estimator, RFC 6298)

**Critical behaviour — EWMA never resets.** Unlike entropy (which is computed fresh each window), the EWMA carries memory *across* windows by design. A DDoS flood that ramps up gradually across multiple windows is still detected because the EWMA accumulates the rising rate over time.

**What it produces:** One scalar `r` per window close — the current smoothed packet rate in packets/second. This `r` feeds directly into the Welford accumulator for rate tracking.

---

### 3. Shannon Source-IP Entropy

**File:** `stage1/src/entropy.rs`

**The problem it solves:** Raw packet count can't distinguish a DDoS from a flash crowd — both produce high volume. Unique IP count misses distribution shape — ten IPs each sending five packets looks the same as one IP sending 41 packets and nine others sending one each. Shannon Entropy captures the *full probability distribution* of source IPs in a single number.

**The formula:**

```
H(X) = −Σ p(xᵢ) · log₂(p(xᵢ))
```

Where `p(xᵢ)` is the fraction of packets in the current window that came from IP `xᵢ`.

**Interpretation for a 50-packet window:**

| Scenario | Entropy |
|---|---|
| All 50 packets from one IP | **0.0 bits** (total concentration — DDoS) |
| 25 packets each from 2 IPs | **1.0 bit** |
| 50 packets from 50 unique IPs | **≈ 5.64 bits** (maximum diversity — normal) |

**Why entropy *drops* during DDoS:** A flood from a spoofed or single source concentrates packets toward one IP, collapsing the distribution and dragging entropy toward zero. Layer 3 fires when entropy drops *below* `μ − k·σ` rather than above it.

**Critical behaviour — entropy resets every window.** The HashMap is cleared after each computation. Entropy measures the diversity of *this* 50-packet batch, not a historical trend. The long-run trend is tracked by the Welford accumulator.

---

### 4. The Anomaly Boundary: μ ± k·σ

**Files:** `stage1/src/welford.rs`, `stage1/src/analysis.rs`

After Welford processes enough windows to establish a baseline, Layer 3 compares each new scalar against a dynamic boundary:

| Metric | Anomaly direction | Meaning |
|---|---|---|
| EWMA rate `r` | `r > μ_rate + k·σ_rate` | Rate spiked above normal → flood |
| Entropy `h` | `h < μ_entropy − k·σ_entropy` | Diversity collapsed → concentrated source |

`k = 2.0` by default (two standard deviations), configurable via `--k`. This covers ~95% of a normal distribution — values outside it are statistically unusual.

**The anomaly flags bitmask:**
- `0x01` — rate only tripped (volumetric, diverse sources → possible flash crowd)
- `0x02` — entropy only tripped (concentrated source, lower volume)
- `0x03` — **both tripped** (high volume + concentrated source → highest-confidence DDoS)

Stage 2 uses this flag plus four additional features in the Random Forest to make the final call.

---

### 5. IPC: Feature Vector Wire Format

**File:** `stage1/src/ipc.rs`

When Stage 1 flags an anomaly, it serialises a `FeatureVector` struct and sends it over a Unix Domain Socket to Stage 2 (Python).

The wire format is **exactly 88 bytes, little-endian**:

| Offset | Size | Field | Type | Description |
|---|---|---|---|---|
| 0 | 8 bytes | `entropy` | f64 | Shannon source IP entropy |
| 8 | 8 bytes | `ewma_rate` | f64 | EWMA packet rate (pps) |
| 16 | 8 bytes | `mean_h` | f64 | Running mean of entropy |
| 24 | 8 bytes | `mean_r` | f64 | Running mean of EWMA rate |
| 32 | 8 bytes | `sigma_h` | f64 | Standard deviation of entropy |
| 40 | 8 bytes | `sigma_r` | f64 | Standard deviation of EWMA rate |
| 48 | 8 bytes | `proto_ratio` | f64 | TCP packet ratio (vs UDP/ICMP) |
| 56 | 8 bytes | `dominant_ip_ratio` | f64 | Ratio of packets from busiest IP |
| 64 | 8 bytes | `timestamp` | f64 | UNIX timestamp of window close |
| 72 | 16 bytes | `dominant_ip` | [u8; 16] | Busiest source IP (IPv6 or mapped IPv4) |

Python unpacks it with: `struct.unpack('<9d16s', data)`

Fields are written manually with `byteorder` rather than transmuting the Rust struct directly. This eliminates invisible padding bugs — Rust structs can insert alignment padding that `struct.unpack` wouldn't know about.

---

### 6. The Capture Thread, BPF, and Memory Tuning

**File:** `stage1/src/capture.rs`

**Why a separate thread?** If packet capture and analysis ran in the same thread, every 50-packet window calculation (calculating floating-point entropy and writing to sockets) would stall the capture loop. Under a 100k pps flood, even microseconds of stall overflow the kernel's raw socket buffer, leading to silent drops.

**The solution:** Two threads connected by a bounded `crossbeam-channel`:
- **Capture thread** calls `pcap::next_packet()` in a tight loop, parses headers with `etherparse`, and sends `PacketMeta` into the channel. It never blocks on calculations.
- **Analysis thread** receives from the channel and executes Layers 1–3.

#### Berkeley Packet Filter (BPF) — In-Kernel Gatekeeping
Our Rust tool applies the filter `"dst host <victim_ip> or (vlan and dst host <victim_ip>)"` using the kernel's native BPF engine:
*   **The Analogy (The Mailroom Sorter):** Imagine a huge corporate building (the OS). If you don't use BPF, the mailroom clerk (the kernel) must load every junk letter onto the elevator, ride to the top floor, and dump them on the CEO's desk (user-space Rust process) to be sorted. With BPF, a fast mechanical scanner sits on the basement loading dock. It scans the envelopes and shreds non-victim letters instantly. The elevator is never clogged.
*   **The Tech:** The user-space filter compiles to BPF bytecode. The Linux kernel verifies the code for safety and uses a **Just-In-Time (JIT) compiler** to turn it into native x86 machine instructions. Packets matching the filter are cloned to our raw socket; everything else is discarded instantly in the kernel network driver.

#### High-Speed Capture Performance Tuning
To survive high-rate volumetric floods (1,000,000+ pps) without crashing the virtual machine, the capture module is tuned with three critical parameters:
1.  **Reduced Snaplen (`snaplen = 256` bytes):** Instead of copying the full 64KB frame buffer to user-space (which saturates the CPU cache and memory bus), we only copy the first 256 bytes. This is more than enough to capture the Ethernet, VLAN, IPv4/IPv6, and TCP/UDP headers, reducing memory transfer costs by **99.6%**.
2.  **Immediate Mode (`immediate_mode = true`):** Bypasses the kernel's internal buffering window. Packets are flushed to the socket buffer instantly rather than waiting for block retirement.
3.  **Scaled Socket Buffer (`buffer_size = 128MB`):** Pins a 128MB ring buffer in kernel memory to act as a runway. If the Rust application experiences a brief context switch stall, the kernel can buffer up to ~1.3 million packet headers (at 96 bytes each) without drops.

---

### 7. Why a Hybrid Architecture? (Rust vs. Python)

One might ask: *If the Rust pre-filter is running in user-space anyway, why not write the entire system in Python?* 

The answer lies in the **Global Interpreter Lock (GIL)** and **runtime overhead**:

*   **Python's Limitations under Flood:** Python is interpreted, garbage-collected, and bound by the GIL (only one thread can execute bytecode at a time, even on multi-core systems). Creating objects and running Scapy/PyShark parsers on every incoming packet caps Python's throughput at **~20,000 packets/second** before hitting 100% CPU.
*   **Rust's Efficiency:** Rust compiles to native code, has no garbage collector, and has zero-cost abstractions. Zero-copy parsing allows it to handle **2,000,000+ packets/second** on a single thread.
*   **The Division of Labor:**
    *   **Stage 1 (Rust):** Handles the high-speed volumetric shield (1,000,000+ pps). It condenses millions of raw packets into a single summary `FeatureVector` per window.
    *   **Stage 2 (Python):** Wakes up to process only **1 Feature Vector per window** (a tiny, low-rate stream of ~10–100 data points per second). At this volume, Python's performance overhead is negligible, allowing us to leverage Python's powerful machine learning libraries (`scikit-learn`, `pandas`) safely.

---

## Project File Structure

```
DDoS Reduction Project/
├── README.md                       ← this file
├── attachments/
│   ├── ***REMOVED***_copy.pdf              ← original assignment brief
│   ├── Abdullah_Armiyao_***REMOVED***_Proposal_Rust.docx  ← submitted proposal
│   └── Stage 1 in depth.txt       ← architecture design notes
├── stage1/                         ← Stage 1: Rust binary
│   ├── Cargo.toml                  ← dependencies and build profile
│   └── src/
│       ├── main.rs                 ← CLI, privilege check, thread orchestrator
│       ├── capture.rs              ← Stage 0: pcap capture thread
│       ├── analysis.rs             ← Three-layer analysis thread
│       ├── welford.rs              ← Welford online variance accumulator
│       ├── ewma.rs                 ← EWMA rate estimator
│       ├── entropy.rs              ← Shannon entropy calculator
│       └── ipc.rs                  ← Binary IPC serialisation → Python
└── scripts/
    ├── install.sh                  ← Linux installer (Debian/Ubuntu, RHEL, Alpine)
    ├── install.bat                 ← Windows installer (dev/test only)
    ├── update.sh                   ← Atomic update script
    └── uninstall.sh                ← Full teardown script
```

---

## Installation

### Linux (Debian/Ubuntu, RHEL/Fedora, Alpine)

```bash
sudo bash scripts/install.sh --interface ens19 --victim-ip 10.0.0.3
```

This will:
1. Detect your OS and install `libpcap-dev` + build tools
2. Install Rust via `rustup` if not present
3. Compile Stage 1 in release mode
4. Install the binary to `/usr/local/bin/ddos_stage1`
5. Grant `CAP_NET_RAW` so it runs without `sudo`
6. Install a systemd service unit

### Windows (Development / Testing Only)

```bat
install.bat
```

> **Note:** Windows does not support Linux bridges or `ipset`. The statistical engine and unit tests work, but production deployment requires Linux.

---

## Usage

### Interactive Testing (Run Both Stages Together)

For testing environments or manual execution, a unified runner script is provided in the project root. This starts the Stage 2 Python ML engine in the background, waits for its IPC socket to initialize, starts the Stage 1 Rust capture filter in the foreground, and handles graceful teardown on `Ctrl+C`:

```bash
# Start both stages with default settings (ens19 interface, 10.0.0.3 victim IP)
sudo ./run.sh

# Start both stages with custom settings
sudo ./run.sh --interface ens19 --victim-ip 10.0.0.3
```

### Individual Components Usage

If you prefer to run the components separately:

#### 1. Stage 1 Rust Pre-Filter
```bash
# Production (on sensor VM)
sudo ddos_stage1 --interface ens19 --victim-ip 10.0.0.3
```
# All options
ddos_stage1 --interface <IFACE>     # required
            --victim-ip <IP>        # BPF filter target
            --k <FLOAT>             # anomaly multiplier (default: 2.0)
            --alpha <FLOAT>         # EWMA smoothing (default: 0.125)
            --socket <PATH>         # IPC socket path (default: /tmp/ddos_stage1.sock)
            --no-filter             # disable BPF (dev only)
```

### Log Levels

```bash
RUST_LOG=info   # startup, warmup progress, anomalies (default)
RUST_LOG=debug  # all of the above + every window's r and h values
RUST_LOG=warn   # anomalies and errors only
```

### Expected Output Sequence

```
# Startup
[INFO] banner
[INFO] BPF filter target victim IP = 10.0.0.3
[INFO] Capture: capture loop started on 'br0'

# Warmup (first 1,500 packets = 30 windows)
[INFO] Analysis: warm-up window 1/30  | r=0.0 pps   | h=0.000 bits
[INFO] Analysis: warm-up window 15/30 | r=842.3 pps  | h=4.821 bits
[INFO] Analysis: warm-up window 30/30 | r=917.1 pps  | h=5.103 bits

# Normal operation — silence at INFO level (no news = good news)
# With RUST_LOG=debug:
[DEBUG] Window #31: NORMAL | r=103.2 | h=4.91

# Anomaly detected
[WARN] ANOMALY window #47 | flags=0x03 | r=58291.4 (boundary=2341.1) | h=0.031 (boundary=3.218) | dom_ratio=0.980

# Clean shutdown (Ctrl+C)
[INFO] Analysis: channel closed; processed 47 windows total. Exiting.
```

### Anomaly Flag Reference

| Flag | Meaning | Likely Cause |
|---|---|---|
| `0x01` | Rate only | Volumetric flood, diverse sources — possible flash crowd |
| `0x02` | Entropy only | Concentrated source, low volume |
| `0x03` | Both | High volume + single dominant source — highest confidence DDoS |

---

## Running Tests

```bash
cd stage1

# Requires libpcap-devel installed
cargo test

# Pure math tests only (no libpcap needed)
rustc --edition 2021 --test src/welford.rs -o /tmp/t && /tmp/t
rustc --edition 2021 --test src/ewma.rs    -o /tmp/t && /tmp/t
rustc --edition 2021 --test src/entropy.rs -o /tmp/t && /tmp/t
```

**Test coverage:** 18 tests across Welford (6), EWMA (5), Entropy (7).  
The golden vector `[4, 7, 13, 16]` → `mean=10.0, variance=30.0` is verified on every run.

---

## Update and Uninstall

```bash
# Update (rebuild Rust + update Python dependencies + restart services)
sudo bash scripts/update.sh

# Uninstall (removes binaries, venv, service units, socket file)
sudo bash scripts/uninstall.sh

# Full uninstall including build cache and Rust toolchain
sudo bash scripts/uninstall.sh --remove-build --remove-rust
```

---

## Stage 2 Integration (Python)

Stage 2 listens on `/tmp/ddos_stage1.sock`, unpacks incoming 88-byte `FeatureVector` structs, and classifies traffic in real-time.

```python
import socket, struct

# Python-side wire format (matches Rust exactly)
FORMAT = '<9d16s'   # little-endian: 9 x f64 + 16-byte IP address = 88 bytes
FIELDS = (
    'entropy', 'ewma_rate', 'mean_h', 'mean_r', 'sigma_h', 'sigma_r',
    'proto_ratio', 'dominant_ip_ratio', 'timestamp', 'dominant_ip'
)

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as srv:
    srv.bind('/tmp/ddos_stage1.sock')
    srv.listen(1)
    conn, _ = srv.accept()
    data = conn.recv(88)
    values = struct.unpack(FORMAT, data)
    fv = dict(zip(FIELDS[:-1], values[:-1]))
    # dominant_ip is values[-1] (16 bytes)
    # → pass features to RandomForestClassifier, then block dominant_ip using ipset
```

The eight features fed to the Random Forest classifier:
1. Source IP Entropy (`entropy`)
2. Packet Rate (`ewma_rate`)
3. Entropy Running Mean (`mean_h`)
4. Packet Rate Running Mean (`mean_r`)
5. Entropy Standard Deviation (`sigma_h`)
6. Packet Rate Standard Deviation (`sigma_r`)
7. Protocol Ratio (`proto_ratio`)
8. Dominant Source IP Ratio (`dominant_ip_ratio`)

---

## Dependencies

| Crate | Purpose |
|---|---|
| `pcap` | Raw frame ingestion from the kernel ring buffer |
| `etherparse` | Zero-copy Ethernet/IP/TCP/UDP header parsing |
| `crossbeam-channel` | Bounded MPSC channel between capture and analysis threads |
| `byteorder` | Explicit little-endian serialisation for IPC struct |
| `log` + `env_logger` | Levelled logging controlled by `RUST_LOG` |

All statistical algorithms (Welford, EWMA, Shannon Entropy) use only the Rust standard library — no external crates.

---

## References

1. T. Bai et al., "ATS-DTA: Adaptive two-stage DDoS detection," *Cybersecurity*, vol. 9, 2026.
2. S. Abiramasundari and V. Ramaswamy, "DDoS detection using supervised ML," *Scientific Reports*, 2025.
3. E. Cohen and M. Strauss, "Maintaining time-decaying stream aggregates," *Journal of Algorithms*, 2004.
4. W. Eddy, "TCP SYN Flooding Attacks and Common Mitigations," RFC 4987, IETF, 2007.
5. NIST SP 800-61 Rev. 2, "Computer Security Incident Handling Guide," 2012.
