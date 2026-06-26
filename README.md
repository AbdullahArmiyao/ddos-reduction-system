# Adaptive Two-Stage DDoS Mitigation Gateway

**Author:** Abdullah Armiyao | ***REMOVED***  
**Course:** ***REMOVED*** — ***REMOVED*** II | ***REMOVED***  
**Project:** Adaptive Two-Stage Framework for Near Real-Time DDoS Mitigation Using Behavioral Traffic Analysis

---

## What This Project Is

Most DDoS mitigation systems use **static thresholds** — hard-coded numbers like "block any IP sending more than 1000 packets/sec." The problem is that your legitimate traffic might naturally spike to 1000 pps during a registration rush, so those systems either miss real attacks or block real users.

This project solves that by building a gateway that **learns what your normal traffic looks like** and adapts its detection boundaries accordingly. It can tell the difference between a DDoS flood and a flash crowd (a legitimate traffic surge) without a human adjusting thresholds.

The system is split into two stages:

- **Stage 1 (Rust):** Sits inline on the network bridge, watches every packet, runs lightweight statistics, and raises an anomaly flag when something looks wrong.
- **Stage 2 (Python, not yet built):** Wakes up only when Stage 1 flags something, runs a Random Forest classifier to confirm whether it's a real attack or a flash crowd, then issues kernel-level blocks via `ipset`.

---

## Network Topology

```
[ Attacker VM ] ──────────────────────────────────────────────┐
                                                               │
                         [ Sensor VM — br0 bridge ]           │
                     ┌──────────────────────────────┐         │
                     │  ddos_stage1 (Rust, Stage 1) │◄────────┘
                     │  stage2.py   (Python, Stage 2)│
                     └──────────────────────────────┘
                                    │
                                    │ (traffic passes through if clean)
                                    ▼
                          [ Victim VM — Nginx ]
```

The Sensor VM acts as a **transparent Layer 2 bridge** (`br0`). All traffic between Attacker and Victim passes through it. The gateway software sits on that bridge and inspects every packet without the Attacker or Victim knowing it exists.

---

## The Three-Layer Pipeline (Stage 1)

Every packet that enters `br0` addressed to the victim goes through this pipeline:

```
[ Packet arrives on br0 ]
         │
         │  BPF filter: dst host <victim_ip>  (kernel drops everything else)
         ▼
[ Stage 0: Capture Thread ]
   pcap reads raw frame → etherparse extracts src_ip + timestamp
   → sends PacketMeta over crossbeam channel →
         │
         ▼
[ LAYER 1: per-packet — Analysis Thread ]
   ├── EwmaState::update(timestamp)      updates smoothed rate estimate
   └── EntropyAccumulator::add(src_ip)   increments IP frequency counter
         │
         │  (every 50th packet — window closes)
         ▼
[ LAYER 2: per-window ]
   ├── h = entropy.compute_and_reset()   → diversity scalar  [0.0 .. 5.64 bits]
   └── r = ewma.snapshot()               → rate scalar       [0.0 .. ∞ pps]
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

**The problem it solves:** You need a *rate* (packets per second) that reacts quickly to floods but isn't thrown off by a single bursty moment. A Simple Moving Average weights all past samples equally — it's slow to react. EWMA weights recent samples exponentially more.

**The formula:**

```
instant_rate = 1.0 / time_between_last_two_packets   (seconds)
ewma_new     = α · instant_rate + (1 − α) · ewma_old
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
- `0x02` — entropy only tripped (concentrated source, lower volume → low-and-slow)
- `0x03` — **both tripped** (high volume + concentrated source → highest-confidence DDoS)

Stage 2 uses this flag plus four additional features in the Random Forest to make the final call.

---

### 5. IPC: Feature Vector Wire Format

**File:** `stage1/src/ipc.rs`

When Stage 1 flags an anomaly, it serialises a `FeatureVector` struct and sends it over a Unix Domain Socket to Stage 2 (Python).

The wire format is **exactly 33 bytes, little-endian**:

| Offset | Size | Field | Type |
|---|---|---|---|
| 0 | 8 bytes | `ewma_rate` | f64 |
| 8 | 8 bytes | `entropy` | f64 |
| 16 | 8 bytes | `dominant_ip_ratio` | f64 |
| 24 | 1 byte | `anomaly_flags` | u8 |
| 25 | 8 bytes | `window_id` | u64 |

Python unpacks it with: `struct.unpack('<dddBQ', data)`

Fields are written manually with `byteorder` rather than transmuting the Rust struct directly. This eliminates invisible padding bugs — Rust structs can insert alignment padding that `struct.unpack` wouldn't know about.

---

### 6. The Capture Thread and Crossbeam Channel

**File:** `stage1/src/capture.rs`

**Why a separate thread?** If capture and analysis ran in the same loop, every 50-packet window computation would stall the capture loop. Under a 100k pps flood, even microseconds of stall overflow the kernel's ring buffer — packets are silently dropped before Rust even sees them.

**The solution:** Two threads connected by a bounded `crossbeam-channel`:
- **Capture thread** calls `pcap::next_packet()` in a tight loop, parses headers with `etherparse`, sends `PacketMeta` into the channel. Never blocks on analysis.
- **Analysis thread** receives from the channel and runs Layers 1–3.

**Why bounded?** If the analysis thread falls behind, the channel fills and the capture thread *blocks* (backpressure) rather than allocating memory without limit. A bounded queue is safer than an unbounded one under sustained flood.

**BPF filter:** `dst host <victim_ip>` is applied at the kernel level before Rust sees a single byte. Outbound replies, ARP, and broadcast are discarded in the kernel — the analysis thread only ever sees inbound unicast packets destined for the victim.

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
sudo bash scripts/install.sh --interface br0 --victim-ip 10.0.0.3
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

```bash
# Production (on sensor VM)
sudo ddos_stage1 --interface br0 --victim-ip 10.0.0.3

# Development (no BPF filter, any interface)
RUST_LOG=debug sudo ddos_stage1 --interface lo --no-filter

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
| `0x02` | Entropy only | Concentrated source, low volume — low-and-slow attack |
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
# Update (rebuild + atomic binary replace + reapply capabilities)
sudo bash scripts/update.sh

# Uninstall (removes binary, service unit, socket file)
sudo bash scripts/uninstall.sh

# Full uninstall including build cache and Rust toolchain
sudo bash scripts/uninstall.sh --remove-build --remove-rust
```

---

## Stage 2 — Coming Next (Python)

Stage 2 will listen on `/tmp/ddos_stage1.sock`, unpack incoming `FeatureVector` structs, and run them through a trained Random Forest classifier.

```python
import socket, struct

# Python-side wire format (matches Rust exactly)
FORMAT = '<dddBQ'   # little-endian: f64 f64 f64 u8 u64 = 33 bytes
FIELDS = ('ewma_rate', 'entropy', 'dominant_ip_ratio', 'anomaly_flags', 'window_id')

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as srv:
    srv.bind('/tmp/ddos_stage1.sock')
    srv.listen(1)
    conn, _ = srv.accept()
    data = conn.recv(33)
    values = struct.unpack(FORMAT, data)
    fv = dict(zip(FIELDS, values))
    # → pass to RandomForestClassifier, then ipset block or k-decay widen
```

The five features fed to the classifier:
1. Source IP Entropy
2. Packet Rate Deviation (EWMA)
3. Packet Size Variance *(added in Stage 2)*
4. SYN/ACK Ratio *(added in Stage 2)*
5. Layer 4 Protocol Distribution *(added in Stage 2)*

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
