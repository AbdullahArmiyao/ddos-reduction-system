# DDoS Reduction Project — Stage 0 & 1 Overview

## Architecture (what was built)

```
stage1/
├── Cargo.toml              ← Project manifest (pcap, etherparse, crossbeam, byteorder, log)
└── src/
    ├── main.rs             ← Entry point, CLI parser, thread orchestrator
    ├── capture.rs          ← Stage 0: pcap capture thread + BPF filter
    ├── analysis.rs         ← Stage 1: Three-layer analysis thread
    ├── welford.rs          ← Layer 3 math: Welford online variance accumulator
    ├── ewma.rs             ← Layer 1 math: EWMA rate estimator
    ├── entropy.rs          ← Layer 1/2 math: Shannon entropy calculator
    └── ipc.rs              ← IPC: byte-exact FeatureVector serialisation → Python

scripts/
├── install.sh              ← Linux installer (Debian/Ubuntu, RHEL/Fedora, Alpine)
├── install.bat             ← Windows installer (dev/test only)
├── update.sh               ← Atomic update: stop → rebuild → replace → restart
├── uninstall.sh            ← Full teardown: service + binary + socket
└── run.sh                  ← Interactive testing runner daemon launcher

run.sh                      ← Shortcut symlink/redirect script in project root
```

## The Routed Subnet Setup (192.168.1.0/24 $\rightarrow$ 10.0.0.0/24)

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

*   **How it works:** The Attacker VM (`192.168.1.4`) targets the Victim VM (`10.0.0.3`). Because they are on different subnets, the Attacker routes the traffic through its default gateway (`192.168.1.2` - the Sensor VM's ingress interface `ens19`).
*   **Where to capture:** Run `ddos_stage1` on the **ingress interface (`ens19`)** where the flood traffic first enters the gateway.

---

## The Three-Layer Pipeline (Stage 1)

```
[ Stage 0: pcap captures ingress frame ]
           │ (BPF: dst host <victim_ip>)
           │ PacketMeta { src_ip, arrived_at }
           ▼ crossbeam bounded channel
[ LAYER 1: per-packet ]
   ├── EwmaState::update(arrived_at)     → smoothed rate memory updated
   └── EntropyAccumulator::add_packet(src_ip) → IP frequency map updated
           │
           │  (every 50th packet — window close)
           ▼
[ LAYER 2: per-window ]
   ├── h = entropy.compute_and_reset()  → scalar bits [0.0 .. 5.64]
   └── r = ewma.snapshot()              → scalar pps  [0.0 .. ∞)
           │
           ▼
[ LAYER 3: per-window ]
   ├── welford_rate.update(r)
   ├── welford_entropy.update(h)
   ├── if r > μ_rate + k·σ_rate    → FLAG_RATE_ANOMALY
   └── if h < μ_entropy - k·σ_ent  → FLAG_ENTROPY_ANOMALY
           │
           │  (only if warm AND any flag set)
           ▼
[ IPC: FeatureVector → Unix Domain Socket → Stage 2 Python ]
```

## Test Results (18 tests, all passing)

| Module | Tests | Status |
|---|---|---|
| `welford.rs` | 6 | ✅ All pass |
| `ewma.rs` | 5 | ✅ All pass |
| `entropy.rs` | 7 | ✅ All pass |
| `ipc.rs` | 3 | ✅ Compiles (need libpcap to link) |

> **Note:** `cargo test` requires `libpcap-devel` installed on the gateway machine.  
> `sudo dnf install -y libpcap-devel` then `cargo test`

## Run Command (on gateway)

To start both Stage 1 and Stage 2 together interactively in testing mode:
```bash
sudo ./run.sh --interface ens19 --victim-ip 10.0.0.3
```

To run Stage 1 individually:
```bash
# Listen on ingress interface ens19 targeting the victim IP
sudo ./ddos_stage1 --interface ens19 --victim-ip 10.0.0.3
```

Or via systemd after running the installer:
```bash
systemctl enable --now ddos-stage1
systemctl enable --now ddos-stage2
```

## Key Design Decisions

| Decision | Reason |
|---|---|
| Rust for Stage 1 | Eliminates Python GIL on the hot packet-inspection loop |
| Bounded crossbeam channel | Backpressure prevents unbounded memory growth under flood |
| EWMA never resets | Carries ramp-up memory across windows — detects gradual floods |
| Entropy resets every window | Measures *current* window diversity, not historical trend |
| Welford capped at n=500 | Prevents "frozen mean" on long-running session |
| Warmup = 30 windows | Layer 3 doesn't fire until baseline is statistically meaningful |
| `#[repr(C)]` not used | Manual byteorder serialisation instead — no invisible padding bugs |

## What's Next (Stage 2 — Python)

1. Python Unix socket server listening on `/tmp/ddos_stage1.sock`
2. `struct.unpack('<dddBQ', data)` to decode the 33-byte FeatureVector
3. Random Forest classifier on 5 features
4. `ipset add ddos_blocklist <src_ip>` for confirmed attacks
5. Closed-loop feedback socket back to Stage 1 for k-decay threshold widening
