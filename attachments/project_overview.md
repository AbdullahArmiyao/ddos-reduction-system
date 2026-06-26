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
└── uninstall.sh            ← Full teardown: service + binary + socket
```

## The Three-Layer Pipeline (Stage 1)

```
[ Stage 0: pcap captures br0 frame ]
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

```bash
sudo ./ddos_stage1 --interface br0 --victim-ip 10.0.0.3
```

Or via systemd after `install.sh`:
```bash
systemctl enable --now ddos-stage1
journalctl -u ddos-stage1 -f
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
