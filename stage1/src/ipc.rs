// =============================================================================
// ipc.rs — Inter-Process Communication: Rust → Python Feature Vector
// =============================================================================
//
// PURPOSE
// -------
// When Layer 3 flags an anomaly, Stage 1 must hand a feature vector to Stage 2
// (Python Random Forest) over a Unix Domain Socket.  This module defines:
//
//   • The `FeatureVector` struct — the exact binary layout sent on the wire.
//   • Serialisation / deserialisation via explicit `byteorder` writes.
//   • The `IpcSocket` abstraction that manages the domain socket lifecycle.
//
// BYTE ALIGNMENT (the #1 source of silent IPC bugs)
// ---------------------------------------------------
// Rust structs can insert invisible padding bytes to satisfy alignment
// requirements. If Python's `struct.unpack()` format string does not account
// for the *same* padding, the fields unpack into garbage silently — no error,
// just wrong numbers.
//
// To eliminate this risk we serialise every field manually using `byteorder`
// into an explicitly sized byte buffer rather than transmuting the Rust struct
// directly. The Python-side format string is therefore:
//
//   struct.unpack('<8d', data)   →   8 × 8 = 64 bytes
//
//   Field order on the wire (all little-endian f64):
//     [0..8]   entropy      — Shannon entropy h (bits, 0.0..5.64)
//     [8..16]  ewma_rate    — EWMA rate snapshot r (packets/sec)
//     [16..24] mean_h       — Welford entropy baseline
//     [24..32] mean_r       — Welford rate baseline
//     [32..40] sigma_h      — entropy standard deviation
//     [40..48] sigma_r      — rate standard deviation
//     [48..56] proto_ratio  — TCP fraction of window (0.0..1.0)
//     [56..64] timestamp    — window close time (UNIX seconds, f64)
//
// ANOMALY FLAGS BITMASK (retained as constants for logging; not sent on wire)
// ---------------------------------------------------------------------------
//   bit 0 (0x01) — EWMA rate breached upper boundary   (μ_rate + k·σ_rate)
//   bit 1 (0x02) — Entropy dropped below lower boundary (μ_ent  − k·σ_ent)
//
// SOCKET PATH
// ------------
// Stage 2 (Python) must listen on the *same* path before Stage 1 connects.
// The startup sequence is:
//   1. Python Stage 2 creates the socket file and calls accept().
//   2. Rust Stage 1 connects to it after its warm-up phase ends.
//
// The socket path is intentionally in /tmp so no special permissions are
// needed in a dev/lab environment.  A production deployment should use
// /run/<service>/ with appropriate systemd-tmpfiles permissions.
// =============================================================================

use byteorder::{LittleEndian, WriteBytesExt};
use log::{debug, warn};
use std::{
    io::Write,
    os::unix::net::UnixStream,
    path::Path,
    time::Duration,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default socket path. Stage 2 (Python) must listen on this path.
pub const SOCKET_PATH: &str = "/tmp/ddos_stage1.sock";

/// Wire size of one serialised `FeatureVector` in bytes.
/// 9 fields × 8 bytes (f64) = 72 bytes.
/// Python format: `struct.unpack('<9d', data)`
pub const FEATURE_VECTOR_BYTES: usize = 72;

/// Anomaly flag: EWMA rate exceeded upper boundary (volume flood).
/// Retained as a logging constant — no longer sent in the wire payload.
pub const FLAG_RATE_ANOMALY: u8 = 0x01;

/// Anomaly flag: Shannon entropy dropped below lower boundary (concentrated source).
/// Retained as a logging constant — no longer sent in the wire payload.
pub const FLAG_ENTROPY_ANOMALY: u8 = 0x02;

// -----------------------------------------------------------------------------
// FeatureVector
// -----------------------------------------------------------------------------

/// The data payload handed to Stage 2 after every anomalous window.
///
/// Wire format: 9 × f64, little-endian, 72 bytes total.
/// Python unpacks with: `struct.unpack('<9d', data)`
///
/// Field order matches the Python unpack string exactly — **do not reorder**.
#[derive(Debug, Clone)]
pub struct FeatureVector {
    /// Shannon entropy of source IPs in the closed window (bits, 0.0–5.64).
    pub entropy: f64,
    /// Current EWMA rate snapshot (packets per second).
    pub ewma_rate: f64,
    /// Welford entropy baseline — mean of entropy over all past windows.
    pub mean_h: f64,
    /// Welford rate baseline — mean of EWMA rate over all past windows.
    pub mean_r: f64,
    /// Entropy standard deviation (Welford).
    pub sigma_h: f64,
    /// Rate standard deviation (Welford).
    pub sigma_r: f64,
    /// Fraction of window packets that were TCP (0.0 = all UDP/ICMP, 1.0 = all TCP).
    pub proto_ratio: f64,
    /// Fraction of packets from the busiest IP.
    pub dominant_ip_ratio: f64,
    /// Wall-clock time of this window close (seconds since UNIX epoch).
    pub timestamp: f64,
}

impl FeatureVector {
    /// Serialise the feature vector into a fixed-size byte buffer.
    ///
    /// All fields are written as **little-endian f64** to match
    /// Python's `struct.unpack('<9d', data)` format string exactly.
    ///
    /// # Returns
    /// `[u8; FEATURE_VECTOR_BYTES]` — exactly 72 bytes, no padding, no surprises.
    pub fn to_bytes(&self) -> [u8; FEATURE_VECTOR_BYTES] {
        let mut buf = Vec::with_capacity(FEATURE_VECTOR_BYTES);

        // Fields written in the exact order Python expects them.
        buf.write_f64::<LittleEndian>(self.entropy)
            .expect("write entropy");
        buf.write_f64::<LittleEndian>(self.ewma_rate)
            .expect("write ewma_rate");
        buf.write_f64::<LittleEndian>(self.mean_h)
            .expect("write mean_h");
        buf.write_f64::<LittleEndian>(self.mean_r)
            .expect("write mean_r");
        buf.write_f64::<LittleEndian>(self.sigma_h)
            .expect("write sigma_h");
        buf.write_f64::<LittleEndian>(self.sigma_r)
            .expect("write sigma_r");
        buf.write_f64::<LittleEndian>(self.proto_ratio)
            .expect("write proto_ratio");
        buf.write_f64::<LittleEndian>(self.dominant_ip_ratio)
            .expect("write dom_ratio");
        buf.write_f64::<LittleEndian>(self.timestamp)
            .expect("write timestamp");

        debug_assert_eq!(buf.len(), FEATURE_VECTOR_BYTES, "serialisation size mismatch");
        buf.try_into().expect("buf has exactly FEATURE_VECTOR_BYTES")
    }
}

// -----------------------------------------------------------------------------
// IpcSocket
// -----------------------------------------------------------------------------

/// Manages the outbound Unix Domain Socket connection to Stage 2 (Python).
///
/// Stage 1 is the *client*: it connects to a socket that Python has already
/// created and is listening on.  The socket is created lazily on first send
/// so Stage 1 can start capturing before Python is ready.
pub struct IpcSocket {
    /// Underlying connected stream, or `None` if not yet connected.
    stream: Option<UnixStream>,
    /// File-system path of the Unix domain socket.
    path: String,
}

impl IpcSocket {
    /// Create a new IPC handle pointing at the default socket path.
    pub fn new() -> Self {
        Self {
            stream: None,
            path: SOCKET_PATH.to_string(),
        }
    }

    /// Create a new IPC handle pointing at a custom socket path (useful for
    /// tests and non-default deployments).
    pub fn with_path<P: AsRef<Path>>(path: P) -> Self {
        Self {
            stream: None,
            path: path.as_ref().to_string_lossy().into_owned(),
        }
    }

    /// Attempt to connect to the socket if not already connected.
    ///
    /// Returns `true` if the socket is ready to use (already connected, or
    /// just connected now).  Returns `false` if connection failed — Stage 1
    /// will retry on the next anomaly event rather than blocking the capture
    /// loop waiting for Stage 2 to come online.
    pub fn ensure_connected(&mut self) -> bool {
        if self.stream.is_some() {
            return true;
        }

        match UnixStream::connect(&self.path) {
            Ok(stream) => {
                // Set a write timeout so a slow Python process can't stall
                // the Stage 1 analysis thread indefinitely.
                let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
                self.stream = Some(stream);
                debug!("IPC: connected to Stage 2 at {}", self.path);
                true
            }
            Err(e) => {
                warn!("IPC: cannot connect to Stage 2 at {} — {e}", self.path);
                false
            }
        }
    }

    /// Serialise and send one `FeatureVector` to Stage 2.
    ///
    /// If the send fails (broken pipe, Python crashed, etc.) the socket is
    /// dropped so the next call to `ensure_connected()` will attempt reconnect.
    ///
    /// Returns `true` on success, `false` on any I/O error.
    pub fn send(&mut self, fv: &FeatureVector) -> bool {
        if !self.ensure_connected() {
            return false;
        }

        let bytes = fv.to_bytes();

        if let Some(ref mut stream) = self.stream {
            if let Err(e) = stream.write_all(&bytes) {
                warn!("IPC: write failed — {e}; dropping connection for reconnect");
                self.stream = None;
                return false;
            }
            debug!(
                "IPC: sent rate={:.1} entropy={:.3} proto_ratio={:.3} ts={:.0}",
                fv.ewma_rate, fv.entropy, fv.proto_ratio, fv.timestamp
            );
            true
        } else {
            false // should not happen given ensure_connected above
        }
    }
}

impl Default for IpcSocket {
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

    fn sample_fv() -> FeatureVector {
        FeatureVector {
            entropy:     4.321,
            ewma_rate:   1234.5,
            mean_h:      4.800,
            mean_r:      900.0,
            sigma_h:     0.250,
            sigma_r:     120.0,
            proto_ratio: 0.72,
            dominant_ip_ratio: 0.66,
            timestamp:   1_700_000_000.0,
        }
    }

    /// Serialisation produces exactly FEATURE_VECTOR_BYTES bytes.
    #[test]
    fn serialised_size_is_correct() {
        let bytes = sample_fv().to_bytes();
        assert_eq!(bytes.len(), FEATURE_VECTOR_BYTES);
        assert_eq!(FEATURE_VECTOR_BYTES, 72);
    }

    /// Round-trip: serialise then re-parse with byteorder.
    /// This is the byte-alignment sanity check — same logic Python uses.
    #[test]
    fn round_trip_byte_layout() {
        use byteorder::{LittleEndian, ReadBytesExt};
        use std::io::Cursor;

        let fv    = sample_fv();
        let bytes = fv.to_bytes();
        let mut cur = Cursor::new(bytes);

        let entropy           = cur.read_f64::<LittleEndian>().unwrap();
        let ewma_rate         = cur.read_f64::<LittleEndian>().unwrap();
        let mean_h            = cur.read_f64::<LittleEndian>().unwrap();
        let mean_r            = cur.read_f64::<LittleEndian>().unwrap();
        let sigma_h           = cur.read_f64::<LittleEndian>().unwrap();
        let sigma_r           = cur.read_f64::<LittleEndian>().unwrap();
        let proto_ratio       = cur.read_f64::<LittleEndian>().unwrap();
        let dominant_ip_ratio = cur.read_f64::<LittleEndian>().unwrap();
        let timestamp         = cur.read_f64::<LittleEndian>().unwrap();

        assert!((entropy           - 4.321           ).abs() < 1e-9);
        assert!((ewma_rate         - 1234.5          ).abs() < 1e-9);
        assert!((mean_h            - 4.800           ).abs() < 1e-9);
        assert!((mean_r            - 900.0           ).abs() < 1e-9);
        assert!((sigma_h           - 0.250           ).abs() < 1e-9);
        assert!((sigma_r           - 120.0           ).abs() < 1e-9);
        assert!((proto_ratio       - 0.72            ).abs() < 1e-9);
        assert!((dominant_ip_ratio - 0.66            ).abs() < 1e-9);
        assert!((timestamp         - 1_700_000_000.0 ).abs() < 1e-3);
    }

    /// FLAG constants must not overlap.
    #[test]
    fn flag_constants_are_disjoint() {
        assert_ne!(FLAG_RATE_ANOMALY & FLAG_ENTROPY_ANOMALY, 0xFF);
        assert_eq!(FLAG_RATE_ANOMALY & FLAG_ENTROPY_ANOMALY, 0x00);
    }
}
