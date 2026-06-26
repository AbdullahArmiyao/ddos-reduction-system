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
//   struct.unpack('<dddBQ', data)   →   8+8+8+1+8 = 33 bytes
//
//   Field order on the wire (all little-endian):
//     [0..8]   ewma_rate      f64 (8 bytes)
//     [8..16]  entropy        f64 (8 bytes)
//     [16..24] dominant_ip_ratio f64 (8 bytes)
//     [24]     anomaly_flags  u8  (1 byte  — bitmask, see below)
//     [25..33] window_id      u64 (8 bytes)
//
// ANOMALY FLAGS BITMASK
// ----------------------
//   bit 0 (0x01) — EWMA rate breached upper boundary   (μ_rate + k·σ_rate)
//   bit 1 (0x02) — Entropy dropped below lower boundary (μ_ent  − k·σ_ent)
//
//   Possible values:
//     0x00 — neither metric tripped  (should not reach IPC in normal flow)
//     0x01 — rate flood only
//     0x02 — concentrated-source attack only
//     0x03 — both metrics tripped simultaneously (highest confidence)
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
/// Python format: `struct.unpack('<dddBQ', data)`  →  8+8+8+1+8 = 33 bytes
pub const FEATURE_VECTOR_BYTES: usize = 33;

/// Anomaly flag: EWMA rate exceeded upper boundary (volume flood).
pub const FLAG_RATE_ANOMALY: u8 = 0x01;

/// Anomaly flag: Shannon entropy dropped below lower boundary (concentrated source).
pub const FLAG_ENTROPY_ANOMALY: u8 = 0x02;

// -----------------------------------------------------------------------------
// FeatureVector
// -----------------------------------------------------------------------------

/// The data payload handed to Stage 2 after every anomalous window.
///
/// Contains the two Layer 1 scalars (which triggered the anomaly), the
/// ratio of the most-common source IP (useful for Stage 2 feature engineering),
/// a bitmask describing which threshold(s) were breached, and a monotonic
/// window counter for ordering on the Python side.
#[derive(Debug, Clone)]
pub struct FeatureVector {
    /// Current EWMA rate snapshot (packets per second).
    pub ewma_rate: f64,
    /// Shannon entropy of source IPs in the closed window (bits).
    pub entropy: f64,
    /// Fraction of packets in the window coming from the single most-common IP.
    /// Range: [1/50, 1.0].  A value near 1.0 is a strong DDoS signal.
    pub dominant_ip_ratio: f64,
    /// Bitmask indicating which anomaly boundary was breached.
    /// See `FLAG_RATE_ANOMALY` / `FLAG_ENTROPY_ANOMALY`.
    pub anomaly_flags: u8,
    /// Monotonically increasing counter of closed windows (not just anomalous
    /// ones) — lets Python detect gaps in the stream if frames are ever dropped.
    pub window_id: u64,
}

impl FeatureVector {
    /// Serialise the feature vector into a fixed-size byte buffer.
    ///
    /// All multi-byte integers are written in **little-endian** order to match
    /// Python's `struct.unpack('<dddBQ', data)` format string exactly.
    ///
    /// # Returns
    /// `[u8; FEATURE_VECTOR_BYTES]` — exactly 33 bytes, no padding, no surprises.
    pub fn to_bytes(&self) -> [u8; FEATURE_VECTOR_BYTES] {
        let mut buf = Vec::with_capacity(FEATURE_VECTOR_BYTES);

        // Field 1: ewma_rate — f64 little-endian (8 bytes, offsets 0..8)
        buf.write_f64::<LittleEndian>(self.ewma_rate)
            .expect("write ewma_rate to in-memory vec cannot fail");

        // Field 2: entropy — f64 little-endian (8 bytes, offsets 8..16)
        buf.write_f64::<LittleEndian>(self.entropy)
            .expect("write entropy to in-memory vec cannot fail");

        // Field 3: dominant_ip_ratio — f64 little-endian (8 bytes, offsets 16..24)
        buf.write_f64::<LittleEndian>(self.dominant_ip_ratio)
            .expect("write dominant_ip_ratio to in-memory vec cannot fail");

        // Field 4: anomaly_flags — u8 (1 byte, offset 24)
        buf.push(self.anomaly_flags);

        // Field 5: window_id — u64 little-endian (8 bytes, offsets 25..33)
        buf.write_u64::<LittleEndian>(self.window_id)
            .expect("write window_id to in-memory vec cannot fail");

        debug_assert_eq!(buf.len(), FEATURE_VECTOR_BYTES, "serialisation size mismatch");

        // Convert Vec into fixed-size array (infallible — sizes match).
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
                "IPC: sent window={} flags={:#04x} rate={:.1} entropy={:.3}",
                fv.window_id, fv.anomaly_flags, fv.ewma_rate, fv.entropy
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

    /// Serialisation produces exactly FEATURE_VECTOR_BYTES bytes.
    #[test]
    fn serialised_size_is_correct() {
        let fv = FeatureVector {
            ewma_rate:        1234.5,
            entropy:          4.321,
            dominant_ip_ratio: 0.02,
            anomaly_flags:    FLAG_RATE_ANOMALY | FLAG_ENTROPY_ANOMALY,
            window_id:        99,
        };
        let bytes = fv.to_bytes();
        assert_eq!(bytes.len(), FEATURE_VECTOR_BYTES);
    }

    /// Round-trip: serialise then manually re-parse with byteorder.
    /// This is the byte-alignment sanity check — same logic Python uses.
    #[test]
    fn round_trip_byte_layout() {
        use byteorder::{LittleEndian, ReadBytesExt};
        use std::io::Cursor;

        let fv = FeatureVector {
            ewma_rate:         500.0,
            entropy:           3.14159,
            dominant_ip_ratio: 0.5,
            anomaly_flags:     FLAG_ENTROPY_ANOMALY,
            window_id:         42,
        };

        let bytes = fv.to_bytes();
        let mut cursor = Cursor::new(bytes);

        let ewma  = cursor.read_f64::<LittleEndian>().unwrap();
        let ent   = cursor.read_f64::<LittleEndian>().unwrap();
        let ratio = cursor.read_f64::<LittleEndian>().unwrap();
        let flags = cursor.read_u8().unwrap();
        let wid   = cursor.read_u64::<LittleEndian>().unwrap();

        assert!((ewma  - 500.0  ).abs() < 1e-9);
        assert!((ent   - 3.14159).abs() < 1e-9);
        assert!((ratio - 0.5    ).abs() < 1e-9);
        assert_eq!(flags, FLAG_ENTROPY_ANOMALY);
        assert_eq!(wid, 42);
    }

    /// FLAG constants must not overlap.
    #[test]
    fn flag_constants_are_disjoint() {
        assert_ne!(FLAG_RATE_ANOMALY & FLAG_ENTROPY_ANOMALY, 0xFF);
        assert_eq!(FLAG_RATE_ANOMALY & FLAG_ENTROPY_ANOMALY, 0x00);
    }
}
