//! Brutal-style congestion control for Spectre (quinn `congestion::Controller`).
//!
//! This follows the Hysteria2 design, adapted to quinn:
//!
//! * The sender is told a **target rate** (bytes/sec). It does not back off on
//!   loss the way Cubic/BBR do.
//! * Loss is measured as an **ack rate** over a sliding 5-second window of
//!   per-second slots (`acked / (acked + lost)`, floored at 0.8).
//! * `cwnd = target_bps * RTT * CWND_GAIN / ack_rate`. Lost packets are
//!   retransmitted by QUIC, so dividing by the ack rate keeps the *goodput*
//!   near the target rate even on a lossy path.
//! * quinn derives its pacing rate from the window (`window * 1.25 / srtt`),
//!   so no separate pacer is needed.
//! * Target rate `0` means "no Brutal": delegate to quinn's BBR.
//!
//! The rate lives in a shared [`BrutalHandle`], so the server can set it
//! *after* authentication, once the client's declared download rate is known,
//! without rebuilding the connection.

use quinn_jls as quinn;
use quinn::congestion::{BbrConfig, Controller, ControllerFactory};
use quinn_proto_jls::RttEstimator;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Number of one-second slots in the ack-rate window (same as Hysteria).
const SLOT_COUNT: u64 = 5;
/// Ignore the loss estimate until this many bytes have been observed
/// (about 50 full-size packets, same as Hysteria's `minSampleCount`).
const MIN_SAMPLE_BYTES: u64 = 50 * 1200;
/// Lower bound for the ack rate. Caps the compensation at 1/0.8 = 1.25x.
const MIN_ACK_RATE: f64 = 0.8;
/// Window headroom over one BDP at the target rate.
///
/// quinn paces at `window * 1.25 / srtt`, so the effective pacing rate is
/// roughly `CWND_GAIN * 1.25 * target / ack_rate`. Hysteria uses 2.0 with its
/// own pacer; with quinn's pacer a smaller value is needed or the sender
/// overshoots the declared rate by 2.5x and causes its own loss.
const CWND_GAIN: f64 = 1.2;
/// Window floor, in packets.
const MIN_WINDOW_PACKETS: u64 = 16;
/// Window ceiling (bytes).
const MAX_WINDOW: u64 = 128 * 1024 * 1024;
/// RTT used before the first sample arrives.
const DEFAULT_RTT: Duration = Duration::from_millis(150);

// ── shared rate handle ────────────────────────────────────────────────────────

/// Shared, thread-safe target rate in **bytes per second** (0 = Brutal off).
#[derive(Clone, Debug)]
pub struct BrutalHandle(Arc<AtomicU64>);

impl BrutalHandle {
    pub fn new(bps: u64) -> Self {
        Self(Arc::new(AtomicU64::new(bps)))
    }

    pub fn set(&self, bps: u64) {
        self.0.store(bps, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

// ── ack-rate tracker ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, Default, Debug)]
struct Slot {
    sec: u64,
    acked: u64,
    lost: u64,
}

#[derive(Clone, Debug)]
struct AckTracker {
    start: Instant,
    slots: [Slot; SLOT_COUNT as usize],
}

impl AckTracker {
    fn new(start: Instant) -> Self {
        Self {
            start,
            slots: [Slot::default(); SLOT_COUNT as usize],
        }
    }

    fn sec(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.start).as_secs()
    }

    fn add(&mut self, now: Instant, acked: u64, lost: u64) {
        let sec = self.sec(now);
        let slot = &mut self.slots[(sec % SLOT_COUNT) as usize];
        if slot.sec != sec {
            *slot = Slot {
                sec,
                acked: 0,
                lost: 0,
            };
        }
        slot.acked += acked;
        slot.lost += lost;
    }

    /// `acked / (acked + lost)` over the last `SLOT_COUNT` seconds, in
    /// `[MIN_ACK_RATE, 1.0]`. Returns 1.0 when there are too few samples.
    fn ack_rate(&self, now: Instant) -> f64 {
        let sec = self.sec(now);
        let (mut acked, mut lost) = (0u64, 0u64);
        for s in &self.slots {
            if s.sec <= sec && sec - s.sec < SLOT_COUNT {
                acked += s.acked;
                lost += s.lost;
            }
        }
        let total = acked + lost;
        if total < MIN_SAMPLE_BYTES {
            return 1.0;
        }
        (acked as f64 / total as f64).clamp(MIN_ACK_RATE, 1.0)
    }
}

// ── controller ────────────────────────────────────────────────────────────────

pub struct BrutalController {
    handle: BrutalHandle,
    /// Used while the target rate is 0.
    fallback: Box<dyn Controller>,
    tracker: AckTracker,
    ack_rate: f64,
    srtt: Duration,
    mtu: u16,
}

impl BrutalController {
    fn new(handle: BrutalHandle, now: Instant, mtu: u16) -> Self {
        Self {
            handle,
            fallback: Arc::new(BbrConfig::default()).build(now, mtu),
            tracker: AckTracker::new(now),
            ack_rate: 1.0,
            srtt: DEFAULT_RTT,
            mtu,
        }
    }

    fn min_window(&self) -> u64 {
        MIN_WINDOW_PACKETS * u64::from(self.mtu)
    }
}

impl std::fmt::Debug for BrutalController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrutalController")
            .field("target_bps", &self.handle.get())
            .field("ack_rate", &self.ack_rate)
            .field("srtt", &self.srtt)
            .finish()
    }
}

impl Controller for BrutalController {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.fallback.on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.tracker.add(now, bytes, 0);
        self.ack_rate = self.tracker.ack_rate(now);
        self.srtt = rtt.get().max(Duration::from_millis(1));
        self.fallback.on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.fallback
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        is_ecn: bool,
        lost_bytes: u64,
    ) {
        // ECN marks carry lost_bytes == 0 and are ignored by Brutal.
        if lost_bytes > 0 {
            self.tracker.add(now, 0, lost_bytes);
            self.ack_rate = self.tracker.ack_rate(now);
        }
        self.fallback
            .on_congestion_event(now, sent, is_persistent_congestion, is_ecn, lost_bytes);
    }

    fn on_spurious_congestion_event(&mut self) {
        self.fallback.on_spurious_congestion_event();
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
        self.fallback.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        let bps = self.handle.get();
        if bps == 0 {
            return self.fallback.window();
        }
        let w = bps as f64 * self.srtt.as_secs_f64() * CWND_GAIN / self.ack_rate;
        (w as u64).clamp(self.min_window(), MAX_WINDOW)
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(BrutalController {
            handle: self.handle.clone(),
            fallback: self.fallback.clone_box(),
            tracker: self.tracker.clone(),
            ack_rate: self.ack_rate,
            srtt: self.srtt,
            mtu: self.mtu,
        })
    }

    fn initial_window(&self) -> u64 {
        if self.handle.get() == 0 {
            self.fallback.initial_window()
        } else {
            self.window()
        }
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

// ── factory & transport tuning ────────────────────────────────────────────────

pub struct BrutalFactory {
    handle: BrutalHandle,
}

impl BrutalFactory {
    pub fn new(handle: BrutalHandle) -> Arc<Self> {
        Arc::new(Self { handle })
    }
}

impl ControllerFactory for BrutalFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(BrutalController::new(self.handle.clone(), now, current_mtu))
    }
}

/// Per-stream flow-control window (bytes).
const STREAM_RECV_WINDOW: u32 = 16 * 1024 * 1024;
/// Per-connection flow-control window (bytes).
const CONN_RECV_WINDOW: u32 = 64 * 1024 * 1024;
/// Per-connection send buffer limit (bytes).
const SEND_WINDOW: u64 = 64 * 1024 * 1024;

/// Install the Brutal controller and raise QUIC flow-control limits.
///
/// quinn's default flow-control windows (about 1.2 MB per stream) cap
/// throughput at `window / RTT` no matter what the congestion controller says,
/// so they must be raised for Brutal to reach high rates.
pub fn tune_transport(transport: &mut quinn::TransportConfig, handle: BrutalHandle) {
    transport
        .congestion_controller_factory(BrutalFactory::new(handle))
        .stream_receive_window(quinn::VarInt::from_u32(STREAM_RECV_WINDOW))
        .receive_window(quinn::VarInt::from_u32(CONN_RECV_WINDOW))
        .send_window(SEND_WINDOW);
}

// ── UDP socket with large buffers ─────────────────────────────────────────────

/// Requested kernel UDP buffer size. The kernel clamps this to
/// `net.core.rmem_max` / `wmem_max`; raise those sysctls for high rates.
const SOCKET_BUF: usize = 16 * 1024 * 1024;

/// Bind a UDP socket with enlarged send/receive buffers.
///
/// Small socket buffers drop packets at high rates; Brutal would then read
/// those drops as network loss and over-compensate.
pub fn bind_udp(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    let _ = socket.set_recv_buffer_size(SOCKET_BUF);
    let _ = socket.set_send_buffer_size(SOCKET_BUF);
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

// ── rate parsing ──────────────────────────────────────────────────────────────

/// Parse a rate into **bytes per second**.
///
/// * `100mbps`, `1gbps`, `512kbps`, `8000bps`: bits per second, like Hysteria.
/// * a bare integer: bytes per second.
/// * `0`: disabled (fall back to BBR).
pub fn parse_rate(s: &str) -> Result<u64, String> {
    let t = s.trim().to_ascii_lowercase();
    let (num, mult): (&str, f64) = if let Some(n) = t.strip_suffix("gbps") {
        (n, 1e9 / 8.0)
    } else if let Some(n) = t.strip_suffix("mbps") {
        (n, 1e6 / 8.0)
    } else if let Some(n) = t.strip_suffix("kbps") {
        (n, 1e3 / 8.0)
    } else if let Some(n) = t.strip_suffix("bps") {
        (n, 1.0 / 8.0)
    } else {
        (t.as_str(), 1.0)
    };
    let v: f64 = num
        .trim()
        .parse()
        .map_err(|_| format!("invalid rate '{s}' (examples: 100mbps, 20mbps, 12500000)"))?;
    if v < 0.0 || !v.is_finite() {
        return Err(format!("invalid rate '{s}'"));
    }
    Ok((v * mult) as u64)
}
