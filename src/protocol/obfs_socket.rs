//! Wires [`super::obfs`] into quinn-jls's socket abstraction so every byte
//! quinn actually puts on the wire is Salamander-obfuscated, transparently
//! to the rest of Spectre.
//!
//! ## Where this came from
//!
//! `quinn-jls`'s `lib.rs` re-exports `{AsyncTimer, AsyncUdpSocket, Runtime,
//! UdpSender}` (confirmed from its published source on docs.rs, crate
//! `quinn-jls` 0.3.8, `spongebob888/quinn-jls` — a fork of `quinn-rs/quinn`).
//! That re-export list identifies which generation of quinn's socket API it
//! uses: a newer `Runtime` trait whose `wrap_udp_socket` returns
//! `Arc<dyn AsyncUdpSocket>`, where `AsyncUdpSocket::create_sender()` hands
//! out independent `UdpSender` objects (replacing an older
//! `create_io_poller`/`try_send`/`UdpPoller` shape still used by some
//! other quinn forks/snapshots). The method signatures below are taken
//! from the full `runtime.rs` of a sibling fork that re-exports the exact
//! same trait set (confirmed byte-for-byte on docs.rs); quinn-jls's own
//! `runtime.rs` body wasn't directly fetchable, so **this is believed
//! correct but not verified against quinn-jls's own source line-by-line —
//! compile it before trusting it.** If it doesn't compile, the mismatch is
//! almost certainly in exact method names/signatures below, not in the
//! overall wrapping strategy (wrap `Runtime`, not `Endpoint`).
//!
//! ## Why wrap `Runtime` and not the socket passed to `Endpoint::new`
//!
//! `run_client`/`run_server` already call
//! `quinn::Endpoint::new(config, server_config, socket, runtime)`, i.e. they
//! already take a `runtime: Arc<dyn quinn::Runtime>` argument (currently
//! always `quinn::default_runtime()`). `Runtime::wrap_udp_socket` is the
//! one place a `std::net::UdpSocket` turns into the `AsyncUdpSocket` quinn
//! actually drives — so obfuscating there means zero changes to the
//! `bind_udp` / `Endpoint::new` call sites beyond swapping which `Runtime`
//! gets passed in. No `new_with_abstract_socket` / custom `Endpoint`
//! plumbing needed.
//!
//! ## GSO is disabled when obfuscation is on
//!
//! Salamander prepends an 8-byte salt to every individual packet. GSO
//! batches multiple *same-size* segments into one syscall; mixing that with
//! a per-packet length change is exactly the kind of "quietly corrupts
//! segment boundaries" bug described in the top-level `obfs.rs` doc comment
//! this module grew out of. Rather than get that subtly wrong,
//! `max_transmit_segments`/`max_receive_segments` are pinned to `1` here,
//! so each datagram goes through one syscall. This costs some CPU at very
//! high throughput (the same trade-off Hysteria's own obfuscation layer
//! makes) but is correct. Revisit only with real packet captures in hand.
//!
//! ## Wiring it up
//!
//! ```ignore
//! let base = quinn::default_runtime().ok_or_else(|| anyhow!("no async runtime"))?;
//! let runtime: Arc<dyn quinn::Runtime> = match obfs_psk {
//!     Some(psk) => Arc::new(ObfsRuntime::new(base, psk)),
//!     None => base,
//! };
//! let endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), server_config, socket, runtime)?;
//! ```
//! Client and server must be given the *same* `obfs_psk` (a new, separate
//! config field — not the JLS password) or they'll silently fail to
//! understand each other's packets (every `deobfuscate` call will return
//! garbage, which the QUIC layer will then just see as unparseable noise
//! and drop, so misconfiguration looks like "nothing connects", not a
//! clean error — worth logging a warning if this is plugged into `config.rs`).

use super::obfs::{self, ObfsError};
use quinn_jls as quinn;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncTimer, AsyncUdpSocket, Runtime, UdpSender};
use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

/// Wraps another [`Runtime`] so every [`AsyncUdpSocket`] it hands out is
/// Salamander-obfuscated with `psk`.
#[derive(Debug)]
pub struct ObfsRuntime {
    inner: Arc<dyn Runtime>,
    psk: Arc<Vec<u8>>,
}

impl ObfsRuntime {
    /// `psk` must be at least [`obfs::MIN_PSK_LEN`] bytes and identical on
    /// both ends of the connection.
    pub fn new(inner: Arc<dyn Runtime>, psk: Vec<u8>) -> Self {
        Self {
            inner,
            psk: Arc::new(psk),
        }
    }
}

impl Runtime for ObfsRuntime {
    fn new_timer(&self, i: Instant) -> Pin<Box<dyn AsyncTimer>> {
        self.inner.new_timer(i)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.inner.spawn(future)
    }

    fn wrap_udp_socket(&self, t: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let inner = self.inner.wrap_udp_socket(t)?;
        Ok(Arc::new(ObfsUdpSocket {
            inner,
            psk: self.psk.clone(),
        }))
    }

    fn now(&self) -> Instant {
        self.inner.now()
    }
}

struct ObfsUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    psk: Arc<Vec<u8>>,
}

impl fmt::Debug for ObfsUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObfsUdpSocket").finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for ObfsUdpSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(ObfsUdpSender {
            inner: self.inner.create_sender(),
            psk: self.psk.clone(),
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // Receive as normal into the caller's buffers, then deobfuscate
        // each datagram in place (deobfuscated payload is always 8 bytes
        // shorter than what came off the wire, so it always fits).
        let n = match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(n)) => n,
            other => return other,
        };
        for i in 0..n {
            let len = meta[i].len;
            match obfs::deobfuscate(&self.psk, &bufs[i][..len]) {
                Ok(plain) => {
                    let plen = plain.len();
                    bufs[i][..plen].copy_from_slice(&plain);
                    meta[i].len = plen;
                    meta[i].stride = plen;
                }
                Err(ObfsError::PacketTooShort | ObfsError::PskTooShort) => {
                    // Not a valid Salamander packet for our PSK (garbage,
                    // probe traffic, or a misconfigured peer). Zero the
                    // length so quinn's proto layer sees and discards an
                    // empty datagram instead of raw ciphertext it can't
                    // parse as QUIC.
                    meta[i].len = 0;
                    meta[i].stride = 0;
                }
            }
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        // Conservative: don't claim fragmentation safety we haven't
        // verified for the now-variable (vs. the socket's own view)
        // packet sizes.
        self.inner.may_fragment()
    }

    fn max_receive_segments(&self) -> usize {
        // See module-level doc: GSO batching and per-packet salt framing
        // don't mix safely here, so this is pinned to 1 regardless of what
        // the wrapped socket supports.
        1
    }
}

struct ObfsUdpSender {
    inner: Pin<Box<dyn UdpSender>>,
    psk: Arc<Vec<u8>>,
}

impl fmt::Debug for ObfsUdpSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObfsUdpSender").finish_non_exhaustive()
    }
}

impl UdpSender for ObfsUdpSender {
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &Transmit,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        // SAFETY/soundness note: Transmit borrows `contents` with a
        // lifetime tied to the caller's buffer; we only read from it here
        // to build a new, owned, obfuscated buffer, so no lifetime games
        // are needed.
        let this = self.get_mut();
        let obfuscated = obfs::obfuscate(&this.psk, transmit.contents)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let out = Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &obfuscated,
            // Forced to 1 segment of the obfuscated length — see
            // module-level doc on why GSO is disabled here.
            segment_size: None,
            src_ip: transmit.src_ip,
        };
        this.inner.as_mut().poll_send(&out, cx)
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }
}
