//! Brutal-style target-rate pacing for Spectre.
//!
//! Provides:
//! - `BrutalConfig` — target bytes/sec
//! - `BrutalPacer` — token-bucket + sleep-based application pacing
//! - `paced_write` / `paced_copy` helpers for stream data

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::sleep;

/// Configuration for Brutal-style rate control.
#[derive(Debug, Clone)]
pub struct BrutalConfig {
    /// Target send rate in bytes per second. 0 = unlimited.
    pub target_bps: u64,
    /// Token bucket capacity in bytes (burst). Default ~200ms of target.
    pub burst_bytes: u64,
    /// Pacing interval granularity.
    pub tick: Duration,
}

impl Default for BrutalConfig {
    fn default() -> Self {
        Self {
            target_bps: 0,
            burst_bytes: 0,
            tick: Duration::from_millis(5),
        }
    }
}

impl BrutalConfig {
    pub fn from_bps(target_bps: u64) -> Self {
        let burst = if target_bps == 0 {
            0
        } else {
            // ~200ms burst
            (target_bps / 5).max(16 * 1024)
        };
        Self {
            target_bps,
            burst_bytes: burst,
            tick: Duration::from_millis(5),
        }
    }
}

/// Token-bucket pacer. Thread-safe via interior mutability on a single task.
pub struct BrutalPacer {
    config: Arc<BrutalConfig>,
    tokens: f64,
    last_refill: Instant,
}

impl BrutalPacer {
    pub fn new(config: BrutalConfig) -> Self {
        let burst = if config.burst_bytes == 0 && config.target_bps > 0 {
            (config.target_bps / 5).max(16 * 1024) as f64
        } else {
            config.burst_bytes as f64
        };
        Self {
            tokens: burst,
            config: Arc::new(config),
            last_refill: Instant::now(),
        }
    }

    pub fn target_bps(&self) -> u64 {
        self.config.target_bps
    }

    fn refill(&mut self) {
        if self.config.target_bps == 0 {
            return;
        }
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        let rate = self.config.target_bps as f64;
        let burst = if self.config.burst_bytes == 0 {
            (rate / 5.0).max(16.0 * 1024.0)
        } else {
            self.config.burst_bytes as f64
        };
        self.tokens = (self.tokens + elapsed * rate).min(burst);
    }

    /// How many bytes may be sent immediately (may be 0).
    pub fn available(&mut self) -> u64 {
        if self.config.target_bps == 0 {
            return u64::MAX;
        }
        self.refill();
        self.tokens.max(0.0) as u64
    }

    /// Consume up to `want` tokens; returns granted amount.
    pub fn take(&mut self, want: u64) -> u64 {
        if self.config.target_bps == 0 {
            return want;
        }
        self.refill();
        let grant = (want as f64).min(self.tokens).max(0.0);
        self.tokens -= grant;
        grant as u64
    }

    /// Wait until at least `need` bytes of budget are available (or unlimited).
    pub async fn wait_for(&mut self, need: u64) {
        if self.config.target_bps == 0 || need == 0 {
            return;
        }
        loop {
            self.refill();
            if self.tokens >= need as f64 {
                return;
            }
            let deficit = need as f64 - self.tokens;
            let rate = self.config.target_bps as f64;
            let secs = (deficit / rate).clamp(0.001, 0.5);
            sleep(Duration::from_secs_f64(secs)).await;
        }
    }

    /// Pace a single write: may split and delay to honor target rate.
    pub async fn write_all_paced<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        mut data: &[u8],
    ) -> std::io::Result<()> {
        if self.config.target_bps == 0 {
            return writer.write_all(data).await;
        }
        while !data.is_empty() {
            self.wait_for(1).await;
            let n = self.take(data.len() as u64) as usize;
            if n == 0 {
                sleep(self.config.tick).await;
                continue;
            }
            writer.write_all(&data[..n]).await?;
            data = &data[n..];
        }
        Ok(())
    }
}

/// Bidirectional copy with independent TX pacing on the forward path.
/// `tx_pacer` limits bytes written to `dst` (upload direction from this side).
pub async fn paced_copy<R, W>(
    mut src: R,
    mut dst: W,
    tx_pacer: Option<&mut BrutalPacer>,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 32 * 1024];
    let mut total = 0u64;
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        if let Some(pacer) = tx_pacer.as_deref_mut() {
            pacer.write_all_paced(&mut dst, &buf[..n]).await?;
        } else {
            dst.write_all(&buf[..n]).await?;
        }
        total += n as u64;
    }
    Ok(total)
}

/// Full-duplex relay with optional Brutal pacing on each direction.
pub async fn paced_relay<A, B>(
    a: A,
    b: B,
    a_to_b_bps: u64,
    b_to_a_bps: u64,
) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::io::split;
    let (mut a_r, mut a_w) = split(a);
    let (mut b_r, mut b_w) = split(b);

    let mut pacer_ab = if a_to_b_bps > 0 {
        Some(BrutalPacer::new(BrutalConfig::from_bps(a_to_b_bps)))
    } else {
        None
    };
    let mut pacer_ba = if b_to_a_bps > 0 {
        Some(BrutalPacer::new(BrutalConfig::from_bps(b_to_a_bps)))
    } else {
        None
    };

    let ab = async {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = a_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if let Some(ref mut p) = pacer_ab {
                p.write_all_paced(&mut b_w, &buf[..n]).await?;
            } else {
                b_w.write_all(&buf[..n]).await?;
            }
        }
        let _ = b_w.shutdown().await;
        Ok::<(), std::io::Error>(())
    };

    let ba = async {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = b_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if let Some(ref mut p) = pacer_ba {
                p.write_all_paced(&mut a_w, &buf[..n]).await?;
            } else {
                a_w.write_all(&buf[..n]).await?;
            }
        }
        let _ = a_w.shutdown().await;
        Ok::<(), std::io::Error>(())
    };

    tokio::select! {
        r = ab => r,
        r = ba => r,
    }
}
