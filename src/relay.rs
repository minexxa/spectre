//! Bidirectional relay between a QUIC stream and a TCP stream.

use tokio::io::{
    copy_buf, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader,
};

/// Copy buffer. tokio's `copy` uses 8 KiB, which costs far too many syscalls
/// at hundreds of Mbit/s.
const RELAY_BUF: usize = 256 * 1024;

/// Copy `r` into `w`, then half-close `w`.
///
/// For a quinn `SendStream`, `shutdown()` finishes the stream.
async fn pipe<R, W>(r: R, mut w: W) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut r = BufReader::with_capacity(RELAY_BUF, r);
    let n = copy_buf(&mut r, &mut w).await?;
    let _ = w.shutdown().await;
    Ok(n)
}

/// Relay both directions until both sides finish.
///
/// Each direction half-closes its destination on EOF, so data still in flight
/// the other way is not cut off. If either direction fails, both are dropped.
pub async fn relay<AR, AW, BR, BW>(a_r: AR, a_w: AW, b_r: BR, b_w: BW) -> std::io::Result<()>
where
    AR: AsyncRead + Unpin,
    AW: AsyncWrite + Unpin,
    BR: AsyncRead + Unpin,
    BW: AsyncWrite + Unpin,
{
    tokio::try_join!(pipe(a_r, b_w), pipe(b_r, a_w))?;
    Ok(())
}
