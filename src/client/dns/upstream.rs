//! UDP DNS upstream only.

use anyhow::{Context, Result};
use std::net::{SocketAddr, ToSocketAddrs};
use tokio::net::UdpSocket;

#[derive(Debug, Clone)]
pub struct DnsUpstream {
    pub addr: SocketAddr,
}

impl std::fmt::Display for DnsUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "udp://{}", self.addr)
    }
}

pub fn parse_nameserver(s: &str) -> Result<DnsUpstream> {
    let s = s.trim();
    let addr_str = s
        .strip_prefix("udp://")
        .or_else(|| s.strip_prefix("UDP://"))
        .unwrap_or(s);

    // Try full SocketAddr first (handles [v6]:port and v4:port)
    if let Ok(addr) = addr_str.parse::<SocketAddr>() {
        return Ok(DnsUpstream { addr });
    }
    // Bare IP or hostname → port 53
    let with_port = format!("{addr_str}:53");
    let addr = with_port
        .to_socket_addrs()
        .context("resolve nameserver")?
        .next()
        .context("nameserver resolved to nothing")?;
    Ok(DnsUpstream { addr })
}

pub async fn exchange(upstream: &DnsUpstream, query: &[u8]) -> Result<Vec<u8>> {
    let bind: SocketAddr = if upstream.addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(upstream.addr).await?;
    sock.send(query).await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv(&mut buf))
        .await
        .context("dns upstream timeout")??;
    Ok(buf[..n].to_vec())
}
