//! Socket helpers (bind dual-stack listeners).

use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::{TcpListener, UdpSocket};

/// Produce listen addresses for `bind_address:port` (IPv4 + IPv6).
pub fn listen_addrs(bind_address: &str, port: u16) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    if let Ok(ip) = bind_address.parse::<IpAddr>() {
        out.push(SocketAddr::new(ip, port));
        // Also add the other family if binding to unspecified/loopback.
        match ip {
            IpAddr::V4(v4) if v4.is_loopback() => {
                out.push(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port));
            }
            IpAddr::V4(v4) if v4.is_unspecified() => {
                out.push(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port));
            }
            IpAddr::V6(v6) if v6.is_loopback() => {
                out.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
            }
            IpAddr::V6(v6) if v6.is_unspecified() => {
                out.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
            }
            _ => {}
        }
    } else {
        // hostname or invalid — fall back to 127.0.0.1 + ::1
        out.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
        out.push(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port));
    }
    out
}

pub async fn bind_tcp(addr: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind TCP {addr}"))
}

pub async fn bind_udp(addr: SocketAddr) -> Result<UdpSocket> {
    UdpSocket::bind(addr)
        .await
        .with_context(|| format!("bind UDP {addr}"))
}
