//! Unified target address representation + fake-ip aware dial helpers.

use crate::client::app::router::Router;
use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum Target {
    Domain { host: String, port: u16 },
    Addr(SocketAddr),
}

impl Target {
    pub fn from_host_port(host: &str, port: u16) -> Self {
        if let Ok(ip) = host.parse::<IpAddr>() {
            Self::Addr(SocketAddr::new(ip, port))
        } else {
            Self::Domain {
                host: host.to_string(),
                port,
            }
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::Domain { port, .. } => *port,
            Self::Addr(a) => a.port(),
        }
    }

    pub fn display(&self) -> String {
        match self {
            Self::Domain { host, port } => format!("{host}:{port}"),
            Self::Addr(a) => a.to_string(),
        }
    }
}

/// For Direct outbound: if `dest` is a fake-ip, resolve the real domain so we
/// never dial the fake range. Otherwise return dest unchanged.
pub async fn resolve_direct(
    router: &Router,
    dest: SocketAddr,
    sniffed: Option<&str>,
) -> Result<SocketAddr> {
    let domain = sniffed
        .map(|s| s.to_string())
        .or_else(|| router.domain_for_fakeip(dest.ip()));
    if let Some(host) = domain {
        if host.parse::<IpAddr>().is_err() {
            // Bootstrap nameserver first (avoids resolution loops when the
            // system DNS points back at spectre itself), system resolver as
            // fallback — same strategy as the DNS upstream path.
            return crate::client::dns::resolve_host_via_bootstrap(&host, dest.port()).await;
        }
    }
    Ok(dest)
}

/// Prefer sniffed domain; else recover domain from fake-ip; else none.
pub fn host_for_route(router: &Router, dest: SocketAddr, sniffed: Option<String>) -> Option<String> {
    sniffed.or_else(|| router.domain_for_fakeip(dest.ip()))
}

#[allow(dead_code)]
pub fn _router_arc_hint(_: &Arc<Router>) {}
