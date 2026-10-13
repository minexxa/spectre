//! Unified target address representation.

use std::net::{IpAddr, SocketAddr};

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
