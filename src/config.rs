//! YAML configuration for Spectre (client + server).

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Top-level config.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// `server` or `client`
    pub mode: Mode,

    /// Bind address for mixed / tproxy / dns (default 127.0.0.1).
    #[serde(default = "default_bind_address", rename = "bind-address")]
    pub bind_address: String,

    #[serde(default, rename = "log-level")]
    pub log_level: Option<String>,

    // ---- server ----
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default, rename = "server-name")]
    pub server_name: Option<String>,
    #[serde(default)]
    pub upstream: Option<String>,

    // ---- client ----
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub rx: Option<String>,
    #[serde(default)]
    pub tx: Option<String>,

    /// Mixed inbound port (HTTP CONNECT + SOCKS4/4a/5), TCP+UDP.
    #[serde(default, rename = "mixed-port")]
    pub mixed_port: Option<u16>,

    /// TProxy port (Linux/Android only), TCP+UDP. 0 / omit = disabled.
    #[serde(default, rename = "tproxy-port")]
    pub tproxy_port: Option<u16>,

    /// Enable protocol sniffing (TLS SNI / HTTP Host / QUIC). Default true.
    #[serde(default = "default_true")]
    pub sniff: bool,

    #[serde(default)]
    pub dns: DnsConfig,

    /// Route rules: `direct,/path/xxx.ars` | `proxy,/path/yyy.ars` | `direct` | `proxy`
    #[serde(default)]
    pub route: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Server,
    Client,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DnsConfig {
    /// Local DNS UDP listen port. Omit / 0 = do not listen
    /// (DNS module can still run for route-hijack only).
    #[serde(default)]
    pub port: Option<u16>,

    /// When true (default), DNS upstream follows route decision.
    #[serde(default = "default_true", rename = "rule-follow-route")]
    pub rule_follow_route: bool,

    /// Hijack DNS queries seen on tproxy/mixed (port 53 or sniffed DNS)
    /// into the local DNS module. Requires DNS module enabled
    /// (port set and/or nameservers configured).
    #[serde(default, rename = "route-hijack", alias = "hijack-dns")]
    pub route_hijack: bool,

    #[serde(default, rename = "direct-nameserver")]
    pub direct_nameserver: Option<String>,

    #[serde(default, rename = "proxy-nameserver")]
    pub proxy_nameserver: Option<String>,

    #[serde(default = "default_cache_size", rename = "cache-size")]
    pub cache_size: usize,
}

fn default_bind_address() -> String {
    "127.0.0.1".into()
}
fn default_true() -> bool {
    true
}
fn default_cache_size() -> usize {
    4096
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read config {path:?}"))?;
        let mut cfg: Config = serde_yaml::from_str(&text)
            .with_context(|| format!("parse config {path:?}"))?;
        cfg.validate(path)?;
        Ok(cfg)
    }

    fn validate(&mut self, config_path: &Path) -> Result<()> {
        match self.mode {
            Mode::Server => {
                if self.listen.is_none() {
                    bail!("server mode requires `listen`");
                }
                if self.password.is_none() {
                    bail!("server mode requires `password`");
                }
            }
            Mode::Client => {
                if self.server.is_none() {
                    bail!("client mode requires `server`");
                }
                if self.password.is_none() {
                    bail!("client mode requires `password`");
                }
                if self.mixed_port.is_none() && self.tproxy_port.unwrap_or(0) == 0 {
                    bail!("client mode requires at least one of `mixed-port` / `tproxy-port`");
                }
                if self.dns.route_hijack && !self.dns_enabled() {
                    bail!("dns.route-hijack requires DNS module enabled (set dns.port and/or nameservers)");
                }
                // Resolve relative ARS paths against config file directory.
                let base = config_path
                    .parent()
                    .unwrap_or_else(|| Path::new("."));
                for rule in &mut self.route {
                    if let Some((outbound, path_part)) = rule.split_once(',') {
                        let p = path_part.trim();
                        if !p.is_empty() && !Path::new(p).is_absolute() {
                            let abs = base.join(p);
                            *rule = format!("{},{}", outbound.trim(), abs.display());
                        }
                    }
                }
            }
        }
        Ok(())
    }

    // ---- helpers ----

    pub fn server_listen(&self) -> Result<SocketAddr> {
        self.listen
            .as_ref()
            .unwrap()
            .parse()
            .context("parse listen address")
    }

    pub fn client_server(&self) -> Result<SocketAddr> {
        self.server
            .as_ref()
            .unwrap()
            .parse()
            .context("parse server address")
    }

    pub fn password(&self) -> &str {
        self.password.as_deref().unwrap_or("")
    }

    pub fn username(&self) -> &str {
        self.username.as_deref().unwrap_or("spectre")
    }

    pub fn server_name(&self) -> &str {
        self.server_name.as_deref().unwrap_or("www.cloudflare.com")
    }

    pub fn upstream(&self) -> &str {
        self.upstream.as_deref().unwrap_or("www.cloudflare.com:443")
    }

    pub fn rx_bps(&self) -> Result<u64> {
        match &self.rx {
            Some(s) => crate::brutal::parse_rate(s).map_err(|e| anyhow::anyhow!("{e}")),
            None => Ok(0),
        }
    }

    pub fn tx_bps(&self) -> Result<u64> {
        match &self.tx {
            Some(s) => crate::brutal::parse_rate(s).map_err(|e| anyhow::anyhow!("{e}")),
            None => Ok(0),
        }
    }

    /// Whether the DNS module should run (listen and/or route-hijack).
    pub fn dns_enabled(&self) -> bool {
        let has_port = matches!(self.dns.port, Some(p) if p > 0);
        let has_ns = self.dns.direct_nameserver.is_some() || self.dns.proxy_nameserver.is_some();
        has_port || (self.dns.route_hijack && has_ns)
    }

    /// DNS route-hijack active (tproxy/mixed steals DNS into local module).
    pub fn dns_route_hijack(&self) -> bool {
        self.dns.route_hijack && self.dns_enabled()
    }
}

/// A single route entry after parsing.
#[derive(Debug, Clone)]
pub enum RouteEntry {
    /// Match an ARS file → given outbound.
    RuleSet { outbound: OutboundKind, path: PathBuf },
    /// Final MATCH.
    Match(OutboundKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundKind {
    Direct,
    Proxy, // Spectre
}

impl OutboundKind {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "direct" => Ok(Self::Direct),
            "proxy" | "spectre" => Ok(Self::Proxy),
            other => bail!("unknown outbound `{other}`; use direct or proxy"),
        }
    }
}

impl RouteEntry {
    pub fn parse(raw: &str) -> Result<Self> {
        let raw = raw.trim();
        if let Some((left, right)) = raw.split_once(',') {
            let outbound = OutboundKind::parse(left)?;
            let path = PathBuf::from(right.trim());
            Ok(Self::RuleSet { outbound, path })
        } else {
            Ok(Self::Match(OutboundKind::parse(raw)?))
        }
    }
}

/// Parse the full route list; last entry must be a Match.
pub fn parse_routes(routes: &[String]) -> Result<Vec<RouteEntry>> {
    if routes.is_empty() {
        // Default: everything goes to proxy.
        return Ok(vec![RouteEntry::Match(OutboundKind::Proxy)]);
    }
    let mut out = Vec::with_capacity(routes.len());
    for r in routes {
        out.push(RouteEntry::parse(r)?);
    }
    if !matches!(out.last(), Some(RouteEntry::Match(_))) {
        bail!("route list must end with a final MATCH (`direct` or `proxy`)");
    }
    Ok(out)
}
