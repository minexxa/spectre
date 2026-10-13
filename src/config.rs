//! YAML configuration for Spectre (client + server).

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Top-level config.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// `server` or `client` (default: client).
    #[serde(default)]
    pub mode: Mode,

    /// Bind address for mixed / tproxy / dns / server listen.
    /// Default: `127.0.0.1` (client), `0.0.0.0` (server). Omit to use default.
    #[serde(default, rename = "bind-address")]
    pub bind_address: Option<String>,

    #[serde(default, rename = "log-level")]
    pub log_level: Option<String>,

    /// Spectre node settings (client remote / server local). Same level as `route`.
    #[serde(default)]
    pub proxy: ProxyConfig,

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

/// Node / endpoint configuration under top-level `proxy:`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ProxyConfig {
    // ---- server ----
    /// Listen port (server mode); bind address from top-level `bind-address`.
    /// Also used as remote port in client mode.
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default, rename = "user", alias = "username")]
    pub user: Option<String>,
    #[serde(default, rename = "sni", alias = "server-name")]
    pub sni: Option<String>,
    #[serde(default)]
    pub upstream: Option<String>,

    // ---- client ----
    /// Remote Spectre server host (no port).
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub rx: Option<String>,
    #[serde(default)]
    pub tx: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Server,
    #[default]
    Client,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DnsConfig {
    /// Local DNS UDP listen port. Omit / 0 = do not listen
    /// (DNS module can still run for route-hijack / fakeip only).
    #[serde(default)]
    pub port: Option<u16>,

    /// `redir-host` (default) or `fakeip`.
    #[serde(default = "default_dns_mode")]
    pub mode: String,

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

    /// IPv4 fake-ip pool, e.g. `198.18.0.0/16`.
    #[serde(default, rename = "fakeip-range")]
    pub fakeip_range: Option<String>,

    /// IPv6 fake-ip pool, e.g. `fc00::/18`.
    #[serde(default, rename = "fakeip6-range")]
    pub fakeip6_range: Option<String>,

    /// ARS paths for fakeip filter (blacklist exclude / whitelist include).
    #[serde(default, rename = "fakeip-filter")]
    pub fakeip_filter: Vec<String>,

    /// `blacklist` (default) or `whitelist`.
    #[serde(default = "default_fakeip_filter_mode", rename = "fakeip-filter-mode")]
    pub fakeip_filter_mode: String,
}

fn default_dns_mode() -> String {
    "redir-host".into()
}
fn default_fakeip_filter_mode() -> String {
    "blacklist".into()
}

fn default_true() -> bool {
    true
}
fn default_cache_size() -> usize {
    4096
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read config {path:?}"))?;
        let mut cfg: Config =
            serde_yaml::from_str(&text).with_context(|| format!("parse config {path:?}"))?;
        cfg.validate(path)?;
        Ok(cfg)
    }

    fn validate(&mut self, config_path: &Path) -> Result<()> {
        // Mode-dependent default for bind-address when omitted.
        if self.bind_address.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
            self.bind_address = Some(match self.mode {
                Mode::Client => "127.0.0.1".into(),
                Mode::Server => "0.0.0.0".into(),
            });
        }
        match self.mode {
            Mode::Server => {
                if self.proxy.port.unwrap_or(0) == 0 {
                    bail!("server mode requires `proxy.port`");
                }
                if self.proxy.password.is_none() {
                    bail!("server mode requires `proxy.password`");
                }
            }
            Mode::Client => {
                if self.proxy.server.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                    bail!("client mode requires `proxy.server`");
                }
                if self.proxy.port.unwrap_or(0) == 0 {
                    bail!("client mode requires `proxy.port`");
                }
                if self.proxy.password.is_none() {
                    bail!("client mode requires `proxy.password`");
                }
                if self.mixed_port.is_none() && self.tproxy_port.unwrap_or(0) == 0 {
                    bail!("client mode requires at least one of `mixed-port` / `tproxy-port`");
                }
                if self.dns.route_hijack && !self.dns_enabled() {
                    bail!(
                        "dns.route-hijack requires DNS module enabled (set dns.port and/or nameservers)"
                    );
                }
                let mode = self.dns.mode.to_ascii_lowercase();
                if mode != "redir-host" && mode != "fakeip" {
                    bail!("dns.mode must be redir-host or fakeip");
                }
                self.dns.mode = mode;
                if self.dns.mode == "fakeip" {
                    let empty_v4 = self
                        .dns
                        .fakeip_range
                        .as_ref()
                        .map(|s| s.is_empty())
                        .unwrap_or(true);
                    let empty_v6 = self
                        .dns
                        .fakeip6_range
                        .as_ref()
                        .map(|s| s.is_empty())
                        .unwrap_or(true);
                    if empty_v4 && empty_v6 {
                        bail!("fakeip mode requires fakeip-range and/or fakeip6-range");
                    }
                    let fmode = self.dns.fakeip_filter_mode.to_ascii_lowercase();
                    if fmode != "blacklist" && fmode != "whitelist" {
                        bail!("dns.fakeip-filter-mode must be blacklist or whitelist");
                    }
                    self.dns.fakeip_filter_mode = fmode;
                    if self.dns.fakeip_filter_mode == "whitelist"
                        && self.dns.fakeip_filter.is_empty()
                    {
                        bail!("fakeip-filter-mode=whitelist requires non-empty fakeip-filter");
                    }
                }
                // Resolve relative ARS paths against config file directory.
                let base = config_path.parent().unwrap_or_else(|| Path::new("."));
                for rule in &mut self.route {
                    if let Some((outbound, path_part)) = rule.split_once(',') {
                        let p = path_part.trim();
                        if !p.is_empty() && !Path::new(p).is_absolute() {
                            let abs = base.join(p);
                            *rule = format!("{},{}", outbound.trim(), abs.display());
                        }
                    }
                }
                for f in &mut self.dns.fakeip_filter {
                    let p = f.trim();
                    if !p.is_empty() && !Path::new(p).is_absolute() {
                        *f = base.join(p).display().to_string();
                    }
                }
            }
        }
        Ok(())
    }

    // ---- helpers (read from proxy:) ----

    pub fn server_listen(&self) -> Result<SocketAddr> {
        let port = self.proxy.port.unwrap_or(0);
        if port == 0 {
            bail!("proxy.port is required in server mode");
        }
        let bind = self.bind_address_str();
        let ip: std::net::IpAddr = bind
            .parse()
            .with_context(|| format!("parse bind-address `{bind}`"))?;
        Ok(SocketAddr::new(ip, port))
    }

    pub fn client_server(&self) -> Result<SocketAddr> {
        let host = self
            .proxy
            .server
            .as_ref()
            .context("proxy.server required")?;
        let port = self.proxy.port.unwrap_or(0);
        if port == 0 {
            bail!("proxy.port required in client mode");
        }
        // host may be IPv6 without brackets
        let s = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        s.parse().with_context(|| format!("parse proxy.server+port `{s}`"))
    }

    /// Effective bind address after applying mode defaults.
    pub fn bind_address_str(&self) -> &str {
        self.bind_address.as_deref().unwrap_or(match self.mode {
            Mode::Client => "127.0.0.1",
            Mode::Server => "0.0.0.0",
        })
    }

    pub fn password(&self) -> &str {
        self.proxy.password.as_deref().unwrap_or("")
    }

    pub fn username(&self) -> &str {
        self.proxy.user.as_deref().unwrap_or("spectre")
    }

    pub fn server_name(&self) -> &str {
        self.proxy.sni.as_deref().unwrap_or("www.cloudflare.com")
    }

    pub fn upstream(&self) -> &str {
        self.proxy
            .upstream
            .as_deref()
            .unwrap_or("www.cloudflare.com:443")
    }

    pub fn rx_bps(&self) -> Result<u64> {
        match &self.proxy.rx {
            Some(s) => crate::protocol::brutal::parse_rate(s).map_err(|e| anyhow::anyhow!("{e}")),
            None => Ok(0),
        }
    }

    pub fn tx_bps(&self) -> Result<u64> {
        match &self.proxy.tx {
            Some(s) => crate::protocol::brutal::parse_rate(s).map_err(|e| anyhow::anyhow!("{e}")),
            None => Ok(0),
        }
    }

    /// Whether the DNS module should run (listen / route-hijack / fakeip).
    pub fn dns_enabled(&self) -> bool {
        let has_port = matches!(self.dns.port, Some(p) if p > 0);
        let has_ns =
            self.dns.direct_nameserver.is_some() || self.dns.proxy_nameserver.is_some();
        let fakeip = self.dns.mode.eq_ignore_ascii_case("fakeip");
        has_port || (self.dns.route_hijack && has_ns) || fakeip
    }

    pub fn fakeip_enabled(&self) -> bool {
        self.dns.mode.eq_ignore_ascii_case("fakeip")
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
    RuleSet {
        outbound: OutboundKind,
        path: PathBuf,
    },
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
