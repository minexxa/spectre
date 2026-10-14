//! Local DNS server: UDP + TCP listen, dual-stack (aligned with ant).
//! Upstream: udp / tcp / tls / https (clash-rs URL style).
//! fakeip mode answers A/AAAA from the pool; every other query follows the
//! route decision (direct/proxy nameserver) with the response cache in front.

mod cache;
mod fakeip;
mod upstream;

pub use cache::DnsCache;
pub use fakeip::FakeIpPool;
pub use upstream::{
    exchange, parse_nameserver, resolve_host_via_bootstrap, set_bootstrap, DnsUpstream,
};

use crate::client::app::router::{Outbound, Router};
use crate::client::app::sockopt;
use crate::config::Config;
use anyhow::{bail, Result};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, info, warn};

/// Shared DNS engine used by the listen socket and by route-hijack paths.
static ENGINE: OnceLock<Arc<DnsEngine>> = OnceLock::new();

pub struct DnsEngine {
    direct_ns: Option<DnsUpstream>,
    proxy_ns: Option<DnsUpstream>,
    cache: Option<Arc<DnsCache>>,
}

impl DnsEngine {
    pub fn from_config(cfg: &Config) -> Result<Self> {
        let direct_ns = cfg
            .dns
            .direct_nameserver
            .as_ref()
            .map(|s| parse_nameserver(s))
            .transpose()?;
        let proxy_ns = cfg
            .dns
            .proxy_nameserver
            .as_ref()
            .map(|s| parse_nameserver(s))
            .transpose()?;
        // Bootstrap upstream for lazy DoT/DoH (and dial-time) host resolution:
        // only a pure-IP udp/tcp nameserver qualifies (ant: default-nameserver).
        // Registration is memory-only — no network IO at startup, and a
        // bootstrap failure only affects the single lookup that used it.
        match &direct_ns {
            Some(ns @ (DnsUpstream::Udp(_) | DnsUpstream::Tcp(_))) => {
                set_bootstrap(ns.clone());
                debug!("dns bootstrap upstream {ns}");
            }
            _ => {
                debug!("dns bootstrap unset (direct-nameserver is not pure-IP udp/tcp)");
            }
        }
        let cache = if cfg.dns.cache_size > 0 {
            Some(Arc::new(DnsCache::new(cfg.dns.cache_size)))
        } else {
            None
        };
        Ok(Self {
            direct_ns,
            proxy_ns,
            cache,
        })
    }
}

/// Install the global engine (idempotent). Call once at client start when DNS is enabled.
pub fn init_engine(cfg: &Config) -> Result<Arc<DnsEngine>> {
    if let Some(e) = ENGINE.get() {
        return Ok(e.clone());
    }
    let eng = Arc::new(DnsEngine::from_config(cfg)?);
    let _ = ENGINE.set(eng.clone());
    Ok(eng)
}

fn engine() -> Option<Arc<DnsEngine>> {
    ENGINE.get().cloned()
}

/// Answer a raw DNS query (used by UDP/TCP listeners and by route-hijack on tproxy/mixed).
pub async fn answer_query(query: &[u8], router: &Router) -> Result<Vec<u8>> {
    let eng = engine().ok_or_else(|| anyhow::anyhow!("dns engine not initialized"))?;
    answer_with(&eng, query, router).await
}

async fn answer_with(eng: &DnsEngine, query: &[u8], router: &Router) -> Result<Vec<u8>> {
    if query.len() < 12 {
        bail!("dns query too short");
    }
    // Unparseable queries keep an empty domain: they match no ruleset and fall
    // through to the default upstream instead of being dropped (same as ant).
    let domain = extract_qname(query).unwrap_or_default();
    let qtype = query_type(query).unwrap_or(1);
    debug!("dns query {domain} type={qtype}");

    // Cache lookup (real + fakeip answers)
    if !domain.is_empty() {
        if let Some(cache) = &eng.cache {
            if let Some(mut hit) = cache.get(&domain, qtype) {
                cache::apply_query_id(&mut hit, query);
                debug!("dns cache hit {domain} type={qtype}");
                return Ok(hit);
            }
        }
    }

    // Fake-IP for A (1) / AAAA (28); other qtypes pass through to the upstream.
    if router.fakeip_enabled() && !domain.is_empty() && router.use_fakeip(&domain) {
        if qtype == 1 {
            if router.has_fakeip_v4() {
                if let Some(ip) = router.allocate_fakeip(&domain, false) {
                    debug!("dns fakeip {domain} A -> {ip}");
                    let resp = fakeip::build_fakeip_answer(query, ip);
                    cache_put(eng, &domain, qtype, &resp, Duration::from_secs(60));
                    return Ok(resp);
                }
            }
            return Ok(make_noerror_empty(query));
        }
        if qtype == 28 {
            if router.has_fakeip_v6() {
                if let Some(ip) = router.allocate_fakeip(&domain, true) {
                    debug!("dns fakeip {domain} AAAA -> {ip}");
                    let resp = fakeip::build_fakeip_answer(query, ip);
                    cache_put(eng, &domain, qtype, &resp, Duration::from_secs(60));
                    return Ok(resp);
                }
            }
            return Ok(make_noerror_empty(query));
        }
    }

    // DNS routing: domain → route match → Direct/Proxy nameserver, with
    // fallback to the other side when the preferred one is unset.
    let upstream = match router.dns_outbound_for_domain(&domain) {
        Outbound::Direct => eng.direct_ns.as_ref().or_else(|| {
            warn!("dns {domain}: route=direct but direct-nameserver unset, falling back");
            eng.proxy_ns.as_ref()
        }),
        Outbound::Proxy => eng.proxy_ns.as_ref().or_else(|| {
            warn!("dns {domain}: route=proxy but proxy-nameserver unset, falling back");
            eng.direct_ns.as_ref()
        }),
    };

    let upstream = match upstream {
        Some(u) => u,
        None => {
            debug!("dns {domain}: no upstream, empty NOERROR");
            return Ok(make_noerror_empty(query));
        }
    };

    debug!("dns {domain} -> {upstream}");
    let resp = exchange(upstream, query).await?;

    // Cache NOERROR / NXDOMAIN with the min TTL across answers (fallback 300s).
    if !domain.is_empty() && resp.len() >= 12 {
        let rcode = resp[3] & 0x0f;
        if rcode == 0 || rcode == 3 {
            let secs = cache::response_ttl_secs(&resp, 300);
            cache_put(eng, &domain, qtype, &resp, Duration::from_secs(secs as u64));
        }
    }
    Ok(resp)
}

fn cache_put(eng: &DnsEngine, domain: &str, qtype: u16, resp: &[u8], ttl: Duration) {
    if let Some(cache) = &eng.cache {
        cache.put(domain, qtype, resp.to_vec(), ttl);
    }
}

fn make_noerror_empty(query: &[u8]) -> Vec<u8> {
    build_rcode_response(query, 0)
}

fn question_section_end(msg: &[u8], offset: usize) -> Option<usize> {
    let mut i = offset;
    loop {
        if i >= msg.len() {
            return None;
        }
        let len = msg[i] as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            if i + 1 > msg.len() {
                return None;
            }
            i += 1;
            break;
        }
        i += len;
        if i > msg.len() {
            return None;
        }
    }
    if i + 4 > msg.len() {
        return None;
    }
    Some(i + 4)
}

fn build_rcode_response(query: &[u8], rcode: u8) -> Vec<u8> {
    let qdcount: u16 = if query.len() >= 6 {
        u16::from_be_bytes([query[4], query[5]])
    } else {
        0
    };
    let question_end = if qdcount >= 1 {
        question_section_end(query, 12)
    } else {
        None
    };
    let id = if query.len() >= 2 {
        [query[0], query[1]]
    } else {
        [0, 0]
    };
    let flag2: u8 = 0x85;
    let flag3: u8 = 0x80 | (rcode & 0x0F);

    if let Some(end) = question_end {
        let mut resp = Vec::with_capacity(end);
        resp.extend_from_slice(&id);
        resp.push(flag2);
        resp.push(flag3);
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&query[12..end]);
        resp
    } else {
        let mut resp = Vec::with_capacity(12);
        resp.extend_from_slice(&id);
        resp.push(flag2);
        resp.push(flag3);
        resp.extend_from_slice(&[0u8; 8]);
        resp
    }
}

fn extract_qname(msg: &[u8]) -> Option<String> {
    if msg.len() < 13 {
        return None;
    }
    let mut i = 12usize;
    let mut labels = Vec::new();
    while i < msg.len() {
        let len = msg[i] as usize;
        if len == 0 {
            break;
        }
        if len & 0xc0 == 0xc0 {
            break;
        }
        i += 1;
        if i + len > msg.len() {
            return None;
        }
        let label = std::str::from_utf8(&msg[i..i + len]).ok()?;
        labels.push(label.to_lowercase());
        i += len;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

fn query_type(msg: &[u8]) -> Option<u16> {
    let end = question_section_end(msg, 12)?;
    if end < 4 {
        return None;
    }
    Some(u16::from_be_bytes([msg[end - 4], msg[end - 3]]))
}

/// Start UDP + TCP DNS listeners if `dns.port` is set. Engine must already be initialized.
pub async fn run_dns_server(cfg: Arc<Config>, router: Arc<Router>) -> Result<()> {
    let port = match cfg.dns.port {
        Some(p) if p > 0 => p,
        _ => {
            // No listen port — route-hijack only
            info!("dns: no listen port (route-hijack only)");
            futures::future::pending::<()>().await;
            return Ok(());
        }
    };

    let eng = init_engine(&cfg)?;
    info!(
        "dns direct={} proxy={} route-hijack={}",
        eng.direct_ns
            .as_ref()
            .map(|u| u.to_string())
            .unwrap_or_else(|| "-".into()),
        eng.proxy_ns
            .as_ref()
            .map(|u| u.to_string())
            .unwrap_or_else(|| "-".into()),
        cfg.dns.route_hijack,
    );

    let mut handles = Vec::new();
    for bind in sockopt::listen_addrs(cfg.bind_address_str(), port) {
        match sockopt::bind_udp(bind).await {
            Ok(sock) => {
                info!("DNS listening on UDP {bind}");
                let sock = Arc::new(sock);
                let router = router.clone();
                handles.push(tokio::spawn(async move {
                    if let Err(e) = run_dns_udp(sock, router).await {
                        warn!("dns udp: {e:#}");
                    }
                }));
            }
            Err(e) => warn!("dns bind {bind}: {e:#}"),
        }
    }
    // TCP listener: required for large responses (UDP truncation) and for
    // clients that force TCP (aligned with ant's dual-stack DNS server).
    for bind in sockopt::listen_addrs(cfg.bind_address_str(), port) {
        match sockopt::bind_tcp(bind).await {
            Ok(listener) => {
                info!("DNS listening on TCP {bind}");
                let router = router.clone();
                handles.push(tokio::spawn(async move {
                    if let Err(e) = run_dns_tcp(listener, router).await {
                        warn!("dns tcp: {e:#}");
                    }
                }));
            }
            Err(e) => warn!("dns tcp bind {bind}: {e:#}"),
        }
    }
    if handles.is_empty() {
        bail!("dns: no listen address succeeded");
    }
    futures::future::pending::<()>().await;
    #[allow(unreachable_code)]
    Ok(())
}

async fn run_dns_udp(sock: Arc<UdpSocket>, router: Arc<Router>) -> Result<()> {
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = sock.recv_from(&mut buf).await?;
        let query = buf[..n].to_vec();
        let sock2 = sock.clone();
        let router2 = router.clone();
        tokio::spawn(async move {
            match answer_query(&query, &router2).await {
                Ok(resp) => {
                    if let Err(e) = sock2.send_to(&resp, peer).await {
                        debug!("dns send to {peer}: {e}");
                    }
                }
                Err(e) => debug!("dns query from {peer}: {e:#}"),
            }
        });
    }
}

async fn run_dns_tcp(listener: TcpListener, router: Arc<Router>) -> Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_dns_tcp(stream, peer, router).await {
                debug!("dns tcp {peer}: {e:#}");
            }
        });
    }
}

/// DNS over TCP: 2-byte big-endian length prefix per message (RFC 1035 §4.2.2).
async fn handle_dns_tcp(
    mut stream: tokio::net::TcpStream,
    _peer: std::net::SocketAddr,
    router: Arc<Router>,
) -> Result<()> {
    loop {
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 || len > 65535 {
            anyhow::bail!("bad dns tcp length {len}");
        }
        let mut query = vec![0u8; len];
        stream.read_exact(&mut query).await?;
        let resp = answer_query(&query, &router).await?;
        let rlen = (resp.len() as u16).to_be_bytes();
        stream.write_all(&rlen).await?;
        stream.write_all(&resp).await?;
    }
}
