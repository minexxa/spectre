//! Minimal local DNS: UDP listen + rule-follow-route + cache + route-hijack.

mod cache;
mod upstream;

pub use cache::DnsCache;
pub use upstream::{exchange, parse_nameserver, DnsUpstream};

use crate::app::router::{Outbound, Router};
use crate::app::sockopt;
use crate::config::Config;
use anyhow::{bail, Result};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// Shared DNS engine used by the listen socket and by route-hijack paths.
static ENGINE: OnceLock<Arc<DnsEngine>> = OnceLock::new();

pub struct DnsEngine {
    direct_ns: Option<DnsUpstream>,
    proxy_ns: Option<DnsUpstream>,
    rule_follow: bool,
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
        let cache = if cfg.dns.cache_size > 0 {
            Some(Arc::new(DnsCache::new(cfg.dns.cache_size)))
        } else {
            None
        };
        Ok(Self {
            direct_ns,
            proxy_ns,
            rule_follow: cfg.dns.rule_follow_route,
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

/// Answer a raw DNS query (used by UDP listener and by route-hijack on tproxy/mixed).
pub async fn answer_query(query: &[u8], router: &Router) -> Result<Vec<u8>> {
    let eng = engine().ok_or_else(|| anyhow::anyhow!("dns engine not initialized"))?;
    answer_with(&eng, query, router).await
}

async fn answer_with(eng: &DnsEngine, query: &[u8], router: &Router) -> Result<Vec<u8>> {
    if query.len() < 12 {
        bail!("dns query too short");
    }
    let (domain, qtype) = parse_question(query)?;
    debug!("dns query {domain} type={qtype}");

    if let Some(cache) = &eng.cache {
        if let Some(mut hit) = cache.get(&domain, qtype) {
            if hit.len() >= 2 && query.len() >= 2 {
                hit[0] = query[0];
                hit[1] = query[1];
            }
            debug!("dns cache hit {domain}");
            return Ok(hit);
        }
    }

    let upstream = if eng.rule_follow {
        let ob = router.dns_outbound_for_domain(&domain);
        match ob {
            Outbound::Direct => eng.direct_ns.as_ref(),
            Outbound::Proxy => eng.proxy_ns.as_ref(),
        }
        .or(eng.proxy_ns.as_ref())
        .or(eng.direct_ns.as_ref())
    } else {
        eng.proxy_ns.as_ref().or(eng.direct_ns.as_ref())
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

    if let Some(cache) = &eng.cache {
        if resp.len() >= 12 {
            let rcode = resp[3] & 0x0f;
            if rcode == 0 || rcode == 3 {
                let ttl = response_ttl_secs(&resp).unwrap_or(300);
                cache.put(
                    &domain,
                    qtype,
                    resp.clone(),
                    Duration::from_secs(ttl as u64),
                );
            }
        }
    }
    Ok(resp)
}

/// Start UDP DNS listeners if `dns.port` is set. Engine must already be initialized.
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
    if cfg.dns.rule_follow_route {
        info!(
            "dns rule-follow-route=true direct={} proxy={} route-hijack={}",
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
    }

    let mut handles = Vec::new();
    for bind in sockopt::listen_addrs(&cfg.bind_address, port) {
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

fn parse_question(msg: &[u8]) -> Result<(String, u16)> {
    if msg.len() < 12 {
        bail!("short");
    }
    let mut i = 12;
    let mut labels = Vec::new();
    loop {
        if i >= msg.len() {
            bail!("truncated qname");
        }
        let len = msg[i] as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len >= 0xc0 {
            i += 1;
            break;
        }
        if i + len > msg.len() {
            bail!("truncated label");
        }
        labels.push(
            std::str::from_utf8(&msg[i..i + len])
                .unwrap_or("")
                .to_ascii_lowercase(),
        );
        i += len;
    }
    if i + 4 > msg.len() {
        bail!("truncated qtype");
    }
    let qtype = u16::from_be_bytes([msg[i], msg[i + 1]]);
    Ok((labels.join("."), qtype))
}

fn make_noerror_empty(query: &[u8]) -> Vec<u8> {
    let mut resp = query.to_vec();
    if resp.len() < 12 {
        resp.resize(12, 0);
    }
    resp[2] = (resp[2] & 0x01) | 0x80;
    resp[3] &= 0xf0;
    resp[6] = 0;
    resp[7] = 0;
    resp[8] = 0;
    resp[9] = 0;
    resp[10] = 0;
    resp[11] = 0;
    if parse_question(query).is_ok() {
        let end = question_end(query).unwrap_or(query.len().min(512));
        resp.truncate(end);
    }
    resp
}

fn question_end(msg: &[u8]) -> Option<usize> {
    if msg.len() < 12 {
        return None;
    }
    let mut i = 12;
    loop {
        if i >= msg.len() {
            return None;
        }
        let len = msg[i] as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len >= 0xc0 {
            i += 1;
            break;
        }
        i += len;
    }
    if i + 4 > msg.len() {
        return None;
    }
    Some(i + 4)
}

fn response_ttl_secs(resp: &[u8]) -> Option<u32> {
    let end = question_end(resp)?;
    if end + 12 > resp.len() {
        return Some(300);
    }
    let mut i = end;
    if resp[i] >= 0xc0 {
        i += 2;
    } else {
        while i < resp.len() {
            let len = resp[i] as usize;
            i += 1;
            if len == 0 {
                break;
            }
            if len >= 0xc0 {
                i += 1;
                break;
            }
            i += len;
        }
    }
    if i + 8 > resp.len() {
        return Some(300);
    }
    i += 4;
    let ttl = u32::from_be_bytes([resp[i], resp[i + 1], resp[i + 2], resp[i + 3]]);
    Some(ttl.clamp(60, 86400))
}
