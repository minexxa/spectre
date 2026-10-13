//! Minimal local DNS: UDP only, rule-follow-route + LRU cache.

mod cache;
mod upstream;

pub use cache::DnsCache;
pub use upstream::{exchange, parse_nameserver, DnsUpstream};

use crate::app::router::{Outbound, Router};
use crate::app::sockopt;
use crate::config::Config;
use anyhow::{bail, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

pub async fn run_dns_server(cfg: Arc<Config>, router: Arc<Router>) -> Result<()> {
    let port = match cfg.dns.port {
        Some(p) if p > 0 => p,
        _ => return Ok(()),
    };

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

    if cfg.dns.rule_follow_route {
        info!(
            "dns rule-follow-route=true direct={} proxy={}",
            direct_ns
                .as_ref()
                .map(|u| u.to_string())
                .unwrap_or_else(|| "-".into()),
            proxy_ns
                .as_ref()
                .map(|u| u.to_string())
                .unwrap_or_else(|| "-".into()),
        );
    }

    let cache = if cfg.dns.cache_size > 0 {
        Some(Arc::new(DnsCache::new(cfg.dns.cache_size)))
    } else {
        None
    };

    let ctx = Arc::new(DnsCtx {
        router,
        direct_ns,
        proxy_ns,
        rule_follow: cfg.dns.rule_follow_route,
        cache,
    });

    let mut handles = Vec::new();
    for bind in sockopt::listen_addrs(&cfg.bind_address, port) {
        match sockopt::bind_udp(bind).await {
            Ok(sock) => {
                info!("DNS listening on UDP {bind}");
                let sock = Arc::new(sock);
                let ctx = ctx.clone();
                handles.push(tokio::spawn(async move {
                    if let Err(e) = run_dns_udp(sock, ctx).await {
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

struct DnsCtx {
    router: Arc<Router>,
    direct_ns: Option<DnsUpstream>,
    proxy_ns: Option<DnsUpstream>,
    rule_follow: bool,
    cache: Option<Arc<DnsCache>>,
}

async fn run_dns_udp(sock: Arc<UdpSocket>, ctx: Arc<DnsCtx>) -> Result<()> {
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = sock.recv_from(&mut buf).await?;
        let query = buf[..n].to_vec();
        let sock2 = sock.clone();
        let ctx2 = ctx.clone();
        tokio::spawn(async move {
            match handle_query(&query, &ctx2).await {
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

async fn handle_query(query: &[u8], ctx: &DnsCtx) -> Result<Vec<u8>> {
    if query.len() < 12 {
        bail!("dns query too short");
    }
    let (domain, qtype) = parse_question(query)?;
    debug!("dns query {domain} type={qtype}");

    if let Some(cache) = &ctx.cache {
        if let Some(hit) = cache.get(&domain, qtype) {
            let mut resp = hit;
            // restore query id
            if resp.len() >= 2 && query.len() >= 2 {
                resp[0] = query[0];
                resp[1] = query[1];
            }
            debug!("dns cache hit {domain}");
            return Ok(resp);
        }
    }

    let upstream = if ctx.rule_follow {
        let ob = ctx.router.dns_outbound_for_domain(&domain);
        match ob {
            Outbound::Direct => ctx.direct_ns.as_ref(),
            Outbound::Proxy => ctx.proxy_ns.as_ref(),
        }
        .or(ctx.proxy_ns.as_ref())
        .or(ctx.direct_ns.as_ref())
    } else {
        ctx.proxy_ns.as_ref().or(ctx.direct_ns.as_ref())
    };

    let upstream = match upstream {
        Some(u) => u,
        None => {
            debug!("dns {domain}: no upstream configured, return empty NOERROR");
            return Ok(make_noerror_empty(query));
        }
    };

    debug!("dns {domain} -> {upstream}");
    let resp = exchange(upstream, query).await?;

    if let Some(cache) = &ctx.cache {
        if resp.len() >= 12 {
            let rcode = resp[3] & 0x0f;
            if rcode == 0 || rcode == 3 {
                let ttl = response_ttl_secs(&resp).unwrap_or(300);
                cache.put(&domain, qtype, resp.clone(), Duration::from_secs(ttl as u64));
            }
        }
    }
    Ok(resp)
}

/// Extract QNAME + QTYPE from a DNS query message.
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
            // compression pointer — unusual in questions, skip
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
    // QR=1, RCODE=0
    resp[2] = (resp[2] & 0x01) | 0x80; // QR
    resp[3] &= 0xf0; // RCODE=0
    // ANCOUNT/NSCOUNT/ARCOUNT = 0
    resp[6] = 0;
    resp[7] = 0;
    resp[8] = 0;
    resp[9] = 0;
    resp[10] = 0;
    resp[11] = 0;
    // keep question section only
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
    // QTYPE + QCLASS
    if i + 4 > msg.len() {
        return None;
    }
    Some(i + 4)
}

fn response_ttl_secs(resp: &[u8]) -> Option<u32> {
    // walk to first answer and read TTL
    let end = question_end(resp)?;
    if end + 12 > resp.len() {
        return Some(300);
    }
    // NAME (possibly pointer) + TYPE(2) + CLASS(2) + TTL(4)
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
    // skip TYPE CLASS
    i += 4;
    let ttl = u32::from_be_bytes([resp[i], resp[i + 1], resp[i + 2], resp[i + 3]]);
    Some(ttl.clamp(60, 86400))
}
