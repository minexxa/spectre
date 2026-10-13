//! Mixed inbound: HTTP CONNECT + SOCKS4/4a/5 on one port (TCP + UDP ASSOCIATE).

use crate::app::router::{Outbound, Router};
use crate::app::sniffer;
use crate::app::sockopt;
use crate::config::Config;
use crate::inbound::target::Target;
use crate::protocol::Address;
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

pub async fn run_mixed(cfg: Arc<Config>, router: Arc<Router>) -> Result<()> {
    let port = cfg.mixed_port.unwrap_or(0);
    if port == 0 {
        return Ok(());
    }
    let addrs = sockopt::listen_addrs(cfg.bind_address_str(), port);
    let mut handles = Vec::new();

    for addr in addrs {
        match sockopt::bind_tcp(addr).await {
            Ok(listener) => {
                info!("mixed TCP listening on {addr}");
                let router = router.clone();
                let cfg = cfg.clone();
                handles.push(tokio::spawn(async move {
                    loop {
                        match listener.accept().await {
                            Ok((stream, peer)) => {
                                let router = router.clone();
                                let cfg = cfg.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = handle_tcp(stream, peer, router, cfg).await {
                                        debug!("mixed tcp {peer}: {e:#}");
                                    }
                                });
                            }
                            Err(e) => warn!("mixed accept: {e}"),
                        }
                    }
                }));
            }
            Err(e) => warn!("mixed bind TCP {addr}: {e:#}"),
        }

        match sockopt::bind_udp(addr).await {
            Ok(sock) => {
                info!("mixed UDP listening on {addr}");
                let router = router.clone();
                let cfg = cfg.clone();
                let sock = Arc::new(sock);
                handles.push(tokio::spawn(async move {
                    if let Err(e) = socks5_udp_relay(sock, router, cfg).await {
                        warn!("mixed udp: {e:#}");
                    }
                }));
            }
            Err(e) => warn!("mixed bind UDP {addr}: {e:#}"),
        }
    }

    if handles.is_empty() {
        bail!("mixed: no listen address succeeded");
    }
    futures::future::pending::<()>().await;
    #[allow(unreachable_code)]
    Ok(())
}

// -------------------- TCP --------------------

async fn handle_tcp(
    mut stream: TcpStream,
    peer: SocketAddr,
    router: Arc<Router>,
    cfg: Arc<Config>,
) -> Result<()> {
    // One-byte peek to distinguish SOCKS vs HTTP (same as ant).
    let mut peek = [0u8; 1];
    let n = stream.peek(&mut peek).await?;
    if n == 0 {
        return Ok(());
    }
    if peek[0] == 0x05 || peek[0] == 0x04 {
        handle_socks(&mut stream, peer, router, cfg).await
    } else {
        handle_http(&mut stream, peer, router, cfg).await
    }
}

async fn handle_http(
    stream: &mut TcpStream,
    _peer: SocketAddr,
    router: Arc<Router>,
    cfg: Arc<Config>,
) -> Result<()> {
    // Consume full request headers (must read, not only peek — otherwise CONNECT
    // request bytes stay in the socket and leak into the TLS tunnel).
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 64 * 1024 {
            bail!("http header too large");
        }
    }

    let header = String::from_utf8_lossy(&buf);
    let first_line = header.lines().next().unwrap_or("").trim();
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    if method.eq_ignore_ascii_case("CONNECT") {
        let tgt = parse_host_port(target)?;
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        dispatch_tcp(stream, tgt, router, cfg).await
    } else if let Some((host, port)) = parse_bare_host_port(first_line) {
        // legacy bare host:port line
        dispatch_tcp(stream, Target::from_host_port(&host, port), router, cfg).await
    } else if method.eq_ignore_ascii_case("GET")
        || method.eq_ignore_ascii_case("POST")
        || method.eq_ignore_ascii_case("HEAD")
        || method.eq_ignore_ascii_case("PUT")
        || method.eq_ignore_ascii_case("DELETE")
        || method.eq_ignore_ascii_case("OPTIONS")
        || method.eq_ignore_ascii_case("PATCH")
    {
        // Absolute-form HTTP proxy: rewrite to origin-form and forward via tunnel.
        let host = header
            .lines()
            .find_map(|l| {
                l.strip_prefix("Host:")
                    .or_else(|| l.strip_prefix("host:"))
                    .map(|s| s.trim().to_string())
            })
            .or_else(|| {
                target
                    .strip_prefix("http://")
                    .and_then(|r| r.split('/').next())
                    .map(|s| s.to_string())
            })
            .context("http proxy: no Host")?;
        let (h, port) = if let Some((a, b)) = host.rsplit_once(':') {
            (a.to_string(), b.parse().unwrap_or(80))
        } else {
            (host.clone(), 80)
        };
        let path = if let Some(rest) = target.strip_prefix("http://") {
            rest.find('/')
                .map(|i| rest[i..].to_string())
                .unwrap_or_else(|| "/".into())
        } else {
            target.to_string()
        };
        let mut new_req = format!("{method} {path} HTTP/1.1\r\n");
        for line in header.lines().skip(1) {
            if line.is_empty() {
                break;
            }
            if line.to_ascii_lowercase().starts_with("proxy-connection") {
                continue;
            }
            new_req.push_str(line);
            new_req.push_str("\r\n");
        }
        new_req.push_str("\r\n");
        let body = if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            buf[pos + 4..].to_vec()
        } else {
            Vec::new()
        };
        // Dial via router then write rewritten request
        let target = Target::from_host_port(&h, port);
        // Prepend rewritten request into the outbound stream by a small wrapper:
        // open outbound, write new_req+body, then relay remaining.
        http_absolute_proxy(stream, target, router, cfg, new_req.into_bytes(), body).await
    } else {
        bail!("unsupported request: {first_line}");
    }
}

async fn http_absolute_proxy(
    local: &mut TcpStream,
    target: Target,
    router: Arc<Router>,
    cfg: Arc<Config>,
    head: Vec<u8>,
    body: Vec<u8>,
) -> Result<()> {
    let mut head_buf = [0u8; 1024];
    let n = local.peek(&mut head_buf).await.unwrap_or(0);
    let sniff = if n > 0 && router.sniff_enabled() {
        sniffer::sniff_tcp_ex(&head_buf[..n], true, false)
    } else {
        sniffer::SniffResult::default()
    };
    let domain = sniff.domain.clone().or_else(|| match &target {
        Target::Domain { host, .. } => Some(host.clone()),
        Target::Addr(_) => None,
    });
    let decision = if let Some(ref d) = domain {
        router.match_domain(d)
    } else if let Target::Addr(a) = &target {
        router.match_ip(a.ip())
    } else {
        router.match_domain("")
    };
    debug!(
        "mixed http {} -> {:?} via {}",
        target.display(),
        decision.outbound,
        decision.rule
    );
    match decision.outbound {
        Outbound::Direct => {
            let mut remote = match &target {
                Target::Addr(a) => TcpStream::connect(a).await?,
                Target::Domain { host, port } => {
                    TcpStream::connect((host.as_str(), *port)).await?
                }
            };
            remote.write_all(&head).await?;
            if !body.is_empty() {
                remote.write_all(&body).await?;
            }
            let (mut lr, mut lw) = tokio::io::split(local);
            let (mut rr, mut rw) = remote.into_split();
            tokio::select! {
                r = tokio::io::copy(&mut lr, &mut rw) => { let _ = r; }
                r = tokio::io::copy(&mut rr, &mut lw) => { let _ = r; }
            }
        }
        Outbound::Proxy => {
            // Use a buffer stream: write head+body after spectre connect via a helper
            crate::client::proxy_via_spectre_with_preface(local, &target, &cfg, &head, &body)
                .await?;
        }
    }
    Ok(())
}

async fn handle_socks(
    stream: &mut TcpStream,
    peer: SocketAddr,
    router: Arc<Router>,
    cfg: Arc<Config>,
) -> Result<()> {
    let mut buf = vec![0u8; 512];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    buf.truncate(n);
    if buf[0] == 0x05 {
        if buf.len() < 2 {
            bail!("socks5 short greeting");
        }
        stream.write_all(&[0x05, 0x00]).await?;
        buf.resize(512, 0);
        let n = stream.read(&mut buf).await?;
        if n < 7 {
            bail!("socks5 short request");
        }
        let cmd = buf[1];
        match cmd {
            0x01 => {
                // CONNECT
                let (target, _) = parse_socks5_addr(&buf[3..])?;
                stream
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;
                dispatch_tcp(stream, target, router, cfg).await
            }
            0x03 => {
                // UDP ASSOCIATE — reply with our UDP listen address
                let local = stream.local_addr().unwrap_or(peer);
                let reply = socks5_udp_associate_reply(local)?;
                stream.write_all(&reply).await?;
                // Keep TCP open until client disconnects (RFC 1928)
                let mut sink = [0u8; 64];
                loop {
                    match stream.read(&mut sink).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
                Ok(())
            }
            other => {
                stream
                    .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;
                bail!("socks5 cmd {other} not supported");
            }
        }
    } else if buf[0] == 0x04 {
        if buf.len() < 8 {
            bail!("socks4 short");
        }
        if buf[1] != 0x01 {
            stream.write_all(&[0x00, 0x5b, 0, 0, 0, 0, 0, 0]).await?;
            bail!("socks4 only CONNECT");
        }
        let port = u16::from_be_bytes([buf[2], buf[3]]);
        let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
        let mut i = 8;
        while i < buf.len() && buf[i] != 0 {
            i += 1;
        }
        i += 1;
        let target = if ip.octets()[0] == 0
            && ip.octets()[1] == 0
            && ip.octets()[2] == 0
            && ip.octets()[3] != 0
        {
            let start = i;
            while i < buf.len() && buf[i] != 0 {
                i += 1;
            }
            let host = std::str::from_utf8(&buf[start..i]).unwrap_or("");
            Target::from_host_port(host, port)
        } else {
            Target::Addr(SocketAddr::new(IpAddr::V4(ip), port))
        };
        stream.write_all(&[0x00, 0x5a, 0, 0, 0, 0, 0, 0]).await?;
        dispatch_tcp(stream, target, router, cfg).await
    } else {
        bail!("unknown socks version {}", buf[0]);
    }
}

async fn dispatch_tcp(
    local: &mut TcpStream,
    target: Target,
    router: Arc<Router>,
    cfg: Arc<Config>,
) -> Result<()> {
    let mut head = [0u8; 1024];
    let n = local.peek(&mut head).await.unwrap_or(0);
    let sniff = if n > 0 && router.sniff_enabled() {
        sniffer::sniff_tcp_ex(&head[..n], true, false)
    } else {
        sniffer::SniffResult::default()
    };
    let domain = sniff.domain.clone().or_else(|| match &target {
        Target::Domain { host, .. } => Some(host.clone()),
        Target::Addr(_) => None,
    });
    let decision = if let Some(ref d) = domain {
        router.match_domain(d)
    } else if let Target::Addr(a) = &target {
        router.match_ip(a.ip())
    } else {
        router.match_domain("")
    };
    debug!(
        "mixed {} -> {:?} via {}",
        target.display(),
        decision.outbound,
        decision.rule
    );
    match decision.outbound {
        Outbound::Direct => {
            let remote = match &target {
                Target::Addr(a) => {
                    let real = crate::inbound::target::resolve_direct(
                        &router,
                        *a,
                        domain.as_deref(),
                    )
                    .await?;
                    TcpStream::connect(real).await?
                }
                Target::Domain { host, port } => {
                    TcpStream::connect((host.as_str(), *port)).await?
                }
            };
            let (mut lr, mut lw) = tokio::io::split(local);
            let (mut rr, mut rw) = remote.into_split();
            tokio::select! {
                r = tokio::io::copy(&mut lr, &mut rw) => { let _ = r; }
                r = tokio::io::copy(&mut rr, &mut lw) => { let _ = r; }
            }
        }
        Outbound::Proxy => {
            // Prefer domain over fake-ip for remote resolution
            let tgt = if let Target::Addr(a) = &target {
                if let Some(d) = router.domain_for_fakeip(a.ip()) {
                    Target::from_host_port(&d, a.port())
                } else {
                    target.clone()
                }
            } else {
                target.clone()
            };
            crate::client::proxy_via_spectre(local, &tgt, &cfg).await?;
        }
    }
    Ok(())
}

// -------------------- SOCKS5 UDP ASSOCIATE --------------------

fn socks5_udp_associate_reply(listen: SocketAddr) -> Result<Vec<u8>> {
    let mut out = vec![0x05, 0x00, 0x00]; // ver, success, rsv
    match listen {
        SocketAddr::V4(a) => {
            out.push(0x01);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            out.push(0x04);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    Ok(out)
}

/// Parse SOCKS5 UDP request header → (target, payload_offset)
fn parse_socks5_udp(buf: &[u8]) -> Result<(Target, usize)> {
    // RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT DATA
    if buf.len() < 4 {
        bail!("socks5 udp short");
    }
    if buf[2] != 0 {
        bail!("socks5 udp frag not supported");
    }
    let (target, addr_len) = parse_socks5_addr(&buf[3..])?;
    Ok((target, 3 + addr_len))
}

fn encode_socks5_udp_reply(src: &SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0, 0, 0]; // RSV FRAG
    match src {
        SocketAddr::V4(a) => {
            out.push(0x01);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            out.push(0x04);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    out.extend_from_slice(data);
    out
}

async fn socks5_udp_relay(
    udp: Arc<UdpSocket>,
    router: Arc<Router>,
    cfg: Arc<Config>,
) -> Result<()> {
    // client SocketAddr → Spectre session id (if proxy)
    let sessions: Arc<Mutex<HashMap<SocketAddr, u32>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut buf = vec![0u8; 65535];

    loop {
        let (n, client) = udp.recv_from(&mut buf).await?;
        let pkt = &buf[..n];
        let (target, off) = match parse_socks5_udp(pkt) {
            Ok(v) => v,
            Err(e) => {
                debug!("socks5 udp parse from {client}: {e:#}");
                continue;
            }
        };
        if off > n {
            continue;
        }
        let payload = pkt[off..n].to_vec();

        let sniff = if router.sniff_enabled() {
            sniffer::sniff_udp_ex(&payload, true, false)
        } else {
            sniffer::SniffResult::default()
        };
        let domain = sniff.domain.clone().or_else(|| match &target {
            Target::Domain { host, .. } => Some(host.clone()),
            _ => None,
        });
        let decision = if let Some(ref d) = domain {
            router.match_domain(d)
        } else if let Target::Addr(a) = &target {
            router.match_ip(a.ip())
        } else {
            router.match_domain("")
        };

        match decision.outbound {
            Outbound::Direct => {
                let dst = match &target {
                    Target::Addr(a) => *a,
                    Target::Domain { host, port } => {
                        match tokio::net::lookup_host((host.as_str(), *port)).await {
                            Ok(mut it) => match it.next() {
                                Some(a) => a,
                                None => continue,
                            },
                            Err(_) => continue,
                        }
                    }
                };
                let bind = if dst.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                if let Ok(sock) = UdpSocket::bind(bind).await {
                    if sock.send_to(&payload, dst).await.is_ok() {
                        let mut rbuf = vec![0u8; 65535];
                        if let Ok(Ok((rn, src))) = tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            sock.recv_from(&mut rbuf),
                        )
                        .await
                        {
                            let reply = encode_socks5_udp_reply(&src, &rbuf[..rn]);
                            let _ = udp.send_to(&reply, client).await;
                        }
                    }
                }
            }
            Outbound::Proxy => {
                let addr = match &target {
                    Target::Domain { host, port } => Address::new(host.clone(), *port),
                    Target::Addr(a) => Address::new(a.ip().to_string(), a.port()),
                };
                let mut map = sessions.lock().await;
                let sid = if let Some(&s) = map.get(&client) {
                    s
                } else {
                    match crate::client::spectre_udp_session(&cfg, &addr).await {
                        Ok((s, mut rx)) => {
                            map.insert(client, s);
                            let udp2 = udp.clone();
                            let sessions2 = sessions.clone();
                            tokio::spawn(async move {
                                while let Some((src_addr, data)) = rx.recv().await {
                                    let src = match format!(
                                        "{}:{}",
                                        src_addr.host, src_addr.port
                                    )
                                    .parse::<SocketAddr>()
                                    {
                                        Ok(a) => a,
                                        Err(_) => SocketAddr::new(
                                            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                                            src_addr.port,
                                        ),
                                    };
                                    let reply = encode_socks5_udp_reply(&src, &data);
                                    let _ = udp2.send_to(&reply, client).await;
                                }
                                sessions2.lock().await.remove(&client);
                                crate::client::spectre_udp_close_session(s);
                            });
                            s
                        }
                        Err(e) => {
                            debug!("spectre udp session: {e:#}");
                            continue;
                        }
                    }
                };
                drop(map);
                if let Err(e) = crate::client::spectre_udp_send(&cfg, sid, &addr, &payload).await
                {
                    debug!("spectre udp send: {e:#}");
                }
            }
        }
    }
}

// -------------------- helpers --------------------

fn parse_host_port(s: &str) -> Result<Target> {
    if let Some((h, p)) = s.rsplit_once(':') {
        let port: u16 = p.parse().context("port")?;
        Ok(Target::from_host_port(
            h.trim_matches(|c| c == '[' || c == ']'),
            port,
        ))
    } else {
        bail!("bad host:port `{s}`")
    }
}

fn parse_bare_host_port(line: &str) -> Option<(String, u16)> {
    let s = line.trim();
    if let Some((h, p)) = s.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return Some((h.to_string(), port));
        }
    }
    None
}

fn parse_socks5_addr(buf: &[u8]) -> Result<(Target, usize)> {
    if buf.is_empty() {
        bail!("empty socks5 addr");
    }
    match buf[0] {
        0x01 => {
            if buf.len() < 7 {
                bail!("short ipv4");
            }
            let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((Target::Addr(SocketAddr::new(IpAddr::V4(ip), port)), 7))
        }
        0x03 => {
            if buf.len() < 2 {
                bail!("short domain");
            }
            let len = buf[1] as usize;
            if buf.len() < 2 + len + 2 {
                bail!("short domain body");
            }
            let host = std::str::from_utf8(&buf[2..2 + len])?.to_string();
            let port = u16::from_be_bytes([buf[2 + len], buf[2 + len + 1]]);
            Ok((Target::from_host_port(&host, port), 2 + len + 2))
        }
        0x04 => {
            if buf.len() < 19 {
                bail!("short ipv6");
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((
                Target::Addr(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)),
                19,
            ))
        }
        other => bail!("unknown atyp {other}"),
    }
}
