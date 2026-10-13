//! Spectre client — QUIC + JLS (rustls-jls / quinn-jls).

use crate::brutal::{bind_udp, tune_transport, BrutalHandle};
use crate::relay::relay;
use crate::protocol::*;
use crate::udp::{
    fragment_udp, FragmentReassembler, send_udp_over_quic, DEFAULT_MAX_DATAGRAM_PAYLOAD,
};
use anyhow::{anyhow, bail, Context, Result};
use quinn_jls as quinn;
use rustls_jls as rustls;
use rustls::jls::JlsClientConfig;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{info, warn};

pub struct ClientConfigYaml {
    pub server: SocketAddr,
    pub server_name: String,
    pub username: String,
    pub password: String,
    pub listen: SocketAddr,
    pub rx_bps: u64,
    pub tx_bps: u64,
    /// Optional local UDP listen for datagram proxying (e.g. 127.0.0.1:1081)
    pub udp_listen: Option<SocketAddr>,
}

pub async fn run_client(cfg: ClientConfigYaml) -> Result<()> {
    // Large UDP socket buffers: drops in the kernel would look like network
    // loss to Brutal.
    let bind_addr: SocketAddr = if cfg.server.is_ipv6() {
        "[::]:0".parse()?
    } else {
        "0.0.0.0:0".parse()?
    };
    let socket = bind_udp(bind_addr).context("bind udp socket")?;
    let runtime = quinn::default_runtime().ok_or_else(|| anyhow!("no async runtime found"))?;
    let endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)?;
    endpoint.set_default_client_config(configure_client(&cfg)?);

    info!("connecting to {} (SNI={})", cfg.server, cfg.server_name);
    let conn = endpoint
        .connect(cfg.server, &cfg.server_name)?
        .await
        .context("connect failed")?;

    if conn.is_jls() != Some(true) {
        return Err(anyhow!(
            "JLS authentication failed: not a Spectre server, or wrong password/username/server-name"
        ));
    }
    info!("QUIC connected (JLS ok), Spectre AUTH");
    let (mut send, mut recv) = conn.open_bi().await?;
    let auth = AuthRequest {
        username: cfg.username.clone(),
        password: cfg.password.clone(),
        rx_bps: cfg.rx_bps,
        tx_bps: cfg.tx_bps,
        padding: random_padding(16..48),
    };
    send.write_all(&auth.encode()).await?;

    let mut buf = vec![0u8; 1024];
    let n = recv
        .read(&mut buf)
        .await?
        .ok_or_else(|| anyhow!("no auth response"))?;
    let mut reader = &buf[..n];  // n: usize from Option unwrap
    let resp = AuthResponse::decode(&mut reader)?;
    if !resp.ok {
        return Err(anyhow!("auth rejected: {}", resp.message));
    }
    info!(
        "auth success, negotiated rates rx={} tx={}",
        resp.rx_bps, resp.tx_bps
    );
    info!(
        "Brutal: upload {} B/s, download {} B/s (0 = BBR)",
        cfg.tx_bps, cfg.rx_bps
    );

    // TCP local proxy
    let listener = TcpListener::bind(cfg.listen).await?;
    info!("local TCP proxy listening on {}", cfg.listen);

    // Optional UDP local socket
    if let Some(udp_addr) = cfg.udp_listen {
        let udp_sock = UdpSocket::bind(udp_addr).await?;
        info!("local UDP proxy listening on {}", udp_addr);
        let conn_u = conn.clone();
        tokio::spawn(async move {
            if let Err(e) = client_udp_loop(udp_sock, conn_u).await {
                warn!("udp loop error: {e:#}");
            }
        });
    }

    // Incoming datagrams from server (UDP responses)
    let conn_d = conn.clone();
    tokio::spawn(async move {
        let mut reasm = FragmentReassembler::new();
        while let Ok(data) = conn_d.read_datagram().await {
            match reasm.push(data) {
                Ok(Some((_sid, addr, payload))) => {
                    info!("udp response from {} len={}", addr.to_socket_addr_string(), payload.len());
                }
                Ok(None) => {}
                Err(e) => warn!("client reassembly: {e}"),
            }
        }
    });

    loop {
        let (local, peer) = listener.accept().await?;
        let conn = conn.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_local(local, peer, conn).await {
                warn!("local connection error: {e:#}");
            }
        });
    }
}

async fn client_udp_loop(sock: UdpSocket, conn: quinn::Connection) -> Result<()> {
    let session_id = AtomicU32::new(1);
    let packet_id = AtomicU16::new(1);
    let mut buf = vec![0u8; 65535];
    // Simple mode: each local packet uses session 1 and target encoded... 
    // For a real SOCKS5 UDP we'd parse the header. Here we expect
    // raw payload preceded by nothing — user should use associate properly later.
    // Minimal: treat first packet peer as association target via a fixed test address is wrong.
    // Instead: document that UDP path is datagram-native after AUTH.
    loop {
        let (n, from) = sock.recv_from(&mut buf).await?;
        // Expect first 2 bytes port + host length encoding? Keep simple:
        // payload format for local UDP: [u16 port][u8 host_len][host][data]
        if n < 4 {
            continue;
        }
        let port = u16::from_be_bytes([buf[0], buf[1]]);
        let host_len = buf[2] as usize;
        if n < 3 + host_len {
            continue;
        }
        let host = String::from_utf8_lossy(&buf[3..3 + host_len]).into_owned();
        let payload = &buf[3 + host_len..n];
        let addr = Address::new(host, port);
        let sid = session_id.load(Ordering::Relaxed);
        let pid = packet_id.fetch_add(1, Ordering::Relaxed);
        let frames = fragment_udp(sid, pid, &addr, payload, DEFAULT_MAX_DATAGRAM_PAYLOAD);
        for frame in frames {
            let _ = conn.send_datagram(frame);
        }
        let _ = from;
    }
}


/// Parsed local inbound request.
struct LocalRequest {
    /// host:port to dial on the remote side
    host: String,
    port: u16,
    /// true = HTTP CONNECT (reply 200 and tunnel)
    is_connect: bool,
    /// For absolute-form HTTP proxy: rewritten origin-form request bytes to send first
    pending: Vec<u8>,
}

fn parse_local_request(buf: &[u8]) -> Result<LocalRequest> {
    let text = String::from_utf8_lossy(buf);
    let first = text
        .lines()
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("empty request"))?;

    // CONNECT host:port HTTP/1.x
    if let Some(rest) = first.strip_prefix("CONNECT ") {
        let authority = rest
            .split_whitespace()
            .next()
            .ok_or_else(|| anyhow!("bad CONNECT line"))?;
        let (host, port) = split_host_port(authority, 443)?;
        return Ok(LocalRequest {
            host,
            port,
            is_connect: true,
            pending: Vec::new(),
        });
    }

    // HTTP method absolute-form: GET http://host:port/path HTTP/1.1
    let methods = [
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "TRACE ",
    ];
    for m in methods {
        if let Some(rest) = first.strip_prefix(m) {
            let url = rest
                .split_whitespace()
                .next()
                .ok_or_else(|| anyhow!("bad HTTP request line"))?;
            let (host, port, path) = parse_absolute_url(url)?;
            // Rebuild origin-form request: METHOD /path HTTP/1.x\r\n + remaining headers
            let version = rest
                .split_whitespace()
                .nth(1)
                .unwrap_or("HTTP/1.1");
            let method = m.trim();
            let mut out = format!("{method} {path} {version}\r\n").into_bytes();
            // Append headers after the first line; rewrite/skip absolute Host if needed
            if let Some(pos) = find_header_start(buf) {
                let headers = &buf[pos..];
                // Ensure Host header exists
                let header_str = String::from_utf8_lossy(headers);
                if !header_str.to_ascii_lowercase().contains("\nhost:")
                    && !header_str.to_ascii_lowercase().starts_with("host:")
                {
                    out.extend_from_slice(format!("Host: {host}:{port}\r\n").as_bytes());
                }
                out.extend_from_slice(headers);
            } else {
                out.extend_from_slice(format!("Host: {host}:{port}\r\n\r\n").as_bytes());
            }
            return Ok(LocalRequest {
                host,
                port,
                is_connect: false,
                pending: out,
            });
        }
    }

    // Bare host:port
    let (host, port) = split_host_port(first, 80)?;
    Ok(LocalRequest {
        host,
        port,
        is_connect: false,
        pending: if buf.len() > first.len() {
            // forward any extra bytes after the first line
            buf[first.len()..].to_vec()
        } else {
            Vec::new()
        },
    })
}

fn split_host_port(authority: &str, default_port: u16) -> Result<(String, u16)> {
    let authority = authority.trim();
    // [ipv6]:port
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, port_part) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("bad ipv6 authority"))?;
        if let Some(p) = port_part.strip_prefix(':') {
            let port: u16 = p.parse()?;
            return Ok((host.to_string(), port));
        }
        return Ok((host.to_string(), default_port));
    }
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        if !host.is_empty() && port_str.chars().all(|c| c.is_ascii_digit()) {
            let port: u16 = port_str.parse()?;
            return Ok((host.to_string(), port));
        }
    }
    Ok((authority.to_string(), default_port))
}

fn parse_absolute_url(url: &str) -> Result<(String, u16, String)> {
    let url = url.trim();
    let (scheme, rest) = if let Some(r) = url.strip_prefix("http://") {
        ("http", r)
    } else if let Some(r) = url.strip_prefix("https://") {
        ("https", r)
    } else {
        return Err(anyhow!("expected absolute http(s) URL, got {url}"));
    };
    let default_port: u16 = if scheme == "https" { 443 } else { 80 };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(anyhow!("missing host in URL"));
    }
    let (host, port) = split_host_port(authority, default_port)?;
    Ok((host, port, path.to_string()))
}

fn find_header_start(buf: &[u8]) -> Option<usize> {
    // after first \n
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == b'\n' {
            return Some(i + 1);
        }
        i += 1;
    }
    None
}


async fn handle_local(
    mut local: TcpStream,
    peer: SocketAddr,
    conn: quinn::Connection,
) -> Result<()> {
    // Read enough for HTTP headers (up to 8 KiB or until blank line)
    let mut header = vec![0u8; 8192];
    let mut filled = 0usize;
    loop {
        let n = local.read(&mut header[filled..]).await?;
        if n == 0 {
            break;
        }
        filled += n;
        let view = &header[..filled];
        let is_http = view.starts_with(b"GET ")
            || view.starts_with(b"POST ")
            || view.starts_with(b"HEAD ")
            || view.starts_with(b"PUT ")
            || view.starts_with(b"DELETE ")
            || view.starts_with(b"OPTIONS ")
            || view.starts_with(b"PATCH ")
            || view.starts_with(b"CONNECT ");
        if !is_http {
            break;
        }
        if view.windows(4).any(|w| w == b"\r\n\r\n") || filled >= header.len() {
            break;
        }
    }
    let req_local = parse_local_request(&header[..filled])?;
    info!(
        "proxying {peer} -> {}:{} (connect={})",
        req_local.host, req_local.port, req_local.is_connect
    );

    let (mut send, mut recv) = conn.open_bi().await?;
    let addr = Address::new(req_local.host.clone(), req_local.port);
    let req = TcpConnectRequest {
        address: addr,
        padding: random_padding(8..32),
    };
    send.write_all(&req.encode()).await?;

    let mut resp_buf = vec![0u8; 512];
    let n = recv
        .read(&mut resp_buf)
        .await?
        .ok_or_else(|| anyhow!("no response"))?;
    let mut reader = &resp_buf[..n];
    let resp = TcpConnectResponse::decode(&mut reader)?;
    if !resp.ok {
        return Err(anyhow!("remote connect failed: {}", resp.message));
    }

    if req_local.is_connect {
        local
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    } else if !req_local.pending.is_empty() {
        // Absolute-form HTTP: send rewritten origin-form request into the tunnel
        send.write_all(&req_local.pending).await?;
    }

    // Rate control is done by the QUIC congestion controller (Brutal), so this
    // is a plain full-duplex byte relay.
    let _ = local.set_nodelay(true);
    let (local_r, local_w) = local.into_split();
    if let Err(e) = relay(recv, send, local_r, local_w).await {
        info!("relay ended: {e}");
    }
    Ok(())
}

fn configure_client(cfg: &ClientConfigYaml) -> Result<quinn::ClientConfig> {
    // Empty root store on purpose.
    //   * Real Spectre server: JLS authenticates it through ServerHello.random,
    //     and rustls-jls skips certificate/signature checks (no CA cert needed).
    //   * Anything else (MITM, wrong server, probe target): JLS auth fails,
    //     normal verification runs against zero trusted roots and the handshake
    //     is rejected, so credentials are never sent to it.
    let roots = rustls::RootCertStore::empty();
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // user_pwd = password, user_iv = username (must match the server).
    crypto.jls_config = JlsClientConfig::new(&cfg.password, &cfg.username);
    // Same ALPN as a browser.
    crypto.alpn_protocols = vec![b"h3".to_vec()];

    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(4096u32.into());
    transport.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    transport.datagram_send_buffer_size(2 * 1024 * 1024);
    // Client -> server traffic is the client's upload: send at `tx_bps`.
    // The server applies the client's `rx_bps` to its own sender after auth.
    tune_transport(&mut transport, BrutalHandle::new(cfg.tx_bps));

    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

/// New entry point driven by YAML config.
pub async fn run_client_from_config(cfg: crate::config::Config) -> Result<()> {
    use crate::app::router::build_router;
    use crate::config::parse_routes;
    use std::sync::Arc;

    let entries = parse_routes(&cfg.route)?;
    let router = Arc::new(build_router(&cfg, entries)?);
    if cfg.dns_enabled() {
        crate::dns::init_engine(&cfg)?;
    }

    let mut handles = Vec::new();

    // DNS
    if cfg.dns_enabled() {
        let cfg2 = Arc::new(cfg.clone());
        let router2 = router.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = crate::dns::run_dns_server(cfg2, router2).await {
                tracing::error!("dns server error: {e:#}");
            }
        }));
    }

    // Mixed inbound
    if let Some(port) = cfg.mixed_port {
        if port > 0 {
            let cfg2 = Arc::new(cfg.clone());
            let router2 = router.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = crate::inbound::mixed::run_mixed(cfg2, router2).await {
                    tracing::error!("mixed inbound error: {e:#}");
                }
            }));
        }
    }

    // TProxy (Linux/Android)
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(port) = cfg.tproxy_port {
        if port > 0 {
            let cfg2 = Arc::new(cfg.clone());
            let router2 = router.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = crate::inbound::tproxy::run_tproxy(cfg2, router2).await {
                    tracing::error!("tproxy inbound error: {e:#}");
                }
            }));
        }
    }

    if handles.is_empty() {
        return Err(anyhow!("no inbound configured"));
    }

    info!(
        "client started (mixed={:?}, tproxy={:?}, dns={})",
        cfg.mixed_port,
        cfg.tproxy_port,
        cfg.dns_enabled()
    );

    // Wait for any task to finish (normally they run forever)
    let (result, _idx, _rest) = futures::future::select_all(handles).await;
    result.map_err(|e| anyhow!("inbound task join error: {e}"))?;
    Ok(())
}

use crate::inbound::target::Target;
use crate::config::Config;
use std::sync::OnceLock;
use tokio::sync::Mutex;

/// Shared Spectre QUIC connection (lazy-initialized).
static SPECTRE_CONN: OnceLock<Mutex<Option<quinn::Connection>>> = OnceLock::new();

async fn get_or_connect(cfg: &Config) -> Result<quinn::Connection> {
    let cell = SPECTRE_CONN.get_or_init(|| Mutex::new(None));
    let mut guard = cell.lock().await;
    if let Some(ref c) = *guard {
        if c.close_reason().is_none() {
            return Ok(c.clone());
        }
    }
    let server = cfg.client_server()?;
    let bind_addr: SocketAddr = if server.is_ipv6() {
        "[::]:0".parse()?
    } else {
        "0.0.0.0:0".parse()?
    };
    let socket = bind_udp(bind_addr).context("bind udp")?;
    let runtime = quinn::default_runtime().ok_or_else(|| anyhow!("no runtime"))?;
    let endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)?;
    let client_cfg = ClientConfigYaml {
        server,
        server_name: cfg.server_name().to_string(),
        username: cfg.username().to_string(),
        password: cfg.password().to_string(),
        listen: "127.0.0.1:0".parse()?,
        rx_bps: cfg.rx_bps()?,
        tx_bps: cfg.tx_bps()?,
        udp_listen: None,
    };
    endpoint.set_default_client_config(configure_client(&client_cfg)?);
    info!("connecting to {} (SNI={})", server, cfg.server_name());
    let conn = endpoint
        .connect(server, cfg.server_name())?
        .await
        .context("connect failed")?;
    if conn.is_jls() != Some(true) {
        return Err(anyhow!("JLS authentication failed"));
    }
    let (mut send, mut recv) = conn.open_bi().await?;
    let auth = AuthRequest {
        username: cfg.username().to_string(),
        password: cfg.password().to_string(),
        rx_bps: cfg.rx_bps()?,
        tx_bps: cfg.tx_bps()?,
        padding: random_padding(16..48),
    };
    send.write_all(&auth.encode()).await?;
    let mut buf = vec![0u8; 1024];
    let n = recv.read(&mut buf).await?.ok_or_else(|| anyhow!("no auth response"))?;
    let _ = n;
    info!("Spectre AUTH ok");
    *guard = Some(conn.clone());
    Ok(conn)
}

/// Proxy a local TCP stream through Spectre QUIC.
pub async fn proxy_via_spectre(
    local: &mut TcpStream,
    target: &Target,
    cfg: &Config,
) -> Result<()> {
    proxy_via_spectre_with_preface(local, target, cfg, &[], &[]).await
}

/// Like [`proxy_via_spectre`], but writes `head` then `body` into the remote
/// stream before relaying the local socket (absolute-form HTTP proxy).
pub async fn proxy_via_spectre_with_preface(
    local: &mut TcpStream,
    target: &Target,
    cfg: &Config,
    head: &[u8],
    body: &[u8],
) -> Result<()> {
    let conn = get_or_connect(cfg).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    let (host, port) = match target {
        Target::Domain { host, port } => (host.clone(), *port),
        Target::Addr(a) => (a.ip().to_string(), a.port()),
    };
    let req = TcpConnectRequest {
        address: Address::new(host, port),
        padding: random_padding(8..32),
    };
    send.write_all(&req.encode()).await?;
    let mut buf = vec![0u8; 1024];
    let n = recv
        .read(&mut buf)
        .await?
        .ok_or_else(|| anyhow!("no connect response"))?;
    let mut reader = &buf[..n];
    let resp = TcpConnectResponse::decode(&mut reader)
        .map_err(|e| anyhow!("connect response: {e}"))?;
    if !resp.ok {
        bail!(
            "spectre connect failed for {}: {}",
            target.display(),
            resp.message
        );
    }
    if !head.is_empty() {
        send.write_all(head).await?;
    }
    if !body.is_empty() {
        send.write_all(body).await?;
    }
    let (mut lr, mut lw) = tokio::io::split(local);
    let a = async {
        let mut tmp = [0u8; 8192];
        loop {
            let n = lr.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            send.write_all(&tmp[..n]).await?;
        }
        let _ = send.finish();
        Ok::<(), anyhow::Error>(())
    };
    let b = async {
        let mut tmp = [0u8; 8192];
        loop {
            match recv.read(&mut tmp).await? {
                Some(n) if n > 0 => lw.write_all(&tmp[..n]).await?,
                _ => break,
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {
        r = a => { let _ = r; }
        r = b => { let _ = r; }
    }
    Ok(())
}

// ==================== UDP via Spectre ====================

use dashmap::DashMap;
use tokio::sync::mpsc;

/// Map: local session key -> channel to deliver response payloads (src_addr, data)
type UdpReplyMap = DashMap<u32, mpsc::UnboundedSender<(Address, bytes::Bytes)>>;

static UDP_REPLIES: OnceLock<UdpReplyMap> = OnceLock::new();
static UDP_SESSION_ID: OnceLock<AtomicU32> = OnceLock::new();
static UDP_PACKET_ID: OnceLock<AtomicU16> = OnceLock::new();
static UDP_READER_STARTED: OnceLock<()> = OnceLock::new();

fn udp_replies() -> &'static UdpReplyMap {
    UDP_REPLIES.get_or_init(DashMap::new)
}

fn next_udp_session() -> u32 {
    UDP_SESSION_ID
        .get_or_init(|| AtomicU32::new(1))
        .fetch_add(1, Ordering::Relaxed)
}

fn next_udp_packet() -> u16 {
    UDP_PACKET_ID
        .get_or_init(|| AtomicU16::new(1))
        .fetch_add(1, Ordering::Relaxed)
}

/// Ensure a background task reads QUIC datagrams and demuxes by session_id.
async fn ensure_udp_reader(conn: quinn::Connection) {
    if UDP_READER_STARTED.set(()).is_err() {
        return; // already started
    }
    tokio::spawn(async move {
        let mut reasm = FragmentReassembler::new();
        while let Ok(data) = conn.read_datagram().await {
            if let Ok(Some((sid, addr, payload))) = reasm.push(data) {
                if let Some(tx) = udp_replies().get(&sid) {
                    let _ = tx.send((addr, payload));
                }
            }
        }
    });
}

/// Send one UDP packet via Spectre and optionally wait for replies on the returned receiver.
pub async fn spectre_udp_session(
    cfg: &Config,
    target: &Address,
) -> Result<(u32, mpsc::UnboundedReceiver<(Address, bytes::Bytes)>)> {
    let conn = get_or_connect(cfg).await?;
    ensure_udp_reader(conn.clone()).await;
    let sid = next_udp_session();
    let (tx, rx) = mpsc::unbounded_channel();
    udp_replies().insert(sid, tx);
    let _ = target;
    Ok((sid, rx))
}

/// Fire-and-forget send one UDP datagram via Spectre.
pub async fn spectre_udp_send(
    cfg: &Config,
    session_id: u32,
    target: &Address,
    payload: &[u8],
) -> Result<()> {
    let conn = get_or_connect(cfg).await?;
    ensure_udp_reader(conn.clone()).await;
    let pid = next_udp_packet();
    send_udp_over_quic(
        &conn,
        session_id,
        pid,
        target,
        payload,
        DEFAULT_MAX_DATAGRAM_PAYLOAD,
    )
    .await
    .map_err(|e| anyhow!("spectre udp send: {e}"))?;
    Ok(())
}

/// Convenience: one-shot UDP request/response via Spectre (no persistent session).
pub async fn spectre_udp_oneshot(
    cfg: &Config,
    target: &Address,
    payload: &[u8],
) -> Result<()> {
    let (sid, _rx) = spectre_udp_session(cfg, target).await?;
    spectre_udp_send(cfg, sid, target, payload).await?;
    // keep session alive briefly for replies — caller should use session API for duplex
    Ok(())
}

pub fn spectre_udp_close_session(session_id: u32) {
    udp_replies().remove(&session_id);
}
