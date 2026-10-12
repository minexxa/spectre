//! Spectre client — QUIC + JLS (rustls-jls / quinn-jls).

use crate::brutal::{bind_udp, tune_transport, BrutalHandle};
use crate::relay::relay;
use crate::protocol::*;
use crate::udp::{
    fragment_udp, FragmentReassembler, DEFAULT_MAX_DATAGRAM_PAYLOAD,
};
use anyhow::{anyhow, Context, Result};
use quinn_jls as quinn;
use rustls_jls as rustls;
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

    info!("QUIC connected, Spectre AUTH");
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
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec(), b"spectre".to_vec()];
    let _ = (&cfg.password, &cfg.username);

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

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
