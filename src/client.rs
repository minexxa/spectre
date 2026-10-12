//! Spectre client — QUIC + JLS (rustls-jls / quinn-jls).

use crate::brutal::{BrutalConfig, BrutalPacer};
use crate::protocol::*;
use crate::udp::{
    fragment_udp, FragmentReassembler, DEFAULT_MAX_DATAGRAM_PAYLOAD,
};
use anyhow::{anyhow, Context, Result};
use bytes::{Bytes, BytesMut};
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
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
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
    let mut reader = &buf[..n];
    let resp = AuthResponse::decode(&mut reader)?;
    if !resp.ok {
        return Err(anyhow!("auth rejected: {}", resp.message));
    }
    info!(
        "auth success, negotiated rates rx={} tx={}",
        resp.rx_bps, resp.tx_bps
    );

    let rates = Arc::new((cfg.tx_bps, cfg.rx_bps)); // (upload, download)

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
        loop {
            match conn_d.read_datagram().await {
                Ok(data) => match reasm.push(data) {
                    Ok(Some((_sid, addr, payload))) => {
                        // Best-effort: log; full demux needs local UDP map
                        info!("udp response from {} len={}", addr.to_socket_addr_string(), payload.len());
                    }
                    Ok(None) => {}
                    Err(e) => warn!("client reassembly: {e}"),
                },
                Err(_) => break,
            }
        }
    });

    loop {
        let (local, peer) = listener.accept().await?;
        let conn = conn.clone();
        let rates = Arc::clone(&rates);
        tokio::spawn(async move {
            if let Err(e) = handle_local(local, peer, conn, rates).await {
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

async fn handle_local(
    mut local: TcpStream,
    peer: SocketAddr,
    conn: quinn::Connection,
    rates: Arc<(u64, u64)>,
) -> Result<()> {
    let mut header = vec![0u8; 256];
    let n = local.read(&mut header).await?;
    let header_str = String::from_utf8_lossy(&header[..n]);
    let target = if let Some(line) = header_str.lines().next() {
        if let Some(rest) = line.strip_prefix("CONNECT ") {
            rest.split_whitespace().next().unwrap_or("").to_string()
        } else {
            line.trim().to_string()
        }
    } else {
        return Err(anyhow!("empty request from {peer}"));
    };
    if target.is_empty() {
        return Err(anyhow!("no target"));
    }

    info!("proxying {peer} -> {target}");
    let (mut send, mut recv) = conn.open_bi().await?;

    let (host, port_str) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("invalid target {target}"))?;
    let port: u16 = port_str.parse()?;
    let addr = Address::new(host, port);

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

    if header_str.starts_with("CONNECT ") {
        local
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    }

    let (tx_bps, rx_bps) = *rates;
    let mut pacer_up = if tx_bps > 0 {
        Some(BrutalPacer::new(BrutalConfig::from_bps(tx_bps)))
    } else {
        None
    };
    let mut pacer_down = if rx_bps > 0 {
        Some(BrutalPacer::new(BrutalConfig::from_bps(rx_bps)))
    } else {
        None
    };

    let (mut local_r, mut local_w) = local.into_split();
    let up = async {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = local_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if let Some(ref mut p) = pacer_up {
                p.write_all_paced(&mut send, &buf[..n]).await?;
            } else {
                send.write_all(&buf[..n]).await?;
            }
        }
        Ok::<(), std::io::Error>(())
    };
    let down = async {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = recv.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if let Some(ref mut p) = pacer_down {
                p.write_all_paced(&mut local_w, &buf[..n]).await?;
            } else {
                local_w.write_all(&buf[..n]).await?;
            }
        }
        Ok::<(), std::io::Error>(())
    };
    tokio::select! {
        r = up => { let _ = r; }
        r = down => { let _ = r; }
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
    transport.datagram_send_buffer_size(Some(2 * 1024 * 1024));

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
