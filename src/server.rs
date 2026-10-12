//! Spectre server — QUIC + JLS (rustls-jls / quinn-jls).

use crate::brutal::{BrutalConfig, BrutalPacer};
use crate::protocol::*;
use crate::udp::{
    fragment_udp, get_or_create_session, gc_sessions, new_session_table, resolve_address,
    FragmentReassembler, SessionTable, DEFAULT_MAX_DATAGRAM_PAYLOAD,
};
use anyhow::{anyhow, Context, Result};
use bytes::{Bytes, BytesMut};
use quinn_jls as quinn;
use rustls_jls as rustls;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

pub struct ServerConfigYaml {
    pub listen: SocketAddr,
    pub password: String,
    pub username: Option<String>,
    pub upstream: Option<String>,
    pub server_name: Option<String>,
}

pub async fn run_server(cfg: ServerConfigYaml) -> Result<()> {
    let username = cfg.username.clone().unwrap_or_else(|| "spectre".into());
    let password = cfg.password.clone();
    let upstream = cfg
        .upstream
        .clone()
        .unwrap_or_else(|| "www.cloudflare.com:443".into());
    let server_name = cfg
        .server_name
        .clone()
        .unwrap_or_else(|| "www.cloudflare.com".into());

    let (cert, key) = generate_self_signed_cert(&server_name)?;
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .context("failed to build tls ServerConfig")?;
    server_crypto.alpn_protocols = vec![b"h3".to_vec(), b"spectre".to_vec()];

    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(4096u32.into());
    transport.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    transport.datagram_send_buffer_size(2 * 1024 * 1024);

    let quic_server_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
        .context("QuicServerConfig")?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_crypto));
    server_config.transport_config(Arc::new(transport));

    let endpoint = quinn::Endpoint::server(server_config, cfg.listen)?;
    info!(
        "Spectre server (JLS) listening on {}  sni={} upstream={}",
        cfg.listen, server_name, upstream
    );

    let password = Arc::new(password);
    let username = Arc::new(username);

    while let Some(connecting) = endpoint.accept().await {
        let password = Arc::clone(&password);
        let username = Arc::clone(&username);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(connecting, password, username).await {
                error!("connection error: {e:#}");
            }
        });
    }
    Ok(())
}

async fn handle_connection(
    connecting: quinn::Incoming,
    password: Arc<String>,
    username: Arc<String>,
) -> Result<()> {
    let conn = connecting.await.context("handshake failed")?;
    let remote = conn.remote_address();
    info!("new connection from {remote}");

    let (mut send, mut recv) = conn.accept_bi().await.context("accept auth stream")?;
    let mut tmp = [0u8; 2048];
    let n = recv
        .read(&mut tmp)
        .await?
        .ok_or_else(|| anyhow!("auth stream closed"))?;
    let buf = BytesMut::from(&tmp[..n]);
    if buf.is_empty() {
        return Err(anyhow!("empty auth"));
    }
    let cmd = Command::try_from(buf[0])?;
    if cmd != Command::Auth {
        warn!("expected AUTH, got {cmd:?} from {remote}");
        let resp = AuthResponse::err("auth required");
        send.write_all(&resp.encode()).await?;
        let _ = send.finish();
        return Ok(());
    }

    let mut reader = &buf[1..];
    let auth_req = AuthRequest::decode(&mut reader)?;
    let user_ok = username.is_empty() || secure_eq(&auth_req.username, &username);
    let pass_ok = secure_eq(&auth_req.password, &password);
    if !(user_ok && pass_ok) {
        warn!("auth failed from {remote}");
        let resp = AuthResponse::err("invalid credentials");
        send.write_all(&resp.encode()).await?;
        let _ = send.finish();
        return Ok(());
    }

    info!(
        "auth ok from {remote}, client rx={} tx={}",
        auth_req.rx_bps, auth_req.tx_bps
    );
    // Echo rates: server tx toward client ≈ client rx, and vice versa
    let resp = AuthResponse::ok(auth_req.rx_bps, auth_req.tx_bps);
    send.write_all(&resp.encode()).await?;
    let _ = send.finish();

    let rates = Arc::new(ConnectionRates {
        // server -> client (download for client)
        to_client_bps: auth_req.rx_bps,
        // client -> server (upload for client)
        from_client_bps: auth_req.tx_bps,
    });

    let sessions = new_session_table();
    let packet_id = Arc::new(AtomicU16::new(1));
    let mut reasm = FragmentReassembler::new();

    // Periodic session GC
    let sessions_gc = Arc::clone(&sessions);
    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            gc_sessions(&sessions_gc);
        }
    });

    loop {
        tokio::select! {
            bi = conn.accept_bi() => {
                match bi {
                    Ok((s, r)) => {
                        let rates = Arc::clone(&rates);
                        tokio::spawn(async move {
                            if let Err(e) = handle_proxy_stream(s, r, rates).await {
                                warn!("proxy stream error: {e:#}");
                            }
                        });
                    }
                    Err(e) => {
                        info!("connection closed: {e}");
                        break;
                    }
                }
            }
            dgram = conn.read_datagram() => {
                match dgram {
                    Ok(data) => {
                        if let Err(e) = handle_udp_datagram(
                            &conn,
                            data,
                            &mut reasm,
                            &sessions,
                            &packet_id,
                        ).await {
                            warn!("udp datagram error: {e:#}");
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
    Ok(())
}

struct ConnectionRates {
    to_client_bps: u64,
    from_client_bps: u64,
}

async fn handle_proxy_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    rates: Arc<ConnectionRates>,
) -> Result<()> {
        let mut header = [0u8; 1];
    if recv.read_exact(&mut header).await.is_err() {
        return Ok(());
    }
    let cmd = Command::try_from(header[0])?;

    match cmd {
        Command::TcpConnect => {
            let mut rest = vec![0u8; 1024];
            let n = match recv.read(&mut rest).await? {
                Some(n) => n,
                None => 0,
            };
            let mut buf = BytesMut::from(&rest[..n]);
            let req = TcpConnectRequest::decode(&mut buf)?;
            info!("TCP CONNECT {}", req.address.to_socket_addr_string());

            match TcpStream::connect(req.address.to_socket_addr_string()).await {
                Ok(tcp) => {
                    let resp = TcpConnectResponse::ok();
                    send.write_all(&resp.encode()).await?;

                    let (mut tcp_r, mut tcp_w) = tcp.into_split();
                    let mut pacer_up = if rates.from_client_bps > 0 {
                        Some(BrutalPacer::new(BrutalConfig::from_bps(rates.from_client_bps)))
                    } else {
                        None
                    };
                    let mut pacer_down = if rates.to_client_bps > 0 {
                        Some(BrutalPacer::new(BrutalConfig::from_bps(rates.to_client_bps)))
                    } else {
                        None
                    };

                    let up = async {
                        let mut buf = vec![0u8; 32 * 1024];
                        loop {
                            // quinn RecvStream::read -> Result<Option<usize>>
                            let n = match recv.read(&mut buf).await? {
                                Some(n) if n > 0 => n,
                                _ => break,
                            };
                            if let Some(ref mut p) = pacer_up {
                                p.write_all_paced(&mut tcp_w, &buf[..n]).await?;
                            } else {
                                                                tcp_w.write_all(&buf[..n]).await?;
                            }
                        }
                        Ok::<(), std::io::Error>(())
                    };
                    let down = async {
                                                let mut buf = vec![0u8; 32 * 1024];
                        loop {
                            let n = tcp_r.read(&mut buf).await?;
                            if n == 0 {
                                break;
                            }
                            if let Some(ref mut p) = pacer_down {
                                p.write_all_paced(&mut send, &buf[..n]).await?;
                            } else {
                                                                send.write_all(&buf[..n]).await?;
                            }
                        }
                        Ok::<(), std::io::Error>(())
                    };
                    tokio::select! {
                        r = up => { let _ = r; }
                        r = down => { let _ = r; }
                    }
                }
                Err(e) => {
                    let resp = TcpConnectResponse::err(format!("connect failed: {e}"));
                    send.write_all(&resp.encode()).await?;
                    let _ = send.finish();
                }
            }
        }
        Command::UdpAssociate => {
            // Control stream reserved; actual data uses datagrams.
            info!("UDP ASSOCIATE control stream opened");
            let resp = TcpConnectResponse::ok(); // reuse status framing lightly
            let _ = send.write_all(&resp.encode()).await;
            // Keep stream open until client closes
            let mut sink = vec![0u8; 256];
            while let Ok(Some(n)) = recv.read(&mut sink).await {
                if n == 0 {
                    break;
                }
            }
            let _ = send.finish();
        }
        _ => {
            warn!("unsupported command {cmd:?}");
            let _ = send.finish();
        }
    }
    Ok(())
}

async fn handle_udp_datagram(
    conn: &quinn::Connection,
    data: Bytes,
    reasm: &mut FragmentReassembler,
    sessions: &SessionTable,
    packet_id: &AtomicU16,
) -> Result<()> {
    let Some((session_id, address, payload)) = reasm.push(data)? else {
        return Ok(()); // incomplete fragment
    };

    let sock = get_or_create_session(sessions, session_id).await?;
    let dest = resolve_address(&address).await?;
    sock.send_to(&payload, dest).await?;

    // Read response(s) briefly — non-blocking style with timeout
    let mut buf = vec![0u8; 65535];
    match tokio::time::timeout(Duration::from_millis(50), sock.recv_from(&mut buf)).await {
        Ok(Ok((n, from))) => {
            let resp_addr = Address::new(from.ip().to_string(), from.port());
            let pid = packet_id.fetch_add(1, Ordering::Relaxed);
            let frames = fragment_udp(
                session_id,
                pid,
                &resp_addr,
                &buf[..n],
                DEFAULT_MAX_DATAGRAM_PAYLOAD,
            );
            for frame in frames {
                let _ = conn.send_datagram(frame);
            }
        }
        _ => {}
    }

    // Spawn a long-lived reader for this session if not already
    // (simplified: poll a few more packets)
    for _ in 0..8 {
        match tokio::time::timeout(Duration::from_millis(20), sock.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => {
                let resp_addr = Address::new(from.ip().to_string(), from.port());
                let pid = packet_id.fetch_add(1, Ordering::Relaxed);
                let frames = fragment_udp(
                    session_id,
                    pid,
                    &resp_addr,
                    &buf[..n],
                    DEFAULT_MAX_DATAGRAM_PAYLOAD,
                );
                for frame in frames {
                    let _ = conn.send_datagram(frame);
                }
            }
            _ => break,
        }
    }
    Ok(())
}

fn generate_self_signed_cert(
    server_name: &str,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec![
        server_name.to_string(),
        "localhost".into(),
        "spectre.local".into(),
    ])?;
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    Ok((cert_der, key_der))
}
