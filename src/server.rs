//! Spectre server — QUIC + JLS (rustls-jls / quinn-jls).

use crate::brutal::{bind_udp, tune_transport, BrutalHandle};
use crate::relay::relay;
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

    let quic_server_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
        .context("QuicServerConfig")?;
    // Base config (Brutal off). Each connection gets its own copy with its own
    // rate handle, which is set after authentication.
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_crypto));
    server_config.transport_config(make_transport(BrutalHandle::new(0)));
    let base_config = Arc::new(server_config);

    let socket = bind_udp(cfg.listen).context("bind udp socket")?;
    let runtime = quinn::default_runtime().ok_or_else(|| anyhow!("no async runtime found"))?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some((*base_config).clone()),
        socket,
        runtime,
    )?;
    info!(
        "Spectre server (JLS) listening on {}  sni={} upstream={}",
        cfg.listen, server_name, upstream
    );

    let password = Arc::new(password);
    let username = Arc::new(username);

    while let Some(incoming) = endpoint.accept().await {
        let password = Arc::clone(&password);
        let username = Arc::clone(&username);
        let base_config = Arc::clone(&base_config);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, base_config, password, username).await {
                error!("connection error: {e:#}");
            }
        });
    }
    Ok(())
}

/// Transport config shared by all connections: stream limits, datagram
/// buffers, large flow-control windows and the Brutal controller bound to
/// `handle`.
fn make_transport(handle: BrutalHandle) -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(4096u32.into());
    transport.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    transport.datagram_send_buffer_size(2 * 1024 * 1024);
    tune_transport(&mut transport, handle);
    Arc::new(transport)
}

async fn handle_connection(
    incoming: quinn::Incoming,
    base_config: Arc<quinn::ServerConfig>,
    password: Arc<String>,
    username: Arc<String>,
) -> Result<()> {
    // Per-connection config so this connection has its own Brutal rate handle.
    let rate = BrutalHandle::new(0);
    let mut conn_config = (*base_config).clone();
    conn_config.transport_config(make_transport(rate.clone()));
    let conn = incoming
        .accept_with(Arc::new(conn_config))
        .context("accept connection")?
        .await
        .context("handshake failed")?;
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

    // Server -> client traffic is the client's download: send at the client's
    // declared rx rate. 0 keeps the BBR fallback. The client's own upload rate
    // (tx) is enforced by the client's controller.
    rate.set(auth_req.rx_bps);

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
                        tokio::spawn(async move {
                            if let Err(e) = handle_proxy_stream(s, r).await {
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

async fn handle_proxy_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<()> {
    let mut header = [0u8; 1];
    if recv.read_exact(&mut header).await.is_err() {
        return Ok(());
    }
    let cmd = Command::try_from(header[0])?;

    match cmd {
        Command::TcpConnect => {
            let mut rest = vec![0u8; 1024];
            let n: usize = recv.read(&mut rest).await?.unwrap_or_default();
            let mut buf = BytesMut::from(&rest[..n]);
            let req = TcpConnectRequest::decode(&mut buf)?;
            info!("TCP CONNECT {}", req.address.to_socket_addr_string());

            match TcpStream::connect(req.address.to_socket_addr_string()).await {
                Ok(tcp) => {
                    let resp = TcpConnectResponse::ok();
                    send.write_all(&resp.encode()).await?;

                    let _ = tcp.set_nodelay(true);
                    let (tcp_r, tcp_w) = tcp.into_split();
                    // Rate control is done by the QUIC congestion controller,
                    // so this is a plain full-duplex byte relay.
                    if let Err(e) = relay(recv, send, tcp_r, tcp_w).await {
                        info!("relay ended: {e}");
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
    if let Ok(Ok((n, from))) = tokio::time::timeout(Duration::from_millis(50), sock.recv_from(&mut buf)).await {
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
