//! TProxy inbound (Linux + Android): TCP + UDP on one port.
//!
//! Requires CAP_NET_ADMIN (IP_TRANSPARENT). External nft/iptables rules are
//! expected to redirect traffic to `tproxy-port`.
//!
//! Behaviour aligned with ant: TCP peek+sniff+dns-hijack; UDP NAT sessions
//! keyed by (peer, dest) with long-lived workers and raw IP reply packets.

use crate::app::router::{Outbound, Router};
use crate::app::sniffer;
use crate::app::sockopt;
use crate::config::Config;
use crate::inbound::target::Target;
use crate::protocol::Address;
use anyhow::{bail, Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

const UDP_IDLE: Duration = Duration::from_secs(60);
const PEEK_TIMEOUT: Duration = Duration::from_millis(300);

pub async fn run_tproxy(cfg: Arc<Config>, router: Arc<Router>) -> Result<()> {
    let port = cfg.tproxy_port.unwrap_or(0);
    if port == 0 {
        return Ok(());
    }
    let addrs = sockopt::listen_addrs(cfg.bind_address_str(), port);
    let mut handles = Vec::new();

    for addr in addrs {
        let router_t = router.clone();
        let cfg_t = cfg.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = run_tproxy_tcp(addr, router_t, cfg_t).await {
                warn!("tproxy tcp {addr}: {e:#}");
            }
        }));
        let router_u = router.clone();
        let cfg_u = cfg.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = run_tproxy_udp(addr, router_u, cfg_u).await {
                warn!("tproxy udp {addr}: {e:#}");
            }
        }));
    }

    if handles.is_empty() {
        bail!("tproxy: no address");
    }
    futures::future::pending::<()>().await;
    #[allow(unreachable_code)]
    Ok(())
}

// ==================== TCP ====================

async fn run_tproxy_tcp(bind: SocketAddr, router: Arc<Router>, cfg: Arc<Config>) -> Result<()> {
    let listener = bind_tproxy_tcp(bind)?;
    info!("tproxy TCP listening on {bind}");
    loop {
        let (stream, peer) = listener.accept().await?;
        let router = router.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tproxy_tcp(stream, peer, router, cfg).await {
                debug!("tproxy tcp {peer}: {e:#}");
            }
        });
    }
}

fn bind_tproxy_tcp(addr: SocketAddr) -> Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(target_os = "solaris")))]
    socket.set_reuse_port(true).ok();
    if addr.is_ipv4() {
        set_ip_transparent_v4(socket.as_raw_fd())?;
    } else {
        set_ip_transparent_v6(socket.as_raw_fd())?;
        socket.set_only_v6(false).ok();
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    let std_listener: std::net::TcpListener = socket.into();
    Ok(TcpListener::from_std(std_listener)?)
}

async fn handle_tproxy_tcp(
    mut stream: TcpStream,
    peer: SocketAddr,
    router: Arc<Router>,
    cfg: Arc<Config>,
) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let dest = stream
        .local_addr()
        .ok()
        .filter(|a| a.port() != 0)
        .or_else(|| {
            if peer.is_ipv4() {
                original_dst_tcp_v4(stream.as_raw_fd())
            } else {
                original_dst_tcp_v6(stream.as_raw_fd())
            }
        })
        .unwrap_or(peer);
    debug!("tproxy tcp {peer} -> {dest}");

    let mut domain = None;
    let mut peek_buf = vec![0u8; 2048];
    // Peek only for protocol sniff or DNS-stream detection (port 53 is always
    // hijacked below when route-hijack is on).
    let want_peek = router.sniff_enabled() || (router.hijack_dns() && dest.port() != 53);
    if want_peek {
        if let Ok(Ok(n)) =
            tokio::time::timeout(PEEK_TIMEOUT, stream.peek(&mut peek_buf)).await
        {
            let sniffed =
                sniffer::sniff_tcp_ex(&peek_buf[..n], router.sniff_enabled(), router.hijack_dns());
            domain = sniffed.domain;
            if router.hijack_dns() && (dest.port() == 53 || sniffed.dns) {
                debug!("tproxy tcp hijack dns {peer} -> {dest}");
                return hijack_dns_tcp(&mut stream, router).await;
            }
        }
    }
    if router.hijack_dns() && dest.port() == 53 {
        debug!("tproxy tcp hijack dns {peer} -> {dest}");
        return hijack_dns_tcp(&mut stream, router).await;
    }

    let decision = if let Some(ref d) = domain {
        router.match_domain(d)
    } else {
        router.match_ip(dest.ip())
    };
    debug!(
        "tproxy tcp {peer} -> {dest} ({:?} via {})",
        decision.outbound, decision.rule
    );

    match decision.outbound {
        Outbound::Direct => {
            let real = crate::inbound::target::resolve_direct(
                &router,
                dest,
                domain.as_deref(),
            )
            .await?;
            let remote = TcpStream::connect(real).await?;
            let (mut lr, mut lw) = tokio::io::split(&mut stream);
            let (mut rr, mut rw) = remote.into_split();
            tokio::select! {
                r = tokio::io::copy(&mut lr, &mut rw) => { let _ = r; }
                r = tokio::io::copy(&mut rr, &mut lw) => { let _ = r; }
            }
        }
        Outbound::Proxy => {
            // Prefer domain (sniffed or fakeip reverse) so server resolves real host
            let host = domain.or_else(|| router.domain_for_fakeip(dest.ip()));
            let tgt = if let Some(d) = host {
                Target::from_host_port(&d, dest.port())
            } else {
                Target::Addr(dest)
            };
            crate::client::proxy_via_spectre(&mut stream, &tgt, &cfg).await?;
        }
    }
    Ok(())
}

async fn hijack_dns_tcp(stream: &mut TcpStream, router: Arc<Router>) -> Result<()> {
    loop {
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 || len > 65535 {
            bail!("bad dns tcp length {len}");
        }
        let mut query = vec![0u8; len];
        stream.read_exact(&mut query).await?;
        let resp = crate::dns::answer_query(&query, &router).await?;
        stream.write_all(&(resp.len() as u16).to_be_bytes()).await?;
        stream.write_all(&resp).await?;
    }
}

// ==================== UDP (NAT sessions, ant-style) ====================

type NatKey = (SocketAddr, SocketAddr); // (peer, dest)

async fn run_tproxy_udp(bind: SocketAddr, router: Arc<Router>, cfg: Arc<Config>) -> Result<()> {
    let sock = Arc::new(bind_tproxy_udp(bind)?);
    let raw = Arc::new(RawSockets::new(bind)?);
    let nat: Arc<Mutex<HashMap<NatKey, mpsc::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    info!("tproxy UDP listening on {bind}");

    let mut buf = vec![0u8; 65535];
    loop {
        let (n, peer, dest) = match recv_tproxy_udp(&sock, &mut buf).await {
            Ok(v) => v,
            Err(e) => {
                debug!("tproxy udp recv: {e}");
                continue;
            }
        };
        if n == 0 {
            continue;
        }
        let data = buf[..n].to_vec();
        let key = (peer, dest);

        // Fast path: existing session (try_send: never block the recv loop)
        {
            let map = nat.lock().await;
            if let Some(tx) = map.get(&key) {
                let _ = tx.try_send(data);
                continue;
            }
        }

        // New session
        let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
        {
            let mut map = nat.lock().await;
            // double-check
            if let Some(existing) = map.get(&key) {
                let _ = existing.try_send(data);
                continue;
            }
            map.insert(key, tx.clone());
        }
        let _ = tx.try_send(data);

        let raw2 = raw.clone();
        let router2 = router.clone();
        let cfg2 = cfg.clone();
        let nat2 = nat.clone();
        tokio::spawn(async move {
            if let Err(e) =
                udp_session_worker(raw2, peer, dest, rx, router2, cfg2).await
            {
                debug!("tproxy udp session {peer} -> {dest}: {e:#}");
            }
            nat2.lock().await.remove(&(peer, dest));
        });
    }
}

async fn udp_session_worker(
    raw: Arc<RawSockets>,
    peer: SocketAddr,
    dest: SocketAddr,
    mut rx: mpsc::Receiver<Vec<u8>>,
    router: Arc<Router>,
    cfg: Arc<Config>,
) -> Result<()> {
    let first = match rx.recv().await {
        Some(d) => d,
        None => return Ok(()),
    };

    let sniffed = sniffer::sniff_udp_ex(&first, router.sniff_enabled(), router.hijack_dns());
    if router.hijack_dns() && (dest.port() == 53 || sniffed.dns) {
        debug!("tproxy udp hijack dns {peer} -> {dest}");
        return hijack_dns_udp(raw, peer, dest, first, rx, router).await;
    }

    let domain = sniffed.domain;
    let decision = if let Some(ref d) = domain {
        router.match_domain(d)
    } else {
        router.match_ip(dest.ip())
    };
    debug!(
        "tproxy udp {peer} -> {dest} ({:?} via {})",
        decision.outbound, decision.rule
    );

    match decision.outbound {
        Outbound::Direct => {
            let real = crate::inbound::target::resolve_direct(
                &router,
                dest,
                domain.as_deref(),
            )
            .await
            .unwrap_or(dest);
            udp_direct_session(raw, peer, dest, real, first, rx).await
        }
        Outbound::Proxy => {
            let host = domain
                .clone()
                .or_else(|| router.domain_for_fakeip(dest.ip()));
            let addr = if let Some(d) = host {
                Address::new(d, dest.port())
            } else {
                Address::new(dest.ip().to_string(), dest.port())
            };
            udp_proxy_session(raw, peer, dest, first, rx, cfg, addr).await
        }
    }
}

async fn hijack_dns_udp(
    raw: Arc<RawSockets>,
    peer: SocketAddr,
    dest: SocketAddr,
    first: Vec<u8>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    router: Arc<Router>,
) -> Result<()> {
    let mut queries = vec![first];
    while let Ok(Some(q)) = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await {
        queries.push(q);
    }
    for query in queries {
        match crate::dns::answer_query(&query, &router).await {
            Ok(resp) => {
                if let Err(e) = sendto_with_src(&raw, &resp, peer, dest) {
                    debug!("hijack dns reply: {e}");
                }
            }
            Err(e) => debug!("hijack dns query: {e:#}"),
        }
    }
    // drain remaining briefly
    while let Ok(Some(q)) = tokio::time::timeout(Duration::from_millis(20), rx.recv()).await {
        if let Ok(resp) = crate::dns::answer_query(&q, &router).await {
            let _ = sendto_with_src(&raw, &resp, peer, dest);
        }
    }
    Ok(())
}

async fn udp_direct_session(
    raw: Arc<RawSockets>,
    peer: SocketAddr,
    dest: SocketAddr, // original dest for source-spoofed replies
    real: SocketAddr, // real dial addr after fake-ip reverse resolve
    first: Vec<u8>,
    mut rx: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let bind = if real.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.send_to(&first, real).await?;

    let mut rbuf = vec![0u8; 65535];
    let mut deadline = tokio::time::Instant::now() + UDP_IDLE;
    loop {
        tokio::select! {
            pkt = rx.recv() => {
                match pkt {
                    Some(d) => {
                        if let Err(e) = sock.send_to(&d, real).await {
                            debug!("tproxy udp direct send: {e}");
                            break;
                        }
                        deadline = tokio::time::Instant::now() + UDP_IDLE;
                    }
                    None => break,
                }
            }
            r = sock.recv_from(&mut rbuf) => {
                match r {
                    Ok((n, _from)) => {
                        // Reply to client; spoof source as original dest
                        if let Err(e) = sendto_with_src(&raw, &rbuf[..n], peer, dest) {
                            debug!("tproxy udp direct reply: {e}");
                        }
                        deadline = tokio::time::Instant::now() + UDP_IDLE;
                    }
                    Err(e) => {
                        debug!("tproxy udp direct recv: {e}");
                        break;
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                break;
            }
        }
    }
    Ok(())
}

async fn udp_proxy_session(
    raw: Arc<RawSockets>,
    peer: SocketAddr,
    dest: SocketAddr,
    first: Vec<u8>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    cfg: Arc<Config>,
    addr: Address,
) -> Result<()> {
    let (sid, mut reply_rx) = crate::client::spectre_udp_session(&cfg, &addr).await?;
    if let Err(e) = crate::client::spectre_udp_send(&cfg, sid, &addr, &first).await {
        debug!("tproxy udp proxy first: {e:#}");
        crate::client::spectre_udp_close_session(sid);
        return Ok(());
    }

    let mut deadline = tokio::time::Instant::now() + UDP_IDLE;
    loop {
        tokio::select! {
            pkt = rx.recv() => {
                match pkt {
                    Some(d) => {
                        if let Err(e) =
                            crate::client::spectre_udp_send(&cfg, sid, &addr, &d).await
                        {
                            debug!("tproxy udp proxy send: {e:#}");
                            break;
                        }
                        deadline = tokio::time::Instant::now() + UDP_IDLE;
                    }
                    None => break,
                }
            }
            r = reply_rx.recv() => {
                match r {
                    Some((_src_addr, payload)) => {
                        if let Err(e) = sendto_with_src(&raw, &payload, peer, dest) {
                            debug!("tproxy udp proxy reply: {e}");
                        }
                        deadline = tokio::time::Instant::now() + UDP_IDLE;
                    }
                    None => break,
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                break;
            }
        }
    }
    crate::client::spectre_udp_close_session(sid);
    Ok(())
}

fn bind_tproxy_udp(addr: SocketAddr) -> Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(target_os = "solaris")))]
    socket.set_reuse_port(true).ok();
    if addr.is_ipv4() {
        set_ip_transparent_v4(socket.as_raw_fd())?;
        set_recv_origdst_v4(socket.as_raw_fd())?;
    } else {
        set_ip_transparent_v6(socket.as_raw_fd())?;
        set_recv_origdst_v6(socket.as_raw_fd())?;
        socket.set_only_v6(false).ok();
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    let std_sock: std::net::UdpSocket = socket.into();
    Ok(UdpSocket::from_std(std_sock)?)
}

async fn recv_tproxy_udp(
    sock: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    // Must use try_io so a WouldBlock clears the readiness interest; otherwise
    // readable().await returns immediately forever and spins one core. (same as ant)
    use tokio::io::Interest;
    loop {
        let ready = sock.ready(Interest::READABLE).await?;
        if !ready.is_readable() {
            continue;
        }
        match sock.try_io(Interest::READABLE, || recvmsg_origdst(sock.as_raw_fd(), buf)) {
            Ok(v) => return Ok(v),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

fn recvmsg_origdst(fd: i32, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    unsafe {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut cmsg_buf = [0u8; 256];
        let mut src_storage: libc::sockaddr_storage = std::mem::zeroed();
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = &mut src_storage as *mut _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of_val(&src_storage) as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_buf.len() as _;

        let n = libc::recvmsg(fd, &mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let src = sockaddr_to_socket_addr(&src_storage, msg.msg_namelen)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad src addr"))?;

        let mut orig_dst: Option<SocketAddr> = None;
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let hdr = &*cmsg;
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                if hdr.cmsg_level == libc::SOL_IP && hdr.cmsg_type == libc::IP_ORIGDSTADDR {
                    let data = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in;
                    let sa = *data;
                    orig_dst = Some(SocketAddr::from(std::net::SocketAddrV4::new(
                        std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)),
                        u16::from_be(sa.sin_port),
                    )));
                }
                if hdr.cmsg_level == libc::SOL_IPV6 && hdr.cmsg_type == libc::IPV6_ORIGDSTADDR {
                    let data = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6;
                    let sa = *data;
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&sa.sin6_addr.s6_addr);
                    orig_dst = Some(SocketAddr::from(std::net::SocketAddrV6::new(
                        std::net::Ipv6Addr::from(octets),
                        u16::from_be(sa.sin6_port),
                        sa.sin6_flowinfo,
                        sa.sin6_scope_id,
                    )));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
        let dst = orig_dst.unwrap_or(src);
        Ok((n as usize, src, dst))
    }
}

// ==================== raw sockets for UDP reply ====================

struct RawSockets {
    v4: Option<Socket>,
    v6: Option<Socket>,
}

impl RawSockets {
    fn new(bind: SocketAddr) -> Result<Self> {
        if bind.is_ipv4() {
            return Ok(Self {
                v4: Some(new_raw_socket(false)?),
                v6: None,
            });
        }
        let v6 = new_raw_socket(true)?;
        let v4 = new_raw_socket(false).ok();
        Ok(Self {
            v4,
            v6: Some(v6),
        })
    }
}

fn new_raw_socket(v6: bool) -> Result<Socket> {
    let domain = if v6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::RAW, Some(Protocol::from(libc::IPPROTO_RAW)))?;
    socket.set_nonblocking(true)?;
    if v6 {
        unsafe {
            let opt: libc::c_int = 1;
            let _ = libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                36, // IPV6_HDRINCL
                &opt as *const _ as *const libc::c_void,
                std::mem::size_of_val(&opt) as libc::socklen_t,
            );
        }
        set_ip_transparent_v6(socket.as_raw_fd()).ok();
    } else {
        unsafe {
            let opt: libc::c_int = 1;
            let _ = libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &opt as *const _ as *const libc::c_void,
                std::mem::size_of_val(&opt) as libc::socklen_t,
            );
        }
        set_ip_transparent_v4(socket.as_raw_fd()).ok();
    }
    Ok(socket)
}

/// Send UDP payload to `dst` with IP/UDP source spoofed as `src`.
/// (ant naming: sendto_with_src(raw, buf, dst, src))
fn sendto_with_src(raw: &RawSockets, buf: &[u8], dst: SocketAddr, src: SocketAddr) -> Result<()> {
    use etherparse::PacketBuilder;
    let socket = match dst {
        SocketAddr::V4(_) => raw.v4.as_ref(),
        SocketAddr::V6(_) => raw.v6.as_ref(),
    }
    .context("no raw socket for this address family")?;
    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => {
            let builder = PacketBuilder::ipv4(s.ip().octets(), d.ip().octets(), 64)
                .udp(s.port(), d.port());
            let mut packet = Vec::with_capacity(builder.size(buf.len()));
            builder
                .write(&mut packet, buf)
                .map_err(|e| anyhow::anyhow!("build udp v4 packet: {e}"))?;
            sendto_raw(socket, &packet, dst)
        }
        (SocketAddr::V6(s), SocketAddr::V6(d)) => {
            let builder = PacketBuilder::ipv6(s.ip().octets(), d.ip().octets(), 64)
                .udp(s.port(), d.port());
            let mut packet = Vec::with_capacity(builder.size(buf.len()));
            builder
                .write(&mut packet, buf)
                .map_err(|e| anyhow::anyhow!("build udp v6 packet: {e}"))?;
            sendto_raw(socket, &packet, dst)
        }
        _ => bail!("tproxy udp family mismatch src={src} dst={dst}"),
    }
}

fn sendto_raw(socket: &Socket, packet: &[u8], dst: SocketAddr) -> Result<()> {
    let dst_sa = socket2::SockAddr::from(dst);
    let ret = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            dst_sa.as_ptr() as *const libc::sockaddr,
            dst_sa.len(),
        )
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::WouldBlock {
            return Err(err.into());
        }
    }
    Ok(())
}

fn sockaddr_to_socket_addr(ss: &libc::sockaddr_storage, len: u32) -> Option<SocketAddr> {
    unsafe {
        match ss.ss_family as i32 {
            libc::AF_INET if len as usize >= std::mem::size_of::<libc::sockaddr_in>() => {
                let sa = &*(ss as *const _ as *const libc::sockaddr_in);
                Some(SocketAddr::from(std::net::SocketAddrV4::new(
                    std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)),
                    u16::from_be(sa.sin_port),
                )))
            }
            libc::AF_INET6 if len as usize >= std::mem::size_of::<libc::sockaddr_in6>() => {
                let sa = &*(ss as *const _ as *const libc::sockaddr_in6);
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&sa.sin6_addr.s6_addr);
                Some(SocketAddr::from(std::net::SocketAddrV6::new(
                    std::net::Ipv6Addr::from(octets),
                    u16::from_be(sa.sin6_port),
                    sa.sin6_flowinfo,
                    sa.sin6_scope_id,
                )))
            }
            _ => None,
        }
    }
}

fn set_ip_transparent_v4(fd: i32) -> Result<()> {
    unsafe {
        let opt: libc::c_int = 1;
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_TRANSPARENT,
            &opt as *const _ as *const libc::c_void,
            std::mem::size_of_val(&opt) as libc::socklen_t,
        );
        if ret != 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    Ok(())
}

fn set_ip_transparent_v6(fd: i32) -> Result<()> {
    unsafe {
        let opt: libc::c_int = 1;
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_TRANSPARENT,
            &opt as *const _ as *const libc::c_void,
            std::mem::size_of_val(&opt) as libc::socklen_t,
        );
        if ret != 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    Ok(())
}

fn set_recv_origdst_v4(fd: i32) -> Result<()> {
    unsafe {
        let opt: libc::c_int = 1;
        let ret = libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::IP_RECVORIGDSTADDR,
            &opt as *const _ as *const libc::c_void,
            std::mem::size_of_val(&opt) as libc::socklen_t,
        );
        if ret != 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    Ok(())
}

fn set_recv_origdst_v6(fd: i32) -> Result<()> {
    unsafe {
        let opt: libc::c_int = 1;
        let ret = libc::setsockopt(
            fd,
            libc::SOL_IPV6,
            libc::IPV6_RECVORIGDSTADDR,
            &opt as *const _ as *const libc::c_void,
            std::mem::size_of_val(&opt) as libc::socklen_t,
        );
        if ret != 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    Ok(())
}

fn original_dst_tcp_v4(fd: i32) -> Option<SocketAddr> {
    unsafe {
        let mut sa: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of_val(&sa) as libc::socklen_t;
        let ret = libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut sa as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if ret != 0 {
            return None;
        }
        Some(SocketAddr::from(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)),
            u16::from_be(sa.sin_port),
        )))
    }
}

fn original_dst_tcp_v6(fd: i32) -> Option<SocketAddr> {
    unsafe {
        let mut sa: libc::sockaddr_in6 = std::mem::zeroed();
        let mut len = std::mem::size_of_val(&sa) as libc::socklen_t;
        // IP6T_SO_ORIGINAL_DST = 80
        let ret = libc::getsockopt(
            fd,
            libc::SOL_IPV6,
            80,
            &mut sa as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if ret != 0 {
            return None;
        }
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&sa.sin6_addr.s6_addr);
        Some(SocketAddr::from(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::from(octets),
            u16::from_be(sa.sin6_port),
            sa.sin6_flowinfo,
            sa.sin6_scope_id,
        )))
    }
}
