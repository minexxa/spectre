//! TProxy inbound (Linux + Android): TCP + UDP on one port.
//!
//! Requires CAP_NET_ADMIN (IP_TRANSPARENT). External nft/iptables rules are
//! expected to redirect traffic to `tproxy-port`.

use crate::app::router::{Outbound, Router};
use crate::app::sniffer;
use crate::app::sockopt;
use crate::config::Config;
use crate::inbound::target::Target;
use anyhow::{bail, Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, info, warn};

pub async fn run_tproxy(cfg: Arc<Config>, router: Arc<Router>) -> Result<()> {
    let port = cfg.tproxy_port.unwrap_or(0);
    if port == 0 {
        return Ok(());
    }
    let addrs = sockopt::listen_addrs(cfg.bind_address_str(), port);
    let mut handles = Vec::new();

    for addr in addrs {
        // TCP
        let router_t = router.clone();
        let cfg_t = cfg.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = run_tproxy_tcp(addr, router_t, cfg_t).await {
                warn!("tproxy tcp {addr}: {e:#}");
            }
        }));
        // UDP
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

// ---------- TCP ----------

async fn run_tproxy_tcp(bind: SocketAddr, router: Arc<Router>, cfg: Arc<Config>) -> Result<()> {
    let listener = bind_tproxy_tcp(bind)?;
    info!("tproxy TCP listening on {bind}");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("tproxy accept: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
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
    if addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
        set_ip_transparent_v6(socket.as_raw_fd())?;
        set_ip_transparent_v4(socket.as_raw_fd())?;
    } else {
        set_ip_transparent_v4(socket.as_raw_fd())?;
    }
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    let std_listener: std::net::TcpListener = socket.into();
    std_listener.set_nonblocking(true)?;
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
        .context("tproxy: cannot determine original destination")?;

    let target = Target::Addr(dest);

    // sniff (domain + optional DNS detect for route-hijack)
    let mut head = [0u8; 1024];
    let n = stream.peek(&mut head).await.unwrap_or(0);
    let want_dns = router.hijack_dns();
    let sniff = if n > 0 && (router.sniff_enabled() || want_dns) {
        sniffer::sniff_tcp_ex(&head[..n], router.sniff_enabled(), want_dns)
    } else {
        sniffer::SniffResult::default()
    };

    // DNS route-hijack
    if router.hijack_dns() && (dest.port() == 53 || sniff.dns) {
        return hijack_dns_tcp(&mut stream, router).await;
    }

    let domain = sniff.domain.clone();
    let decision = if let Some(ref d) = domain {
        router.match_domain(d)
    } else {
        router.match_ip(dest.ip())
    };
    debug!(
        "tproxy tcp {peer} -> {} ({:?} via {})",
        target.display(),
        decision.outbound,
        decision.rule
    );

    match decision.outbound {
        Outbound::Direct => {
            let remote = TcpStream::connect(dest).await?;
            let (mut lr, mut lw) = tokio::io::split(&mut stream);
            let (mut rr, mut rw) = remote.into_split();
            tokio::select! {
                r = tokio::io::copy(&mut lr, &mut rw) => { let _ = r; }
                r = tokio::io::copy(&mut rr, &mut lw) => { let _ = r; }
            }
        }
        Outbound::Proxy => {
            // Prefer sniffed domain for Spectre address
            let tgt = if let Some(d) = domain {
                Target::from_host_port(&d, dest.port())
            } else {
                target
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

// ---------- UDP ----------

async fn run_tproxy_udp(bind: SocketAddr, router: Arc<Router>, cfg: Arc<Config>) -> Result<()> {
    let sock = bind_tproxy_udp(bind)?;
    let raw = Arc::new(RawSockets::new(bind)?);
    info!("tproxy UDP listening on {bind}");
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src, dst) = match recv_tproxy_udp(&sock, &mut buf).await {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => {
                debug!("tproxy udp recv: {e}");
                continue;
            }
        };
        let data = buf[..n].to_vec();
        let router = router.clone();
        let cfg = cfg.clone();
        let raw = raw.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tproxy_udp_pkt(src, dst, &data, router, cfg, raw).await {
                debug!("tproxy udp {src}->{dst}: {e:#}");
            }
        });
    }
}

fn bind_tproxy_udp(addr: SocketAddr) -> Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    if addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
        set_ip_transparent_v6(socket.as_raw_fd())?;
        set_ip_transparent_v4(socket.as_raw_fd())?;
        set_recv_origdst_v6(socket.as_raw_fd())?;
        set_recv_origdst_v4(socket.as_raw_fd())?;
    } else {
        set_ip_transparent_v4(socket.as_raw_fd())?;
        set_recv_origdst_v4(socket.as_raw_fd())?;
    }
    socket.bind(&addr.into())?;
    let std_sock: std::net::UdpSocket = socket.into();
    Ok(UdpSocket::from_std(std_sock)?)
}

async fn recv_tproxy_udp(
    sock: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    sock.readable().await?;
    sock.try_io(tokio::io::Interest::READABLE, || {
        recvmsg_origdst(sock.as_raw_fd(), buf)
    })
}

fn recvmsg_origdst(fd: i32, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    unsafe {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut _,
            iov_len: buf.len(),
        };
        let mut cbuf = [0u8; 256];
        let mut src_storage: libc::sockaddr_storage = std::mem::zeroed();
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = &mut src_storage as *mut _ as *mut _;
        msg.msg_namelen = std::mem::size_of_val(&src_storage) as u32;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut _;
        msg.msg_controllen = cbuf.len() as _;

        let n = libc::recvmsg(fd, &mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let src = sockaddr_to_socket_addr(&src_storage, msg.msg_namelen)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad src addr"))?;

        let mut dst: Option<SocketAddr> = None;
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let hdr = &*cmsg;
            if hdr.cmsg_level == libc::SOL_IP && hdr.cmsg_type == libc::IP_RECVORIGDSTADDR {
                let data = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in;
                let a = *data;
                let ip = std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr));
                let port = u16::from_be(a.sin_port);
                dst = Some(SocketAddr::new(ip.into(), port));
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            if hdr.cmsg_level == libc::IPPROTO_IPV6 && hdr.cmsg_type == 74 /* IPV6_RECVORIGDSTADDR */ {
                let data = libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6;
                let a = *data;
                let ip = std::net::Ipv6Addr::from(a.sin6_addr.s6_addr);
                let port = u16::from_be(a.sin6_port);
                dst = Some(SocketAddr::new(ip.into(), port));
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
        let dst = dst.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing ORIGDSTADDR")
        })?;
        Ok((n as usize, src, dst))
    }
}


async fn handle_tproxy_udp_pkt(
    src: SocketAddr,
    dst: SocketAddr,
    data: &[u8],
    router: Arc<Router>,
    cfg: Arc<Config>,
    raw: Arc<RawSockets>,
) -> Result<()> {
    let want_dns = router.hijack_dns();
    let sniff = if router.sniff_enabled() || want_dns {
        sniffer::sniff_udp_ex(data, router.sniff_enabled(), want_dns)
    } else {
        sniffer::SniffResult::default()
    };
    if router.hijack_dns() && (dst.port() == 53 || sniff.dns) {
        match crate::dns::answer_query(data, &router).await {
            Ok(resp) => {
                if let Err(e) = sendto_with_src(&raw, &resp, src, dst) {
                    debug!("hijack dns reply: {e}");
                }
            }
            Err(e) => debug!("hijack dns query: {e:#}"),
        }
        return Ok(());
    }
    let decision = if let Some(ref d) = sniff.domain {
        router.match_domain(d)
    } else {
        router.match_ip(dst.ip())
    };
    debug!(
        "tproxy udp {src} -> {dst} ({:?} via {})",
        decision.outbound, decision.rule
    );
    match decision.outbound {
        Outbound::Direct => {
            let bind = if dst.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
            let sock = UdpSocket::bind(bind).await?;
            sock.send_to(data, dst).await?;
            let mut rbuf = vec![0u8; 65535];
            if let Ok(Ok((n, _from))) = tokio::time::timeout(
                Duration::from_secs(5),
                sock.recv_from(&mut rbuf),
            )
            .await
            {
                // Reply to original client with original dst as source
                sendto_with_src(&raw, &rbuf[..n], src, dst)?;
            }
        }
        Outbound::Proxy => {
            use crate::protocol::Address;
            let addr = if let Some(ref d) = sniff.domain {
                Address::new(d.clone(), dst.port())
            } else {
                Address::new(dst.ip().to_string(), dst.port())
            };
            let (sid, mut rx) = crate::client::spectre_udp_session(&cfg, &addr).await?;
            crate::client::spectre_udp_send(&cfg, sid, &addr, data).await?;
            // collect a few replies
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while let Ok(Some((_src_addr, payload))) =
                tokio::time::timeout_at(deadline, rx.recv()).await
            {
                let _ = sendto_with_src(&raw, &payload, src, dst);
            }
            crate::client::spectre_udp_close_session(sid);
        }
    }
    Ok(())
}

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
        // IPV6_HDRINCL = 36
        unsafe {
            let opt: libc::c_int = 1;
            let _ = libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                36,
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
                .map_err(|e| anyhow::anyhow!("build udp v4: {e}"))?;
            sendto_raw(socket, &packet, dst)
        }
        (SocketAddr::V6(s), SocketAddr::V6(d)) => {
            let builder = PacketBuilder::ipv6(s.ip().octets(), d.ip().octets(), 64)
                .udp(s.port(), d.port());
            let mut packet = Vec::with_capacity(builder.size(buf.len()));
            builder
                .write(&mut packet, buf)
                .map_err(|e| anyhow::anyhow!("build udp v6: {e}"))?;
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

// ---------- helpers ----------

fn sockaddr_to_socket_addr(ss: &libc::sockaddr_storage, len: u32) -> Option<SocketAddr> {
    unsafe {
        match ss.ss_family as i32 {
            libc::AF_INET if len as usize >= std::mem::size_of::<libc::sockaddr_in>() => {
                let a = &*(ss as *const _ as *const libc::sockaddr_in);
                let ip = std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr));
                let port = u16::from_be(a.sin_port);
                Some(SocketAddr::new(ip.into(), port))
            }
            libc::AF_INET6 if len as usize >= std::mem::size_of::<libc::sockaddr_in6>() => {
                let a = &*(ss as *const _ as *const libc::sockaddr_in6);
                let ip = std::net::Ipv6Addr::from(a.sin6_addr.s6_addr);
                let port = u16::from_be(a.sin6_port);
                Some(SocketAddr::new(ip.into(), port))
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
            libc::SOL_IP,
            libc::IP_TRANSPARENT,
            &opt as *const _ as *const libc::c_void,
            std::mem::size_of_val(&opt) as libc::socklen_t,
        );
        if ret != 0 {
            warn!(
                "IP_TRANSPARENT failed (need CAP_NET_ADMIN): {}",
                io::Error::last_os_error()
            );
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
            warn!("IPV6_TRANSPARENT failed: {}", io::Error::last_os_error());
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
            warn!("IP_RECVORIGDSTADDR failed: {}", io::Error::last_os_error());
        }
    }
    Ok(())
}

fn set_recv_origdst_v6(fd: i32) -> Result<()> {
    unsafe {
        let opt: libc::c_int = 1;
        // IPV6_RECVORIGDSTADDR = 74 on Linux
        const IPV6_RECVORIGDSTADDR: libc::c_int = 74;
        let ret = libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            IPV6_RECVORIGDSTADDR,
            &opt as *const _ as *const libc::c_void,
            std::mem::size_of_val(&opt) as libc::socklen_t,
        );
        if ret != 0 {
            warn!("IPV6_RECVORIGDSTADDR failed: {}", io::Error::last_os_error());
        }
    }
    Ok(())
}

fn original_dst_tcp_v4(fd: i32) -> Option<SocketAddr> {
    unsafe {
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of_val(&addr) as libc::socklen_t;
        let ret = libc::getsockopt(
            fd,
            libc::SOL_IP,
            80 /* SO_ORIGINAL_DST */,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if ret != 0 {
            return None;
        }
        let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);
        Some(SocketAddr::new(ip.into(), port))
    }
}

fn original_dst_tcp_v6(fd: i32) -> Option<SocketAddr> {
    unsafe {
        let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
        let mut len = std::mem::size_of_val(&addr) as libc::socklen_t;
        const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;
        let ret = libc::getsockopt(
            fd,
            libc::IPPROTO_IPV6,
            IP6T_SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if ret != 0 {
            return None;
        }
        let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
        let port = u16::from_be(addr.sin6_port);
        Some(SocketAddr::new(ip.into(), port))
    }
}

