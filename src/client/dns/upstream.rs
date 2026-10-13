//! DNS upstream: udp / tcp / tls (DoT) / https (DoH).
//! Clash-rs style URL: no scheme → UDP; udp:// tcp:// tls:// https://

use anyhow::{bail, Context, Result};
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub enum DnsUpstream {
    Udp(SocketAddr),
    Tcp(SocketAddr),
    Dot {
        host: String,
        port: u16,
        /// Known address when configured as pure IP; domain configs leave this
        /// as None and resolve lazily at exchange time.
        addr: Option<SocketAddr>,
        sni: String,
    },
    Doh {
        host: String,
        port: u16,
        path: String,
        sni: String,
        addr: Option<SocketAddr>,
    },
}

impl std::fmt::Display for DnsUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Udp(a) => write!(f, "udp://{a}"),
            Self::Tcp(a) => write!(f, "tcp://{a}"),
            Self::Dot {
                host,
                port,
                addr,
                sni,
            } => match addr {
                Some(a) => write!(f, "tls://{a} (sni={sni})"),
                None => write!(f, "tls://{host}:{port} (sni={sni})"),
            },
            Self::Doh {
                host,
                port,
                path,
                sni,
                ..
            } => write!(f, "https://{host}:{port}{path} (sni={sni})"),
        }
    }
}

/// Parse nameserver string (clash-rs compatible).
/// - `1.1.1.1` / `1.1.1.1:53` → UDP
/// - `udp://1.1.1.1:53` → UDP
/// - `tcp://1.1.1.1:53` → TCP
/// - `tls://1.1.1.1:853` / `tls://cloudflare-dns.com` → DoT
/// - `https://1.1.1.1/dns-query` → DoH
pub fn parse_nameserver(s: &str) -> Result<DnsUpstream> {
    let raw = s.trim();
    if raw.is_empty() {
        bail!("empty dns nameserver");
    }

    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("udp://{raw}")
    };

    let (scheme, rest) = with_scheme
        .split_once("://")
        .context("invalid dns nameserver URL")?;
    let scheme = scheme.to_ascii_lowercase();

    match scheme.as_str() {
        "udp" => {
            let addr = parse_host_port(rest, 53)?;
            Ok(DnsUpstream::Udp(addr))
        }
        "tcp" => {
            let addr = parse_host_port(rest, 53)?;
            Ok(DnsUpstream::Tcp(addr))
        }
        "tls" => {
            let (host, port) = split_host_port(rest, 853)?;
            let sni = host.trim_matches(|c| c == '[' || c == ']').to_string();
            let addr = sni
                .parse::<std::net::IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, port));
            Ok(DnsUpstream::Dot {
                host: sni.clone(),
                port,
                addr,
                sni,
            })
        }
        "https" => {
            let (authority, path) = match rest.split_once('/') {
                Some((a, p)) => (a, format!("/{p}")),
                None => (rest, "/dns-query".to_string()),
            };
            let (host, port) = split_host_port(authority, 443)?;
            let sni = host.trim_matches(|c| c == '[' || c == ']').to_string();
            let addr = if let Ok(ip) = sni.parse::<std::net::IpAddr>() {
                Some(SocketAddr::new(ip, port))
            } else {
                None
            };
            Ok(DnsUpstream::Doh {
                host: sni.clone(),
                port,
                path,
                sni,
                addr,
            })
        }
        other => bail!("unsupported dns scheme: {other} (use udp/tcp/tls/https)"),
    }
}

fn split_host_port(s: &str, default_port: u16) -> Result<(String, u16)> {
    let s = s.trim();
    if s.starts_with('[') {
        let end = s
            .find(']')
            .context("invalid IPv6 bracket in dns address")?;
        let host = s[1..end].to_string();
        let rest = &s[end + 1..];
        if let Some(p) = rest.strip_prefix(':') {
            let port: u16 = p.parse().context("invalid dns port")?;
            Ok((host, port))
        } else {
            Ok((host, default_port))
        }
    } else if let Some((h, p)) = s.rsplit_once(':') {
        if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            let port: u16 = p.parse().context("invalid dns port")?;
            Ok((h.to_string(), port))
        } else {
            Ok((s.to_string(), default_port))
        }
    } else {
        Ok((s.to_string(), default_port))
    }
}

fn parse_host_port(s: &str, default_port: u16) -> Result<SocketAddr> {
    let (host, port) = split_host_port(s, default_port)?;
    resolve_host_port(&host, port)
}

fn resolve_host_port(host: &str, port: u16) -> Result<SocketAddr> {
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let addrs: Vec<_> = std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
        .with_context(|| format!("resolve dns host {host}"))?
        .collect();
    addrs
        .into_iter()
        .next()
        .with_context(|| format!("no address for dns host {host}"))
}

pub async fn exchange(upstream: &DnsUpstream, query: &[u8]) -> Result<Vec<u8>> {
    match upstream {
        DnsUpstream::Udp(addr) => exchange_udp(*addr, query).await,
        DnsUpstream::Tcp(addr) => exchange_tcp(*addr, query).await,
        DnsUpstream::Dot {
            host,
            port,
            addr,
            sni,
        } => {
            let a = match addr {
                Some(a) => *a,
                None => lookup_host_async(host, *port).await?,
            };
            exchange_dot(a, sni, query).await
        }
        DnsUpstream::Doh {
            host,
            port,
            path,
            sni,
            addr,
        } => {
            let a = match addr {
                Some(a) => *a,
                None => lookup_host_async(host, *port).await?,
            };
            exchange_doh(host, path, sni, a, query).await
        }
    }
}

async fn lookup_host_async(host: &str, port: u16) -> Result<SocketAddr> {
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut it = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolve dns upstream host {host}"))?;
    it.next()
        .with_context(|| format!("no address for dns upstream host {host}"))
}

async fn exchange_udp(addr: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    let bind = if addr.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(addr).await?;
    sock.send(query).await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(TIMEOUT, sock.recv(&mut buf))
        .await
        .context("dns udp timeout")??;
    Ok(buf[..n].to_vec())
}

async fn exchange_tcp(addr: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    let mut stream = tokio::time::timeout(TIMEOUT, TcpStream::connect(addr))
        .await
        .context("dns tcp connect timeout")??;
    write_tcp_msg(&mut stream, query).await?;
    read_tcp_msg(&mut stream).await
}

async fn exchange_dot(addr: SocketAddr, sni: &str, query: &[u8]) -> Result<Vec<u8>> {
    let stream = tokio::time::timeout(TIMEOUT, TcpStream::connect(addr))
        .await
        .context("dns dot connect timeout")??;
    let connector = tls_connector_dot();
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from(sni.to_string())
        .map_err(|_| anyhow::anyhow!("invalid sni for DoT: {sni}"))?;
    let mut tls = tokio::time::timeout(TIMEOUT, connector.connect(name, stream))
        .await
        .context("dns dot tls timeout")??;
    write_tcp_msg(&mut tls, query).await?;
    read_tcp_msg(&mut tls).await
}

async fn exchange_doh(
    host: &str,
    path: &str,
    sni: &str,
    addr: SocketAddr,
    query: &[u8],
) -> Result<Vec<u8>> {
    let stream = tokio::time::timeout(TIMEOUT, TcpStream::connect(addr))
        .await
        .context("dns doh connect timeout")??;
    let connector = tls_connector_doh();
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from(sni.to_string())
        .map_err(|_| anyhow::anyhow!("invalid sni for DoH: {sni}"))?;
    let mut tls = tokio::time::timeout(TIMEOUT, connector.connect(name, stream))
        .await
        .context("dns doh tls timeout")??;

    let req = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/dns-message\r\n\
         Accept: application/dns-message\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        query.len()
    );
    tls.write_all(req.as_bytes()).await?;
    tls.write_all(query).await?;
    tls.flush().await?;

    let mut buf = Vec::with_capacity(4096);
    tokio::time::timeout(TIMEOUT, async {
        let mut tmp = [0u8; 2048];
        loop {
            let n = tls.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > 64 * 1024 {
                bail!("DoH response too large");
            }
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("dns doh read timeout")??;

    parse_http_body(&buf)
}

fn parse_http_body(resp: &[u8]) -> Result<Vec<u8>> {
    let header_end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("DoH: no HTTP header end")?;
    let headers = std::str::from_utf8(&resp[..header_end]).unwrap_or("");
    let status_line = headers.lines().next().unwrap_or("");
    if !status_line.contains("200") {
        bail!("DoH HTTP status not 200: {status_line}");
    }
    let body = &resp[header_end + 4..];
    // Handle Transfer-Encoding: chunked (first chunk only).
    if headers.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        if let Some(idx) = body.iter().position(|&b| b == b'\n') {
            let size_line = std::str::from_utf8(&body[..idx]).unwrap_or("").trim();
            if let Ok(sz) = usize::from_str_radix(size_line.trim_end_matches('\r'), 16) {
                let start = idx + 1;
                if start + sz <= body.len() {
                    return Ok(body[start..start + sz].to_vec());
                }
            }
        }
    }
    Ok(body.to_vec())
}

async fn write_tcp_msg<S: AsyncWriteExt + Unpin>(stream: &mut S, query: &[u8]) -> Result<()> {
    let len = (query.len() as u16).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(query).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_tcp_msg<S: AsyncReadExt + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut len_buf))
        .await
        .context("dns tcp read len timeout")??;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 65535 {
        bail!("bad dns tcp message length {len}");
    }
    let mut buf = vec![0u8; len];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut buf))
        .await
        .context("dns tcp read body timeout")??;
    Ok(buf)
}

fn tls_connector_dot() -> TlsConnector {
    static CONNECTOR: LazyLock<TlsConnector> = LazyLock::new(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        TlsConnector::from(Arc::new(cfg))
    });
    CONNECTOR.clone()
}

fn tls_connector_doh() -> TlsConnector {
    static CONNECTOR: LazyLock<TlsConnector> = LazyLock::new(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        TlsConnector::from(Arc::new(cfg))
    });
    CONNECTOR.clone()
}
