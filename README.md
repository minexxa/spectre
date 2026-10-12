# Spectre

**Spectre** is a new, from-scratch QUIC-based proxy protocol designed for:

- Strong resistance to **active probing** and DPI
- **JLS-style** camouflage via `rustls-jls` / `quinn-jls` (no real public CA certificate required for legitimate clients; unauthenticated traffic is intended to fall back to a real website)
- **Brutal-style** target-bandwidth congestion control
- UDP relay via QUIC Datagrams + fragmentation
- Written in pure **Rust**

**Not compatible** with Hysteria2, ShadowQUIC, TUIC, or any existing client/server.

## Dependencies (JLS)

| Crate | Role |
|-------|------|
| `quinn-jls` | QUIC transport with JLS-capable crypto layer |
| `rustls-jls` | TLS/JLS handshake, SNI camouflage hooks |

MSRV: **Rust 1.80+**

## Status (v0.1)

- [x] Protocol specification (`PROTOCOL.md`)
- [x] Wire framing (TCP Connect, Auth, UDP header)
- [x] Server + client using **quinn-jls / rustls-jls**
- [x] TCP proxying over QUIC bidirectional streams
- [x] GitHub Actions release builds (Linux gnu/musl, aarch64, Windows)
- [ ] Full `JlsServerConfig` field wiring for automatic probe → upstream TCP forward (hooks prepared)
- [ ] Production Brutal controller plugged into quinn-jls `TransportConfig`
- [ ] Complete UDP session table & fragment reassembly
- [ ] SOCKS5 inbound on client

## Quick Start

```bash
# Server
cargo run --release -- server \
  --listen 0.0.0.0:4433 \
  --password 'your-strong-password' \
  --username spectre \
  --server-name www.cloudflare.com \
  --upstream www.cloudflare.com:443

# Client
cargo run --release -- client \
  --server SERVER_IP:4433 \
  --server-name www.cloudflare.com \
  --password 'your-strong-password' \
  --username spectre \
  --listen 127.0.0.1:1080
```

Client accepts `CONNECT host:port` (HTTP proxy style) or a bare `host:port` line.

## CI

See `.github/workflows/release.yml`:

- `x86_64-unknown-linux-gnu` / `musl`
- `aarch64-unknown-linux-gnu` (cross)
- `x86_64-pc-windows-msvc`
- Tag `v*` → GitHub Release with artifacts

## License

MIT
