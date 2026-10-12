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
- [x] JLS wiring: certificate-less authentication, unauthenticated QUIC traffic is forwarded to the real upstream site
- [x] Brutal congestion controller (quinn `Controller`, Hysteria2-style ack-rate compensation) plugged into `TransportConfig`
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

`--rx` is the download rate and `--tx` the upload rate. `200mbps` means bits per
second; a bare number means bytes per second; `0` (default) uses BBR instead of Brutal.
Set them to your real line speed, not higher.

```bash
spectre client ... --rx 200mbps --tx 50mbps
```

### High-speed tuning

Brutal cannot outrun the kernel's UDP buffers. Spectre requests 16 MiB socket
buffers, but Linux clamps this to `rmem_max`/`wmem_max`. Raise them on **both** ends:

```bash
sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216
```

Client accepts `CONNECT host:port` (HTTP proxy style) or a bare `host:port` line.

## Camouflage (JLS)

- `--password` / `--username` are the JLS secret (`user_pwd` / `user_iv`) and must match on both ends.
- The client's `--server-name` is the SNI it sends. It must equal the server's `--server-name`,
  and should be the host of `--upstream`, or the server treats the client as unauthenticated.
- `--upstream` must be a real site that speaks **HTTP/3 on UDP**, for example `www.cloudflare.com:443`.
  Packets from anyone who fails JLS (probers, scanners, wrong SNI) are forwarded there unchanged.
- No CA certificate is needed. The server uses a throwaway self-signed certificate that JLS clients never validate.
  The client trusts no CA at all, so anything that is not your server (including a MITM) is rejected.
- Known limit: JLS has no replay protection. A censor that replays a captured ClientHello gets a
  ServerHello from your server instead of the real site's.

## CI

See `.github/workflows/release.yml`:

- `x86_64-unknown-linux-gnu` / `musl`
- `aarch64-unknown-linux-gnu` (cross)
- `x86_64-pc-windows-msvc`
- Tag `v*` → GitHub Release with artifacts

## License

MIT
