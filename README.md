# Spectre

**Spectre** is a new, from-scratch QUIC-based proxy protocol designed for:

- Strong resistance to **active probing** and DPI
- **JLS-style** camouflage (no real certificate required for legitimate clients; unauthenticated traffic falls back to a real website)
- **Brutal-style** target-bandwidth congestion control (keeps pushing near the configured rate even under loss)
- UDP relay via QUIC Datagrams + fragmentation
- Written in pure **Rust**

This is **not compatible** with Hysteria2, ShadowQUIC, TUIC, or any existing client/server.

## Status (v0.1)

- [x] Protocol specification (`PROTOCOL.md`)
- [x] Wire framing (TCP Connect, Auth, UDP header)
- [x] Basic server + client (password auth over control stream)
- [x] TCP proxying over QUIC bidirectional streams
- [ ] Full JLS integration (`rustls-jls` / `quinn-jls`) — planned next
- [ ] Production Brutal controller + pacing
- [ ] Complete UDP session management & reassembly
- [ ] Upstream camouflage forwarding for probes
- [ ] SOCKS5 / HTTP CONNECT inbound on client

Current implementation uses self-signed certificates + skip-verify as a development stepping stone. The architecture is ready to swap in real JLS.

## Quick Start

```bash
# Server
cargo run --release -- server --listen 0.0.0.0:4433 --password 'your-strong-password'

# Client (local TCP proxy on 127.0.0.1:1080)
cargo run --release -- client \
  --server 1.2.3.4:4433 \
  --server-name localhost \
  --password 'your-strong-password' \
  --listen 127.0.0.1:1080
```

Client currently accepts a simple `CONNECT host:port` request (HTTP proxy style) or a bare `host:port` line.

## Protocol Overview

See [PROTOCOL.md](./PROTOCOL.md) for the full wire format.

## Roadmap

1. Integrate `quinn-jls` + `rustls-jls` for true cert-less JLS auth and probe fallback.
2. Implement a proper `Controller` that paces at the target bitrate.
3. Finish UDP association + fragment reassembly.
4. Add SOCKS5 inbound and basic ACL / multi-user support.
5. Optional Salamander-style packet obfuscation layer.

## License

MIT
