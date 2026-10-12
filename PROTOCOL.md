# Spectre Protocol Specification v0.1

**Spectre** is a new QUIC-based proxy protocol designed for high censorship resistance and strong performance on lossy networks.

## Design Goals

- **Anti-active probing**: Unauthenticated connections must be indistinguishable from connections to a legitimate website (JLS-style fallback).
- **No certificate required** (target): Prefer JLS authentication that does not rely on server certificates for legitimate clients.
- **Brutal-style congestion control**: Client declares target upload/download bandwidth; the sender keeps pushing near that rate even under loss.
- **UDP via QUIC Datagram + fragmentation**.
- Completely new wire format — **not compatible** with Hysteria2, ShadowQUIC, TUIC, or any existing client.

## Layers

```
Application Proxy (TCP streams / UDP sessions)
Spectre Framing Layer (commands, addresses, padding)
QUIC (streams + datagrams) + JLS / TLS 1.3 (camouflage)
UDP
```

## Authentication & Camouflage (JLS-style)

1. Client and server share a pre-shared secret (password / username:password).
2. Authentication material is embedded inside the TLS ClientHello / ServerHello (via JLS).
3. If authentication succeeds → the QUIC connection becomes a Spectre proxy session.
4. If authentication fails (or is absent) → the server transparently forwards the flow to a configured upstream camouflage target. Active probers only see a normal website response.

Current implementation uses a simplified control-stream auth + self-signed/ephemeral certs as a stepping stone. Full rustls-jls / quinn-jls integration is planned.

## Framing (after successful auth)

All multi-byte integers are big-endian.

### Command Types (first byte on a bidirectional stream)

| Value | Name          | Description                          |
|-------|---------------|--------------------------------------|
| 0x01  | TCP_CONNECT   | Open a TCP proxy connection          |
| 0x02  | UDP_ASSOCIATE | Create a UDP session (control stream)|
| 0x03  | AUTH          | Explicit auth (fallback path)        |
| 0xFF  | PADDING       | Pure padding / keep-alive            |

### TCP_CONNECT (0x01)

```
[u8]     cmd = 0x01
[u16]    address_len
[bytes]  address   (UTF-8 "host:port")
[u16]    padding_len
[bytes]  random_padding
```

Server responds:

```
[u8]     status   (0x00 = OK, 0x01 = error)
[u16]    msg_len
[bytes]  message
[u16]    padding_len
[bytes]  random_padding
```

After status == OK, the stream becomes a pure bidirectional byte pipe.

### UDP

UDP packets travel over QUIC unreliable datagrams.

```
[u32]    session_id
[u16]    packet_id
[u8]     fragment_id
[u8]     fragment_count
[u16]    address_len
[bytes]  address
[bytes]  payload
```

## Congestion Control — Brutal Mode

Client declares tx_bps / rx_bps during auth. Non-zero target rate → sender ignores classic loss-based backoff and maintains the rate (compensating loss by retransmission). Rate 0 → fall back to BBR/Cubic.

## Version

Spectre wire format version 0x01.
