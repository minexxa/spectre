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
┌─────────────────────────────────────┐
│          Application Proxy          │  (TCP streams / UDP sessions)
├─────────────────────────────────────┤
│       Spectre Framing Layer         │  (commands, addresses, padding)
├─────────────────────────────────────┤
│   QUIC (streams + datagrams)        │
│   + JLS / TLS 1.3 (camouflage)      │
├─────────────────────────────────────┤
│              UDP                    │
└─────────────────────────────────────┘
```

## Authentication & Camouflage (JLS-style)

1. Client and server share a pre-shared secret (password / username:password).
2. Authentication material is embedded inside the TLS ClientHello / ServerHello (via JLS).
3. If authentication succeeds → the QUIC connection becomes a Spectre proxy session.
4. If authentication fails (or is absent) → the server transparently forwards the TCP/UDP flow to a configured **upstream camouflage target** (e.g. a real website). Active probers only see a normal website response.

> Current implementation uses a simplified control-stream auth + self-signed/ephemeral certs as a stepping stone. Full rustls-jls / quinn-jls integration is planned.

## Framing (after successful auth)

All multi-byte integers are **big-endian**. Variable-length integers follow QUIC varint encoding where noted.

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
[varint] address_len
[bytes]  address   (UTF-8 "host:port" or binary SOCKS-like)
[varint] padding_len
[bytes]  random_padding
```

Server responds on the same stream:

```
[u8]     status   (0x00 = OK, 0x01 = error)
[varint] msg_len
[bytes]  message  (optional error string)
[varint] padding_len
[bytes]  random_padding
```

After status == OK, the stream becomes a pure bidirectional byte pipe to the remote TCP endpoint.

### UDP

UDP packets travel over **QUIC unreliable datagrams**.

Each datagram payload:

```
[u32]    session_id
[u16]    packet_id
[u8]     fragment_id
[u8]     fragment_count   (1 = not fragmented)
[varint] address_len
[bytes]  address
[bytes]  payload
```

- `session_id` is chosen by the client and unique per UDP association.
- Large packets are fragmented; receiver reassembles by `(session_id, packet_id)`.
- Missing fragments → drop the whole packet.

A control bidirectional stream (cmd = 0x02) may be used to negotiate session lifetime / close, but is optional for the first version.

## Congestion Control — Brutal Mode

During (or right after) authentication the client may declare:

- `tx_bps` — desired upload rate (bytes/sec)
- `rx_bps` — desired download rate (bytes/sec)

Semantics (inspired by Hysteria Brutal):

- When a non-zero target rate is set, the sender **ignores classic loss-based backoff** and tries to maintain the target rate, compensating loss by retransmission.
- Rate 0 → fall back to standard BBR / Cubic.
- Server may also return its preferred rates.

Implementation note: custom `quinn::congestion::Controller` that implements a token-bucket / pacing at the target rate.

## Padding & Obfuscation

- Random padding of variable length is mandatory on control messages.
- Optional packet-level obfuscation (XOR with keyed stream) can be added later (Salamander-style).

## Security Considerations

- Password must be high-entropy.
- Replay protection is provided by the underlying QUIC / TLS handshake.
- 0-RTT is disabled by default until careful anti-replay is designed.
- Active probing resistance relies on correct upstream fallback behaviour.

## Version

This document describes Spectre wire format version 0x01.
