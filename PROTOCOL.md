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

### How JLS authenticates

- Client: `ClientHello.random = AES-256-GCM(key = SHA256(pwd || CH), nonce = SHA256(iv || CH), plaintext = 16 random bytes)`.
  `CH` is the whole ClientHello with `random` zeroed (and PSK binders zeroed), so the value is bound to the SNI and key share.
  The 32-byte output is 16 bytes of ciphertext plus a 16-byte tag, which looks like ordinary random.
- Server: decrypts and checks the tag with each configured user. SNI must also equal `upstream_sni`.
- Server replies with `ServerHello.random` built the same way over the ServerHello bytes, so the client knows the server holds the secret.
- On success both sides skip certificate-chain and signature verification, which is why no CA certificate is needed.
- On failure the server never answers; the QUIC layer forwards the packets to the upstream site.
- HelloRetryRequest is illegal on a JLS connection.
- ALPN is `h3` only.

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

The client declares in AUTH:

- `tx_bps` — its upload rate (bytes/sec); the client's sender uses it.
- `rx_bps` — its download rate (bytes/sec); the server's sender uses it after AUTH succeeds.

Sender behaviour (implemented as a quinn `congestion::Controller`):

- `ack_rate = acked / (acked + lost)` over a sliding 5 x 1 s window, floored at 0.8
  and ignored until about 60 KB has been observed.
- `cwnd = rate * srtt * 1.2 / ack_rate`. quinn's pacer then paces at about
  `cwnd * 1.25 / srtt`. Loss is repaired by QUIC retransmission, and dividing by
  `ack_rate` keeps goodput near `rate`.
- Loss does not shrink the window below `rate * srtt * 1.2 / 0.8`.
- Rate 0 falls back to BBR.
- Flow-control windows are raised (16 MiB per stream, 64 MiB per connection), because
  the defaults cap throughput at about 1.2 MB per RTT regardless of congestion control.

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
