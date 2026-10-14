//! Optional outer-layer packet obfuscation ("Salamander"-style), ported from
//! Hysteria's `extras/obfs/salamander.go` design.
//!
//! ## Why this exists
//!
//! JLS camouflage (see `PROTOCOL.md`) makes an *active prober* that opens a
//! connection and speaks TLS see a normal website. It does nothing against a
//! *passive* observer who just watches UDP packets go by without ever
//! completing a handshake: every Spectre packet is still a QUIC Initial /
//! Handshake / 1-RTT packet with QUIC's own (public, well-known) header
//! structure, so a classifier trained on "this header layout = QUIC, and
//! this clustering of sizes/timings = probably a proxy, not a CDN-fronted
//! website" can flag it without ever touching the TLS layer.
//!
//! Salamander defeats that specific signal cheaply: every outer UDP payload
//! is XORed with a keystream derived from a pre-shared key and a random
//! per-packet salt, so what hits the wire no longer parses as QUIC at all —
//! to an observer it is undifferentiated random bytes, like WireGuard or any
//! other encrypted-datagram protocol. It is a shared-secret scheme, not
//! encryption with integrity (no AEAD tag), so it is meant to sit *outside*
//! QUIC's own crypto, purely as camouflage against structural fingerprinting
//! -- QUIC/TLS still does the real authentication and confidentiality work.
//!
//! ## Wire format
//!
//! ```text
//! [8-byte random salt][payload XORed with SHA256(psk || salt), repeated]
//! ```
//!
//! Same layout Hysteria uses, with SHA-256 in place of BLAKE2b-256 purely so
//! Spectre doesn't need a new dependency (`sha2` is already in `Cargo.toml`);
//! the security property (a keyed, salt-diversified XOR keystream obfuscating
//! the public QUIC header) is the same.
//!
//! ## Integration status
//!
//! The functions below are a complete, self-contained, testable unit — they
//! obfuscate/deobfuscate one packet buffer at a time and do not depend on
//! quinn. **They are not yet wired into the live send/receive path.** Doing
//! that means every packet quinn sends or receives has to pass through
//! [`obfuscate`]/[`deobfuscate`] transparently, which requires wrapping the
//! socket quinn drives with something implementing `quinn::AsyncUdpSocket`
//! (quinn-jls's equivalent of quinn's own `quinn::AsyncUdpSocket` trait) that
//! delegates to the real OS socket created in `bind_udp`
//! (`protocol::brutal::bind_udp`) and calls these two functions on every
//! `poll_send` / `poll_recv`. That trait's exact method surface in
//! `quinn-jls`/`quinn-proto-jls` wasn't available to check against here, so
//! rather than guess at an API and ship something that silently fails to
//! compile or, worse, compiles but mis-handles GSO/ECN metadata, this is
//! left as the next concrete step with the approach spelled out rather than
//! a half-verified socket shim.
//!
//! Config-wise this should be an **opt-in, symmetric, per-listener** setting
//! (client and server must agree on the same PSK), independent of the JLS
//! password — e.g. a new `obfs-psk` field alongside `jls-upstream` in
//! `config.rs`.

use sha2::{Digest, Sha256};

/// Minimum PSK length, same floor Hysteria enforces.
pub const MIN_PSK_LEN: usize = 4;
const SALT_LEN: usize = 8;
const KEY_LEN: usize = 32; // SHA-256 output

#[derive(Debug, thiserror::Error)]
pub enum ObfsError {
    #[error("obfuscation PSK must be at least {MIN_PSK_LEN} bytes")]
    PskTooShort,
    #[error("packet too short to contain a salt")]
    PacketTooShort,
}

fn keystream(psk: &[u8], salt: &[u8; SALT_LEN]) -> [u8; KEY_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(psk);
    hasher.update(salt);
    hasher.finalize().into()
}

/// Obfuscate one outbound packet: `[8-byte random salt][in XORed with
/// SHA256(psk || salt)]`. Returns the full wire-format buffer.
pub fn obfuscate(psk: &[u8], input: &[u8]) -> Result<Vec<u8>, ObfsError> {
    if psk.len() < MIN_PSK_LEN {
        return Err(ObfsError::PskTooShort);
    }
    use rand::RngCore;
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let key = keystream(psk, &salt);

    let mut out = Vec::with_capacity(SALT_LEN + input.len());
    out.extend_from_slice(&salt);
    out.extend(
        input
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % KEY_LEN]),
    );
    Ok(out)
}

/// Reverse [`obfuscate`]: read the salt off the front, rebuild the same
/// keystream, XOR the rest back to plaintext (the original QUIC packet).
pub fn deobfuscate(psk: &[u8], packet: &[u8]) -> Result<Vec<u8>, ObfsError> {
    if psk.len() < MIN_PSK_LEN {
        return Err(ObfsError::PskTooShort);
    }
    if packet.len() <= SALT_LEN {
        return Err(ObfsError::PacketTooShort);
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&packet[..SALT_LEN]);
    let key = keystream(psk, &salt);

    let out = packet[SALT_LEN..]
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % KEY_LEN])
        .collect();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let psk = b"correct horse battery staple";
        let msg = b"this looks like a QUIC Initial packet header, maybe";
        let packet = obfuscate(psk, msg).unwrap();
        // Different salt each call -> different ciphertext for the same input.
        let packet2 = obfuscate(psk, msg).unwrap();
        assert_ne!(packet, packet2);
        assert_eq!(deobfuscate(psk, &packet).unwrap(), msg);
        assert_eq!(deobfuscate(psk, &packet2).unwrap(), msg);
    }

    #[test]
    fn wrong_psk_does_not_panic_and_does_not_match() {
        let packet = obfuscate(b"real-psk-value", b"hello world").unwrap();
        let wrong = deobfuscate(b"wrong-psk-value", &packet).unwrap();
        assert_ne!(wrong, b"hello world");
    }

    #[test]
    fn psk_too_short_rejected() {
        assert!(matches!(obfuscate(b"ab", b"x"), Err(ObfsError::PskTooShort)));
    }

    #[test]
    fn truncated_packet_rejected() {
        assert!(matches!(
            deobfuscate(b"0123456789", &[1, 2, 3]),
            Err(ObfsError::PacketTooShort)
        ));
    }
}
