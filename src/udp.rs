//! UDP session management and datagram fragment reassembly for Spectre.

use crate::protocol::{Address, ProtocolError, UdpHeader};
use bytes::{Buf, Bytes, BytesMut};
use dashmap::DashMap;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::debug;

/// Max concurrent incomplete reassembly slots per session.
const MAX_REASSEMBLY_SLOTS: usize = 256;
/// Drop incomplete packets older than this.
const REASSEMBLY_TTL: Duration = Duration::from_secs(5);
/// Idle UDP session timeout on server.
const SESSION_IDLE: Duration = Duration::from_secs(120);
/// Max fragment count we accept.
const MAX_FRAGMENTS: u8 = 64;
/// Default max payload we try to put in one QUIC datagram (before header).
pub const DEFAULT_MAX_DATAGRAM_PAYLOAD: usize = 1200;

/// Key for an in-flight fragmented packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FragKey {
    session_id: u32,
    packet_id: u16,
}

#[derive(Debug)]
struct FragSlot {
    total: u8,
    parts: HashMap<u8, Bytes>,
    address: Address,
    created: Instant,
}

impl FragSlot {
    fn new(total: u8, address: Address) -> Self {
        Self {
            total,
            parts: HashMap::new(),
            address,
            created: Instant::now(),
        }
    }

    fn insert(&mut self, id: u8, data: Bytes) -> Option<(Address, Bytes)> {
        if id >= self.total {
            return None;
        }
        self.parts.insert(id, data);
        if self.parts.len() == self.total as usize {
            let mut out = BytesMut::new();
            for i in 0..self.total {
                if let Some(p) = self.parts.remove(&i) {
                    out.extend_from_slice(&p);
                } else {
                    return None;
                }
            }
            Some((self.address.clone(), out.freeze()))
        } else {
            None
        }
    }
}

/// Reassembles Spectre UDP datagrams (possibly fragmented).
pub struct FragmentReassembler {
    slots: HashMap<FragKey, FragSlot>,
}

impl Default for FragmentReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl FragmentReassembler {
    pub fn new() -> Self {
        Self {
            slots: HashMap::new(),
        }
    }

    /// Feed one datagram payload (already decrypted QUIC datagram body).
    /// Returns Some((session_id, address, full_payload)) when a complete packet is ready.
    pub fn push(&mut self, data: Bytes) -> Result<Option<(u32, Address, Bytes)>, ProtocolError> {
        self.gc();
        let mut buf = data.clone();
        let header = UdpHeader::decode(&mut buf)?;
        let payload = buf.copy_to_bytes(buf.remaining());

        if header.fragment_count == 0 || header.fragment_count > MAX_FRAGMENTS {
            return Err(ProtocolError::BufferTooShort);
        }

        // Non-fragmented fast path
        if header.fragment_count == 1 {
            return Ok(Some((header.session_id, header.address, payload)));
        }

        let key = FragKey {
            session_id: header.session_id,
            packet_id: header.packet_id,
        };

        if self.slots.len() >= MAX_REASSEMBLY_SLOTS && !self.slots.contains_key(&key) {
            // Drop oldest
            if let Some(old) = self
                .slots
                .iter()
                .min_by_key(|(_, s)| s.created)
                .map(|(k, _)| *k)
            {
                self.slots.remove(&old);
            }
        }

        let slot = self
            .slots
            .entry(key)
            .or_insert_with(|| FragSlot::new(header.fragment_count, header.address.clone()));

        if slot.total != header.fragment_count {
            // Inconsistent — drop slot
            self.slots.remove(&key);
            return Ok(None);
        }

        if let Some((addr, full)) = slot.insert(header.fragment_id, payload) {
            self.slots.remove(&key);
            Ok(Some((header.session_id, addr, full)))
        } else {
            Ok(None)
        }
    }

    fn gc(&mut self) {
        let now = Instant::now();
        self.slots
            .retain(|_, s| now.duration_since(s.created) < REASSEMBLY_TTL);
    }
}

/// Split a large UDP payload into Spectre-framed fragments fitting `max_datagram`.
pub fn fragment_udp(
    session_id: u32,
    packet_id: u16,
    address: &Address,
    payload: &[u8],
    max_datagram: usize,
) -> Vec<Bytes> {
    // Estimate header size: 4+2+1+1 + 2+addr + safety
    let addr_len = address.to_socket_addr_string().len() + 2;
    let hdr_overhead = 4 + 2 + 1 + 1 + addr_len + 8;
    let max_payload = max_datagram.saturating_sub(hdr_overhead).max(200);

    if payload.len() <= max_payload {
        let mut buf = BytesMut::with_capacity(hdr_overhead + payload.len());
        let h = UdpHeader {
            session_id,
            packet_id,
            fragment_id: 0,
            fragment_count: 1,
            address: address.clone(),
        };
        h.encode(&mut buf);
        buf.extend_from_slice(payload);
        return vec![buf.freeze()];
    }

    let chunks: Vec<&[u8]> = payload.chunks(max_payload).collect();
    let total = chunks.len().min(MAX_FRAGMENTS as usize) as u8;
    let mut out = Vec::with_capacity(total as usize);
    for (i, chunk) in chunks.iter().enumerate().take(total as usize) {
        let mut buf = BytesMut::with_capacity(hdr_overhead + chunk.len());
        let h = UdpHeader {
            session_id,
            packet_id,
            fragment_id: i as u8,
            fragment_count: total,
            address: address.clone(),
        };
        h.encode(&mut buf);
        buf.extend_from_slice(chunk);
        out.push(buf.freeze());
    }
    out
}

/// Server-side UDP session: one outbound UdpSocket bound for a client session_id.
pub struct UdpSession {
    pub socket: Arc<UdpSocket>,
    pub last_active: Instant,
    /// Optional fixed peer when client uses connected-style associate
    pub peer: Option<SocketAddr>,
}

impl UdpSession {
    pub fn touch(&mut self) {
        self.last_active = Instant::now();
    }

    pub fn idle(&self) -> bool {
        Instant::now().duration_since(self.last_active) > SESSION_IDLE
    }
}

/// Shared session table on the server.
pub type SessionTable = Arc<DashMap<u32, UdpSession>>;

pub fn new_session_table() -> SessionTable {
    Arc::new(DashMap::new())
}

/// Ensure a session exists; create ephemeral UDP socket if needed.
pub async fn get_or_create_session(
    table: &SessionTable,
    session_id: u32,
) -> Result<Arc<UdpSocket>, std::io::Error> {
    if let Some(mut s) = table.get_mut(&session_id) {
        s.touch();
        return Ok(Arc::clone(&s.socket));
    }
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    let arc = Arc::new(sock);
    table.insert(
        session_id,
        UdpSession {
            socket: Arc::clone(&arc),
            last_active: Instant::now(),
            peer: None,
        },
    );
    Ok(arc)
}

pub fn gc_sessions(table: &SessionTable) {
    table.retain(|_, s| !s.idle());
}

/// Client-side: map local (src addr) -> session_id for demux.
pub struct ClientUdpMap {
    pub next_id: u32,
    pub by_local: HashMap<SocketAddr, u32>,
    pub by_id: HashMap<u32, SocketAddr>,
}

impl Default for ClientUdpMap {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientUdpMap {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            by_local: HashMap::new(),
            by_id: HashMap::new(),
        }
    }

    pub fn session_for(&mut self, local: SocketAddr) -> u32 {
        if let Some(&id) = self.by_local.get(&local) {
            return id;
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.by_local.insert(local, id);
        self.by_id.insert(id, local);
        id
    }

    pub fn local_for(&self, session_id: u32) -> Option<SocketAddr> {
        self.by_id.get(&session_id).copied()
    }
}

/// Channel message: inbound complete UDP packet from reassembly.
#[derive(Debug)]
pub struct CompleteUdp {
    pub session_id: u32,
    pub address: Address,
    pub payload: Bytes,
}

/// Background task helper: read QUIC datagrams, reassemble, send complete packets.
pub async fn datagram_reassemble_loop(
    mut rx: mpsc::Receiver<Bytes>,
    tx: mpsc::Sender<CompleteUdp>,
) {
    let mut reasm = FragmentReassembler::new();
    while let Some(data) = rx.recv().await {
        match reasm.push(data) {
            Ok(Some((sid, addr, payload))) => {
                let _ = tx
                    .send(CompleteUdp {
                        session_id: sid,
                        address: addr,
                        payload,
                    })
                    .await;
            }
            Ok(None) => {}
            Err(e) => debug!("udp reassembly error: {e}"),
        }
    }
}

/// Resolve Address to SocketAddr (async DNS via tokio).
pub async fn resolve_address(addr: &Address) -> Result<SocketAddr, std::io::Error> {
    let s = addr.to_socket_addr_string();
    let mut it = tokio::net::lookup_host(s.clone()).await?;
    match it.next() {
        Some(a) => Ok(a),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("resolve failed: {s}"),
        )),
    }
}

/// Encode a single non-fragmented or multi-fragment set and send via QUIC connection.
pub async fn send_udp_over_quic(
    conn: &quinn_jls::Connection,
    session_id: u32,
    packet_id: u16,
    address: &Address,
    payload: &[u8],
    max_datagram: usize,
) -> Result<(), std::io::Error> {
    let frames = fragment_udp(session_id, packet_id, address, payload, max_datagram);
    for frame in frames {
        conn.send_datagram(frame).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("send_datagram: {e}"))
        })?;
    }
    Ok(())
}
