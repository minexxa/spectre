//! Spectre shared protocol core (wire format, congestion, relay, UDP framing).

pub mod brutal;
pub mod relay;
pub mod udp;

//! Spectre wire protocol definitions and helpers.

use bytes::{Buf, BufMut, BytesMut};
use thiserror::Error;

/// Protocol version
pub const VERSION: u8 = 0x01;

/// Command types on bidirectional streams
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    TcpConnect = 0x01,
    UdpAssociate = 0x02,
    Auth = 0x03,
    Padding = 0xFF,
}

impl TryFrom<u8> for Command {
    type Error = ProtocolError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Command::TcpConnect),
            0x02 => Ok(Command::UdpAssociate),
            0x03 => Ok(Command::Auth),
            0xFF => Ok(Command::Padding),
            _ => Err(ProtocolError::UnknownCommand(v)),
        }
    }
}

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("unknown command: {0:#x}")]
    UnknownCommand(u8),
    #[error("invalid address")]
    InvalidAddress,
    #[error("buffer too short")]
    BufferTooShort,
    #[error("invalid status")]
    InvalidStatus,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Address encoding: currently simple UTF-8 "host:port"
#[derive(Debug, Clone)]
pub struct Address {
    pub host: String,
    pub port: u16,
}

impl Address {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    pub fn to_socket_addr_string(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let s = self.to_socket_addr_string();
        let len = s.len() as u16;
        buf.put_u16(len);
        buf.put_slice(s.as_bytes());
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, ProtocolError> {
        if buf.remaining() < 2 {
            return Err(ProtocolError::BufferTooShort);
        }
        let len = buf.get_u16() as usize;
        if buf.remaining() < len {
            return Err(ProtocolError::BufferTooShort);
        }
        let mut bytes = vec![0u8; len];
        buf.copy_to_slice(&mut bytes);
        let s = String::from_utf8(bytes).map_err(|_| ProtocolError::InvalidAddress)?;
        let (host, port_str) = s.rsplit_once(':').ok_or(ProtocolError::InvalidAddress)?;
        let port: u16 = port_str.parse().map_err(|_| ProtocolError::InvalidAddress)?;
        Ok(Self {
            host: host.to_string(),
            port,
        })
    }
}

/// TCP Connect request
#[derive(Debug)]
pub struct TcpConnectRequest {
    pub address: Address,
    pub padding: Vec<u8>,
}

impl TcpConnectRequest {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u8(Command::TcpConnect as u8);
        self.address.encode(&mut buf);
        buf.put_u16(self.padding.len() as u16);
        buf.put_slice(&self.padding);
        buf
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, ProtocolError> {
        // cmd already consumed
        let address = Address::decode(buf)?;
        if buf.remaining() < 2 {
            return Err(ProtocolError::BufferTooShort);
        }
        let pad_len = buf.get_u16() as usize;
        if buf.remaining() < pad_len {
            return Err(ProtocolError::BufferTooShort);
        }
        let mut padding = vec![0u8; pad_len];
        buf.copy_to_slice(&mut padding);
        Ok(Self { address, padding })
    }
}

/// TCP Connect response
#[derive(Debug)]
pub struct TcpConnectResponse {
    pub ok: bool,
    pub message: String,
    pub padding: Vec<u8>,
}

impl TcpConnectResponse {
    pub fn ok() -> Self {
        Self {
            ok: true,
            message: String::new(),
            padding: random_padding(16..64),
        }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: msg.into(),
            padding: random_padding(16..64),
        }
    }

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u8(if self.ok { 0x00 } else { 0x01 });
        let msg_bytes = self.message.as_bytes();
        buf.put_u16(msg_bytes.len() as u16);
        buf.put_slice(msg_bytes);
        buf.put_u16(self.padding.len() as u16);
        buf.put_slice(&self.padding);
        buf
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, ProtocolError> {
        if buf.remaining() < 1 {
            return Err(ProtocolError::BufferTooShort);
        }
        let status = buf.get_u8();
        let ok = match status {
            0x00 => true,
            0x01 => false,
            _ => return Err(ProtocolError::InvalidStatus),
        };
        if buf.remaining() < 2 {
            return Err(ProtocolError::BufferTooShort);
        }
        let msg_len = buf.get_u16() as usize;
        if buf.remaining() < msg_len {
            return Err(ProtocolError::BufferTooShort);
        }
        let mut msg_bytes = vec![0u8; msg_len];
        buf.copy_to_slice(&mut msg_bytes);
        let message = String::from_utf8_lossy(&msg_bytes).into_owned();

        if buf.remaining() < 2 {
            return Err(ProtocolError::BufferTooShort);
        }
        let pad_len = buf.get_u16() as usize;
        if buf.remaining() < pad_len {
            return Err(ProtocolError::BufferTooShort);
        }
        let mut padding = vec![0u8; pad_len];
        buf.copy_to_slice(&mut padding);

        Ok(Self { ok, message, padding })
    }
}

/// Auth request (simplified control-stream auth)
#[derive(Debug)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
    /// Client's desired receive rate (download) in bytes/sec. 0 = auto
    pub rx_bps: u64,
    /// Client's desired send rate (upload) in bytes/sec. 0 = auto
    pub tx_bps: u64,
    pub padding: Vec<u8>,
}

impl AuthRequest {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u8(Command::Auth as u8);
        buf.put_u8(VERSION);

        let u = self.username.as_bytes();
        buf.put_u16(u.len() as u16);
        buf.put_slice(u);

        let p = self.password.as_bytes();
        buf.put_u16(p.len() as u16);
        buf.put_slice(p);

        buf.put_u64(self.rx_bps);
        buf.put_u64(self.tx_bps);

        buf.put_u16(self.padding.len() as u16);
        buf.put_slice(&self.padding);
        buf
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, ProtocolError> {
        // cmd already consumed
        if buf.remaining() < 1 {
            return Err(ProtocolError::BufferTooShort);
        }
        let _ver = buf.get_u8(); // ignore for now

        if buf.remaining() < 2 {
            return Err(ProtocolError::BufferTooShort);
        }
        let ulen = buf.get_u16() as usize;
        if buf.remaining() < ulen {
            return Err(ProtocolError::BufferTooShort);
        }
        let mut ub = vec![0u8; ulen];
        buf.copy_to_slice(&mut ub);
        let username = String::from_utf8(ub).map_err(|_| ProtocolError::InvalidAddress)?;

        if buf.remaining() < 2 {
            return Err(ProtocolError::BufferTooShort);
        }
        let plen = buf.get_u16() as usize;
        if buf.remaining() < plen {
            return Err(ProtocolError::BufferTooShort);
        }
        let mut pb = vec![0u8; plen];
        buf.copy_to_slice(&mut pb);
        let password = String::from_utf8(pb).map_err(|_| ProtocolError::InvalidAddress)?;

        if buf.remaining() < 16 {
            return Err(ProtocolError::BufferTooShort);
        }
        let rx_bps = buf.get_u64();
        let tx_bps = buf.get_u64();

        if buf.remaining() < 2 {
            return Err(ProtocolError::BufferTooShort);
        }
        let pad_len = buf.get_u16() as usize;
        if buf.remaining() < pad_len {
            return Err(ProtocolError::BufferTooShort);
        }
        let mut padding = vec![0u8; pad_len];
        buf.copy_to_slice(&mut padding);

        Ok(Self {
            username,
            password,
            rx_bps,
            tx_bps,
            padding,
        })
    }
}

/// Auth response
#[derive(Debug)]
pub struct AuthResponse {
    pub ok: bool,
    /// Server's preferred receive rate (what client should send at)
    pub rx_bps: u64,
    /// Server's preferred send rate
    pub tx_bps: u64,
    pub message: String,
    pub padding: Vec<u8>,
}

impl AuthResponse {
    pub fn ok(rx_bps: u64, tx_bps: u64) -> Self {
        Self {
            ok: true,
            rx_bps,
            tx_bps,
            message: String::new(),
            padding: random_padding(16..64),
        }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            rx_bps: 0,
            tx_bps: 0,
            message: msg.into(),
            padding: random_padding(16..64),
        }
    }

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u8(if self.ok { 0x00 } else { 0x01 });
        buf.put_u64(self.rx_bps);
        buf.put_u64(self.tx_bps);
        let msg = self.message.as_bytes();
        buf.put_u16(msg.len() as u16);
        buf.put_slice(msg);
        buf.put_u16(self.padding.len() as u16);
        buf.put_slice(&self.padding);
        buf
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, ProtocolError> {
        if buf.remaining() < 1 + 8 + 8 + 2 {
            return Err(ProtocolError::BufferTooShort);
        }
        let status = buf.get_u8();
        let ok = status == 0x00;
        let rx_bps = buf.get_u64();
        let tx_bps = buf.get_u64();
        let msg_len = buf.get_u16() as usize;
        if buf.remaining() < msg_len {
            return Err(ProtocolError::BufferTooShort);
        }
        let mut mb = vec![0u8; msg_len];
        buf.copy_to_slice(&mut mb);
        let message = String::from_utf8_lossy(&mb).into_owned();

        if buf.remaining() < 2 {
            return Err(ProtocolError::BufferTooShort);
        }
        let pad_len = buf.get_u16() as usize;
        if buf.remaining() < pad_len {
            return Err(ProtocolError::BufferTooShort);
        }
        let mut padding = vec![0u8; pad_len];
        buf.copy_to_slice(&mut padding);

        Ok(Self {
            ok,
            rx_bps,
            tx_bps,
            message,
            padding,
        })
    }
}

/// UDP datagram header (placed in front of payload inside QUIC datagram)
#[derive(Debug, Clone)]
pub struct UdpHeader {
    pub session_id: u32,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub fragment_count: u8,
    pub address: Address,
}

impl UdpHeader {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.session_id);
        buf.put_u16(self.packet_id);
        buf.put_u8(self.fragment_id);
        buf.put_u8(self.fragment_count);
        self.address.encode(buf);
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, ProtocolError> {
        if buf.remaining() < 4 + 2 + 1 + 1 {
            return Err(ProtocolError::BufferTooShort);
        }
        let session_id = buf.get_u32();
        let packet_id = buf.get_u16();
        let fragment_id = buf.get_u8();
        let fragment_count = buf.get_u8();
        let address = Address::decode(buf)?;
        Ok(Self {
            session_id,
            packet_id,
            fragment_id,
            fragment_count,
            address,
        })
    }
}

/// Generate random padding of length in the given range
pub fn random_padding(range: std::ops::Range<usize>) -> Vec<u8> {
    use rand::{Rng, RngCore};
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(range);
    let mut v = vec![0u8; len];
    rng.fill_bytes(&mut v);
    v
}

/// Simple constant-time-ish password compare
pub fn secure_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes()
        .iter()
        .zip(b.as_bytes().iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}
