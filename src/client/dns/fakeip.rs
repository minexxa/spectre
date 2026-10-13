//! Fake-IP allocator (aligned with ant).
//!
//! Blacklist mode: every domain gets a fake address unless it hits an exclude
//! ruleset (then real DNS). Whitelist mode: only domains hitting a filter
//! ruleset get fake addresses.

use anyhow::{bail, Result};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use tracing::debug;

pub struct FakeIpPool {
    v4: Option<V4Range>,
    v6: Option<V6Range>,
    by_domain4: Mutex<HashMap<String, Ipv4Addr>>,
    by_domain6: Mutex<HashMap<String, Ipv6Addr>>,
    by_ip: Mutex<HashMap<IpAddr, String>>,
}

struct V4Range {
    start: u32,
    end: u32,
    next: Mutex<u32>,
}

struct V6Range {
    start: u128,
    end: u128,
    next: Mutex<u128>,
}

impl FakeIpPool {
    pub fn new(v4: Option<&str>, v6: Option<&str>) -> Result<Self> {
        let v4 = match v4 {
            Some(s) if !s.is_empty() => Some(parse_v4(s)?),
            _ => None,
        };
        let v6 = match v6 {
            Some(s) if !s.is_empty() => Some(parse_v6(s)?),
            _ => None,
        };
        if v4.is_none() && v6.is_none() {
            bail!("fakeip mode requires fakeip-range and/or fakeip6-range");
        }
        Ok(Self {
            v4,
            v6,
            by_domain4: Mutex::new(HashMap::new()),
            by_domain6: Mutex::new(HashMap::new()),
            by_ip: Mutex::new(HashMap::new()),
        })
    }

    pub fn has_v4(&self) -> bool {
        self.v4.is_some()
    }
    pub fn has_v6(&self) -> bool {
        self.v6.is_some()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v) => self
                .v4
                .as_ref()
                .map(|r| {
                    let n = u32::from(v);
                    n >= r.start && n <= r.end
                })
                .unwrap_or(false),
            IpAddr::V6(v) => self
                .v6
                .as_ref()
                .map(|r| {
                    let n = u128::from(v);
                    n >= r.start && n <= r.end
                })
                .unwrap_or(false),
        }
    }

    pub fn domain_of(&self, ip: IpAddr) -> Option<String> {
        self.by_ip.lock().ok()?.get(&ip).cloned()
    }

    pub fn allocate(&self, domain: &str, v6: bool) -> Option<IpAddr> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            return None;
        }
        if v6 {
            let range = self.v6.as_ref()?;
            if let Some(ip) = self.by_domain6.lock().ok()?.get(&domain).copied() {
                return Some(IpAddr::V6(ip));
            }
            let ip = next_v6(range)?;
            if let Ok(mut m) = self.by_domain6.lock() {
                m.insert(domain.clone(), ip);
            }
            if let Ok(mut m) = self.by_ip.lock() {
                m.insert(IpAddr::V6(ip), domain.clone());
            }
            debug!("fakeip {domain} AAAA -> {ip}");
            Some(IpAddr::V6(ip))
        } else {
            let range = self.v4.as_ref()?;
            if let Some(ip) = self.by_domain4.lock().ok()?.get(&domain).copied() {
                return Some(IpAddr::V4(ip));
            }
            let ip = next_v4(range)?;
            if let Ok(mut m) = self.by_domain4.lock() {
                m.insert(domain.clone(), ip);
            }
            if let Ok(mut m) = self.by_ip.lock() {
                m.insert(IpAddr::V4(ip), domain.clone());
            }
            debug!("fakeip {domain} A -> {ip}");
            Some(IpAddr::V4(ip))
        }
    }
}

fn next_v4(r: &V4Range) -> Option<Ipv4Addr> {
    let mut n = r.next.lock().ok()?;
    // skip network / broadcast-ish ends by only using [start+1, end)
    if *n < r.start + 1 {
        *n = r.start + 1;
    }
    if *n >= r.end {
        *n = r.start + 1;
    }
    let ip = Ipv4Addr::from(*n);
    *n = n.wrapping_add(1);
    if *n >= r.end {
        *n = r.start + 1;
    }
    Some(ip)
}

fn next_v6(r: &V6Range) -> Option<Ipv6Addr> {
    let mut n = r.next.lock().ok()?;
    if *n < r.start + 1 {
        *n = r.start + 1;
    }
    if *n >= r.end {
        *n = r.start + 1;
    }
    let ip = Ipv6Addr::from(*n);
    *n = n.wrapping_add(1);
    if *n >= r.end {
        *n = r.start + 1;
    }
    Some(ip)
}

fn parse_v4(s: &str) -> Result<V4Range> {
    let (ip, prefix) = parse_cidr(s)?;
    let IpAddr::V4(v4) = ip else {
        bail!("fakeip-range must be IPv4 CIDR, got {s}");
    };
    let host_bits = 32u32.saturating_sub(prefix as u32);
    if host_bits == 0 {
        bail!("fakeip-range too small: {s}");
    }
    let mask = !((1u32 << host_bits) - 1);
    let start = u32::from(v4) & mask;
    let end = start + (1u32 << host_bits) - 1;
    Ok(V4Range {
        start,
        end,
        next: Mutex::new(start + 1),
    })
}

fn parse_v6(s: &str) -> Result<V6Range> {
    let (ip, prefix) = parse_cidr(s)?;
    let IpAddr::V6(v6) = ip else {
        bail!("fakeip6-range must be IPv6 CIDR, got {s}");
    };
    let host_bits = 128u32.saturating_sub(prefix as u32);
    if host_bits == 0 || host_bits > 64 {
        // Cap practical size; still accept /64..
        if host_bits == 0 {
            bail!("fakeip6-range too small: {s}");
        }
    }
    let mask = if host_bits >= 128 {
        0u128
    } else {
        !((1u128 << host_bits) - 1)
    };
    let start = u128::from(v6) & mask;
    let end = if host_bits >= 128 {
        u128::MAX
    } else {
        start + (1u128 << host_bits) - 1
    };
    Ok(V6Range {
        start,
        end,
        next: Mutex::new(start + 1),
    })
}

fn parse_cidr(s: &str) -> Result<(IpAddr, u8)> {
    let (addr, pref) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("CIDR expected host/prefix, got `{s}`"))?;
    let ip: IpAddr = addr.parse().map_err(|e| anyhow::anyhow!("bad IP in `{s}`: {e}"))?;
    let prefix: u8 = pref
        .parse()
        .map_err(|e| anyhow::anyhow!("bad prefix in `{s}`: {e}"))?;
    let max = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max {
        bail!("prefix /{prefix} out of range for {s}");
    }
    Ok((ip, prefix))
}

/// Build a minimal DNS response with one A or AAAA answer.
pub fn build_fakeip_answer(query: &[u8], ip: IpAddr) -> Vec<u8> {
    // Keep question section, set QR/AA, one answer RR.
    let mut resp = query.to_vec();
    if resp.len() < 12 {
        resp.resize(12, 0);
    }
    // QR=1, AA=1, RCODE=0
    resp[2] = 0x84;
    resp[3] = 0x00;
    // ANCOUNT = 1
    resp[6] = 0;
    resp[7] = 1;
    resp[8] = 0;
    resp[9] = 0;
    resp[10] = 0;
    resp[11] = 0;

    // Truncate to end of question
    let q_end = question_end(query).unwrap_or(query.len().min(512));
    resp.truncate(q_end);

    // Answer: pointer to qname at offset 12, type, class IN, TTL 1, RDATA
    resp.extend_from_slice(&[0xc0, 0x0c]); // name pointer
    match ip {
        IpAddr::V4(v4) => {
            resp.extend_from_slice(&1u16.to_be_bytes()); // A
            resp.extend_from_slice(&1u16.to_be_bytes()); // IN
            resp.extend_from_slice(&1u32.to_be_bytes()); // TTL
            resp.extend_from_slice(&4u16.to_be_bytes());
            resp.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            resp.extend_from_slice(&28u16.to_be_bytes()); // AAAA
            resp.extend_from_slice(&1u16.to_be_bytes());
            resp.extend_from_slice(&1u32.to_be_bytes());
            resp.extend_from_slice(&16u16.to_be_bytes());
            resp.extend_from_slice(&v6.octets());
        }
    }
    resp
}

fn question_end(msg: &[u8]) -> Option<usize> {
    if msg.len() < 12 {
        return None;
    }
    let mut i = 12;
    loop {
        if i >= msg.len() {
            return None;
        }
        let len = msg[i] as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len >= 0xc0 {
            i += 1;
            break;
        }
        i += len;
    }
    if i + 4 > msg.len() {
        return None;
    }
    Some(i + 4)
}
