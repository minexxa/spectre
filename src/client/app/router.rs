//! Simplified router: RULE-SET (ARS) + MATCH → Direct | Proxy(Spectre).
//! Fake-IP pool + reverse mapping (aligned with ant).

use crate::config::{OutboundKind, RouteEntry};
use crate::client::dns::FakeIpPool;
use crate::client::ruleset::RuleSet;
use anyhow::Result;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outbound {
    Direct,
    Proxy,
}

#[derive(Debug, Clone)]
pub struct RouteMatch {
    pub outbound: Outbound,
    pub rule: String,
}

pub struct Router {
    rules: Vec<(RouteEntry, Option<Arc<RuleSet>>)>,
    sniff: bool,
    hijack_dns: bool,
    fakeip: bool,
    fakeip_pool: Option<FakeIpPool>,
    /// Filter rulesets for fakeip blacklist/whitelist.
    fakeip_filters: Vec<Arc<RuleSet>>,
    fakeip_whitelist: bool,
}

impl Router {
    pub fn sniff_enabled(&self) -> bool {
        self.sniff
    }

    pub fn hijack_dns(&self) -> bool {
        self.hijack_dns
    }

    pub fn fakeip_enabled(&self) -> bool {
        self.fakeip
    }

    pub fn has_fakeip_v4(&self) -> bool {
        self.fakeip_pool.as_ref().map(|p| p.has_v4()).unwrap_or(false)
    }

    pub fn has_fakeip_v6(&self) -> bool {
        self.fakeip_pool.as_ref().map(|p| p.has_v6()).unwrap_or(false)
    }

    /// Blacklist: true unless domain hits a filter ruleset.
    /// Whitelist: true only if domain hits a filter ruleset.
    pub fn use_fakeip(&self, domain: &str) -> bool {
        if !self.fakeip || domain.is_empty() {
            return false;
        }
        let hit = self
            .fakeip_filters
            .iter()
            .any(|rs| rs.match_domain(domain));
        if self.fakeip_whitelist {
            hit
        } else {
            !hit
        }
    }

    pub fn allocate_fakeip(&self, domain: &str, v6: bool) -> Option<IpAddr> {
        self.fakeip_pool.as_ref()?.allocate(domain, v6)
    }

    pub fn domain_for_fakeip(&self, ip: IpAddr) -> Option<String> {
        let pool = self.fakeip_pool.as_ref()?;
        if !pool.contains(ip) {
            return None;
        }
        pool.domain_of(ip)
    }

    pub fn match_domain(&self, domain: &str) -> RouteMatch {
        for (entry, rs) in &self.rules {
            match entry {
                RouteEntry::RuleSet { outbound, path } => {
                    if let Some(set) = rs {
                        if set.match_domain(domain) {
                            return RouteMatch {
                                outbound: outbound_to(outbound),
                                rule: path.display().to_string(),
                            };
                        }
                    }
                }
                RouteEntry::Match(ob) => {
                    return RouteMatch {
                        outbound: outbound_to(ob),
                        rule: "MATCH".into(),
                    };
                }
            }
        }
        RouteMatch {
            outbound: Outbound::Proxy,
            rule: "MATCH".into(),
        }
    }

    /// ant-style combined match (`match_route_ex` semantics for RULE-SET/MATCH):
    /// rules are tried in order and **each** RULE-SET entry may hit via the
    /// domain *or* the destination IP. A known (sniffed) domain therefore does
    /// not bypass IP rulesets — e.g. `direct,cn-ip.ars` + `match,proxy` still
    /// sends SNI'd traffic to a CN IP through Direct.
    ///
    /// Fake-IP destinations never hit IP rulesets: they route by the mapped
    /// domain instead (ant: `dst_ip.filter(|a| domain_for_fakeip(a).is_none())`).
    pub fn match_route(&self, domain: Option<&str>, ip: Option<IpAddr>) -> RouteMatch {
        let mapped = ip.and_then(|a| self.domain_for_fakeip(a));
        // Fake-IP must not match ip rulesets; the mapped domain is used below.
        let ip_rule = if mapped.is_some() { None } else { ip };
        let domain = domain.map(|s| s.to_string()).or(mapped);
        for (entry, rs) in &self.rules {
            match entry {
                RouteEntry::RuleSet { outbound, path } => {
                    if let Some(set) = rs {
                        if let Some(d) = domain.as_deref() {
                            if set.match_domain(d) {
                                return RouteMatch {
                                    outbound: outbound_to(outbound),
                                    rule: path.display().to_string(),
                                };
                            }
                        }
                        if let Some(addr) = ip_rule {
                            if set.match_ip(addr) {
                                return RouteMatch {
                                    outbound: outbound_to(outbound),
                                    rule: path.display().to_string(),
                                };
                            }
                        }
                    }
                }
                RouteEntry::Match(ob) => {
                    return RouteMatch {
                        outbound: outbound_to(ob),
                        rule: "MATCH".into(),
                    };
                }
            }
        }
        RouteMatch {
            outbound: Outbound::Proxy,
            rule: "MATCH".into(),
        }
    }

    pub fn match_ip(&self, ip: IpAddr) -> RouteMatch {
        // Fake-IP → route by original domain
        if let Some(domain) = self.domain_for_fakeip(ip) {
            return self.match_domain(&domain);
        }
        for (entry, rs) in &self.rules {
            match entry {
                RouteEntry::RuleSet { outbound, path } => {
                    if let Some(set) = rs {
                        if set.match_ip(ip) {
                            return RouteMatch {
                                outbound: outbound_to(outbound),
                                rule: path.display().to_string(),
                            };
                        }
                    }
                }
                RouteEntry::Match(ob) => {
                    return RouteMatch {
                        outbound: outbound_to(ob),
                        rule: "MATCH".into(),
                    };
                }
            }
        }
        RouteMatch {
            outbound: Outbound::Proxy,
            rule: "MATCH".into(),
        }
    }

    pub fn dns_outbound_for_domain(&self, domain: &str) -> Outbound {
        self.match_domain(domain).outbound
    }
}

fn outbound_to(k: &OutboundKind) -> Outbound {
    match k {
        OutboundKind::Direct => Outbound::Direct,
        OutboundKind::Proxy => Outbound::Proxy,
    }
}

pub fn build_router(cfg: &crate::config::Config, entries: Vec<RouteEntry>) -> Result<Router> {
    let mut rulesets = Vec::with_capacity(entries.len());
    for e in &entries {
        match e {
            RouteEntry::RuleSet { path, .. } => {
                let name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("ars");
                let rs = crate::client::ruleset::load_file(name, path)?;
                tracing::info!(
                    "loaded ruleset {} ({} rules)",
                    path.display(),
                    rs.rule_count
                );
                rulesets.push(Some(Arc::new(rs)));
            }
            RouteEntry::Match(_) => rulesets.push(None),
        }
    }

    let fakeip = cfg.fakeip_enabled();
    let fakeip_pool = if fakeip {
        Some(FakeIpPool::new(
            cfg.dns.fakeip_range.as_deref(),
            cfg.dns.fakeip6_range.as_deref(),
        )?)
    } else {
        None
    };

    let mut fakeip_filters = Vec::new();
    if fakeip {
        for p in &cfg.dns.fakeip_filter {
            let path = PathBuf::from(p);
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("filter");
            match crate::client::ruleset::load_file(name, &path) {
                Ok(rs) => {
                    tracing::info!(
                        "loaded fakeip-filter {} ({} rules)",
                        path.display(),
                        rs.rule_count
                    );
                    fakeip_filters.push(Arc::new(rs));
                }
                Err(e) => {
                    tracing::warn!("fakeip-filter {}: {e:#}", path.display());
                }
            }
        }
    }

    Ok(Router {
        rules: entries.into_iter().zip(rulesets).collect(),
        sniff: cfg.sniff,
        hijack_dns: cfg.dns_route_hijack(),
        fakeip,
        fakeip_pool,
        fakeip_filters,
        fakeip_whitelist: cfg.dns.fakeip_filter_mode == "whitelist",
    })
}
