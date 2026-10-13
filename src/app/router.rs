//! Simplified router: RULE-SET (ARS) + MATCH → Direct | Proxy(Spectre).
//! Fake-IP pool + reverse mapping (aligned with ant).

use crate::config::{OutboundKind, RouteEntry};
use crate::dns::FakeIpPool;
use crate::ruleset::RuleSet;
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
                let rs = crate::ruleset::load_file(name, path)?;
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
            match crate::ruleset::load_file(name, &path) {
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
