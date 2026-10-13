//! Simplified router: RULE-SET (ARS) + MATCH → Direct | Proxy(Spectre).

use crate::config::{OutboundKind, RouteEntry};
use crate::ruleset::RuleSet;
use anyhow::Result;
use std::net::IpAddr;
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
    /// When true, tproxy/mixed should feed DNS queries into the local DNS module.
    hijack_dns: bool,
}

impl Router {
    pub fn new(
        entries: Vec<RouteEntry>,
        rulesets: Vec<Option<Arc<RuleSet>>>,
        sniff: bool,
        hijack_dns: bool,
    ) -> Self {
        assert_eq!(entries.len(), rulesets.len());
        let rules = entries.into_iter().zip(rulesets).collect();
        Self {
            rules,
            sniff,
            hijack_dns,
        }
    }

    pub fn sniff_enabled(&self) -> bool {
        self.sniff
    }

    pub fn hijack_dns(&self) -> bool {
        self.hijack_dns
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

    /// DNS upstream decision under rule-follow-route.
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

pub fn build_router(entries: Vec<RouteEntry>, sniff: bool, hijack_dns: bool) -> Result<Router> {
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
    Ok(Router::new(entries, rulesets, sniff, hijack_dns))
}
