//! Binary `.ars` ruleset loading, matching, and offline compilation.
//!
//! - Runtime: load `.ars` → match domain / IP.
//! - Offline: YAML (mihomo payload / classical text) or sing-box JSON → `.ars`
//!   via [`convert_to_ars`] / the `convert-ruleset` CLI.

mod format;
mod compiler;
mod loader;
mod matcher;

pub use compiler::{
    compile_mihomo_ruleset, compile_singbox_json, write_ars, ProviderBehavior,
};
pub use matcher::RuleSet;

use anyhow::{bail, Context, Result};
use std::path::Path;

/// Load a single `.ars` file into a [`RuleSet`].
pub fn load_file(name: &str, path: &Path) -> Result<RuleSet> {
    let data = std::fs::read(path).with_context(|| format!("read ruleset {path:?}"))?;
    RuleSet::from_bytes(name, &data).with_context(|| format!("parse ruleset {path:?}"))
}

/// Convert a ruleset source file → `.ars`.
///
/// Input formats:
/// - mihomo YAML with `payload:` (and optional `behavior:`)
/// - plain text classical lines / domain list / CIDR list
/// - sing-box rule-set JSON (`.json`)
pub fn convert_to_ars(
    input: &Path,
    output: &Path,
    behavior: Option<ProviderBehavior>,
) -> Result<()> {
    let raw = std::fs::read_to_string(input)
        .with_context(|| format!("read {input:?}"))?;
    let ext = input
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let compiled = if ext == "json" {
        if behavior.is_some() {
            bail!(
                "--behavior applies to mihomo YAML/text sources only; \
                 sing-box JSON is self-describing"
            );
        }
        compile_singbox_json(&raw)?
    } else {
        compile_mihomo_ruleset(&raw, behavior)?
    };
    let mut out =
        std::fs::File::create(output).with_context(|| format!("create {output:?}"))?;
    write_ars(&compiled, &mut out)?;
    tracing::info!(
        "wrote .ars {} (domains={} suffixes={} keywords={} regex={} v4={} v6={})",
        output.display(),
        compiled.domains.len(),
        compiled.domain_suffixes.len(),
        compiled.domain_keywords.len(),
        compiled.domain_regexes.len(),
        compiled.ipv4_cidrs.len(),
        compiled.ipv6_cidrs.len(),
    );
    Ok(())
}
