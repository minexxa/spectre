//! Binary `.ars` ruleset loading and matching.
//!
//! Only matching is supported — no compilation / generation of `.ars` files.

mod format;
mod loader;
mod matcher;

pub use matcher::RuleSet;

use anyhow::{Context, Result};
use std::path::Path;

/// Load a single `.ars` file into a [`RuleSet`].
pub fn load_file(name: &str, path: &Path) -> Result<RuleSet> {
    let data = std::fs::read(path).with_context(|| format!("read ruleset {path:?}"))?;
    RuleSet::from_bytes(name, &data).with_context(|| format!("parse ruleset {path:?}"))
}
