use anyhow::{bail, Context, Result};
use clap::Parser;
use spectre::config::{Config, Mode};
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "spectre", about = "Spectre QUIC proxy with JLS camouflage")]
struct Cli {
    /// Path to YAML config file
    #[arg(short = 'c', long = "config", value_name = "FILE", conflicts_with = "dir")]
    config: Option<PathBuf>,

    /// Directory containing config.yaml (or any *.yaml / *.yml)
    #[arg(short = 'd', long = "dir", value_name = "DIR", conflicts_with = "config")]
    dir: Option<PathBuf>,
}

fn find_config_in_dir(dir: &Path) -> Result<PathBuf> {
    if !dir.is_dir() {
        bail!("not a directory: {}", dir.display());
    }
    // Prefer well-known names, then any *.yaml / *.yml (sorted).
    const PREFERRED: &[&str] = &[
        "config.yaml",
        "config.yml",
        "spectre.yaml",
        "spectre.yml",
    ];
    for name in PREFERRED {
        let p = dir.join(name);
        if p.is_file() {
            return Ok(p);
        }
    }
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("read dir {}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .and_then(|s| s.to_str())
                    .map(|ext| {
                        let e = ext.to_ascii_lowercase();
                        e == "yaml" || e == "yml"
                    })
                    .unwrap_or(false)
        })
        .collect();
    found.sort();
    found
        .into_iter()
        .next()
        .with_context(|| format!("no .yaml/.yml config found in {}", dir.display()))
}

fn resolve_config_path(cli: &Cli) -> Result<PathBuf> {
    match (&cli.config, &cli.dir) {
        (Some(c), None) => Ok(c.clone()),
        (None, Some(d)) => find_config_in_dir(d),
        (None, None) => {
            // Default: ./config.yaml if present, else require explicit -c/-d
            let p = PathBuf::from("config.yaml");
            if p.is_file() {
                Ok(p)
            } else {
                bail!("specify -c <file> or -d <dir> (or place config.yaml in cwd)");
            }
        }
        (Some(_), Some(_)) => unreachable!("clap conflicts_with"),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config_path = resolve_config_path(&cli)?;
    let cfg = Config::load(&config_path)?;

    let level = cfg.log_level.as_deref().unwrap_or("info");
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(format!("spectre={level}"))),
        )
        .init();

    match cfg.mode {
        Mode::Server => {
            let server_cfg = spectre::server::ServerConfigYaml {
                listen: cfg.server_listen()?,
                password: cfg.password().to_string(),
                username: Some(cfg.username().to_string()),
                upstream: Some(cfg.upstream().to_string()),
                server_name: Some(cfg.server_name().to_string()),
            };
            spectre::server::run_server(server_cfg).await?;
        }
        Mode::Client => {
            spectre::client::run_client_from_config(cfg).await?;
        }
    }
    Ok(())
}
