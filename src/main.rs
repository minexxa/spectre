use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use spectre::config::{Config, Mode};
use spectre::client::ruleset::{convert_to_ars, ProviderBehavior};
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "spectre", about = "Spectre QUIC proxy with JLS camouflage")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to YAML config file (proxy mode)
    #[arg(short = 'c', long = "config", value_name = "FILE", global = true)]
    config: Option<PathBuf>,

    /// Directory containing config.yaml (or any *.yaml / *.yml) (proxy mode)
    #[arg(short = 'd', long = "dir", value_name = "DIR", global = true)]
    dir: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Convert mihomo YAML / text / sing-box JSON ruleset → binary `.ars`
    #[command(name = "convert-ruleset", visible_alias = "ruleset-convert")]
    ConvertRuleset {
        /// Input: `.yaml`/`.yml` (mihomo payload or classical text) or `.json` (sing-box)
        #[arg(short = 'i', long = "input", value_name = "FILE")]
        input: PathBuf,

        /// Output `.ars` path
        #[arg(short = 'o', long = "output", value_name = "FILE")]
        output: PathBuf,

        /// Force behavior for mihomo sources: domain | ipcidr | classical
        /// (default: auto-detect from content / YAML `behavior:`)
        #[arg(long = "behavior", value_name = "BEHAVIOR")]
        behavior: Option<String>,
    },
}

fn find_config_in_dir(dir: &Path) -> Result<PathBuf> {
    if !dir.is_dir() {
        bail!("not a directory: {}", dir.display());
    }
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
    if cli.config.is_some() && cli.dir.is_some() {
        bail!("-c/--config and -d/--dir are mutually exclusive");
    }
    match (&cli.config, &cli.dir) {
        (Some(c), None) => Ok(c.clone()),
        (None, Some(d)) => find_config_in_dir(d),
        (None, None) => {
            let p = PathBuf::from("config.yaml");
            if p.is_file() {
                Ok(p)
            } else {
                bail!("specify -c <file> or -d <dir> (or place config.yaml in cwd)");
            }
        }
        (Some(_), Some(_)) => unreachable!(),
    }
}

fn init_tracing(level: &str) {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(format!("spectre={level}"))),
        )
        .init();
}

async fn run_proxy(config_path: &Path) -> Result<()> {
    let cfg = Config::load(config_path)?;
    let level = cfg.log_level.as_deref().unwrap_or("info");
    init_tracing(level);

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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::ConvertRuleset {
            input,
            output,
            behavior,
        }) => {
            init_tracing("info");
            let beh = behavior
                .as_deref()
                .map(ProviderBehavior::parse)
                .transpose()?;
            convert_to_ars(&input, &output, beh)?;
            Ok(())
        }
        None => {
            let path = resolve_config_path(&cli)?;
            run_proxy(&path).await
        }
    }
}
