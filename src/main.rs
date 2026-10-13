use anyhow::Result;
use clap::Parser;
use spectre::config::{Config, Mode};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "spectre", about = "Spectre QUIC proxy with JLS camouflage")]
struct Cli {
    /// Path to YAML config file
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = Config::load(&cli.config)?;

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
