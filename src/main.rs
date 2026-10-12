use anyhow::Result;
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "spectre", about = "Spectre - censorship-resistant QUIC proxy (JLS)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Server {
        #[arg(short, long, default_value = "0.0.0.0:4433")]
        listen: SocketAddr,
        #[arg(short, long)]
        password: String,
        #[arg(short, long)]
        username: Option<String>,
        #[arg(long, default_value = "www.cloudflare.com:443")]
        upstream: String,
        #[arg(long, default_value = "www.cloudflare.com")]
        server_name: String,
    },
    Client {
        #[arg(short, long)]
        server: SocketAddr,
        #[arg(long, default_value = "www.cloudflare.com")]
        server_name: String,
        #[arg(short, long)]
        password: String,
        #[arg(short, long, default_value = "spectre")]
        username: String,
        #[arg(short, long, default_value = "127.0.0.1:1080")]
        listen: SocketAddr,
        /// Download rate, e.g. `200mbps` (bits/s) or `25000000` (bytes/s). 0 = BBR.
        #[arg(long, default_value = "0", value_parser = spectre::brutal::parse_rate)]
        rx: u64,
        /// Upload rate, e.g. `50mbps` (bits/s) or `6250000` (bytes/s). 0 = BBR.
        #[arg(long, default_value = "0", value_parser = spectre::brutal::parse_rate)]
        tx: u64,
        /// Optional local UDP listen address for datagram proxy
        #[arg(long)]
        udp_listen: Option<SocketAddr>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("spectre=info".parse()?))
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Server {
            listen,
            password,
            username,
            upstream,
            server_name,
        } => {
            let cfg = spectre::server::ServerConfigYaml {
                listen,
                password,
                username,
                upstream: Some(upstream),
                server_name: Some(server_name),
            };
            spectre::server::run_server(cfg).await?;
        }
        Commands::Client {
            server,
            server_name,
            password,
            username,
            listen,
            rx,
            tx,
            udp_listen,
        } => {
            let cfg = spectre::client::ClientConfigYaml {
                server,
                server_name,
                username,
                password,
                listen,
                rx_bps: rx,
                tx_bps: tx,
                udp_listen,
            };
            spectre::client::run_client(cfg).await?;
        }
    }
    Ok(())
}
