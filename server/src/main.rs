//! `creamote-server` : rendezvous et relay auto-hébergeables.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use creamote_server::{Config, Policy, Server};

#[derive(Parser)]
#[command(version, about = "Serveur Creamote : rendezvous et relay")]
struct Args {
    /// Adresse d'écoute (UDP).
    #[arg(long, default_value = "0.0.0.0:21400")]
    listen: SocketAddr,
    /// Dossier où conserver le certificat du serveur.
    #[arg(long, default_value = "creamote-data")]
    data_dir: PathBuf,
    /// Adresse du relay annoncée aux pairs (par défaut : celle du serveur).
    #[arg(long)]
    relay_addr: Option<String>,
    /// Mode serveur public : limite le nombre et la durée des sessions relay.
    #[arg(long)]
    public: bool,
    /// Sessions relay simultanées (0 = illimité). Par défaut : 200 en mode
    /// public, illimité sinon.
    #[arg(long)]
    max_relay_sessions: Option<u32>,
    /// Durée maximale d'une session relay en secondes (0 = illimitée). Par
    /// défaut : 1800 en mode public, illimitée sinon.
    #[arg(long)]
    max_relay_seconds: Option<u32>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let mut policy = if args.public {
        Policy::public()
    } else {
        Policy::private()
    };
    if let Some(n) = args.max_relay_sessions {
        policy.max_relay_sessions = n;
    }
    if let Some(s) = args.max_relay_seconds {
        policy.max_relay_seconds = s;
    }

    let server = Server::start(Config {
        listen: args.listen,
        data_dir: Some(args.data_dir),
        relay_addr: args.relay_addr,
        policy: policy.clone(),
    })
    .await?;

    println!("creamote-server {}", env!("CARGO_PKG_VERSION"));
    println!("Écoute     : {} (UDP)", server.local_addr()?);
    println!("Empreinte  : {}", server.pin());
    println!(
        "Mode       : {}",
        if policy.public_mode {
            "public"
        } else {
            "privé"
        }
    );
    println!(
        "Relay      : {} sessions max, {} s max par session (0 = illimité)",
        policy.max_relay_sessions, policy.max_relay_seconds
    );
    println!("Les pairs se connectent avec --server <adresse> --server-pin <empreinte>.");

    tokio::signal::ctrl_c().await?;
    server.shutdown().await;
    Ok(())
}
