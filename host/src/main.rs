//! Host Creamote.
//!
//! M1 : s'enregistre auprès d'un serveur et accepte les sessions entrantes
//! via le relay. Chaque session établit un canal Noise de bout en bout puis,
//! en attendant la capture d'écran (M2), renvoie en écho les messages reçus.
//!
//! Le consentement de l'utilisateur et les permissions arrivent avec M2/M4 :
//! en M1, toute demande est acceptée, mais elle ne donne accès qu'à l'écho.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use creamote_crypto::{DeviceIdentity, PublicIdentity, store};
use creamote_net::ident;
use creamote_net::relay::RelayStream;
use creamote_net::rendezvous::{Event, RendezvousClient};
use creamote_net::secure::SecureChannel;
use creamote_net::tls::ServerPin;

#[derive(Parser)]
#[command(version, about = "Host Creamote")]
struct Args {
    /// Fichier de l'identité de l'appareil (créé s'il n'existe pas).
    #[arg(long, default_value = "creamote-host.identity")]
    identity_file: PathBuf,
    /// Serveur Creamote, `hôte:port`. Sans serveur, affiche seulement l'ID.
    #[arg(long, requires = "server_pin")]
    server: Option<String>,
    /// Empreinte du serveur (affichée au démarrage de creamote-server).
    #[arg(long)]
    server_pin: Option<ServerPin>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();

    let (identity, created) = store::load_or_create(&args.identity_file)
        .with_context(|| format!("identité {}", args.identity_file.display()))?;
    let state = if created { "créée" } else { "chargée" };
    println!("Identité {state} : {}", args.identity_file.display());
    println!("ID de l'appareil : {}", identity.device_id());
    println!("Empreinte        : {}", identity.public().fingerprint());

    let (Some(server), Some(pin)) = (args.server, args.server_pin) else {
        return Ok(());
    };
    let addr = tokio::net::lookup_host(&server)
        .await?
        .next()
        .with_context(|| format!("adresse introuvable : {server}"))?;
    serve(addr, pin, Arc::new(identity)).await
}

async fn serve(
    addr: std::net::SocketAddr,
    pin: ServerPin,
    identity: Arc<DeviceIdentity>,
) -> anyhow::Result<()> {
    let mut rv = RendezvousClient::register(addr, pin, &identity).await?;
    println!("En ligne sur {addr}, en attente de connexions.");

    let mut offers: HashMap<Vec<u8>, PublicIdentity> = HashMap::new();
    while let Some(event) = rv.next_event().await? {
        match event {
            Event::Offer(offer) => {
                let Some(requester) = offer
                    .requester
                    .as_ref()
                    .and_then(|p| ident::from_proto(p).ok())
                else {
                    rv.answer(&offer, false).await?;
                    continue;
                };
                println!(
                    "Demande de {} (empreinte {}) : acceptée",
                    requester.device_id(),
                    requester.fingerprint()
                );
                rv.answer(&offer, true).await?;
                offers.insert(offer.session_id.clone(), requester);
            }
            Event::Grant(grant) => {
                let Some(expected) = offers.remove(&grant.session_id) else {
                    continue;
                };
                let relay = rv.relay_addr(&grant)?;
                let identity = identity.clone();
                tokio::spawn(async move {
                    if let Err(e) = echo_session(relay, pin, grant, expected, identity).await {
                        eprintln!("Session interrompue : {e:#}");
                    }
                });
            }
            Event::Rejected(_) => {}
        }
    }
    println!("Serveur déconnecté.");
    Ok(())
}

async fn echo_session(
    relay: std::net::SocketAddr,
    pin: ServerPin,
    grant: creamote_net::rendezvous::RelayGrant,
    expected: PublicIdentity,
    identity: Arc<DeviceIdentity>,
) -> anyhow::Result<()> {
    let stream = RelayStream::join(relay, pin, &grant).await?;
    let mut chan = SecureChannel::respond(stream, &identity).await?;
    // Le serveur a annoncé une identité ; Noise prouve celle du pair réel.
    anyhow::ensure!(
        chan.remote() == &expected,
        "l'identité authentifiée ne correspond pas à celle annoncée par le serveur"
    );
    println!(
        "Session chiffrée avec {} — code de vérification {}",
        expected.device_id(),
        chan.verification_code()
    );
    while let Some(m) = chan.recv().await? {
        let text = String::from_utf8_lossy(&m);
        chan.send(format!("écho : {text}").as_bytes()).await?;
    }
    println!("Session avec {} terminée.", expected.device_id());
    Ok(())
}
