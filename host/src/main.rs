//! Host Creamote.
//!
//! S'enregistre auprès d'un serveur et accepte les sessions entrantes via le
//! relay. Chaque session établit un canal Noise de bout en bout puis, en
//! attendant la capture d'écran (M2), renvoie en écho les messages reçus.
//!
//! - **Host enrôlé** dans un parc (`--enroll <jeton>`) : une session n'est
//!   acceptée que sur présentation d'un ticket signé par le serveur, émis
//!   pour ce host et pour l'appareil qui se connecte, et accordant
//!   `view_screen` + `unattended`.
//! - **Host non enrôlé** (mode développement) : toute demande est acceptée.
//!   Le consentement de l'utilisateur présent arrive avec M2.

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
use creamote_net::ticket::{self, Decision, Enrollment};
use creamote_net::tls::ServerPin;

#[derive(Parser)]
#[command(version, about = "Host Creamote")]
struct Args {
    /// Fichier de l'identité de l'appareil (créé s'il n'existe pas).
    #[arg(long, default_value = "creamote-host.identity")]
    identity_file: PathBuf,
    /// Fichier d'enrôlement (créé par `--enroll`).
    #[arg(long, default_value = "creamote-host.enrollment")]
    enrollment_file: PathBuf,
    /// Serveur Creamote, `hôte:port`. Par défaut, celui de l'enrôlement ;
    /// sans serveur ni enrôlement, affiche seulement l'ID.
    #[arg(long, requires = "server_pin")]
    server: Option<String>,
    /// Empreinte du serveur (affichée au démarrage de creamote-server).
    #[arg(long)]
    server_pin: Option<ServerPin>,
    /// Enrôle ce host dans un parc avec un jeton créé par un administrateur.
    #[arg(long, requires = "server")]
    enroll: Option<String>,
    /// Nom affiché de la machine à l'enrôlement (par défaut, son ID).
    #[arg(long, requires = "enroll")]
    name: Option<String>,
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

    let mut enrollment = Enrollment::load(&args.enrollment_file)
        .with_context(|| format!("enrôlement {}", args.enrollment_file.display()))?;
    let (server, pin) = match (args.server, args.server_pin, &enrollment) {
        (Some(s), Some(p), _) => (s, p),
        (None, _, Some(e)) => (
            e.server.clone(),
            e.server_pin
                .parse()
                .context("empreinte du fichier d'enrôlement")?,
        ),
        _ => return Ok(()),
    };
    let addr = tokio::net::lookup_host(&server)
        .await?
        .next()
        .with_context(|| format!("adresse introuvable : {server}"))?;
    let mut rv = RendezvousClient::register(addr, pin, &identity).await?;

    if let Some(token) = args.enroll {
        anyhow::ensure!(
            enrollment.is_none(),
            "ce host est déjà enrôlé ({}) : supprimez ce fichier pour le réenrôler",
            args.enrollment_file.display()
        );
        let name = args
            .name
            .unwrap_or_else(|| identity.device_id().to_string());
        let r = rv.enroll(&token, &name).await.context("enrôlement")?;
        let e = Enrollment {
            ticket_key: r
                .ticket_public_key
                .as_slice()
                .try_into()
                .context("clé de tickets invalide")?,
            server: server.clone(),
            server_pin: pin.to_string(),
            entity_name: r.entity_name,
            fleet_name: r.fleet_name,
        };
        e.save(&args.enrollment_file)?;
        enrollment = Some(e);
    } else if let Some(e) = &enrollment {
        anyhow::ensure!(
            e.server_pin == pin.to_string(),
            "ce host est enrôlé auprès d'un autre serveur ({})",
            e.server
        );
    }
    match &enrollment {
        Some(e) => println!(
            "Enrôlé dans « {} » / parc « {} » : sessions sur ticket uniquement.",
            e.entity_name, e.fleet_name
        ),
        None => println!("Non enrôlé : mode développement, toute demande est acceptée."),
    }
    serve(rv, addr, pin, Arc::new(identity), enrollment).await
}

async fn serve(
    mut rv: RendezvousClient,
    addr: std::net::SocketAddr,
    pin: ServerPin,
    identity: Arc<DeviceIdentity>,
    enrollment: Option<Enrollment>,
) -> anyhow::Result<()> {
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
                let decision = ticket::decide(
                    enrollment.as_ref(),
                    &offer.session_ticket,
                    identity.public(),
                    &requester,
                    ticket::unix_now(),
                );
                let who = format!(
                    "{} (empreinte {})",
                    requester.device_id(),
                    requester.fingerprint()
                );
                match decision {
                    Decision::AcceptUnmanaged => println!("Demande de {who} : acceptée"),
                    Decision::Accept(t) => {
                        println!("Demande de {who} pour {} : acceptée", t.user_email)
                    }
                    Decision::Decline(e) => {
                        println!("Demande de {who} : refusée ({e})");
                        rv.answer(&offer, false).await?;
                        continue;
                    }
                }
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
