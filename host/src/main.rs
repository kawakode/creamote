//! Host Creamote.
//!
//! S'enregistre auprès d'un serveur et accepte les sessions entrantes via le
//! relay. Chaque session établit un canal Noise de bout en bout, puis diffuse
//! l'écran (capture et encodage H.264 natifs) et injecte clavier et souris
//! selon les permissions accordées.
//!
//! - **Host enrôlé** dans un parc (`--enroll <jeton>`) : une session n'est
//!   acceptée que sur présentation d'un ticket signé par le serveur, émis
//!   pour ce host et pour l'appareil qui se connecte. Avec `unattended`, elle
//!   s'ouvre sans intervention ; sinon l'utilisateur présent doit consentir.
//! - **Host non enrôlé** : toute demande est soumise au consentement de
//!   l'utilisateur présent (`--unattended-dev` le désactive, pour les tests).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

mod consent;

use anyhow::Context;
use clap::Parser;
use creamote_codec::Preference;
use creamote_crypto::{DeviceIdentity, PublicIdentity, store};
use creamote_net::ident;
use creamote_net::relay::RelayStream;
use creamote_net::rendezvous::{Event, RendezvousClient};
use creamote_net::secure::SecureChannel;
use creamote_net::ticket::{self, Decision, Enrollment};
use creamote_net::tls::ServerPin;
use creamote_proto::permissions::Permissions;
use creamote_session::host::{self, Media, Policy};

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
    /// Encodeur vidéo : `auto` (matériel si possible) ou `software`.
    #[arg(long, default_value = "auto")]
    encoder: Preference,
    /// Host non enrôlé seulement : accepte les sessions sans demander à
    /// l'utilisateur présent. Pour les tests ; ne l'utilisez pas sur un poste
    /// réel.
    #[arg(long)]
    unattended_dev: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    creamote_capture::init();

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
    anyhow::ensure!(
        !(args.unattended_dev && enrollment.is_some()),
        "--unattended-dev est réservé aux hosts non enrôlés"
    );
    match &enrollment {
        Some(e) => println!(
            "Enrôlé dans « {} » / parc « {} » : sessions sur ticket uniquement.",
            e.entity_name, e.fleet_name
        ),
        None if args.unattended_dev => {
            println!("Non enrôlé, --unattended-dev : toute demande est acceptée SANS consentement.")
        }
        None => println!("Non enrôlé : chaque demande est soumise à l'utilisateur présent."),
    }
    let ctx = Ctx {
        identity: Arc::new(identity),
        pin,
        enrollment,
        media: Media::native(args.encoder),
        unattended_dev: args.unattended_dev,
    };
    serve(rv, addr, ctx).await
}

struct Ctx {
    identity: Arc<DeviceIdentity>,
    pin: ServerPin,
    enrollment: Option<Enrollment>,
    media: Media,
    unattended_dev: bool,
}

impl Ctx {
    /// Règles de session selon la décision prise sur le ticket.
    fn policy(&self, decision: Decision) -> Result<Policy, ticket::TicketError> {
        let prompt = || Some(Arc::new(consent::ask) as host::ConsentPrompt);
        Ok(match decision {
            Decision::AcceptUnmanaged => Policy {
                allowed: Permissions::ALL,
                consent: if self.unattended_dev { None } else { prompt() },
                user_email: None,
            },
            Decision::Accept(t) => Policy {
                allowed: Permissions::from_bits_truncate(t.permissions),
                consent: None,
                user_email: Some(t.user_email),
            },
            Decision::AcceptWithConsent(t) => Policy {
                allowed: Permissions::from_bits_truncate(t.permissions),
                consent: prompt(),
                user_email: Some(t.user_email),
            },
            Decision::Decline(e) => return Err(e),
        })
    }
}

async fn serve(
    mut rv: RendezvousClient,
    addr: std::net::SocketAddr,
    ctx: Ctx,
) -> anyhow::Result<()> {
    println!("En ligne sur {addr}, en attente de connexions.");
    let ctx = Arc::new(ctx);

    let mut offers: HashMap<Vec<u8>, (PublicIdentity, Policy)> = HashMap::new();
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
                    ctx.enrollment.as_ref(),
                    &offer.session_ticket,
                    ctx.identity.public(),
                    &requester,
                    ticket::unix_now(),
                );
                let who = format!(
                    "{} (empreinte {})",
                    requester.device_id(),
                    requester.fingerprint()
                );
                let policy = match ctx.policy(decision) {
                    Ok(p) => p,
                    Err(e) => {
                        println!("Demande de {who} : refusée ({e})");
                        rv.answer(&offer, false).await?;
                        continue;
                    }
                };
                let account = policy
                    .user_email
                    .as_deref()
                    .map(|e| format!(" pour {e}"))
                    .unwrap_or_default();
                let mode = if policy.consent.is_some() {
                    "soumise à l'utilisateur présent"
                } else {
                    "acceptée sans surveillance"
                };
                println!("Demande de {who}{account} : {mode}");
                rv.answer(&offer, true).await?;
                offers.insert(offer.session_id.clone(), (requester, policy));
            }
            Event::Grant(grant) => {
                let Some((expected, policy)) = offers.remove(&grant.session_id) else {
                    continue;
                };
                let relay = rv.relay_addr(&grant)?;
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let who = expected.device_id().to_string();
                    match session(relay, grant, expected, policy, &ctx).await {
                        Ok(s) => println!("Session avec {who} terminée ({:?}).", s.granted),
                        Err(e) => eprintln!("Session avec {who} interrompue : {e:#}"),
                    }
                });
            }
            Event::Rejected(_) => {}
        }
    }
    println!("Serveur déconnecté.");
    Ok(())
}

/// Ouvre le canal chiffré de bout en bout avec le viewer et vérifie son
/// identité.
async fn open_channel(
    relay: std::net::SocketAddr,
    pin: ServerPin,
    grant: &creamote_net::rendezvous::RelayGrant,
    expected: &PublicIdentity,
    identity: &DeviceIdentity,
) -> anyhow::Result<SecureChannel<RelayStream>> {
    let stream = RelayStream::join(relay, pin, grant).await?;
    let chan = SecureChannel::respond(stream, identity).await?;
    // Le serveur a annoncé une identité ; Noise prouve celle du pair réel.
    anyhow::ensure!(
        chan.remote() == expected,
        "l'identité authentifiée ne correspond pas à celle annoncée par le serveur"
    );
    Ok(chan)
}

async fn session(
    relay: std::net::SocketAddr,
    grant: creamote_net::rendezvous::RelayGrant,
    expected: PublicIdentity,
    policy: Policy,
    ctx: &Ctx,
) -> anyhow::Result<host::Summary> {
    let chan = open_channel(relay, ctx.pin, &grant, &expected, &ctx.identity).await?;
    println!(
        "Session chiffrée avec {} — code de vérification {}",
        expected.device_id(),
        chan.verification_code()
    );
    let (tx, rx) = chan.split();
    Ok(host::serve(tx, rx, policy, ctx.media.clone()).await?)
}
