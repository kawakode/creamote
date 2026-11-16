//! Host Creamote.
//!
//! S'enregistre auprès d'un serveur et accepte les sessions entrantes, en
//! connexion directe si possible, via le relay sinon. Chaque session établit un canal Noise de bout en bout, puis diffuse
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
use std::time::{Duration, Instant};

mod config;
mod consent;
mod service;

use anyhow::Context;
use clap::{Parser, Subcommand};
use config::HostConfig;
use creamote_codec::Preference;
use creamote_crypto::{DeviceIdentity, PublicIdentity, store};
use creamote_net::ident;
use creamote_net::rendezvous::{Connector, Event, RegisterOptions, RendezvousClient};
use creamote_net::secure::SecureChannel;
use creamote_net::stream::{PeerPath, PeerStream};
use creamote_net::ticket::{self, Decision, Enrollment};
use creamote_net::tls::ServerPin;
use creamote_proto::permissions::Permissions;
use creamote_session::creamote_transfer::clipboard::{ClipboardBackend, NativeClipboard};
use creamote_session::creamote_transfer::files::AcceptPolicy;
use creamote_session::host::{self, Media, Policy};
use creamote_session::{FilesConfig, Sharing};

#[derive(Parser)]
#[command(version, about = "Host Creamote")]
struct Args {
    /// Fichier de l'identité de l'appareil (créé s'il n'existe pas). Par
    /// défaut `creamote-host.identity`, ou le dossier de la plateforme avec
    /// `--service`.
    #[arg(long)]
    identity_file: Option<PathBuf>,
    /// Fichier d'enrôlement (créé par `--enroll`).
    #[arg(long)]
    enrollment_file: Option<PathBuf>,
    /// Serveur Creamote, `hôte:port`. Par défaut, celui de la configuration
    /// ou de l'enrôlement ; sans serveur, affiche seulement l'ID.
    #[arg(long, requires = "server_pin")]
    server: Option<String>,
    /// Empreinte du serveur (affichée au démarrage de creamote-server).
    #[arg(long)]
    server_pin: Option<ServerPin>,
    /// Enrôle ce host dans un parc avec un jeton créé par un administrateur.
    #[arg(long)]
    enroll: Option<String>,
    /// Nom affiché de la machine à l'enrôlement (par défaut, son nom réseau).
    #[arg(long)]
    name: Option<String>,
    /// Encodeur vidéo : `auto` (matériel si possible) ou `software`.
    #[arg(long, default_value = "auto")]
    encoder: Preference,
    /// Host non enrôlé seulement : accepte les sessions sans demander à
    /// l'utilisateur présent. Pour les tests ; ne l'utilisez pas sur un poste
    /// réel.
    #[arg(long)]
    unattended_dev: bool,
    /// Refuse la connexion directe : l'adresse de cette machine n'est pas
    /// communiquée aux viewers, toutes les sessions passent par le relay.
    #[arg(long)]
    relay_only: bool,
    /// Ne partage pas le presse-papier avec les viewers.
    #[arg(long)]
    no_clipboard: bool,
    /// Refuse le transfert de fichiers.
    #[arg(long)]
    no_files: bool,
    /// Dossier des fichiers reçus (par défaut, `Téléchargements/Creamote`
    /// de l'utilisateur).
    #[arg(long)]
    files_dir: Option<PathBuf>,
    /// Fichier de configuration (`clé = valeur`). Par défaut, avec
    /// `--service`, le fichier système (`/etc/creamote/host.conf`,
    /// `/Library/Application Support/Creamote/host.conf`,
    /// `%ProgramData%\Creamote\host.conf`).
    #[arg(long)]
    config: Option<PathBuf>,
    /// Mode service : configuration système, données dans le dossier de la
    /// plateforme, reconnexion automatique au serveur. C'est ainsi que le
    /// lance le service installé.
    #[arg(long)]
    service: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Service lancé au démarrage (droits administrateur requis).
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Installe et démarre le service.
    Install,
    /// Arrête et supprime le service.
    Uninstall,
    /// Point d'entrée du service Windows (lancé par le système).
    #[command(hide = true)]
    Run,
}

/// Réglages résolus : ligne de commande, puis fichier de configuration, puis
/// valeurs par défaut.
struct Settings {
    identity_file: PathBuf,
    enrollment_file: PathBuf,
    server: Option<(String, Option<ServerPin>)>,
    enroll_token: Option<String>,
    /// Le jeton vient de la ligne de commande : un host déjà enrôlé est une
    /// erreur (avec la configuration, le jeton est simplement déjà utilisé).
    enroll_explicit: bool,
    name: Option<String>,
    encoder: Preference,
    unattended_dev: bool,
    relay_only: bool,
    clipboard: bool,
    files_dir: Option<PathBuf>,
    service: bool,
}

impl Settings {
    fn resolve(args: Args) -> anyhow::Result<Self> {
        let config_file = args
            .config
            .clone()
            .or_else(|| args.service.then(config::system_config_file));
        let cfg = match &config_file {
            Some(path) => HostConfig::load(path)?,
            None => HostConfig::default(),
        };
        let data = args.service.then(config::state_dir);
        if let Some(dir) = &data {
            std::fs::create_dir_all(dir).with_context(|| dir.display().to_string())?;
        }
        let in_data = |name: &str, default: &str| match &data {
            Some(dir) => dir.join(name),
            None => PathBuf::from(default),
        };
        let pin = match (args.server_pin, &cfg.server_pin) {
            (Some(p), _) => Some(p),
            (None, Some(p)) => Some(p.parse().context("server_pin de la configuration")?),
            (None, None) => None,
        };
        let server = args.server.or(cfg.server).map(|s| (s, pin));
        let files = !args.no_files && cfg.file_transfer.unwrap_or(true);
        let files_dir = args.files_dir.or(cfg.files_dir);
        Ok(Self {
            identity_file: args
                .identity_file
                .unwrap_or_else(|| in_data("identity", "creamote-host.identity")),
            enrollment_file: args
                .enrollment_file
                .unwrap_or_else(|| in_data("enrollment", "creamote-host.enrollment")),
            server,
            enroll_explicit: args.enroll.is_some(),
            enroll_token: args.enroll.or(cfg.enroll_token),
            name: args.name.or(cfg.name).or_else(config::hostname),
            encoder: args.encoder,
            unattended_dev: args.unattended_dev,
            relay_only: args.relay_only || cfg.relay_only.unwrap_or(false),
            clipboard: !args.no_clipboard && cfg.clipboard.unwrap_or(true),
            files_dir: files.then(|| files_dir.unwrap_or_else(|| default_files_dir(args.service))),
            service: args.service,
        })
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if let Some(Command::Service { action }) = &args.command {
        return match action {
            ServiceAction::Install => service::install(),
            ServiceAction::Uninstall => service::uninstall(),
            #[cfg(windows)]
            ServiceAction::Run => service::windows::run_dispatcher(),
            #[cfg(not(windows))]
            ServiceAction::Run => anyhow::bail!("réservé au service Windows"),
        };
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let settings = Settings::resolve(args)?;
    tokio::runtime::Runtime::new()?.block_on(run(settings))
}

/// Délais entre deux tentatives de connexion en mode service.
const RETRY_MIN: Duration = Duration::from_secs(2);
const RETRY_MAX: Duration = Duration::from_secs(60);

async fn run(settings: Settings) -> anyhow::Result<()> {
    creamote_capture::init();

    let (identity, created) = store::load_or_create(&settings.identity_file)
        .with_context(|| format!("identité {}", settings.identity_file.display()))?;
    let state = if created { "créée" } else { "chargée" };
    println!("Identité {state} : {}", settings.identity_file.display());
    println!("ID de l'appareil : {}", identity.device_id());
    println!("Empreinte        : {}", identity.public().fingerprint());
    let identity = Arc::new(identity);

    if !settings.service {
        return connect_and_serve(&settings, &identity).await;
    }
    // Mode service : on ne s'arrête jamais, le serveur peut redémarrer ou le
    // réseau disparaître.
    let mut delay = RETRY_MIN;
    loop {
        let started = Instant::now();
        match connect_and_serve(&settings, &identity).await {
            Ok(()) => println!("Serveur déconnecté."),
            Err(e) => eprintln!("Connexion au serveur : {e:#}"),
        }
        if started.elapsed() > RETRY_MAX {
            delay = RETRY_MIN;
        }
        println!("Nouvelle tentative dans {} s.", delay.as_secs());
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(RETRY_MAX);
    }
}

async fn connect_and_serve(
    settings: &Settings,
    identity: &Arc<DeviceIdentity>,
) -> anyhow::Result<()> {
    let mut enrollment = Enrollment::load(&settings.enrollment_file)
        .with_context(|| format!("enrôlement {}", settings.enrollment_file.display()))?;
    let (server, pin) = match (&settings.server, &enrollment) {
        (Some((s, Some(p))), _) => (s.clone(), *p),
        (Some((_, None)), _) => {
            anyhow::bail!("empreinte du serveur manquante (--server-pin ou server_pin)")
        }
        (None, Some(e)) => (
            e.server.clone(),
            e.server_pin
                .parse()
                .context("empreinte du fichier d'enrôlement")?,
        ),
        (None, None) if settings.service => {
            anyhow::bail!(
                "aucun serveur configuré ({})",
                config::system_config_file().display()
            )
        }
        (None, None) => return Ok(()),
    };
    let addr = tokio::net::lookup_host(&server)
        .await?
        .next()
        .with_context(|| format!("adresse introuvable : {server}"))?;
    let options = RegisterOptions {
        accept_direct: true,
        relay_only: settings.relay_only,
    };
    let mut rv = RendezvousClient::register_with(addr, pin, identity, options).await?;

    match (&settings.enroll_token, &enrollment) {
        (Some(_), Some(_)) if settings.enroll_explicit => anyhow::bail!(
            "ce host est déjà enrôlé ({}) : supprimez ce fichier pour le réenrôler",
            settings.enrollment_file.display()
        ),
        (Some(token), None) => {
            let name = settings
                .name
                .clone()
                .unwrap_or_else(|| identity.device_id().to_string());
            let r = rv.enroll(token, &name).await.context("enrôlement")?;
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
            e.save(&settings.enrollment_file)?;
            println!("Enrôlé sous le nom « {name} ».");
            enrollment = Some(e);
        }
        _ => {}
    }
    if let Some(e) = &enrollment {
        anyhow::ensure!(
            e.server_pin == pin.to_string(),
            "ce host est enrôlé auprès d'un autre serveur ({})",
            e.server
        );
    }
    anyhow::ensure!(
        !(settings.unattended_dev && enrollment.is_some()),
        "--unattended-dev est réservé aux hosts non enrôlés"
    );
    match &enrollment {
        Some(e) => println!(
            "Enrôlé dans « {} » / parc « {} » : sessions sur ticket uniquement.",
            e.entity_name, e.fleet_name
        ),
        None if settings.unattended_dev => {
            println!("Non enrôlé, --unattended-dev : toute demande est acceptée SANS consentement.")
        }
        None => println!("Non enrôlé : chaque demande est soumise à l'utilisateur présent."),
    }
    // Plafond de débit du relay (serveur public) : l'encodeur reste un peu
    // en dessous pour ne pas remplir la file du relay.
    let relay_bitrate_cap = rv
        .registration()
        .policy
        .as_ref()
        .map(|p| p.max_relay_bitrate_bps)
        .filter(|&bps| bps > 0)
        .map(|bps| u32::try_from(bps * 9 / 10).unwrap_or(u32::MAX));
    if let Some(bps) = relay_bitrate_cap {
        println!("Débit du relay limité : {} kbit/s", bps / 900);
    }
    let ctx = Ctx {
        identity: identity.clone(),
        relay_bitrate_cap,
        enrollment,
        media: Media::native(settings.encoder),
        unattended_dev: settings.unattended_dev,
        clipboard: settings.clipboard,
        files_dir: settings.files_dir.clone(),
    };
    serve(rv, addr, ctx).await
}

struct Ctx {
    identity: Arc<DeviceIdentity>,
    relay_bitrate_cap: Option<u32>,
    enrollment: Option<Enrollment>,
    media: Media,
    unattended_dev: bool,
    clipboard: bool,
    files_dir: Option<PathBuf>,
}

impl Ctx {
    /// Presse-papier natif et fichiers offerts à une session.
    fn sharing(&self) -> Sharing {
        let clipboard = if self.clipboard {
            match NativeClipboard::new() {
                Ok(c) => Some(Box::new(c) as Box<dyn ClipboardBackend>),
                Err(e) => {
                    tracing::warn!("presse-papier indisponible : {e}");
                    None
                }
            }
        } else {
            None
        };
        Sharing {
            clipboard,
            files: self.files_dir.clone().map(|dest| FilesConfig {
                dest,
                // L'utilisateur présent (ou le ticket) a accordé le
                // transfert de fichiers pour cette session.
                policy: AcceptPolicy::AcceptAll,
                events: None,
            }),
        }
    }
}

/// `Téléchargements/Creamote` (ou `Downloads/Creamote`) de l'utilisateur.
/// Le service Windows tourne sous SYSTEM : il dépose les fichiers dans les
/// téléchargements publics (`C:\Users\Public\Downloads\Creamote`).
fn default_files_dir(service: bool) -> PathBuf {
    if cfg!(windows)
        && service
        && let Some(public) = std::env::var_os("PUBLIC")
    {
        return PathBuf::from(public).join("Downloads").join("Creamote");
    }
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let downloads = ["Téléchargements", "Downloads"]
        .iter()
        .map(|d| home.join(d))
        .find(|d| d.is_dir())
        .unwrap_or_else(|| home.join("Downloads"));
    downloads.join("Creamote")
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
                let connector = rv.connector();
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let who = expected.device_id().to_string();
                    match session(connector, grant, expected, policy, &ctx).await {
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
    connector: &Connector,
    grant: &creamote_net::rendezvous::RelayGrant,
    expected: &PublicIdentity,
    identity: &DeviceIdentity,
) -> anyhow::Result<(SecureChannel<PeerStream>, PeerPath)> {
    // Connexion directe si possible, relay sinon.
    let stream = connector.host(grant).await?;
    let path = stream.path();
    let chan = SecureChannel::respond(stream, identity).await?;
    // Le serveur a annoncé une identité ; Noise prouve celle du pair réel.
    anyhow::ensure!(
        chan.remote() == expected,
        "l'identité authentifiée ne correspond pas à celle annoncée par le serveur"
    );
    Ok((chan, path))
}

async fn session(
    connector: Connector,
    grant: creamote_net::rendezvous::RelayGrant,
    expected: PublicIdentity,
    policy: Policy,
    ctx: &Ctx,
) -> anyhow::Result<host::Summary> {
    let (chan, path) = open_channel(&connector, &grant, &expected, &ctx.identity).await?;
    let mut media = ctx.media.clone();
    if path == PeerPath::Relay
        && let Some(cap) = ctx.relay_bitrate_cap
    {
        media.max_bitrate_bps = cap;
    }
    let path = match path {
        PeerPath::Direct => "connexion directe",
        PeerPath::Relay => "via le relay",
    };
    println!(
        "Session chiffrée avec {} ({path}) — code de vérification {}",
        expected.device_id(),
        chan.verification_code()
    );
    let (tx, rx) = chan.split();
    Ok(host::serve_with(tx, rx, policy, media, ctx.sharing()).await?)
}
