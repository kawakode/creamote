//! `creamote-cli` : outil de test du protocole.
//!
//! `creamote-cli view <ID> --server <hôte:port> --server-pin <empreinte>`
//! ouvre une session de bout en bout vers un host via le relay, affiche le
//! déroulement (consentement, encodeur, images reçues) et peut enregistrer le
//! flux H.264 brut (`--record flux.h264`, lisible par `ffplay`).
//!
//! Pour un host enrôlé dans un parc, ajoutez `--api-url` et `--api-token`
//! (obtenu avec `creamote-cli login`) : la CLI demande alors un ticket de
//! session à l'API de gestion et le présente au host.

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use creamote_crypto::{DeviceId, store};
use creamote_net::relay::RelayStream;
use creamote_net::rendezvous::RendezvousClient;
use creamote_net::secure::SecureChannel;
use creamote_net::tls::ServerPin;
use creamote_proto::permissions::Permissions;
use creamote_session::viewer::{self, Event};
use std::io::Write;

#[derive(Parser)]
#[command(version, about = "Outil en ligne de commande Creamote")]
struct Args {
    /// Fichier de l'identité de cet appareil (créé s'il n'existe pas).
    #[arg(long, default_value = "creamote-cli.identity", global = true)]
    identity_file: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Affiche l'ID et l'empreinte de cet appareil.
    Id,
    /// Ouvre une session vers un host et reçoit son écran.
    #[command(alias = "connect")]
    View {
        /// ID du host, ex. « 123 456 789 ».
        target: String,
        /// Serveur Creamote, `hôte:port`.
        #[arg(long)]
        server: String,
        /// Empreinte du serveur.
        #[arg(long)]
        server_pin: ServerPin,
        /// URL de l'API de gestion, ex. `https://creamote.example.org`, pour
        /// obtenir un ticket de session (hosts enrôlés).
        #[arg(long, requires = "api_token")]
        api_url: Option<String>,
        /// Jeton d'API (`creamote-cli login`).
        #[arg(long, env = "CREAMOTE_API_TOKEN", hide_env_values = true)]
        api_token: Option<String>,
        /// Enregistre le flux H.264 (Annex B) dans ce fichier.
        #[arg(long)]
        record: Option<PathBuf>,
        /// Durée de la session en secondes (0 : jusqu'à Ctrl+C).
        #[arg(long, default_value_t = 0)]
        seconds: u64,
        /// Demande seulement la vue, sans le contrôle.
        #[arg(long)]
        view_only: bool,
        /// Cadence maximale demandée.
        #[arg(long, default_value_t = 30)]
        fps: u32,
    },
    /// Ouvre une session d'API et affiche le jeton (mot de passe lu sur
    /// l'entrée standard).
    Login {
        #[arg(long)]
        api_url: String,
        #[arg(long)]
        email: String,
    },
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(s.len() % 2 == 0 && s.is_ascii(), "hexadécimal invalide");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).context("hexadécimal invalide"))
        .collect()
}

fn api(base: &str, path: &str) -> String {
    format!("{}/api/v1{path}", base.trim_end_matches('/'))
}

async fn api_post(
    url: String,
    token: Option<&str>,
    body: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let mut req = reqwest::Client::new().post(&url).json(&body);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let resp = req.send().await.with_context(|| format!("requête {url}"))?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    anyhow::ensure!(
        status.is_success(),
        "{url} : {status} {}",
        body["message"].as_str().unwrap_or_default()
    );
    Ok(body)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();
    let args = Args::parse();
    let (identity, _) = store::load_or_create(&args.identity_file)
        .with_context(|| format!("identité {}", args.identity_file.display()))?;

    match args.command {
        Command::Id => {
            println!("ID de l'appareil : {}", identity.device_id());
            println!("Empreinte        : {}", identity.public().fingerprint());
            Ok(())
        }
        Command::Login { api_url, email } => {
            let mut password = String::new();
            std::io::stdin().read_line(&mut password)?;
            let body = api_post(
                api(&api_url, "/auth/login"),
                None,
                serde_json::json!({ "email": email, "password": password.trim_end_matches(['\r', '\n']) }),
            )
            .await?;
            println!("{}", body["token"].as_str().context("réponse sans jeton")?);
            Ok(())
        }
        Command::View {
            target,
            server,
            server_pin,
            api_url,
            api_token,
            record,
            seconds,
            view_only,
            fps,
        } => {
            let target = DeviceId::parse(&target).context("ID invalide (9 chiffres attendus)")?;
            let addr = tokio::net::lookup_host(&server)
                .await?
                .next()
                .with_context(|| format!("adresse introuvable : {server}"))?;

            let ticket = match (&api_url, &api_token) {
                (Some(url), Some(token)) => {
                    let body = api_post(
                        api(url, "/tickets"),
                        Some(token),
                        serde_json::json!({
                            "device_id": target.to_string(),
                            "viewer_key": hex(identity.public().signing_key()),
                        }),
                    )
                    .await
                    .context("demande de ticket")?;
                    unhex(body["ticket"].as_str().context("réponse sans ticket")?)?
                }
                _ => Vec::new(),
            };

            let mut rv = RendezvousClient::register(addr, server_pin, &identity).await?;
            let grant = rv.request_session_with_ticket(target, ticket).await?;
            let relay = rv.relay_addr(&grant)?;
            let stream = RelayStream::join(relay, server_pin, &grant).await?;
            let chan = SecureChannel::initiate(stream, &identity).await?;

            // Seul Noise fait foi : on vérifie que la clé authentifiée
            // correspond bien à l'ID demandé.
            anyhow::ensure!(
                chan.remote().device_id() == target,
                "le pair authentifié n'est pas {target}"
            );
            println!(
                "Connecté à {} (empreinte {}), chiffré de bout en bout.",
                target,
                chan.remote().fingerprint()
            );
            println!("Code de vérification : {}", chan.verification_code());
            if grant.max_session_seconds > 0 {
                println!(
                    "Serveur public : session limitée à {} min.",
                    grant.max_session_seconds / 60
                );
            }
            println!("En attente de l'accord du host…");
            let requested = if view_only {
                Permissions::VIEW
            } else {
                Permissions::VIEW | Permissions::CONTROL
            };
            let (tx, rx) = chan.split();
            let (handle, mut events) = viewer::start(
                tx,
                rx,
                viewer::Options {
                    display_name: "creamote-cli".into(),
                    requested,
                    max_fps: fps,
                    bitrate_bps: 0,
                },
            );
            let mut out = match &record {
                Some(p) => Some(std::io::BufWriter::new(std::fs::File::create(p)?)),
                None => None,
            };
            let deadline = (seconds > 0)
                .then(|| tokio::time::Instant::now() + std::time::Duration::from_secs(seconds));
            let (mut frames, mut bytes) = (0u64, 0u64);
            let started = std::time::Instant::now();
            loop {
                let ev = tokio::select! {
                    ev = events.recv() => ev,
                    _ = tokio::signal::ctrl_c() => None,
                    _ = async {
                        match deadline {
                            Some(d) => tokio::time::sleep_until(d).await,
                            None => std::future::pending().await,
                        }
                    } => None,
                };
                match ev {
                    Some(Event::Accepted { granted, displays }) => {
                        println!("Session acceptée, permissions {granted:?}.");
                        for d in displays {
                            println!("  écran {} « {} » {}×{}", d.id, d.name, d.width, d.height);
                        }
                    }
                    Some(Event::Video(c)) => println!(
                        "Flux : {}×{} à {} i/s, {} kbit/s, encodeur {}",
                        c.width,
                        c.height,
                        c.max_fps,
                        c.target_bitrate_bps / 1000,
                        c.encoder
                    ),
                    Some(Event::Frame(f)) => {
                        frames += 1;
                        bytes += f.data.len() as u64;
                        if let Some(o) = &mut out {
                            o.write_all(&f.data)?;
                        }
                        handle.ack(f.frame_id).await.ok();
                        if frames % 30 == 1 {
                            let secs = started.elapsed().as_secs_f64().max(0.001);
                            println!(
                                "{frames} images, {:.0} kbit/s en moyenne",
                                bytes as f64 * 8.0 / secs / 1000.0
                            );
                        }
                    }
                    Some(Event::Ended { reason, message }) => {
                        println!("Session terminée par le host : {reason:?} {message}");
                        break;
                    }
                    None => {
                        handle.close().await;
                        break;
                    }
                }
            }
            if let Some(mut o) = out {
                o.flush()?;
                if let Some(p) = &record {
                    println!("{frames} images enregistrées dans {}", p.display());
                }
            }
            rv.close();
            Ok(())
        }
    }
}
