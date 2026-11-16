//! `creamote-cli` : outil de test du protocole.
//!
//! `creamote-cli connect <ID> --server <hôte:port> --server-pin <empreinte>`
//! ouvre une session chiffrée de bout en bout vers un host via le relay, puis
//! envoie chaque ligne saisie et affiche les réponses (écho du host en M1).
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
use tokio::io::{AsyncBufReadExt, BufReader};

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
    /// Ouvre une session chiffrée vers un host.
    Connect {
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
        Command::Connect {
            target,
            server,
            server_pin,
            api_url,
            api_token,
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
            let mut chan = SecureChannel::initiate(stream, &identity).await?;

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
            println!("Tapez un message, Ctrl+D pour quitter.");

            let mut lines = BufReader::new(tokio::io::stdin()).lines();
            loop {
                tokio::select! {
                    line = lines.next_line() => match line? {
                        Some(l) => chan.send(l.as_bytes()).await?,
                        None => break,
                    },
                    msg = chan.recv() => match msg? {
                        Some(m) => println!("{}", String::from_utf8_lossy(&m)),
                        None => {
                            println!("Le host a fermé la session.");
                            return Ok(());
                        }
                    },
                }
            }
            chan.close().await?;
            rv.close();
            Ok(())
        }
    }
}
