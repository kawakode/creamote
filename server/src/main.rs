//! `creamote-server` : rendezvous, relay et gestion de parc auto-hébergeables.

use std::io::BufRead;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use creamote_server::{Config, Policy, Server, db::Db};

#[derive(Parser)]
#[command(
    version,
    about = "Serveur Creamote : rendezvous, relay et gestion de parc"
)]
struct Args {
    /// Adresse d'écoute (UDP).
    #[arg(long, default_value = "0.0.0.0:21400")]
    listen: SocketAddr,
    /// Dossier des données (certificat, base SQLite par défaut).
    #[arg(long, default_value = "creamote-data")]
    data_dir: PathBuf,
    /// Adresse du relay annoncée aux pairs (par défaut : celle du serveur).
    #[arg(long)]
    relay_addr: Option<String>,
    /// Mode serveur public : une session relay par IP, 10 min par session,
    /// pas de gestion de parc.
    #[arg(long)]
    public: bool,
    /// Sessions relay simultanées (0 = illimité). Par défaut : 200 en mode
    /// public, illimité sinon.
    #[arg(long)]
    max_relay_sessions: Option<u32>,
    /// Sessions relay simultanées par IP du demandeur (0 = illimité). Par
    /// défaut : 1 en mode public, illimité sinon.
    #[arg(long)]
    max_relay_sessions_per_ip: Option<u32>,
    /// Durée maximale d'une session relay en secondes (0 = illimitée). Par
    /// défaut : 600 en mode public, illimitée sinon.
    #[arg(long)]
    max_relay_seconds: Option<u32>,
    /// Base de données de la gestion de parc : `sqlite://…` ou
    /// `postgres://…`. Par défaut : SQLite dans le dossier des données.
    #[arg(long, env = "CREAMOTE_DATABASE_URL")]
    database_url: Option<String>,
    /// Adresse HTTP de l'API de gestion (en clair : à placer derrière un
    /// reverse proxy TLS si elle n'est pas sur 127.0.0.1).
    #[arg(long, default_value = "127.0.0.1:21401")]
    api_listen: SocketAddr,
    /// L'API est derrière un reverse proxy de confiance : lire l'adresse du
    /// client dans `X-Forwarded-For`. N'activez pas sans proxy, sinon un
    /// client peut contourner la limitation des tentatives de connexion.
    #[arg(long, env = "CREAMOTE_TRUST_FORWARDED_FOR")]
    trust_forwarded_for: bool,
    /// URL publique de la console (`https://admin.example.org`), exigée par
    /// la connexion OIDC pour l'URL de retour.
    #[arg(long, env = "CREAMOTE_PUBLIC_URL")]
    public_url: Option<String>,
    /// Émetteur OpenID Connect (active la connexion SSO).
    #[arg(long, env = "CREAMOTE_OIDC_ISSUER", requires_all = ["oidc_client_id", "public_url"])]
    oidc_issuer: Option<String>,
    #[arg(long, env = "CREAMOTE_OIDC_CLIENT_ID")]
    oidc_client_id: Option<String>,
    /// Secret du client OIDC (préférez la variable d'environnement).
    #[arg(long, env = "CREAMOTE_OIDC_CLIENT_SECRET", hide_env_values = true)]
    oidc_client_secret: Option<String>,
    /// Libellé du bouton de connexion SSO.
    #[arg(long, env = "CREAMOTE_OIDC_NAME", default_value = "SSO")]
    oidc_name: String,
    /// Accepter les e-mails que le fournisseur ne déclare pas vérifiés
    /// (nécessaire pour Entra ID, qui n'envoie pas `email_verified`).
    #[arg(long, env = "CREAMOTE_OIDC_ALLOW_UNVERIFIED_EMAIL")]
    oidc_allow_unverified_email: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Crée un compte. Le mot de passe est lu sur l'entrée standard.
    UserAdd {
        #[arg(long)]
        email: String,
        #[arg(long)]
        name: String,
        /// Super-administrateur du serveur (crée les entités).
        #[arg(long)]
        superadmin: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    std::fs::create_dir_all(&args.data_dir)?;
    let database_url = args
        .database_url
        .clone()
        .unwrap_or_else(|| format!("sqlite://{}", args.data_dir.join("creamote.db").display()));

    if let Some(Command::UserAdd {
        email,
        name,
        superadmin,
    }) = args.command
    {
        let db = Db::connect(&database_url).await?;
        eprintln!("Mot de passe (12 caractères minimum), puis Entrée :");
        let mut password = String::new();
        std::io::stdin().lock().read_line(&mut password)?;
        let password = password.trim_end_matches(['\r', '\n']);
        anyhow::ensure!(
            password.chars().count() >= creamote_server::auth::MIN_PASSWORD_LEN,
            "mot de passe trop court"
        );
        let id = db.create_user(&email, &name, password, superadmin).await?;
        db.audit(
            None,
            None,
            "user.create",
            &id,
            serde_json::json!({ "email": email, "via": "cli" }),
        )
        .await?;
        println!("Compte créé : {email} ({id})");
        return Ok(());
    }

    let mut policy = if args.public {
        Policy::public()
    } else {
        Policy::private()
    };
    if let Some(n) = args.max_relay_sessions {
        policy.max_relay_sessions = n;
    }
    if let Some(n) = args.max_relay_sessions_per_ip {
        policy.max_relay_sessions_per_ip = n;
    }
    if let Some(s) = args.max_relay_seconds {
        policy.max_relay_seconds = s;
    }
    // Pas de gestion de parc sur le serveur officiel.
    let (database_url, api_listen) = if policy.public_mode {
        (None, None)
    } else {
        (Some(database_url), Some(args.api_listen))
    };

    let args_public_url = args.public_url.clone();
    let server = Server::start(Config {
        listen: args.listen,
        data_dir: Some(args.data_dir),
        relay_addr: args.relay_addr,
        policy: policy.clone(),
        database_url,
        api_listen,
        trust_forwarded_for: args.trust_forwarded_for,
        oidc: args
            .oidc_issuer
            .map(|issuer| creamote_server::oidc::OidcConfig {
                issuer,
                client_id: args.oidc_client_id.unwrap_or_default(),
                client_secret: args.oidc_client_secret,
                public_url: args.public_url.clone().unwrap_or_default(),
                display_name: args.oidc_name,
                allow_unverified_email: args.oidc_allow_unverified_email,
            }),
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
        "Relay      : {} sessions max, {} par IP, {} s max par session (0 = illimité)",
        policy.max_relay_sessions, policy.max_relay_sessions_per_ip, policy.max_relay_seconds
    );
    match server.api_addr() {
        Some(a) => {
            println!("API        : http://{a}/api/v1");
            println!("Console    : http://{a}/");
            if let Some(url) = &args_public_url {
                println!("URL publique : {url}");
            }
        }
        None => println!("API        : désactivée (mode public)"),
    }
    println!("Les pairs se connectent avec --server <adresse> --server-pin <empreinte>.");

    tokio::signal::ctrl_c().await?;
    server.shutdown().await;
    Ok(())
}
