//! Client desktop Creamote (Tauri 2).
//!
//! L'interface (`client/ui`) est en HTML/JS sans dépendances ; ce module
//! expose les commandes de session. La vidéo arrive par un canal IPC binaire :
//! H.264 brut décodé par WebCodecs dans la WebView (décodeur matériel du
//! système), ou RGBA décodé ici par openh264 quand la WebView n'a pas
//! WebCodecs.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;
use std::sync::mpsc as std_mpsc;

use anyhow::Context;
use creamote_crypto::{DeviceId, DeviceIdentity, store};
use creamote_net::rendezvous::RendezvousClient;
use creamote_net::secure::SecureChannel;
use creamote_net::stream::PeerPath;
use creamote_net::tls::ServerPin;
use creamote_proto::permissions::Permissions;
use creamote_proto::session::v1::PointerEvent;
use creamote_session::VideoFrame;
use creamote_session::viewer::{self, Event, Handle};
use serde::Serialize;
use serde_json::json;
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::{Manager, State};
use tokio::sync::Mutex;

struct App {
    identity: Arc<DeviceIdentity>,
    session: Mutex<Option<Handle>>,
}

#[derive(Serialize)]
struct IdentityInfo {
    device_id: String,
    fingerprint: String,
}

#[tauri::command]
fn identity(app: State<'_, App>) -> IdentityInfo {
    IdentityInfo {
        device_id: app.identity.device_id().to_string(),
        fingerprint: app.identity.public().fingerprint(),
    }
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

/// Ticket de session auprès de l'API de gestion (hosts enrôlés).
async fn fetch_ticket(
    api_url: &str,
    token: &str,
    target: DeviceId,
    identity: &DeviceIdentity,
) -> anyhow::Result<Vec<u8>> {
    let url = format!("{}/api/v1/tickets", api_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(token)
        .json(&json!({
            "device_id": target.to_string(),
            "viewer_key": hex(identity.public().signing_key()),
        }))
        .send()
        .await
        .with_context(|| format!("requête {url}"))?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();
    anyhow::ensure!(
        status.is_success(),
        "ticket refusé : {status} {}",
        body["message"].as_str().unwrap_or_default()
    );
    unhex(body["ticket"].as_str().context("réponse sans ticket")?)
}

/// En-tête des images envoyées à l'interface (16 octets, petit-boutiste) :
/// type (0 = H.264 Annex B, 1 = RGBA), image clé, 2 octets nuls, largeur,
/// hauteur, numéro d'image.
fn frame_message(kind: u8, keyframe: bool, w: u32, h: u32, id: u64, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(16 + body.len());
    m.extend_from_slice(&[kind, keyframe as u8, 0, 0]);
    m.extend_from_slice(&w.to_le_bytes());
    m.extend_from_slice(&h.to_le_bytes());
    m.extend_from_slice(&(id as u32).to_le_bytes());
    m.extend_from_slice(body);
    m
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectArgs {
    server: String,
    server_pin: String,
    target: String,
    api_url: Option<String>,
    api_token: Option<String>,
    view_only: bool,
    /// La WebView n'a pas WebCodecs : décoder ici.
    decode_in_rust: bool,
}

#[tauri::command]
async fn connect(
    app: State<'_, App>,
    args: ConnectArgs,
    events: Channel<serde_json::Value>,
    frames: Channel<InvokeResponseBody>,
) -> Result<(), String> {
    if let Some(old) = app.session.lock().await.take() {
        old.close().await;
    }
    let handle = open(&app.identity, args, events, frames)
        .await
        .map_err(|e| format!("{e:#}"))?;
    *app.session.lock().await = Some(handle);
    Ok(())
}

async fn open(
    identity: &Arc<DeviceIdentity>,
    args: ConnectArgs,
    events: Channel<serde_json::Value>,
    frames: Channel<InvokeResponseBody>,
) -> anyhow::Result<Handle> {
    let target = DeviceId::parse(&args.target).context("ID invalide (9 chiffres attendus)")?;
    let pin: ServerPin = args
        .server_pin
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("empreinte du serveur invalide : {e}"))?;
    let addr = tokio::net::lookup_host(args.server.trim())
        .await
        .with_context(|| format!("adresse introuvable : {}", args.server))?
        .next()
        .with_context(|| format!("adresse introuvable : {}", args.server))?;
    let ticket = match (&args.api_url, &args.api_token) {
        (Some(url), Some(token)) if !url.is_empty() && !token.is_empty() => {
            fetch_ticket(url, token, target, identity).await?
        }
        _ => Vec::new(),
    };

    let mut rv = RendezvousClient::register(addr, pin, identity)
        .await
        .context("connexion au serveur")?;
    let grant = rv.request_session_with_ticket(target, ticket).await?;
    // Connexion directe si possible, relay sinon.
    let stream = rv.connector().viewer(&grant).await?;
    let direct = stream.path() == PeerPath::Direct;
    let chan = SecureChannel::initiate(stream, identity).await?;
    anyhow::ensure!(
        chan.remote().device_id() == target,
        "le pair authentifié n'est pas {target}"
    );
    let _ = events.send(json!({
        "type": "connected",
        "code": chan.verification_code(),
        "fingerprint": chan.remote().fingerprint(),
        "direct": direct,
        // La limite du serveur public ne s'applique qu'au relay.
        "maxSessionSeconds": if direct { 0 } else { grant.max_session_seconds },
    }));

    let requested = if args.view_only {
        Permissions::VIEW
    } else {
        Permissions::VIEW | Permissions::CONTROL
    };
    let (tx, rx) = chan.split();
    let (handle, mut session_events) = viewer::start(
        tx,
        rx,
        viewer::Options {
            display_name: hostname(),
            requested,
            ..Default::default()
        },
    );

    let decoder = args
        .decode_in_rust
        .then(|| spawn_decoder(handle.clone(), frames.clone()));
    tauri::async_runtime::spawn(async move {
        // Le client de rendezvous reste ouvert pendant la session.
        let _rv = rv;
        while let Some(ev) = session_events.recv().await {
            match ev {
                Event::Accepted { granted, displays } => {
                    let displays: Vec<_> = displays
                        .iter()
                        .map(|d| json!({"id": d.id, "name": d.name, "width": d.width, "height": d.height, "primary": d.primary}))
                        .collect();
                    let _ = events.send(json!({
                        "type": "accepted",
                        "granted": granted.names(),
                        "displays": displays,
                    }));
                }
                Event::Video(c) => {
                    let _ = events.send(json!({
                        "type": "video",
                        "displayId": c.display_id,
                        "width": c.width,
                        "height": c.height,
                        "fps": c.max_fps,
                        "bitrate": c.target_bitrate_bps,
                        "encoder": c.encoder,
                    }));
                }
                Event::Frame(f) => match &decoder {
                    Some(d) => {
                        let _ = d.send(f);
                    }
                    None => {
                        let m = frame_message(0, f.keyframe, 0, 0, f.frame_id, &f.data);
                        let _ = frames.send(InvokeResponseBody::Raw(m));
                    }
                },
                // Transfert de fichiers : pas encore proposé par cette
                // interface (la session ne l'active pas).
                Event::Files(_) => {}
                Event::Ended { reason, message } => {
                    let _ = events.send(json!({
                        "type": "ended",
                        "reason": format!("{reason:?}"),
                        "message": message,
                    }));
                    break;
                }
            }
        }
    });
    Ok(handle)
}

/// Décodage openh264 dans un thread dédié ; les images RGBA partent vers
/// l'interface et sont acquittées une fois décodées.
fn spawn_decoder(
    handle: Handle,
    frames: Channel<InvokeResponseBody>,
) -> std_mpsc::Sender<VideoFrame> {
    let (tx, rx) = std_mpsc::channel::<VideoFrame>();
    std::thread::spawn(move || {
        let Ok(mut dec) = creamote_codec::H264Decoder::new() else {
            return;
        };
        while let Ok(f) = rx.recv() {
            match dec.decode(&f.data) {
                Ok(Some(img)) => {
                    let m =
                        frame_message(1, f.keyframe, img.width, img.height, f.frame_id, &img.rgba);
                    let _ = frames.send(InvokeResponseBody::Raw(m));
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!("décodage : {e}");
                    let h = handle.clone();
                    tauri::async_runtime::spawn(async move { h.request_keyframe().await });
                }
            }
            let (h, id) = (handle.clone(), f.frame_id);
            tauri::async_runtime::spawn(async move { h.ack(id).await });
        }
    });
    tx
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "Creamote".into())
}

async fn with_session<F, Fut>(app: &State<'_, App>, f: F) -> Result<(), String>
where
    F: FnOnce(Handle) -> Fut,
    Fut: std::future::Future<Output = creamote_session::Result<()>>,
{
    let handle = app.session.lock().await.clone();
    match handle {
        Some(h) => f(h).await.map_err(|e| e.to_string()),
        None => Err("pas de session".into()),
    }
}

#[tauri::command]
async fn ack(app: State<'_, App>, frame_id: u32) -> Result<(), String> {
    with_session(&app, |h| async move { h.ack(frame_id.into()).await }).await
}

#[tauri::command]
async fn key(app: State<'_, App>, hid: u32, pressed: bool) -> Result<(), String> {
    with_session(&app, |h| async move { h.key(hid, pressed).await }).await
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn pointer(
    app: State<'_, App>,
    display_id: u32,
    x: f32,
    y: f32,
    buttons: u32,
    wheel_dx: f32,
    wheel_dy: f32,
) -> Result<(), String> {
    let p = PointerEvent {
        display_id,
        x,
        y,
        buttons,
        wheel_dx,
        wheel_dy,
    };
    with_session(&app, |h| async move { h.pointer(p).await }).await
}

#[tauri::command]
async fn request_keyframe(app: State<'_, App>) -> Result<(), String> {
    with_session(&app, |h| async move { h.request_keyframe().await }).await
}

#[tauri::command]
async fn select_display(app: State<'_, App>, display_id: u32) -> Result<(), String> {
    with_session(&app, |h| async move {
        h.select_display(display_id, creamote_session::DEFAULT_FPS, 0)
            .await
    })
    .await
}

#[tauri::command]
async fn disconnect(app: State<'_, App>) -> Result<(), String> {
    if let Some(h) = app.session.lock().await.take() {
        h.close().await;
    }
    Ok(())
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    tauri::Builder::default()
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            let (identity, _) = store::load_or_create(&dir.join("creamote-client.identity"))?;
            app.manage(App {
                identity: Arc::new(identity),
                session: Mutex::new(None),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            identity,
            connect,
            ack,
            key,
            pointer,
            request_keyframe,
            select_display,
            disconnect
        ])
        .run(tauri::generate_context!())
        .expect("démarrage de l'application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_header_layout() {
        let m = frame_message(1, true, 640, 480, 7, &[9, 9]);
        assert_eq!(&m[..4], &[1, 1, 0, 0]);
        assert_eq!(u32::from_le_bytes(m[4..8].try_into().unwrap()), 640);
        assert_eq!(u32::from_le_bytes(m[8..12].try_into().unwrap()), 480);
        assert_eq!(u32::from_le_bytes(m[12..16].try_into().unwrap()), 7);
        assert_eq!(&m[16..], &[9, 9]);
    }

    #[test]
    fn hex_roundtrip() {
        assert_eq!(unhex(&hex(&[0, 255, 16])).unwrap(), [0, 255, 16]);
        assert!(unhex("zz").is_err());
    }
}
