//! Client desktop Creamote (Tauri 2).
//!
//! L'interface (`client/ui`) est en HTML/JS sans dépendances ; ce module
//! expose les commandes de session. La vidéo arrive par un canal IPC binaire :
//! H.264 brut décodé par WebCodecs dans la WebView (décodeur matériel du
//! système), ou RGBA décodé ici par openh264 quand la WebView n'a pas
//! WebCodecs.
//!
//! Presse-papier partagé et transfert de fichiers : voir [`sharing`].
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod sharing;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex as StdMutex};

use anyhow::Context;
use creamote_crypto::{DeviceId, DeviceIdentity, store};
use creamote_net::rendezvous::RendezvousClient;
use creamote_net::secure::SecureChannel;
use creamote_net::stream::PeerPath;
use creamote_net::tls::ServerPin;
use creamote_proto::permissions::Permissions;
use creamote_proto::session::v1::PointerEvent;
use creamote_session::creamote_transfer::clipboard::{ClipboardBackend, NativeClipboard};
use creamote_session::creamote_transfer::files::{AcceptPolicy, FilesHandle};
use creamote_session::viewer::{self, Event, Handle};
use creamote_session::{FilesConfig, Sharing, VideoFrame};
use serde::Serialize;
use serde_json::json;
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::{DragDropEvent, Manager, State, WindowEvent};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_opener::OpenerExt;
use tokio::sync::Mutex;

struct App {
    identity: Arc<DeviceIdentity>,
    /// Dossier où sont écrits les fichiers reçus.
    downloads: PathBuf,
    session: Mutex<Option<Live>>,
}

/// Session en cours.
struct Live {
    handle: Handle,
    /// Événements vers l'interface.
    events: Channel<serde_json::Value>,
    /// Transferts de fichiers, une fois accordés par le host.
    files: Arc<StdMutex<Option<FilesHandle>>>,
    /// Synchronisation du presse-papier active (bouton de la barre).
    clipboard: Arc<AtomicBool>,
}

impl Live {
    fn files(&self) -> Option<FilesHandle> {
        self.files.lock().expect("verrou sain").clone()
    }
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
    /// Synchroniser le presse-papier dès le début (modifiable ensuite).
    #[serde(default)]
    clipboard: bool,
}

#[tauri::command]
async fn connect(
    app: State<'_, App>,
    args: ConnectArgs,
    events: Channel<serde_json::Value>,
    frames: Channel<InvokeResponseBody>,
) -> Result<(), String> {
    if let Some(old) = app.session.lock().await.take() {
        old.handle.close().await;
    }
    let live = open(&app.identity, &app.downloads, args, events, frames)
        .await
        .map_err(|e| format!("{e:#}"))?;
    *app.session.lock().await = Some(live);
    Ok(())
}

async fn open(
    identity: &Arc<DeviceIdentity>,
    downloads: &std::path::Path,
    args: ConnectArgs,
    events: Channel<serde_json::Value>,
    frames: Channel<InvokeResponseBody>,
) -> anyhow::Result<Live> {
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
    // Presse-papier et fichiers toujours proposés au host (qui décide de
    // les accorder) ; le presse-papier peut être suspendu localement.
    let clipboard_on = Arc::new(AtomicBool::new(args.clipboard));
    let clipboard = match NativeClipboard::new() {
        Ok(c) => Some(Box::new(sharing::GatedClipboard::new(
            Box::new(c),
            clipboard_on.clone(),
        )) as Box<dyn ClipboardBackend>),
        Err(e) => {
            tracing::warn!("presse-papier indisponible : {e}");
            None
        }
    };
    let (transfer_tx, mut transfers) = tokio::sync::mpsc::unbounded_channel();
    let sharing = Sharing {
        clipboard,
        files: Some(FilesConfig {
            dest: downloads.to_owned(),
            policy: AcceptPolicy::Ask,
            events: Some(transfer_tx),
        }),
    };
    let transfer_events = events.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(ev) = transfers.recv().await {
            let _ = transfer_events.send(sharing::event_json(&ev));
        }
    });

    let (tx, rx) = chan.split();
    let (handle, mut session_events) = viewer::start_with(
        tx,
        rx,
        viewer::Options {
            display_name: hostname(),
            requested,
            ..Default::default()
        },
        sharing,
    );
    let live = Live {
        handle: handle.clone(),
        events: events.clone(),
        files: Arc::new(StdMutex::new(None)),
        clipboard: clipboard_on,
    };
    let files_slot = live.files.clone();
    let downloads = downloads.to_string_lossy().into_owned();

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
                Event::Displays(displays) => {
                    let displays: Vec<_> = displays
                        .iter()
                        .map(|d| json!({"id": d.id, "name": d.name, "width": d.width, "height": d.height, "primary": d.primary}))
                        .collect();
                    let _ = events.send(json!({ "type": "displays", "displays": displays }));
                }
                Event::Files(f) => {
                    *files_slot.lock().expect("verrou sain") = Some(f);
                    let _ = events.send(json!({ "type": "files", "folder": downloads }));
                }
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
    Ok(live)
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
    let handle = app.session.lock().await.as_ref().map(|l| l.handle.clone());
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
    if let Some(l) = app.session.lock().await.take() {
        l.handle.close().await;
    }
    Ok(())
}

// ----- Presse-papier et fichiers -----

#[tauri::command]
async fn set_clipboard(app: State<'_, App>, enabled: bool) -> Result<(), String> {
    match app.session.lock().await.as_ref() {
        Some(l) => {
            l.clipboard.store(enabled, Ordering::Relaxed);
            Ok(())
        }
        None => Err("pas de session".into()),
    }
}

/// Transferts de la session et canal d'événements, si accordés.
async fn session_files(app: &App) -> Result<(FilesHandle, Channel<serde_json::Value>), String> {
    let session = app.session.lock().await;
    let live = session.as_ref().ok_or("pas de session")?;
    let files = live
        .files()
        .ok_or("transfert de fichiers non autorisé par le host")?;
    Ok((files, live.events.clone()))
}

/// Envoie des fichiers choisis par l'utilisateur hors de la WebView.
async fn send_local(app: &App, paths: Vec<PathBuf>) -> Result<(), String> {
    let (files, events) = session_files(app).await?;
    tauri::async_runtime::spawn(async move {
        sharing::send_paths(&files, paths, |v| {
            let _ = events.send(v);
        })
        .await;
    });
    Ok(())
}

/// Boîte de dialogue native de choix de fichiers (ou d'un dossier) à
/// envoyer.
#[tauri::command]
async fn pick_and_send(app: tauri::AppHandle, folder: bool) -> Result<(), String> {
    let state = app.state::<App>();
    // Vérifié avant d'ouvrir la boîte de dialogue.
    session_files(&state).await?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let dialog = app.dialog().file().set_title("Envoyer au poste distant");
    if folder {
        dialog.pick_folder(move |p| {
            let _ = tx.send(p.into_iter().collect::<Vec<_>>());
        });
    } else {
        dialog.pick_files(move |p| {
            let _ = tx.send(p.unwrap_or_default());
        });
    }
    let picked: Vec<PathBuf> = rx
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|p| p.into_path().ok())
        .collect();
    if picked.is_empty() {
        return Ok(());
    }
    send_local(&state, picked).await
}

#[tauri::command]
async fn accept_file(app: State<'_, App>, id: u64) -> Result<(), String> {
    let (files, _) = session_files(&app).await?;
    files.accept(id).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn reject_file(app: State<'_, App>, id: u64) -> Result<(), String> {
    let (files, _) = session_files(&app).await?;
    files
        .reject(id, "refusé par l'utilisateur")
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn cancel_file(app: State<'_, App>, id: u64, direction: String) -> Result<(), String> {
    let d = sharing::parse_direction(&direction).ok_or("sens inconnu")?;
    let (files, _) = session_files(&app).await?;
    files.cancel(id, d).await.map_err(|e| e.to_string())
}

/// Ouvre le dossier de réception dans le gestionnaire de fichiers.
#[tauri::command]
async fn open_downloads(app: tauri::AppHandle) -> Result<(), String> {
    let dir = app.state::<App>().downloads.clone();
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| e.to_string())?;
    app.opener()
        .open_path(dir.to_string_lossy(), None::<&str>)
        .map_err(|e| e.to_string())
}

/// Glisser-déposer de fichiers sur la fenêtre : l'interface affiche une zone
/// de dépôt, les fichiers déposés sont envoyés au pair.
fn on_drag_drop(app: &tauri::AppHandle, ev: &DragDropEvent) {
    // Survol : rien à faire (émis à chaque mouvement de souris).
    if matches!(ev, DragDropEvent::Over { .. }) {
        return;
    }
    let app = app.clone();
    let ev = ev.clone();
    tauri::async_runtime::spawn(async move {
        let state = app.state::<App>();
        let Ok((_, events)) = session_files(&state).await else {
            return;
        };
        match ev {
            DragDropEvent::Enter { paths, .. } if !paths.is_empty() => {
                let _ = events.send(json!({ "type": "drag", "over": true }));
            }
            DragDropEvent::Leave => {
                let _ = events.send(json!({ "type": "drag", "over": false }));
            }
            DragDropEvent::Drop { paths, .. } => {
                let _ = events.send(json!({ "type": "drag", "over": false }));
                if let Err(e) = send_local(&state, paths).await {
                    tracing::warn!("dépôt de fichiers : {e}");
                }
            }
            _ => {}
        }
    });
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            let (identity, _) = store::load_or_create(&dir.join("creamote-client.identity"))?;
            // Fichiers reçus : Téléchargements/Creamote (créé au premier
            // fichier accepté).
            let downloads = app
                .path()
                .download_dir()
                .unwrap_or_else(|_| dir.clone())
                .join("Creamote");
            app.manage(App {
                identity: Arc::new(identity),
                downloads,
                session: Mutex::new(None),
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::DragDrop(ev) = event {
                on_drag_drop(window.app_handle(), ev);
            }
        })
        .invoke_handler(tauri::generate_handler![
            identity,
            connect,
            ack,
            key,
            pointer,
            request_keyframe,
            select_display,
            disconnect,
            set_clipboard,
            pick_and_send,
            accept_file,
            reject_file,
            cancel_file,
            open_downloads
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
