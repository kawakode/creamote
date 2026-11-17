//! Mise à jour automatique du client (greffon `updater` de Tauri).
//!
//! Actif seulement si la configuration embarquée déclare une clé publique
//! (`plugins.updater.pubkey`), ajoutée par le workflow de release : une
//! version compilée à la main ne cherche jamais de mise à jour. Le paquet
//! téléchargé doit être signé par cette clé (minisign), sinon il est refusé.

use tauri::{AppHandle, Context, Runtime};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tauri_plugin_updater::UpdaterExt;

/// La configuration embarquée active-t-elle la mise à jour ?
pub fn enabled<R: Runtime>(context: &Context<R>) -> bool {
    context
        .config()
        .plugins
        .0
        .get("updater")
        .and_then(|u| u.get("pubkey"))
        .and_then(|k| k.as_str())
        .is_some_and(|k| !k.trim().is_empty())
}

/// Vérifie en tâche de fond et propose l'installation.
pub fn spawn_check<R: Runtime>(app: AppHandle<R>) {
    tauri::async_runtime::spawn(async move {
        if let Err(e) = check(&app).await {
            tracing::info!("vérification de mise à jour : {e:#}");
        }
    });
}

async fn check<R: Runtime>(app: &AppHandle<R>) -> anyhow::Result<()> {
    let Some(update) = app.updater()?.check().await? else {
        return Ok(());
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .message(format!(
            "Creamote {} est disponible (vous avez la version {}).\n\nL'installer maintenant ? \
             Le client redémarrera.",
            update.version, update.current_version
        ))
        .title("Mise à jour de Creamote")
        .kind(MessageDialogKind::Info)
        .buttons(MessageDialogButtons::OkCancelCustom(
            "Installer".into(),
            "Plus tard".into(),
        ))
        .show(move |ok| {
            let _ = tx.send(ok);
        });
    if !rx.await.unwrap_or(false) {
        return Ok(());
    }
    update.download_and_install(|_, _| {}, || {}).await?;
    app.restart();
}
