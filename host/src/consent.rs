//! Consentement de l'utilisateur présent, par une boîte de dialogue native :
//! `MessageBox` sous Windows, `osascript` (AppleScript) sous macOS, zenity ou
//! kdialog sous Linux ; à défaut, question dans le terminal du host.
//!
//! Sans réponse dans le délai imparti, la demande est refusée et la boîte
//! fermée.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use creamote_session::host::{CONSENT_TIMEOUT, Consent, ConsentRequest};

const TITLE: &str = "Creamote : demande de connexion";
/// Fermer la boîte un peu avant que la session n'abandonne.
const DIALOG_TIMEOUT: Duration = CONSENT_TIMEOUT.saturating_sub(Duration::from_secs(2));

/// Texte présenté à l'utilisateur. Le nom annoncé par le viewer n'est pas
/// vérifié ; l'appareil et le compte le sont.
pub fn message(req: &ConsentRequest) -> String {
    let name: String = req
        .viewer_name
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let mut m = if name.is_empty() {
        "Quelqu'un souhaite accéder à cet ordinateur.\n\n".to_string()
    } else {
        format!("« {name} » souhaite accéder à cet ordinateur.\n\n")
    };
    if let Some(email) = &req.user_email {
        m += &format!("Compte vérifié : {email}\n");
    }
    m += &format!(
        "Appareil : {} (empreinte {})\nCode de vérification : {}\n\n\
         Vérifiez ce code avec votre interlocuteur avant d'accepter.",
        req.device_id, req.fingerprint, req.verification_code
    );
    m
}

pub fn ask(req: ConsentRequest) -> Consent {
    let text = message(&req);
    let answer = platform_dialog(&text).or_else(|| terminal(&text));
    let answer = answer.unwrap_or_else(|| {
        eprintln!(
            "Aucun moyen de demander le consentement (ni boîte de dialogue, ni terminal) : refus."
        );
        Consent::Deny
    });
    println!("Réponse de l'utilisateur présent : {answer:?}");
    answer
}

/// Lance une commande et attend sa fin au plus `DIALOG_TIMEOUT` ; `None`
/// si elle n'a pas pu être lancée. En cas de dépassement, elle est tuée.
#[cfg_attr(windows, allow(dead_code))]
fn run(mut cmd: Command) -> Option<(Option<i32>, String)> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + DIALOG_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut out = String::new();
                if let Some(mut o) = child.stdout.take() {
                    use std::io::Read;
                    let _ = o.read_to_string(&mut out);
                }
                return Some((status.code(), out));
            }
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Some((None, String::new()));
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn platform_dialog(text: &str) -> Option<Consent> {
    if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
        return None;
    }
    let mut zenity = Command::new("zenity");
    zenity.args([
        "--question",
        "--no-markup",
        "--title",
        TITLE,
        "--text",
        text,
        "--ok-label",
        "Autoriser le contrôle",
        "--cancel-label",
        "Refuser",
        "--extra-button",
        "Vue seule",
        "--default-cancel",
    ]);
    if let Some((code, out)) = run(zenity) {
        return Some(match (code, out.trim()) {
            (Some(0), _) => Consent::Control,
            (_, "Vue seule") => Consent::ViewOnly,
            _ => Consent::Deny,
        });
    }
    let mut kdialog = Command::new("kdialog");
    kdialog.args([
        "--title",
        TITLE,
        "--yes-label",
        "Autoriser le contrôle",
        "--no-label",
        "Vue seule",
        "--cancel-label",
        "Refuser",
        "--yesnocancel",
        text,
    ]);
    run(kdialog).map(|(code, _)| match code {
        Some(0) => Consent::Control,
        Some(1) => Consent::ViewOnly,
        _ => Consent::Deny,
    })
}

#[cfg(target_os = "macos")]
fn platform_dialog(text: &str) -> Option<Consent> {
    // Le texte passe en argument (argv) : aucune interprétation AppleScript
    // du nom annoncé par le viewer.
    let secs = DIALOG_TIMEOUT.as_secs().to_string();
    let mut cmd = Command::new("osascript");
    cmd.args([
        "-e",
        "on run argv",
        "-e",
        "set r to display dialog (item 1 of argv) with title (item 2 of argv) \
         buttons {\"Refuser\", \"Vue seule\", \"Autoriser le contrôle\"} \
         default button \"Refuser\" cancel button \"Refuser\" with icon caution \
         giving up after ((item 3 of argv) as integer)",
        "-e",
        "if gave up of r then return \"\"",
        "-e",
        "return button returned of r",
        "-e",
        "end run",
        text,
        TITLE,
        &secs,
    ]);
    run(cmd).map(|(code, out)| match (code, out.trim()) {
        (Some(0), "Autoriser le contrôle") => Consent::Control,
        (Some(0), "Vue seule") => Consent::ViewOnly,
        _ => Consent::Deny,
    })
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn platform_dialog(text: &str) -> Option<Consent> {
    use windows::Win32::Foundation::{LPARAM, WPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{
        FindWindowW, IDNO, IDYES, MB_DEFBUTTON3, MB_ICONQUESTION, MB_SETFOREGROUND, MB_SYSTEMMODAL,
        MB_TOPMOST, MB_YESNOCANCEL, MessageBoxW, PostMessageW, WM_CLOSE,
    };
    use windows::core::{HSTRING, PCWSTR};

    // Titre unique, pour retrouver la boîte et la fermer à l'expiration.
    let title = format!(
        "{TITLE} ({})",
        std::process::id() ^ Instant::now().elapsed().subsec_nanos()
    );
    let body = format!("{text}\n\nOui : autoriser le contrôle\nNon : vue seule\nAnnuler : refuser");
    let (wide_title, wide_body) = (HSTRING::from(title.as_str()), HSTRING::from(body));
    let watcher_title = wide_title.clone();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watcher_done = done.clone();
    std::thread::spawn(move || {
        let deadline = Instant::now() + DIALOG_TIMEOUT;
        while Instant::now() < deadline {
            if watcher_done.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        // SAFETY : recherche de fenêtre par titre et message de fermeture.
        unsafe {
            if let Ok(hwnd) = FindWindowW(PCWSTR::null(), &watcher_title) {
                let _ = PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0));
            }
        }
    });
    // SAFETY : chaînes UTF-16 terminées par zéro, valides pendant l'appel.
    let r = unsafe {
        MessageBoxW(
            None,
            &wide_body,
            &wide_title,
            MB_YESNOCANCEL
                | MB_ICONQUESTION
                | MB_DEFBUTTON3
                | MB_TOPMOST
                | MB_SETFOREGROUND
                | MB_SYSTEMMODAL,
        )
    };
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    Some(if r == IDYES {
        Consent::Control
    } else if r == IDNO {
        Consent::ViewOnly
    } else {
        Consent::Deny
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn platform_dialog(_text: &str) -> Option<Consent> {
    None
}

/// Question dans le terminal, si le host y est attaché.
fn terminal(text: &str) -> Option<Consent> {
    use std::io::{BufRead, IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return None;
    }
    println!("\n=== {TITLE} ===\n{text}");
    print!("Autoriser ? [c] contrôle, [v] vue seule, [N] refuser : ");
    let _ = std::io::stdout().flush();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = std::io::stdin().lock().read_line(&mut line);
        let _ = tx.send(line);
    });
    let line = rx.recv_timeout(DIALOG_TIMEOUT).unwrap_or_default();
    Some(match line.trim().to_lowercase().as_str() {
        "c" | "contrôle" | "controle" => Consent::Control,
        "v" | "vue" => Consent::ViewOnly,
        _ => Consent::Deny,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use creamote_proto::permissions::Permissions;

    #[test]
    fn message_shows_verified_identity_and_strips_controls() {
        let req = ConsentRequest {
            viewer_name: "Bob\n\u{7}Support".into(),
            device_id: "123 456 789".into(),
            fingerprint: "abcd".into(),
            user_email: Some("bob@example.org".into()),
            verification_code: "042042".into(),
            requested: Permissions::VIEW,
        };
        let m = message(&req);
        assert!(m.starts_with("« BobSupport » souhaite"));
        assert!(m.contains("Compte vérifié : bob@example.org"));
        assert!(m.contains("Code de vérification : 042042"));
    }
}
