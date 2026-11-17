//! Agent launchd (macOS) et service utilisateur systemd (Linux), plus la
//! vérification des mises à jour toutes les 6 heures avec les droits root :
//! démon launchd ou timer systemd qui lancent `creamote-host update`.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Context;

#[cfg(target_os = "macos")]
const AGENT_PLIST: &str = "/Library/LaunchAgents/org.creamote.host.plist";
#[cfg(target_os = "macos")]
const UPDATE_DAEMON: &str = "/Library/LaunchDaemons/org.creamote.host.update.plist";
#[cfg(not(target_os = "macos"))]
const USER_UNIT: &str = "/etc/systemd/user/creamote-host.service";
#[cfg(not(target_os = "macos"))]
const UPDATE_SERVICE: &str = "/etc/systemd/system/creamote-host-update.service";
#[cfg(not(target_os = "macos"))]
const UPDATE_TIMER: &str = "/etc/systemd/system/creamote-host-update.timer";

/// Démon launchd (root) de mise à jour.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn update_daemon(exe: &Path) -> String {
    let exe = xml_escape(&exe.display().to_string());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>org.creamote.host.update</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>update</string>
    </array>
    <key>StartInterval</key>
    <integer>21600</integer>
    <key>StandardOutPath</key>
    <string>/Library/Logs/Creamote-update.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Logs/Creamote-update.log</string>
</dict>
</plist>
"#
    )
}

/// Service et timer systemd (système) de mise à jour.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub fn update_units(exe: &Path) -> (String, String) {
    let service = format!(
        "[Unit]\n\
         Description=Creamote host : mise à jour\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         ExecStart=\"{}\" update\n",
        exe.display()
    );
    let timer = "[Unit]\n\
         Description=Creamote host : vérification des mises à jour\n\
         \n\
         [Timer]\n\
         OnBootSec=10min\n\
         OnUnitActiveSec=6h\n\
         RandomizedDelaySec=1h\n\
         Persistent=true\n\
         \n\
         [Install]\n\
         WantedBy=timers.target\n"
        .to_owned();
    (service, timer)
}

/// Contenu de l'agent launchd : journal dans `~/Library/Logs`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn launch_agent(exe: &Path) -> String {
    let exe = xml_escape(&exe.display().to_string());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>org.creamote.host</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>mkdir -p "$HOME/Library/Logs" &amp;&amp; exec "$0" --service &gt;&gt;"$HOME/Library/Logs/Creamote-host.log" 2&gt;&amp;1</string>
        <string>{exe}</string>
    </array>
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
"#
    )
}

/// Service utilisateur systemd, journal dans journald.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub fn user_unit(exe: &Path) -> String {
    format!(
        "[Unit]\n\
         Description=Creamote host (accès à distance)\n\
         Documentation=https://github.com/kawakode/creamote\n\
         PartOf=graphical-session.target\n\
         After=graphical-session.target\n\
         \n\
         [Service]\n\
         ExecStart=\"{}\" --service\n\
         Restart=always\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=graphical-session.target\n",
        exe.display()
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn current_exe() -> anyhow::Result<PathBuf> {
    std::env::current_exe().context("chemin du programme")
}

fn write_root_file(path: &str, content: &str) -> anyhow::Result<()> {
    let path = Path::new(path);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, content).with_context(|| format!("{} (lancer en root ?)", path.display()))
}

fn run(cmd: &mut Command) {
    match cmd.status() {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!("{cmd:?} : {s}"),
        Err(e) => eprintln!("{cmd:?} : {e}"),
    }
}

#[cfg(target_os = "macos")]
pub fn install() -> anyhow::Result<()> {
    let exe = current_exe()?;
    write_root_file(AGENT_PLIST, &launch_agent(&exe))?;
    write_root_file(UPDATE_DAEMON, &update_daemon(&exe))?;
    run(Command::new("launchctl").args(["bootout", "system", UPDATE_DAEMON]));
    run(Command::new("launchctl").args(["bootstrap", "system", UPDATE_DAEMON]));
    // Démarre tout de suite pour l'utilisateur connecté, s'il y en a un.
    if let Some(uid) = console_uid() {
        run(Command::new("launchctl").args(["bootstrap", &format!("gui/{uid}"), AGENT_PLIST]));
    }
    println!("Agent installé : {AGENT_PLIST}");
    println!(
        "Autorisez « creamote-host » dans Réglages Système > Confidentialité et sécurité > \
         Enregistrement de l'écran et Accessibilité (ou par un profil PPPC MDM)."
    );
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn uninstall() -> anyhow::Result<()> {
    if let Some(uid) = console_uid() {
        run(Command::new("launchctl").args(["bootout", &format!("gui/{uid}"), AGENT_PLIST]));
    }
    run(Command::new("launchctl").args(["bootout", "system", UPDATE_DAEMON]));
    let _ = std::fs::remove_file(UPDATE_DAEMON);
    match std::fs::remove_file(AGENT_PLIST) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e).context(AGENT_PLIST),
        _ => {
            println!("Agent désinstallé.");
            Ok(())
        }
    }
}

/// Utilisateur de la session graphique affichée.
#[cfg(target_os = "macos")]
fn console_uid() -> Option<String> {
    let out = Command::new("stat")
        .args(["-f", "%u", "/dev/console"])
        .output()
        .ok()?;
    let uid = String::from_utf8(out.stdout).ok()?.trim().to_owned();
    (!uid.is_empty() && uid != "0").then_some(uid)
}

#[cfg(not(target_os = "macos"))]
pub fn install() -> anyhow::Result<()> {
    let exe = current_exe()?;
    write_root_file(USER_UNIT, &user_unit(&exe))?;
    run(Command::new("systemctl").args(["--global", "enable", "creamote-host.service"]));
    let (service, timer) = update_units(&exe);
    write_root_file(UPDATE_SERVICE, &service)?;
    write_root_file(UPDATE_TIMER, &timer)?;
    run(Command::new("systemctl").arg("daemon-reload"));
    run(Command::new("systemctl").args(["enable", "--now", "creamote-host-update.timer"]));
    println!("Service utilisateur installé : {USER_UNIT}");
    println!("Il démarre à la prochaine ouverture de session graphique.");
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn uninstall() -> anyhow::Result<()> {
    run(Command::new("systemctl").args(["--global", "disable", "creamote-host.service"]));
    run(Command::new("systemctl").args(["disable", "--now", "creamote-host-update.timer"]));
    let _ = std::fs::remove_file(UPDATE_TIMER);
    let _ = std::fs::remove_file(UPDATE_SERVICE);
    match std::fs::remove_file(USER_UNIT) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e).context(USER_UNIT),
        _ => {
            println!("Service désinstallé (les sessions ouvertes le gardent jusqu'à leur fin).");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_reference_the_binary_in_service_mode() {
        let exe = Path::new("/opt/Creamote & co/creamote-host");
        let plist = launch_agent(exe);
        assert!(plist.contains("<string>/opt/Creamote &amp; co/creamote-host</string>"));
        assert!(plist.contains("--service"));
        let unit = user_unit(exe);
        assert!(unit.contains("ExecStart=\"/opt/Creamote & co/creamote-host\" --service\n"));
        assert!(unit.contains("WantedBy=graphical-session.target"));
        assert!(update_daemon(exe).contains("<string>update</string>"));
        let (service, timer) = update_units(exe);
        assert!(service.contains("ExecStart=\"/opt/Creamote & co/creamote-host\" update\n"));
        assert!(timer.contains("OnUnitActiveSec=6h\n"));
    }
}
