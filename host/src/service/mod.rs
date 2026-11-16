//! Installation du host comme service lancé au démarrage.
//!
//! - **Windows** : service système `CreamoteHost` (compte SYSTEM). Il lance
//!   le host dans la session de l'utilisateur affichée à l'écran et le
//!   relance quand elle change (ouverture, changement d'utilisateur) ou s'il
//!   s'arrête. Les données sont dans `%ProgramData%\Creamote`.
//! - **macOS** : agent `launchd` (`/Library/LaunchAgents`) lancé dans chaque
//!   session graphique ; seul un processus de la session peut capturer
//!   l'écran.
//! - **Linux** : service utilisateur systemd lié à `graphical-session.target`,
//!   activé pour tous les utilisateurs (`systemctl --global`).
//!
//! Le host lancé ainsi tourne avec `--service` : configuration système,
//! dossiers de données de la plateforme et reconnexion automatique.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
pub mod windows;

#[cfg(unix)]
pub use unix::{install, uninstall};
#[cfg(windows)]
pub use windows::{install, uninstall};
