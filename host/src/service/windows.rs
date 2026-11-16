//! Service Windows `CreamoteHost`.
//!
//! Un service tourne dans la session 0, sans accès à l'écran. Il lance donc
//! le host (`creamote-host --service`) dans la session affichée à l'écran,
//! avec son propre jeton SYSTEM rattaché à cette session : le host peut
//! capturer le bureau et injecter les entrées quel que soit l'utilisateur
//! connecté. Le service surveille la session active toutes les 2 s et
//! relance le host quand elle change ou quand il s'arrête.
//!
//! Le journal du host est écrit dans `%ProgramData%\Creamote\host.log`.

#![allow(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::Context;
use windows::Win32::Foundation::{
    CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation, WAIT_OBJECT_0,
};
use windows::Win32::Security::{
    DuplicateTokenEx, SecurityImpersonation, SetTokenInformation, TOKEN_ACCESS_MASK,
    TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_SESSIONID, TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DUPLICATE, TOKEN_QUERY, TokenPrimary, TokenSessionId,
};
use windows::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, GetCurrentProcess,
    OpenProcessToken, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW, TerminateProcess,
    WaitForSingleObject,
};
use windows::core::{PCWSTR, PWSTR};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "CreamoteHost";
const DISPLAY_NAME: &str = "Creamote Host";
const POLL: Duration = Duration::from_secs(2);
/// Taille au-delà de laquelle le journal est renommé en `host.log.1`.
const LOG_MAX: u64 = 10 * 1024 * 1024;

pub fn install() -> anyhow::Result<()> {
    let exe = std::env::current_exe()?;
    secure_data_dir()?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("gestionnaire de services (lancer en administrateur ?)")?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![OsString::from("service"), OsString::from("run")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager
        .create_service(
            &info,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
        )
        .context("création du service")?;
    service.set_description("Rend cette machine accessible à distance avec Creamote.")?;
    // Relance automatique en cas d'arrêt inattendu.
    let restart = ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(5),
    };
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(3600)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart.clone(), restart.clone(), restart]),
    })?;
    service
        .start::<&OsStr>(&[])
        .context("démarrage du service")?;
    println!("Service {SERVICE_NAME} installé et démarré.");
    Ok(())
}

pub fn uninstall() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("gestionnaire de services (lancer en administrateur ?)")?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
        for _ in 0..20 {
            std::thread::sleep(Duration::from_millis(500));
            if service.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
        }
    }
    service.delete()?;
    println!("Service {SERVICE_NAME} désinstallé.");
    Ok(())
}

/// `%ProgramData%\Creamote` : accès réservé à SYSTEM et aux
/// administrateurs (la clé d'identité de la machine y est).
pub fn secure_data_dir() -> anyhow::Result<()> {
    let dir = crate::config::program_data();
    std::fs::create_dir_all(&dir)?;
    let status = Command::new("icacls")
        .arg(&dir)
        .args([
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "/grant:r",
            "*S-1-5-32-544:(OI)(CI)F",
        ])
        .status()
        .context("icacls")?;
    anyhow::ensure!(status.success(), "icacls : {status}");
    Ok(())
}

/// Point d'entrée quand le gestionnaire de services lance `service run`.
pub fn run_dispatcher() -> anyhow::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("à lancer par le gestionnaire de services (`service install`)")?;
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!("service : {e:#}");
    }
}

fn run_service() -> anyhow::Result<()> {
    let (stop_tx, stop_rx) = mpsc::channel();
    let handler = move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(SERVICE_NAME, handler)?;
    let set = |state, accept| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(5),
            process_id: None,
        })
    };
    set(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
    )?;

    // Aussi quand le service est installé par le MSI plutôt que par
    // `service install`.
    if let Err(e) = secure_data_dir() {
        tracing::warn!("droits de %ProgramData%\\Creamote : {e:#}");
    }
    std::thread::spawn(update_loop);
    let exe = std::env::current_exe()?;
    let mut agent: Option<(u32, Agent)> = None;
    loop {
        // 0xFFFFFFFF : aucune session attachée à la console (transition).
        let session = unsafe { WTSGetActiveConsoleSessionId() };
        let stale = match &agent {
            Some((s, a)) => *s != session || a.exited(),
            None => true,
        };
        if stale {
            agent = None; // termine l'ancien host
            if session != u32::MAX {
                match Agent::spawn(&exe, session) {
                    Ok(a) => agent = Some((session, a)),
                    Err(e) => tracing::warn!("lancement du host dans la session {session} : {e:#}"),
                }
            }
        }
        if stop_rx.recv_timeout(POLL).is_ok() {
            break;
        }
    }
    drop(agent);
    set(ServiceState::Stopped, ServiceControlAccept::empty())?;
    Ok(())
}

/// Vérifie les mises à jour 10 minutes après le démarrage, puis toutes les
/// 6 heures. L'installeur arrête et relance lui-même le service.
fn update_loop() {
    std::thread::sleep(Duration::from_secs(600));
    let Ok(rt) = tokio::runtime::Runtime::new() else {
        return;
    };
    loop {
        let cfg = crate::config::HostConfig::load(&crate::config::system_config_file())
            .unwrap_or_default();
        if let Err(e) = rt.block_on(crate::update::run(&cfg, true)) {
            tracing::warn!("mise à jour : {e:#}");
        }
        std::thread::sleep(crate::update::INTERVAL);
    }
}

/// Host lancé dans une session utilisateur ; terminé quand il est détruit.
struct Agent {
    process: HANDLE,
}

// Le handle de processus peut être utilisé depuis n'importe quel thread.
unsafe impl Send for Agent {}

impl Agent {
    fn spawn(exe: &Path, session: u32) -> anyhow::Result<Self> {
        let log = open_log()?;
        let log_handle = HANDLE(log.as_raw_handle());
        unsafe {
            SetHandleInformation(log_handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)?;
        }

        let mut own = HANDLE::default();
        let mut token = HANDLE::default();
        let access: TOKEN_ACCESS_MASK = TOKEN_DUPLICATE
            | TOKEN_QUERY
            | TOKEN_ASSIGN_PRIMARY
            | TOKEN_ADJUST_SESSIONID
            | TOKEN_ADJUST_DEFAULT;
        let mut app = wide(exe.as_os_str());
        let mut cmdline = wide(OsStr::new(&format!("\"{}\" --service", exe.display())));
        let mut desktop = wide(OsStr::new("winsta0\\default"));
        let mut info = PROCESS_INFORMATION::default();
        let result = unsafe {
            (|| -> windows::core::Result<()> {
                OpenProcessToken(GetCurrentProcess(), access, &mut own)?;
                DuplicateTokenEx(
                    own,
                    TOKEN_ALL_ACCESS,
                    None,
                    SecurityImpersonation,
                    TokenPrimary,
                    &mut token,
                )?;
                SetTokenInformation(
                    token,
                    TokenSessionId,
                    (&session as *const u32).cast(),
                    std::mem::size_of::<u32>() as u32,
                )?;
                let startup = STARTUPINFOW {
                    cb: std::mem::size_of::<STARTUPINFOW>() as u32,
                    lpDesktop: PWSTR(desktop.as_mut_ptr()),
                    dwFlags: STARTF_USESTDHANDLES,
                    hStdOutput: log_handle,
                    hStdError: log_handle,
                    ..Default::default()
                };
                CreateProcessAsUserW(
                    Some(token),
                    PCWSTR(app.as_mut_ptr()),
                    Some(PWSTR(cmdline.as_mut_ptr())),
                    None,
                    None,
                    true,
                    CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                    None,
                    None,
                    &startup,
                    &mut info,
                )
            })()
        };
        unsafe {
            if !own.is_invalid() {
                let _ = CloseHandle(own);
            }
            if !token.is_invalid() {
                let _ = CloseHandle(token);
            }
        }
        result.context("CreateProcessAsUser")?;
        unsafe {
            let _ = CloseHandle(info.hThread);
        }
        tracing::info!(session, pid = info.dwProcessId, "host lancé");
        Ok(Self {
            process: info.hProcess,
        })
    }

    fn exited(&self) -> bool {
        unsafe { WaitForSingleObject(self.process, 0) == WAIT_OBJECT_0 }
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        unsafe {
            if !self.exited() {
                let _ = TerminateProcess(self.process, 0);
                let _ = WaitForSingleObject(self.process, 5000);
            }
            let _ = CloseHandle(self.process);
        }
    }
}

fn open_log() -> anyhow::Result<std::fs::File> {
    let dir = crate::config::program_data();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("host.log");
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > LOG_MAX) {
        let _ = std::fs::rename(&path, dir.join("host.log.1"));
    }
    Ok(std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?)
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}
