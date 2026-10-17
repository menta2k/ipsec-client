//! Service Control Manager integration (research R4): the SCM entry point,
//! and install/uninstall/start/stop management commands.

use crate::host::{self, Mode};
use crate::paths::{DESCRIPTION, DISPLAY_NAME, SERVICE_NAME};
use std::ffi::{OsStr, OsString};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType, SessionChangeReason,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

define_windows_service!(ffi_service_main, service_main);

/// Hand the process over to the SCM dispatcher (`ipsec-service service`).
pub fn run_dispatcher() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        super::eventlog::error(&format!("IpsecClient service failed: {e}"));
    }
}

fn status(
    state: ServiceState,
    accept: ServiceControlAccept,
    wait: Duration,
    code: u32,
) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint: wait,
        process_id: None,
    }
}

/// Only a real sign-out ends the tunnel; lock/unlock, fast user switching
/// and remote (dis)connects do not (003 FR-014).
pub fn is_signout(reason: SessionChangeReason) -> bool {
    reason == SessionChangeReason::SessionLogoff
}

type SignoutHook = Box<dyn Fn() -> bool + Send + Sync>;

fn run_service() -> Result<(), Box<dyn std::error::Error>> {
    let (stop_tx, stop_rx) = channel();
    // Filled once the host is running; the handler is registered before.
    let signout: Arc<Mutex<Option<SignoutHook>>> = Arc::new(Mutex::new(None));
    let signout_slot = signout.clone();
    let handler = move |ev| match ev {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::SessionChange(p) => {
            if is_signout(p.reason) {
                // Synchronous: the network is restored before Winlogon shows
                // the sign-in screen again (003 research R5).
                if let Some(hook) = signout_slot.lock().unwrap().as_ref() {
                    if hook() {
                        super::eventlog::info("IpsecClient disconnected the VPN at sign-out");
                    }
                }
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let sh = service_control_handler::register(SERVICE_NAME, handler)?;
    sh.set_service_status(status(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        Duration::from_secs(15),
        0,
    ))?;

    let host = match host::start(Mode::Real, false) {
        Ok(h) => h,
        Err(e) => {
            super::eventlog::error(&format!("IpsecClient service could not start: {e}"));
            sh.set_service_status(status(
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                Duration::ZERO,
                1,
            ))?;
            return Err(e.into());
        }
    };
    *signout.lock().unwrap() = Some(Box::new(host.signout_hook()));
    sh.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP
            | ServiceControlAccept::SHUTDOWN
            | ServiceControlAccept::SESSION_CHANGE,
        Duration::ZERO,
        0,
    ))?;
    super::eventlog::info("IpsecClient service started");

    let _ = stop_rx.recv();
    // FR-007: end the session and remove all network changes before exiting.
    sh.set_service_status(status(
        ServiceState::StopPending,
        ServiceControlAccept::empty(),
        Duration::from_secs(25),
        0,
    ))?;
    host.stop();
    super::eventlog::info("IpsecClient service stopped");
    sh.set_service_status(status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        Duration::ZERO,
        0,
    ))?;
    Ok(())
}

fn manager(access: ServiceManagerAccess) -> windows_service::Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, access)
}

pub fn install() -> windows_service::Result<()> {
    let m = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let exe = std::env::current_exe().map_err(windows_service::Error::Winapi)?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![OsString::from("service")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let svc = m.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
    svc.set_description(DESCRIPTION)?;
    svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 3600)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(5),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(5),
            },
            ServiceAction {
                action_type: ServiceActionType::None,
                delay: Duration::ZERO,
            },
        ]),
    })?;
    svc.start(&[] as &[&OsStr])?;
    Ok(())
}

pub fn uninstall() -> windows_service::Result<()> {
    let m = manager(ServiceManagerAccess::CONNECT)?;
    let svc = m.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;
    if svc.query_status()?.current_state != ServiceState::Stopped {
        let _ = svc.stop();
        wait_for(&svc, ServiceState::Stopped, Duration::from_secs(30))?;
    }
    svc.delete()?;
    Ok(())
}

pub fn start() -> windows_service::Result<()> {
    let m = manager(ServiceManagerAccess::CONNECT)?;
    let svc = m.open_service(
        SERVICE_NAME,
        ServiceAccess::START | ServiceAccess::QUERY_STATUS,
    )?;
    svc.start(&[] as &[&OsStr])?;
    wait_for(&svc, ServiceState::Running, Duration::from_secs(20))
}

pub fn stop() -> windows_service::Result<()> {
    let m = manager(ServiceManagerAccess::CONNECT)?;
    let svc = m.open_service(
        SERVICE_NAME,
        ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
    )?;
    svc.stop()?;
    wait_for(&svc, ServiceState::Stopped, Duration::from_secs(30))
}

fn wait_for(
    svc: &windows_service::service::Service,
    want: ServiceState,
    max: Duration,
) -> windows_service::Result<()> {
    let until = Instant::now() + max;
    while Instant::now() < until {
        if svc.query_status()?.current_state == want {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Ok(())
}

/// Exit code for a management error: 5 when access was denied.
pub fn exit_code(e: &windows_service::Error) -> i32 {
    let denied = match e {
        windows_service::Error::Winapi(io) => io.raw_os_error() == Some(5),
        _ => false,
    };
    if denied {
        5
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_logoff_counts_as_signout() {
        use SessionChangeReason::*;
        assert!(is_signout(SessionLogoff));
        for r in [
            ConsoleConnect,
            ConsoleDisconnect,
            RemoteConnect,
            RemoteDisconnect,
            SessionLogon,
            SessionLock,
            SessionUnlock,
            SessionRemoteControl,
            SessionCreate,
            SessionTerminate,
        ] {
            assert!(!is_signout(r), "{r:?}");
        }
    }
}
