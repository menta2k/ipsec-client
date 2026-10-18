//! Service identity and file locations (contracts/service-cli.md).

use std::ffi::OsString;
use std::path::PathBuf;

#[cfg(windows)]
pub const SERVICE_NAME: &str = "IpsecClient";
#[cfg(windows)]
pub const DISPLAY_NAME: &str = "IPsec VPN Client Service";
#[cfg(windows)]
pub const DESCRIPTION: &str =
    "Establishes IPsec/IKEv2 VPN tunnels on behalf of the IPsec Client GUI.";

/// macOS (004 data-model.md): the launchd label and the installed service
/// binary. The `net.ipsec-client` prefix is a placeholder until
/// the bundle identifier is fixed with the Developer ID (004 research R7).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub const LAUNCHD_LABEL: &str = "net.ipsec-client.service";
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub const SERVICE_BINARY: &str = "/Library/PrivilegedHelperTools/ipsec-service";

/// macOS: the data and log directories (004 contracts/macos-system-integration.md).
pub const MACOS_DATA_DIR: &str = "/Library/Application Support/IpsecClient";
pub const MACOS_LOG_DIR: &str = "/Library/Logs/IpsecClient";

/// State directory of the real service, or a per-user temporary directory
/// in mock mode:
/// * Windows: `%ProgramData%\IpsecClient`
/// * Linux: `$IPSEC_CLIENT_STATE_DIR` or `/var/lib/ipsec-client` (002)
/// * macOS: `$IPSEC_CLIENT_STATE_DIR` or `/Library/Application Support/IpsecClient` (004)
pub fn data_dir(mock: bool) -> PathBuf {
    if mock {
        return std::env::temp_dir().join("ipsec-client-mock");
    }
    state_dir_for(Platform::current(), |k| std::env::var_os(k))
}

/// IPC socket of the real Linux or macOS service (`$IPSEC_CLIENT_SOCKET`
/// overrides).
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub fn socket_path() -> PathBuf {
    socket_path_for(Platform::current(), |k| std::env::var_os(k))
}

/// Log directory of the real service: `logs` under the state directory, except
/// on macOS, where logs belong in `/Library/Logs/IpsecClient` (004).
#[allow(dead_code)]
pub fn log_dir() -> PathBuf {
    log_dir_for(Platform::current(), |k| std::env::var_os(k))
}

#[derive(Clone, Copy)]
enum Platform {
    Windows,
    Linux,
    MacOs,
}

impl Platform {
    fn current() -> Platform {
        if cfg!(windows) {
            Platform::Windows
        } else if cfg!(target_os = "macos") {
            Platform::MacOs
        } else {
            Platform::Linux
        }
    }
}

fn state_dir_for(p: Platform, env: impl Fn(&str) -> Option<OsString>) -> PathBuf {
    match p {
        Platform::Windows => env("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("IpsecClient"),
        Platform::Linux => env("IPSEC_CLIENT_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/lib/ipsec-client")),
        Platform::MacOs => env("IPSEC_CLIENT_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(MACOS_DATA_DIR)),
    }
}

fn log_dir_for(p: Platform, env: impl Fn(&str) -> Option<OsString>) -> PathBuf {
    match p {
        // A test's private state directory keeps its logs with it.
        Platform::MacOs if env("IPSEC_CLIENT_STATE_DIR").is_none() => PathBuf::from(MACOS_LOG_DIR),
        _ => state_dir_for(p, env).join("logs"),
    }
}

#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
fn socket_path_for(p: Platform, env: impl Fn(&str) -> Option<OsString>) -> PathBuf {
    let system = match p {
        Platform::MacOs => ipc_proto::client::MACOS_SYSTEM_SOCKET,
        _ => ipc_proto::client::SYSTEM_SOCKET,
    };
    env(ipc_proto::client::SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(system))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(vars: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<OsString> {
        move |k| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.into())
    }

    #[test]
    fn linux_state_dir_defaults_and_override() {
        assert_eq!(
            state_dir_for(Platform::Linux, env(&[])),
            PathBuf::from("/var/lib/ipsec-client")
        );
        assert_eq!(
            state_dir_for(
                Platform::Linux,
                env(&[("IPSEC_CLIENT_STATE_DIR", "/tmp/s")])
            ),
            PathBuf::from("/tmp/s")
        );
    }

    #[test]
    fn windows_state_dir_is_unchanged() {
        assert_eq!(
            state_dir_for(Platform::Windows, env(&[("ProgramData", r"D:\PD")])),
            PathBuf::from(r"D:\PD").join("IpsecClient")
        );
        assert_eq!(
            state_dir_for(Platform::Windows, env(&[("IPSEC_CLIENT_STATE_DIR", "/x")])),
            PathBuf::from(r"C:\ProgramData").join("IpsecClient")
        );
    }

    #[test]
    fn socket_path_defaults_and_override() {
        assert_eq!(
            socket_path_for(Platform::Linux, env(&[])),
            PathBuf::from("/run/ipsec-client/ipsec-client.sock")
        );
        assert_eq!(
            socket_path_for(
                Platform::Linux,
                env(&[("IPSEC_CLIENT_SOCKET", "/tmp/t.sock")])
            ),
            PathBuf::from("/tmp/t.sock")
        );
        assert_eq!(
            socket_path_for(Platform::MacOs, env(&[])),
            PathBuf::from("/var/run/ipsec-client/ipsec-client.sock")
        );
        assert_eq!(
            socket_path_for(
                Platform::MacOs,
                env(&[("IPSEC_CLIENT_SOCKET", "/tmp/t.sock")])
            ),
            PathBuf::from("/tmp/t.sock")
        );
    }

    #[test]
    fn macos_state_and_log_dirs() {
        assert_eq!(
            state_dir_for(Platform::MacOs, env(&[])),
            PathBuf::from("/Library/Application Support/IpsecClient")
        );
        assert_eq!(
            log_dir_for(Platform::MacOs, env(&[])),
            PathBuf::from("/Library/Logs/IpsecClient")
        );
        // Tests with a private state directory keep the logs inside it.
        let e = env(&[("IPSEC_CLIENT_STATE_DIR", "/tmp/s")]);
        assert_eq!(state_dir_for(Platform::MacOs, &e), PathBuf::from("/tmp/s"));
        assert_eq!(
            log_dir_for(Platform::MacOs, &e),
            PathBuf::from("/tmp/s/logs")
        );
        // Elsewhere logs stay under the state directory.
        assert_eq!(
            log_dir_for(Platform::Linux, env(&[])),
            PathBuf::from("/var/lib/ipsec-client/logs")
        );
    }
}
