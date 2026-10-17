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

/// State directory of the real service, or a per-user temporary directory
/// in mock mode:
/// * Windows: `%ProgramData%\IpsecClient`
/// * Linux: `$IPSEC_CLIENT_STATE_DIR` or `/var/lib/ipsec-client` (002)
pub fn data_dir(mock: bool) -> PathBuf {
    if mock {
        return std::env::temp_dir().join("ipsec-client-mock");
    }
    state_dir_for(Platform::current(), |k| std::env::var_os(k))
}

/// IPC socket of the real Linux service (`$IPSEC_CLIENT_SOCKET` overrides).
// TODO(T016): used by the Linux host; remove the allow once wired.
#[allow(dead_code)]
pub fn socket_path() -> PathBuf {
    socket_path_for(|k| std::env::var_os(k))
}

#[derive(Clone, Copy)]
enum Platform {
    Windows,
    Linux,
}

impl Platform {
    fn current() -> Platform {
        if cfg!(windows) {
            Platform::Windows
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
    }
}

#[allow(dead_code)]
fn socket_path_for(env: impl Fn(&str) -> Option<OsString>) -> PathBuf {
    env(ipc_proto::client::SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(ipc_proto::client::SYSTEM_SOCKET))
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
            socket_path_for(env(&[])),
            PathBuf::from("/run/ipsec-client/ipsec-client.sock")
        );
        assert_eq!(
            socket_path_for(env(&[("IPSEC_CLIENT_SOCKET", "/tmp/t.sock")])),
            PathBuf::from("/tmp/t.sock")
        );
    }
}
