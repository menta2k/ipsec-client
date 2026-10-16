//! Service identity and file locations (contracts/service-cli.md).

use std::path::PathBuf;

pub const SERVICE_NAME: &str = "IpsecClient";
pub const DISPLAY_NAME: &str = "IPsec VPN Client Service";
pub const DESCRIPTION: &str =
    "Establishes IPsec/IKEv2 VPN tunnels on behalf of the IPsec Client GUI.";

/// `%ProgramData%\IpsecClient` for the real service; a per-user temporary
/// directory in mock mode.
pub fn data_dir(mock: bool) -> PathBuf {
    if mock {
        return std::env::temp_dir().join("ipsec-client-mock");
    }
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("IpsecClient")
}
