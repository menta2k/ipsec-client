# IPsec Client

**A lightweight IKEv2/IPsec remote-access VPN client for Windows, Linux and macOS, written
entirely in Rust.**

IPsec Client connects your computer to a corporate IKEv2 gateway, such as a FortiGate or
strongSwan, with a pre-shared key, or with a pre-shared key plus a username and password
(EAP-MSCHAPv2). It lives in the system tray or menu bar, sets up routes and DNS for you, and
puts your network back exactly as it was when you disconnect, even after a crash.

[![CI](https://github.com/menta2k/ipsec-client/actions/workflows/ci.yml/badge.svg)](https://github.com/menta2k/ipsec-client/actions/workflows/ci.yml)

> **Status: pre-release.** The client works end to end and is tested continuously on all
> three platforms, but it has not had its full real-world validation yet. See
> [Status](#status).

## Features

- **One click from the tray.** Pick a profile from the tray or menu-bar icon and you are
  connected. The icon shows whether you are connected, connecting, or have a problem, and a
  notification tells you when that changes.
- **Works with standard gateways.** IKEv2 with a PSK or PSK + EAP-MSCHAPv2, NAT traversal,
  the gateway's internal address and DNS servers (mode-config), and ESP with AES-256-GCM or
  AES-256-CBC/HMAC-SHA-256.
- **Full tunnel or split tunnel**, decided by what the gateway offers. In full-tunnel mode the
  route to the gateway itself is protected so the tunnel never swallows its own traffic.
- **Stays connected.** Keepalives and dead-peer detection notice a lost gateway, and
  auto-reconnect brings the tunnel back after sleep, a Wi-Fi change or a gateway restart.
- **Leaves no trace.** Every route and DNS change is journaled before it is made and undone on
  disconnect, on shutdown, and at the next start after a crash.
- **Secure by design.** The part that holds keys and changes the network runs as a protected
  system service; the app you click on runs as you and never sees a key. Saved secrets are
  encrypted with the operating system's protection, and passwords never appear in logs.
- **Managed machines.** Profiles can be imported from a file by an administrator
  (`ipsec-service profile import`), and on macOS the administrator chooses which group may
  control the VPN.

## Platforms

| | Windows | Linux | macOS |
|---|---|---|---|
| Versions | Windows 10 and 11, 64-bit | Ubuntu 22.04+, Debian 12+, Fedora 39+ | macOS 13 Ventura or later, Apple Silicon and Intel |
| Installer | `.msi` | `.deb`, `.rpm` | `.pkg` (also inside a `.dmg`) |
| App | system tray | system tray (GNOME needs the AppIndicator extension) | menu bar |
| Who may connect | any signed-in user | members of the `ipsec-client` group | members of the VPN group (`admin` by default) |

## Install

Download the installer for your system from the
[Releases](https://github.com/menta2k/ipsec-client/releases) page, and check it against
`SHA256SUMS` if you like (`sha256sum -c SHA256SUMS`).

### Windows

Run `IpsecClient-<version>-x64.msi`. It installs to `C:\Program Files\IpsecClient`, starts the
IPsec Client service, adds a Start menu entry, and starts the tray icon at every sign-in.
Uninstall from **Settings › Apps**. Your profiles are kept for a later reinstall.

### Linux

```sh
sudo apt install ./ipsec-client_*_amd64.deb      # Ubuntu, Debian
sudo dnf install ./ipsec-client-*.x86_64.rpm      # Fedora
```

The package starts the service and adds you to the `ipsec-client` group. **Log out and back
in** once so the group membership takes effect, then start **IPsec Client** from your
applications menu (it also starts at login). Other users need to be added to the group:
`sudo usermod -aG ipsec-client <user>`. Removing the package keeps your profiles; `apt purge`
deletes them.

### macOS

Open `IpsecClient-<version>.pkg` (or the `.dmg`, then the package inside it). It installs
**IPsec Client** in Applications and a small background service, and starts the service.
Unsigned pre-release builds have to be opened with right-click › **Open** the first time.

The app lives in the menu bar and has no Dock icon. Turn on **Start at login** in its window if
you want it at every login. If macOS asks you to allow the background item, approve it under
**System Settings › General › Login Items**.

## Getting started

1. Open IPsec Client from the tray or menu-bar icon.
2. On **Profiles**, create a profile with the details from your administrator:
   - **Gateway**: the VPN server's name or address (port 500 by default)
   - **Local ID**: the identity the gateway expects from you (a name, an e-mail address or an
     IP address)
   - **Authentication**: pre-shared key only, or pre-shared key + username and password
   - optionally the Diffie-Hellman group, and **Auto-reconnect**
3. Click **Connect**, from the window or from the tray menu. With a username and password you
   are asked for the password, and can choose to save it.

The **Status** page shows your VPN address, the DNS servers, the routes, how long you have
been connected, and the traffic counters. **Log** shows what the service is doing, which helps when a connection
fails.

## Command line

The `ipsec-service` command manages the service. Most commands need an administrator
(`sudo` on Linux and macOS, an elevated prompt on Windows).

| Command | What it does |
|---|---|
| `ipsec-service start` / `stop` | Start or stop the service (stopping disconnects) |
| `ipsec-service install` / `uninstall` | Register or remove the service (the installers do this for you) |
| `ipsec-service uninstall --remove-data` | macOS: also delete profiles, keys and logs |
| `ipsec-service profile import <file.json>` | Create or update profiles from a file |
| `ipsec-service access-group [<group>]` | macOS: show or choose the group allowed to control the VPN |
| `ipsec-service cleanup` | Undo network changes left behind by an unclean exit |
| `ipsec-service run` | Run the service in the foreground, for troubleshooting (stop the installed one first) |

A profile file looks like this; secrets in it are encrypted as soon as they are imported:

```json
{ "profiles": [
  { "name": "Office", "gateway": "vpn.example.com", "local_id": "laptop-42",
    "auth": "eap", "username": "alice", "psk": "the-shared-key" }
] }
```

## Security

- **Privilege separation.** The service (LocalSystem on Windows, a dedicated account with only
  the network capabilities it needs on Linux, a root daemon on macOS) owns the keys, the tunnel,
  routes and DNS. The app runs as you and only sends requests.
- **Only authorized users.** The local control channel is restricted by the operating system:
  on Linux and macOS only members of the VPN group can open it, and everyone else is told they
  are not allowed to control the VPN.
- **Only the real service.** Before sending anything, the app checks that the channel belongs
  to the system service, so another program cannot impersonate it to collect a password.
- **Secrets at rest.** Saved pre-shared keys and passwords are encrypted: with DPAPI under the
  service's own account on Windows, and with a machine key readable only by the service on
  Linux and macOS. They are never written to logs.
- **Gateway authentication first.** The gateway has to prove its identity before your password
  is sent, and it has to prove it again with the result of the password exchange, so a
  look-alike gateway learns nothing.
- **Memory-safe code.** The protocol, IPC and engine crates forbid `unsafe`; the few operating
  system calls that need it are confined to small, reviewed modules.

Please report security issues privately to the maintainers rather than in public issues.

## Where things are stored

| | Windows | Linux | macOS |
|---|---|---|---|
| Profiles and keys | `%ProgramData%\IpsecClient` | `/var/lib/ipsec-client` | `/Library/Application Support/IpsecClient` |
| Logs | `%ProgramData%\IpsecClient\logs` | `/var/lib/ipsec-client/logs` and `journalctl -u ipsec-client` | `/Library/Logs/IpsecClient` and the unified log |

Profiles and keys are readable only by the service (and administrators). Logs never contain
secrets; they rotate daily and seven days are kept.

## Status

| Platform | State |
|---|---|
| **Windows** | Connected to a FortiGate and carried traffic in both directions. The MSI builds and validates. The formal real-tunnel checklist is still open. |
| **Linux** | Every CI run connects to a real strongSwan gateway (PSK and EAP), checks routes, DNS and traffic through the tunnel, and checks the cleanup. A manual desktop validation is still open. |
| **macOS** | Every CI run on real Macs (Apple Silicon and Intel) installs, upgrades and removes the package, and tests the tunnel, routes, DNS, crash recovery and access control against a test gateway. Not yet run against a real gateway, and builds are unsigned until a Developer ID is set up. |
| **Sign-in screen (Windows)** | Connecting before Windows sign-in (Pre-Login Connect) works on the service side; the sign-in screen component is still being built. See [docs/pre-login-connect.md](docs/pre-login-connect.md). |

Not supported yet: certificate authentication, IPv6 inside the tunnel, split DNS, IKE over
TCP, and in-place rekeying (the client reconnects instead).

## Building from source

```sh
cargo build --release
```

Building, testing, the CI pipeline, making releases and the architecture are described in
[docs/development.md](docs/development.md).

## License

MIT OR Apache-2.0, at your option.
