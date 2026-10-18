# IPsec Client

A pure-Rust IKEv2/IPsec remote-access VPN client, built in two parts:

- **`ipsec-service`**: the service that owns the IKE and ESP state, the tunnel adapter, routes
  and DNS:
  - on Windows, a Windows service running as LocalSystem, with a Wintun adapter
  - on Linux, a systemd service running as the unprivileged `ipsec-client` account with only
    `CAP_NET_ADMIN` and `CAP_NET_BIND_SERVICE`, with a TUN device (in development, feature 002)
  - on macOS, a launchd daemon running as root, with a utun interface (in development,
    feature 004)
- **`ipsec-gui`**: an unprivileged, cross-platform window with a system tray (Windows,
  Linux and macOS). It controls the service over a versioned local IPC protocol.

The protocol functionality comes from the `ike-connect` prototype, re-implemented in this
workspace with no dependency on the prototype crates:

- **IKEv2 handshake**: IKE_SA_INIT and IKE_AUTH, with PSK or with PSK + EAP-MSCHAPv2.
- **NAT traversal**: NAT-T to gateway port 4500 from an ephemeral local port.
- **Mode-config**: the internal address and DNS servers.
- **ESP**: AES-256-GCM-16 or AES-256-CBC/HMAC-SHA-256-128, over Wintun, a Linux TUN device or a
  macOS utun.
- **Liveness and teardown**: keepalives, DPD, and an IKE DELETE on disconnect.

The work is organised in features:

- 001: the Windows client
- 002: the Linux service and desktop
- 003: connecting from the Windows sign-in screen (Pre-Login Connect)
- 004: macOS (in development)

## Architecture

```text
 ipsec-gui (user)                         ipsec-service (LocalSystem)
 ┌──────────────────────┐   named pipe    ┌────────────────────────────────────────┐
 │ egui window + tray   │  \\.\pipe\      │ server ── ConnectionManager (vpn-core) │
 │ conn: command conn + │  IpsecClient.v1 │            │ session (IKE)  datapath   │
 │       event conn     │◀───────────────▶│            ▼                (ESP)      │
 └──────────────────────┘  JSON frames,   │  ike (protocol)   Wintun · IP Helper · │
   links ipc-proto only    DACL: SY,BA,IU │                   DPAPI · journal      │
                                          └────────────────────────────────────────┘
```

| Crate | Purpose | `unsafe` |
|-------|---------|----------|
| `crates/ike` | IKEv2/ESP/EAP codecs, key schedule, DH, SK payload, anti-replay | forbidden |
| `crates/ipc-proto` | GUI↔service messages, framing, blocking client | forbidden |
| `crates/vpn-core` | Session driver, data path, state machine, profile store, mocks | forbidden |
| `crates/ipsec-service` | IPC server and host. Windows: SCM, Wintun, IP Helper, DPAPI, pipe. Linux: systemd, TUN, iproute2/resolvectl, Unix socket. macOS: launchd, utun, route/ifconfig/scutil, Unix socket. | `src/windows/`, `src/linux/sys.rs` and `src/macos/sys.rs` only |
| `crates/ipsec-gui` | eframe window + tray-icon + notifications | `src/pipe_owner.rs` (Windows) and `src/macos.rs` (macOS) only |
| `crates/ipsec-plap` | Pre-Login Connect: the sign-in screen provider DLL (logic and bounded IPC done; COM layer pending) | `src/pipe_owner.rs` and the COM layer (not yet written), Windows only |

On Linux the service listens on `/run/ipsec-client/ipsec-client.sock`. The socket's permissions
admit only root and the `ipsec-client` group. On macOS it listens on
`/var/run/ipsec-client/ipsec-client.sock`, open to root and the VPN group (`admin` unless an
administrator chose another), and the GUI uses it only if root owns it.

## Build & test

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release
```

The tests include end-to-end runs of the real session and data-path code against an
in-process mock IKEv2 gateway (`vpn-core/tests/end_to_end.rs`), covering:

- PSK and EAP connects
- a wrong password, and a gateway AUTH mismatch
- an INVALID_KE group switch
- gateway lost, and deleted by the gateway
- auto-reconnect
- rollback and crash-journal cleanup
- log redaction

They also include an IPC integration test against the real binary
(`ipsec-service/tests/mock_service.rs`).

On Linux, the GUI needs `pkg-config`, `libgtk-3-dev`, `libxdo-dev` and
`libayatana-appindicator3-dev`.

On a Windows machine you can still lint the Linux code. The GUI is left out because its GTK
dependencies need Linux:

```sh
rustup target add x86_64-unknown-linux-gnu
cargo clippy --target x86_64-unknown-linux-gnu --all-targets -p ike -p ipc-proto -p vpn-core -p ipsec-service -p ipsec-plap -- -D warnings
```

The macOS code (feature 004, in development) is linted the same way:

```sh
rustup target add aarch64-apple-darwin
cargo clippy --target aarch64-apple-darwin --all-targets -p ike -p ipc-proto -p vpn-core -p ipsec-service -p ipsec-gui -- -D warnings
```

CI (`.github/workflows/ci.yml`) runs these jobs:

- **Windows, Ubuntu 24.04 and macOS 15 gates:** fmt, clippy and tests.
- **Root-only tests:** the Linux TUN device; on macOS the utun, routes and DNS.
- **End-to-end tests of the real service:** on Linux against a strongSwan gateway in network
  namespaces (`sudo tests/linux-e2e/run.sh`); on macOS against the `vpn-core` mock gateway
  on a loopback alias (`sudo tests/macos-e2e/run.sh`).
- **Installers**, uploaded as build artifacts:
  - `windows-msi`: the MSI (Wintun 0.14.1 is downloaded and checksum-verified)
  - `linux-packages`: the `.deb` and `.rpm`
  - `macos-installer`: an unsigned universal `.pkg` (the app and the root service
    daemon) and a `.dmg` holding it. CI installs, upgrades and uninstalls it on the
    runner (`tests/macos-e2e/package.sh`).

Pushing a `v*` tag runs `.github/workflows/release.yml`: it builds the macOS installer, signs
and notarizes it when the Apple Developer ID secrets are configured (see
`packaging/macos/sign-and-notarize.sh`), and attaches it to a draft release.

## Run

### GUI development on any OS (simulated tunnels)

```sh
cargo run -p ipsec-service -- run --mock   # terminal 1
cargo run -p ipsec-gui                     # terminal 2
```

On Windows, clients send nothing over `\\.\pipe\IpsecClient.v1` unless SYSTEM or
Administrators own the pipe. That keeps passwords away from another user's process that
took the name. A mock service runs as you, so on Windows give it a private pipe name, and set
the same name in both terminals:

```bat
set IPSEC_CLIENT_PIPE=\\.\pipe\IpsecClient.dev
```

In mock mode, a password of `fail` simulates an authentication failure, and the gateway
`unreachable.invalid` simulates a timeout.

### Real tunnels (Windows, elevated)

1. Download `wintun.dll` (amd64) from https://www.wintun.net, and put it next to
   `ipsec-service.exe`.
2. Install the service: `ipsec-service install`. It registers with automatic start under
   LocalSystem and starts.
3. Run `ipsec-gui` as a normal user. Create a profile and connect from the window or the tray.

Other commands:

- `ipsec-service run`: the service in a console, which is useful for debugging. Ctrl-C stops
  it cleanly. It runs as you, not as LocalSystem, so it cannot read secrets the installed
  service saved: those profiles behave as if no secret were saved. Secrets saved in `run` are
  machine-scope until the service next starts and re-seals them.
- `ipsec-service stop`, `uninstall` and `cleanup`.

Data lives in `%ProgramData%\IpsecClient`, which only SYSTEM and Administrators can access:

| Path | Contents |
|------|----------|
| `profiles.json` | Profiles, with secrets DPAPI-encrypted under the service account (LocalSystem) key |
| `netstate.json` | The network-change journal |
| `logs\` | Daily rotating logs |

The service runs IKE_SA_INIT from UDP source port 500 if it is free. If the Windows IKEEXT
service holds that port, it falls back to an ephemeral port.

### Windows installer (MSI)

```powershell
.\installer\build.ps1 -Wintun <path to wintun\bin\amd64\wintun.dll>
```

The script needs the .NET SDK, and installs WiX 5 as a repo-local dotnet tool on first use. It builds the
release binaries and writes `target\installer\IpsecClient-<version>-x64.msi`. Without
`-Wintun`, it looks for `wintun.dll` in `target\release`, then `target\debug`.

The MSI is per-machine. It installs to `C:\Program Files\IpsecClient` and:

- registers and starts the `IpsecClient` service, the same way `ipsec-service install` does
  (automatic start, LocalSystem, restart 5 s after a failure)
- adds a Start menu shortcut
- starts the tray hidden at every logon (`HKLM\...\Run`)

Uninstalling stops the service, which removes the tunnel, and deletes the service. It keeps
`%ProgramData%\IpsecClient`, so profiles survive a reinstall. Upgrades replace the previous
version in place once the workspace version in `Cargo.toml` is raised.

If the service was registered earlier with `ipsec-service install`, run
`ipsec-service uninstall` first. Otherwise the MSI can't create a service with the same name.

### Real tunnels (Linux, in development)

Install the package (see below), or run the service by hand as root:

```sh
sudo target/release/ipsec-service run       # foreground; Ctrl-C or SIGTERM stops cleanly
target/release/ipsec-gui                    # as a normal user in the ipsec-client group
```

With the package, the `ipsec-client.service` systemd unit runs it:

- `sudo ipsec-service install | uninstall | start | stop` wrap `systemctl`.
- `sudo ipsec-service cleanup` replays the network-change journal.

Users must be in the `ipsec-client` group, then log in again. Others see "not allowed to control
the VPN".

| Path | Contents |
|------|----------|
| `/var/lib/ipsec-client/profiles.json` | Profiles, with secrets encrypted under the machine key |
| `/var/lib/ipsec-client/secret.key` | The machine key (0600, service account only) |
| `/var/lib/ipsec-client/netstate.json` | The network-change journal |
| `/var/lib/ipsec-client/logs/` | Daily rotating logs (also in `journalctl -u ipsec-client`) |

DNS uses systemd-resolved: the VPN servers are set on the tunnel interface with the `~.`
routing domain. Without resolved, the service backs up and rewrites `/etc/resolv.conf`. This
needs root, so the packages depend on systemd-resolved.

### Real tunnels (macOS, in development)

Install the package (`target/macos/IpsecClient-<version>.pkg` from `packaging/macos/build.sh`,
or the CI artifact). It installs `IPsec Client.app`, the service daemon
(`net.ipsec-client.service`) and the `ipsec-service` command, and starts the daemon. The
package is unsigned until a Developer ID is configured, so open it with right-click › Open.

- `sudo ipsec-service install | start | stop` drive `launchctl`. If an administrator turned
  the daemon off under System Settings › General › Login Items, `start` says so.
- `sudo ipsec-service uninstall` removes the daemon, the app and the command, and keeps
  profiles; `uninstall --remove-data` deletes them too.
- `ipsec-service access-group` shows the group allowed to control the VPN (`admin` by
  default); `sudo ipsec-service access-group <group>` changes it.
- For debugging, `sudo ipsec-service stop`, then `sudo ipsec-service run` in the foreground.
  `sudo ipsec-service cleanup` replays the network-change journal.

The app lives in the menu bar (no Dock icon), can start at login, and posts notifications.

| Path | Contents |
|------|----------|
| `/Library/Application Support/IpsecClient/profiles.json` | Profiles, with secrets encrypted under the machine key |
| `/Library/Application Support/IpsecClient/secret.key` | The machine key (root only, 0600) |
| `/Library/Application Support/IpsecClient/netstate.json` | The network-change journal |
| `/Library/Logs/IpsecClient/` | Daily rotating logs; lifecycle events and errors also go to the unified log |

DNS is set through a service of its own in the dynamic store, so the network settings in
System Settings are never edited, and a reboot clears it too.

### Linux packages

```sh
cargo install cargo-deb cargo-generate-rpm
packaging/linux/build.sh            # or --deb-only / --rpm-only
sudo apt install ./target/debian/ipsec-client_*.deb    # Ubuntu 22.04+, Debian 12+
sudo dnf install ./target/generate-rpm/*.rpm           # Fedora 39+
```

The `ipsec-client` package installs:

- both programs, the systemd unit, the account (sysusers.d), and a polkit rule for the DNS
  changes
- the desktop entry, a tray autostart entry, and the icons

Installing creates the account and group, adds the installing user to the group, and enables
and starts the service. Removing it stops the service, which tears down any tunnel, and keeps
`/var/lib/ipsec-client`. A Debian `purge` deletes it. The package maintainer field is a
placeholder to set before publishing.

### Pre-Login Connect (Windows, in development)

Pre-Login Connect lets users connect the VPN from the Windows sign-in screen, through
**Network sign-in**. The service side already works:

- administrator-chosen sign-in profiles (`ipsec-service plc enable <name>`)
- the sign-out policy (`plc policy`)
- unattended profile import (`profile import`)

The sign-in screen component itself is not built yet. The administrator guide, including the
recovery procedure, is [docs/pre-login-connect.md](docs/pre-login-connect.md).

## Status

- **Windows (001):**
  - The protocol core, IPC, engine and GUI build and pass their tests. The pipe and DPAPI are
    exercised by tests.
  - A live tunnel has been run against a FortiGate: it connected and carried traffic in both
    directions, and the status showed the full-tunnel routes and the VPN DNS servers. The
    routing table and DNS were not checked independently.
  - The MSI installer builds and passes validation.
  - The formal real-tunnel validation checklist is still open.
- **Linux (002):**
  - The service code is written: TUN, network and DNS configuration, machine-key secrets,
    systemd, the socket and the packages. The logic is unit-tested on every OS.
  - CI builds everything on Ubuntu 24.04, including the GTK tray, runs the root-only TUN test,
    and passes the end-to-end test against strongSwan (PSK and EAP-MSCHAPv2, routes, DNS,
    traffic through the tunnel, cleanup). A manual validation on a desktop VM is still open.
- **Pre-Login Connect (003):**
  - The service side is done, with tests: sign-in profiles, administrator checks, sign-out
    policy, the `plc` and `profile import` commands, and the sign-in logic and bounded IPC.
  - The sign-in screen DLL's COM layer and its installer feature wait on a VM spike (T001).
- **macOS (004):**
  - The service (utun, routes, DNS, socket and access group, launchd, logging), the installer
    and the menu-bar app are written. Their logic is unit-tested on every OS.
  - CI on macOS 15 runs the gates, the root-only utun/route/DNS tests, an end-to-end test
    against the mock gateway, and installs, upgrades and removes the package.
  - Not yet run on a real Mac, and not against a real gateway. Signing waits for a Developer ID.

Not in v1:

- certificate authentication
- in-place rekeying (the client reconnects instead)
- IPv6 inner traffic
- IKE over TCP
- COOKIE retry
- split DNS
