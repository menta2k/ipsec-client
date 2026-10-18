# Development

How the IPsec Client is built, tested and released. For what the product does and how to
install it, see the [README](../README.md).

## Architecture

The client has two halves that talk over a versioned local IPC protocol (length-prefixed JSON
frames):

- **`ipsec-service`**, privileged, owns everything that matters: the IKE and ESP state, the
  tunnel interface, routes, DNS and the saved secrets.
- **`ipsec-gui`**, unprivileged, is the window and tray. It never sees keys.

```text
 ipsec-gui (user)                       ipsec-service (privileged)
 ┌──────────────────────┐  local IPC    ┌────────────────────────────────────────┐
 │ egui window + tray   │  pipe/socket  │ server ── ConnectionManager (vpn-core) │
 │ command conn +       │◀─────────────▶│            │ session (IKE)  datapath   │
 │ event conn           │  JSON frames  │            ▼                (ESP)      │
 └──────────────────────┘               │  ike (protocol)   tunnel · routes ·    │
   links ipc-proto only                 │                   DNS · secrets ·      │
                                        └────────────────────────────────────────┘
```

| Platform | Service | Tunnel | IPC endpoint |
|----------|---------|--------|--------------|
| Windows | Windows service, LocalSystem | Wintun | `\\.\pipe\IpsecClient.v1` (DACL: SYSTEM, Administrators, interactive users) |
| Linux | systemd unit, user `ipsec-client` with `CAP_NET_ADMIN` and `CAP_NET_BIND_SERVICE` | TUN | `/run/ipsec-client/ipsec-client.sock` (group `ipsec-client`) |
| macOS | launchd daemon, root | utun | `/var/run/ipsec-client/ipsec-client.sock` (the VPN group, `admin` by default) |

Before sending anything, the GUI checks that the endpoint belongs to the real service: on
Windows the pipe's owner must be SYSTEM or Administrators, on macOS the socket and its
directory must belong to root, and a per-user (development) socket must belong to the user.

| Crate | Purpose | `unsafe` |
|-------|---------|----------|
| `crates/ike` | IKEv2/ESP/EAP codecs, key schedule, DH, SK payload, anti-replay | forbidden |
| `crates/ipc-proto` | GUI↔service messages, framing, blocking client, endpoint checks | forbidden |
| `crates/vpn-core` | Session driver, data path, state machine, profile store, mock gateway | forbidden |
| `crates/ipsec-service` | IPC server and host. Windows: SCM, Wintun, IP Helper, DPAPI, pipe. Linux: systemd, TUN, iproute2/resolvectl. macOS: launchd, utun, route/ifconfig/scutil. | `src/windows/`, `src/linux/sys.rs`, `src/macos/sys.rs` |
| `crates/ipsec-gui` | eframe window, tray icon, notifications, login item | `src/pipe_owner.rs` (Windows), `src/macos.rs` (macOS) |
| `crates/ipsec-plap` | Pre-Login Connect sign-in screen provider (logic and IPC; COM layer pending) | `src/pipe_owner.rs`, the COM layer (Windows) |

Every network change the service makes is written to a journal before it is applied, so a
crash or power loss is undone at the next start (`ipsec-service cleanup` does it by hand).

## Build and test

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release
```

On Linux the GUI needs `pkg-config`, `libgtk-3-dev`, `libxdo-dev` and
`libayatana-appindicator3-dev`.

From Windows you can lint the Linux and macOS code too (the Linux GUI is left out, its GTK
dependencies need Linux):

```sh
rustup target add x86_64-unknown-linux-gnu aarch64-apple-darwin
cargo clippy --target x86_64-unknown-linux-gnu --all-targets -p ike -p ipc-proto -p vpn-core -p ipsec-service -p ipsec-plap -- -D warnings
cargo clippy --target aarch64-apple-darwin --all-targets -p ike -p ipc-proto -p vpn-core -p ipsec-service -p ipsec-gui -- -D warnings
```

What the tests cover:

- **Engine end-to-end** (`vpn-core/tests/end_to_end.rs`): the real session and data-path code
  against an in-process mock IKEv2 gateway. PSK and EAP connects, wrong password, gateway
  AUTH mismatch and impostor gateways, INVALID_KE, gateway lost or deleting the SA,
  auto-reconnect (also after a silent period, as after sleep), rollback, crash-journal
  cleanup and log redaction.
- **IPC** (`ipsec-service/tests/mock_service.rs`): the real binary in mock mode.
- **Root-only platform tests** (`--ignored`): the Linux TUN device; the macOS utun, routes and
  DNS.
- **Real service end-to-end:**
  - Linux, against strongSwan in network namespaces: `sudo tests/linux-e2e/run.sh`
  - macOS, against the mock gateway on a loopback alias: `sudo tests/macos-e2e/run.sh`, plus
    the launchd lifecycle and access checks in `tests/macos-e2e/daemon.sh` and the installer
    lifecycle in `tests/macos-e2e/package.sh` (these two change the system; CI only)

## GUI development with simulated tunnels

```sh
cargo run -p ipsec-service -- run --mock   # terminal 1
cargo run -p ipsec-gui                     # terminal 2
```

On Windows the GUI only talks to a pipe owned by SYSTEM or Administrators, and the mock runs
as you, so give it a private pipe name in both terminals:

```bat
set IPSEC_CLIENT_PIPE=\\.\pipe\IpsecClient.dev
```

In mock mode a password of `fail` simulates an authentication failure, and the gateway
`unreachable.invalid` simulates a timeout.

## Building the installers

**Windows (MSI)** needs the .NET SDK; WiX 5 is installed as a repo-local tool on first use.
Download `wintun.dll` (amd64) from https://www.wintun.net:

```powershell
.\installer\build.ps1 -Wintun <path to wintun\bin\amd64\wintun.dll>
# target\installer\IpsecClient-<version>-x64.msi
```

**Linux (.deb, .rpm):**

```sh
cargo install cargo-deb cargo-generate-rpm
packaging/linux/build.sh            # or --deb-only / --rpm-only
```

The package maintainer field in `crates/ipsec-gui/Cargo.toml` is a placeholder to set before
publishing to a distribution.

**macOS (.pkg, .dmg)**, on a Mac with the Xcode command-line tools:

```sh
rustup target add aarch64-apple-darwin x86_64-apple-darwin
sh packaging/macos/build.sh         # target/macos/IpsecClient-<version>.pkg and .dmg
```

The macOS package is universal (Apple Silicon and Intel) and needs macOS 13 or later.
`packaging/macos/sign-and-notarize.sh` signs it with a Developer ID and notarizes it.

## CI

`.github/workflows/ci.yml` runs on every push and pull request:

| Job | What it does |
|-----|--------------|
| `windows` | fmt, clippy, tests; builds the MSI (Wintun 0.14.1, checksum-verified) |
| `linux` | fmt, clippy, tests, the root-only TUN test; builds the `.deb` and `.rpm` |
| `linux-e2e` | the real service against strongSwan in network namespaces |
| `macos` | builds the `.pkg` and `.dmg`, then installs, upgrades and removes the package |
| `macos-test` | fmt, clippy, tests, the root-only utun/route/DNS tests, the end-to-end, launchd and access tests |
| `macos-intel` | tests and root-only tests on Intel hardware |

The installers are uploaded as build artifacts. When an end-to-end step fails, its key log lines
are also posted as an annotation on the run.

## Releases

Raise `version` in the workspace `Cargo.toml`, commit, then push a matching tag:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

`.github/workflows/release.yml` checks that the tag matches the version, tests and builds the
MSI, the `.deb` and `.rpm`, and the macOS `.pkg` and `.dmg`, and publishes a GitHub release
with all of them, a `SHA256SUMS` file and generated notes. A tag with a hyphen (`v0.2.0-rc1`)
makes a prerelease.

The macOS package is signed and notarized when these repository secrets exist:
`MACOS_APP_CERT_P12`, `MACOS_INSTALLER_CERT_P12`, `MACOS_CERT_PASSWORD`, `MACOS_NOTARY_KEY`,
`MACOS_NOTARY_KEY_ID` and `MACOS_NOTARY_ISSUER` (see `packaging/macos/sign-and-notarize.sh`).
Without them it ships unsigned, and the release notes say so.
