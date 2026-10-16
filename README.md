# IPsec Client

A pure-Rust IKEv2/IPsec remote-access VPN client, built in two parts:

- **`ipsec-service`**: a privileged Windows service (LocalSystem). It owns the IKE and ESP
  state, the Wintun adapter, routes and DNS.
- **`ipsec-gui`**: an unprivileged, cross-platform window with a system tray (Windows,
  Linux and macOS). It controls the service over a versioned local IPC protocol.

The protocol functionality comes from the `ike-connect` prototype, re-implemented in this
workspace with no dependency on the prototype crates:

- **IKEv2 handshake**: IKE_SA_INIT and IKE_AUTH, with PSK or with PSK + EAP-MSCHAPv2.
- **NAT traversal**: NAT-T to gateway port 4500 from an ephemeral local port.
- **Mode-config**: the internal address and DNS servers.
- **ESP**: AES-256-GCM-16 or AES-256-CBC/HMAC-SHA-256-128, over Wintun.
- **Liveness and teardown**: keepalives, DPD, and an IKE DELETE on disconnect.

Specs live in [`specs/001-ipsec-vpn-client/`](specs/001-ipsec-vpn-client/) (Spec Kit), and the
project's principles in [`.specify/memory/constitution.md`](.specify/memory/constitution.md).

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
| `crates/ipsec-service` | SCM host, IPC server, Wintun / IP Helper / DPAPI / pipe back-ends | Windows modules only |
| `crates/ipsec-gui` | eframe window + tray-icon + notifications | none |

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

Linux GUI build dependencies: `libgtk-3-dev`, `libxdo-dev` and
`libayatana-appindicator3-dev`.

## Run

### GUI development on any OS (simulated tunnels)

```sh
cargo run -p ipsec-service -- run --mock   # terminal 1
cargo run -p ipsec-gui                     # terminal 2
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
  it cleanly.
- `ipsec-service stop`, `uninstall` and `cleanup`.

Data lives in `%ProgramData%\IpsecClient`, which only SYSTEM and Administrators can access:

| Path | Contents |
|------|----------|
| `profiles.json` | Profiles, with secrets DPAPI-encrypted |
| `netstate.json` | The network-change journal |
| `logs\` | Daily rotating logs |

The service runs IKE_SA_INIT from UDP source port 500 if it is free. If the Windows IKEEXT
service holds that port, it falls back to an ephemeral port.

## Status

The protocol core, IPC, engine and GUI build and pass their tests. The Windows platform layer
(Wintun, IP Helper routes and DNS, DPAPI, the SCM, the named pipe) compiles, and the pipe and
DPAPI are exercised by tests. **A live tunnel against a real gateway has not been validated
yet.** Follow the "Real tunnel" steps in
[`quickstart.md`](specs/001-ipsec-vpn-client/quickstart.md) to do that. The Linux and macOS
tray code paths compile only on those platforms, so they are unverified from a Windows build.

Not in v1:

- certificate authentication
- in-place rekeying (the client reconnects instead)
- IPv6 inner traffic
- IKE over TCP
- COOKIE retry
- split DNS
- service back-ends for Linux and macOS
