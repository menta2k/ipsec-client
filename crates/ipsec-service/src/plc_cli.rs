//! `ipsec-service plc …` and `ipsec-service profile import …` (003
//! contracts/service-cli-plc.md). These talk to the running service over IPC;
//! the service decides who is an administrator.

use ipc_proto::{
    AuthMode, ClientError, CommandClient, DhGroupSel, IdType, Policy, ProfileEdit, ProfileView,
    Request, RequestError, Response, SecretString, SecretUpdate,
};
use serde::Deserialize;

/// A parsed command line.
#[derive(Debug, PartialEq, Eq)]
pub enum Cmd {
    List,
    Enable(String),
    Disable(String),
    ShowPolicy,
    SetPolicy { keep_on_signout: bool },
    DisableProvider,
    Import { file: String, sign_in: bool },
}

pub const USAGE: &str = "\
usage:
  ipsec-service plc list
  ipsec-service plc enable <profile-name>
  ipsec-service plc disable <profile-name>
  ipsec-service plc policy [keep-on-signout | disconnect-on-signout]
  ipsec-service plc disable-provider
  ipsec-service profile import <file.json> [--sign-in]";

/// Parse the words after `ipsec-service`.
pub fn parse(args: &[&str]) -> Result<Cmd, String> {
    match args {
        ["plc", "list"] => Ok(Cmd::List),
        ["plc", "enable", name] => Ok(Cmd::Enable(name.to_string())),
        ["plc", "disable", name] => Ok(Cmd::Disable(name.to_string())),
        ["plc", "policy"] => Ok(Cmd::ShowPolicy),
        ["plc", "policy", "keep-on-signout"] => Ok(Cmd::SetPolicy {
            keep_on_signout: true,
        }),
        ["plc", "policy", "disconnect-on-signout"] => Ok(Cmd::SetPolicy {
            keep_on_signout: false,
        }),
        ["plc", "disable-provider"] => Ok(Cmd::DisableProvider),
        ["profile", "import", file] => Ok(Cmd::Import {
            file: file.to_string(),
            sign_in: false,
        }),
        ["profile", "import", file, "--sign-in"] => Ok(Cmd::Import {
            file: file.to_string(),
            sign_in: true,
        }),
        _ => Err(USAGE.to_string()),
    }
}

/// One profile in an import file (contracts/service-cli-plc.md).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    name: String,
    gateway: String,
    #[serde(default = "default_port")]
    port: u16,
    local_id: String,
    #[serde(default)]
    id_type: IdType,
    #[serde(default)]
    dh_group: DhGroupSel,
    #[serde(default)]
    auth: AuthMode,
    #[serde(default)]
    username: String,
    #[serde(default)]
    auto_reconnect: bool,
    #[serde(default)]
    psk: Option<SecretString>,
    #[serde(default)]
    password: Option<SecretString>,
}

fn default_port() -> u16 {
    500
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportFile {
    profiles: Vec<Entry>,
}

/// Parse an import file into profile edits (secrets become `Set`, absent
/// ones `Keep`).
pub fn parse_import(json: &str) -> Result<Vec<ProfileEdit>, String> {
    let json = json.strip_prefix('\u{feff}').unwrap_or(json);
    let f: ImportFile =
        serde_json::from_str(json).map_err(|e| format!("invalid import file: {e}"))?;
    if f.profiles.is_empty() {
        return Err("the import file contains no profiles".into());
    }
    let secret = |s: Option<SecretString>| s.map(SecretUpdate::Set).unwrap_or(SecretUpdate::Keep);
    Ok(f.profiles
        .into_iter()
        .map(|e| ProfileEdit {
            name: e.name,
            gateway: e.gateway,
            port: e.port,
            local_id: e.local_id,
            id_type: e.id_type,
            dh_group: e.dh_group,
            auth: e.auth,
            username: e.username,
            auto_reconnect: e.auto_reconnect,
            psk: secret(e.psk),
            password: secret(e.password),
        })
        .collect())
}

/// Exit code for a failed request: 5 when administrator rights are missing.
fn code_for(e: &ClientError) -> i32 {
    match e {
        ClientError::Unauthorized
        | ClientError::Failed {
            code: RequestError::AdminRequired,
            ..
        } => 5,
        _ => 1,
    }
}

fn describe(e: &ClientError) -> String {
    match e {
        ClientError::Unavailable(_) => "the VPN service is not running".into(),
        other => other.to_string(),
    }
}

fn find<'a>(profiles: &'a [ProfileView], name: &str) -> Result<&'a ProfileView, String> {
    profiles
        .iter()
        .find(|p| p.name.eq_ignore_ascii_case(name.trim()))
        .ok_or_else(|| {
            let names: Vec<&str> = profiles.iter().map(|p| p.name.as_str()).collect();
            format!(
                "no profile named \"{name}\"; available: {}",
                if names.is_empty() {
                    "(none)".to_string()
                } else {
                    names.join(", ")
                }
            )
        })
}

fn policy_name(p: Policy) -> &'static str {
    if p.keep_tunnel_on_signout {
        "keep-on-signout"
    } else {
        "disconnect-on-signout"
    }
}

/// Run a command; returns the process exit code (0, 1, 2 usage, 5 access).
pub fn run(
    cmd: &Cmd,
    connect: &dyn Fn() -> Result<CommandClient, ClientError>,
    out: &mut dyn std::io::Write,
) -> i32 {
    match run_inner(cmd, connect, out) {
        Ok(code) => code,
        Err(e) => {
            let _ = writeln!(out, "error: {}", describe(&e));
            code_for(&e)
        }
    }
}

fn run_inner(
    cmd: &Cmd,
    connect: &dyn Fn() -> Result<CommandClient, ClientError>,
    out: &mut dyn std::io::Write,
) -> Result<i32, ClientError> {
    let edits = match cmd {
        Cmd::DisableProvider => return Ok(disable_provider(out)),
        Cmd::Import { file, .. } => {
            let text = match std::fs::read_to_string(file) {
                Ok(t) => t,
                Err(e) => {
                    let _ = writeln!(out, "error: cannot read {file}: {e}");
                    return Ok(1);
                }
            };
            match parse_import(&text) {
                Ok(edits) => Some(edits),
                Err(e) => {
                    let _ = writeln!(out, "error: {e}");
                    return Ok(1);
                }
            }
        }
        _ => None,
    };
    let mut c = connect()?;
    let profiles = |c: &mut CommandClient| -> Result<Vec<ProfileView>, ClientError> {
        match c.request(Request::ListProfiles)? {
            Response::Profiles { profiles } => Ok(profiles),
            r => Err(ClientError::Protocol(format!("unexpected response {r:?}"))),
        }
    };
    let policy = |c: &mut CommandClient| -> Result<Policy, ClientError> {
        match c.request(Request::GetPolicy)? {
            Response::Policy { policy } => Ok(policy),
            r => Err(ClientError::Protocol(format!("unexpected response {r:?}"))),
        }
    };
    match cmd {
        Cmd::List => {
            for p in profiles(&mut c)? {
                let tag = if p.sign_in { "  [sign-in]" } else { "" };
                let _ = writeln!(out, "{}{tag}", p.name);
            }
            let _ = writeln!(out, "sign-out policy: {}", policy_name(policy(&mut c)?));
            Ok(0)
        }
        Cmd::Enable(name) | Cmd::Disable(name) => {
            let list = profiles(&mut c)?;
            let p = match find(&list, name) {
                Ok(p) => p,
                Err(msg) => {
                    let _ = writeln!(out, "error: {msg}");
                    return Ok(1);
                }
            };
            let enabled = matches!(cmd, Cmd::Enable(_));
            c.request(Request::SetSignIn {
                id: p.id.clone(),
                enabled,
            })?;
            let state = if enabled {
                "available"
            } else {
                "no longer available"
            };
            let _ = writeln!(out, "{} is {state} at sign-in", p.name);
            Ok(0)
        }
        Cmd::ShowPolicy => {
            let _ = writeln!(out, "{}", policy_name(policy(&mut c)?));
            Ok(0)
        }
        Cmd::SetPolicy { keep_on_signout } => {
            let p = Policy {
                keep_tunnel_on_signout: *keep_on_signout,
            };
            c.request(Request::SetPolicy { policy: p })?;
            let _ = writeln!(out, "sign-out policy: {}", policy_name(p));
            Ok(0)
        }
        Cmd::Import { sign_in, .. } => {
            let mut code = 0;
            for edit in edits.unwrap_or_default() {
                let name = edit.name.clone();
                match c.request(Request::ImportProfile {
                    profile: edit,
                    sign_in: *sign_in,
                }) {
                    Ok(_) => {
                        let at = if *sign_in {
                            " (available at sign-in)"
                        } else {
                            ""
                        };
                        let _ = writeln!(out, "imported {name}{at}");
                    }
                    Err(e) if code_for(&e) == 5 => return Err(e),
                    Err(e) => {
                        let _ = writeln!(out, "{name}: {}", describe(&e));
                        code = 1;
                    }
                }
            }
            Ok(code)
        }
        Cmd::DisableProvider => unreachable!("handled above"),
    }
}

/// Recovery: remove the Network sign-in provider registration so LogonUI no
/// longer loads it (003 contracts/plap-registration.md). Works without the
/// service.
#[cfg(windows)]
fn disable_provider(out: &mut dyn std::io::Write) -> i32 {
    let key = format!(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\PLAP Providers\{}",
        ipc_proto::PLAP_CLSID
    );
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let reg = std::path::Path::new(&root).join("System32").join("reg.exe");
    match std::process::Command::new(reg)
        .args(["delete", &key, "/f"])
        .output()
    {
        Ok(o) if o.status.success() => {
            let _ = writeln!(out, "Pre-Login Connect provider disabled");
            0
        }
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            if err.contains("unable to find") {
                let _ = writeln!(out, "Pre-Login Connect provider is not registered");
                0
            } else if err.contains("Access is denied") {
                let _ = writeln!(out, "error: access denied (run from an elevated prompt)");
                5
            } else {
                let _ = writeln!(out, "error: {}", err.trim());
                1
            }
        }
        Err(e) => {
            let _ = writeln!(out, "error: cannot run reg.exe: {e}");
            1
        }
    }
}

#[cfg(not(windows))]
fn disable_provider(out: &mut dyn std::io::Write) -> i32 {
    let _ = writeln!(out, "error: Pre-Login Connect exists only on Windows");
    1
}

/// Entry point from `main`.
pub fn main(args: &[&str]) -> i32 {
    let cmd = match parse(args) {
        Ok(c) => c,
        Err(usage) => {
            eprintln!("{usage}");
            return 2;
        }
    };
    // Verify who serves the pipe before sending profiles and secrets.
    #[cfg(windows)]
    ipc_proto::client::set_pipe_owner_probe(crate::windows::pipe::owner_sid);
    let mut out = std::io::stdout();
    run(
        &cmd,
        &|| CommandClient::connect("ipsec-service-cli"),
        &mut out,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{serve, Peer, ServerCtx};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use vpn_core::mock::InsecureMockProtector;
    use vpn_core::{EventBus, LogBuffer, ProfileStore, SettingsStore};

    #[test]
    fn parses_every_verb() {
        assert_eq!(parse(&["plc", "list"]), Ok(Cmd::List));
        assert_eq!(
            parse(&["plc", "enable", "Office"]),
            Ok(Cmd::Enable("Office".into()))
        );
        assert_eq!(
            parse(&["plc", "disable", "Office"]),
            Ok(Cmd::Disable("Office".into()))
        );
        assert_eq!(parse(&["plc", "policy"]), Ok(Cmd::ShowPolicy));
        assert_eq!(
            parse(&["plc", "policy", "keep-on-signout"]),
            Ok(Cmd::SetPolicy {
                keep_on_signout: true
            })
        );
        assert_eq!(
            parse(&["plc", "policy", "disconnect-on-signout"]),
            Ok(Cmd::SetPolicy {
                keep_on_signout: false
            })
        );
        assert_eq!(
            parse(&["plc", "disable-provider"]),
            Ok(Cmd::DisableProvider)
        );
        assert_eq!(
            parse(&["profile", "import", "p.json", "--sign-in"]),
            Ok(Cmd::Import {
                file: "p.json".into(),
                sign_in: true
            })
        );
        assert_eq!(
            parse(&["profile", "import", "p.json"]),
            Ok(Cmd::Import {
                file: "p.json".into(),
                sign_in: false
            })
        );
        for bad in [
            &["plc"][..],
            &["plc", "enable"],
            &["plc", "policy", "sometimes"],
            &["profile", "import"],
            &["profile", "import", "f", "--bogus"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn import_file_maps_to_edits() {
        let edits = parse_import(
            r#"{ "profiles": [
                { "name": "Office", "gateway": "vpn.example.com", "local_id": "laptop",
                  "auth": "eap", "username": "alice", "psk": "k", "dh_group": "x25519" },
                { "name": "Lab", "gateway": "10.0.0.1", "port": 4500, "local_id": "lab",
                  "auth": "psk" }
            ] }"#,
        )
        .unwrap();
        assert_eq!(edits.len(), 2);
        assert_eq!(edits[0].port, 500, "default port");
        assert_eq!(edits[0].dh_group, DhGroupSel::X25519);
        assert_eq!(edits[0].psk, SecretUpdate::Set(SecretString::new("k")));
        assert_eq!(edits[0].password, SecretUpdate::Keep);
        assert_eq!(edits[1].auth, AuthMode::Psk);
        assert_eq!(edits[1].psk, SecretUpdate::Keep);
        assert_eq!(edits[1].id_type, IdType::Fqdn);
        // Windows PowerShell 5.1 and Notepad may write a UTF-8 byte-order mark.
        let bom = format!(
            "\u{feff}{}",
            r#"{"profiles":[{"name":"A","gateway":"g","local_id":"l","auth":"psk"}]}"#
        );
        assert_eq!(parse_import(&bom).unwrap().len(), 1);
        assert!(parse_import("{").is_err());
        assert!(parse_import(r#"{"profiles":[{"gateway":"x"}]}"#).is_err());
        assert!(parse_import(r#"{"profiles":[]}"#).is_err());
    }

    /// The real server, in-process, with a peer that is or is not an admin.
    fn served(ctx: &Arc<ServerCtx>, is_admin: bool) -> Result<CommandClient, ClientError> {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (s, _) = l.accept().unwrap();
        let ctx = ctx.clone();
        let peer = Peer {
            is_admin,
            desc: "test".into(),
        };
        std::thread::spawn(move || serve(Box::new(s), peer, &ctx));
        CommandClient::over(Box::new(c), "cli")
    }

    fn ctx() -> Arc<ServerCtx> {
        let bus = EventBus::new();
        let store = Arc::new(ProfileStore::open(None, Arc::new(InsecureMockProtector)).unwrap());
        let dir = std::env::temp_dir().join(format!(
            "ipsec-plc-cli-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        Arc::new(ServerCtx {
            engine: crate::simulate::SimulatedEngine::new(store.clone(), bus.clone()),
            store,
            settings: Arc::new(SettingsStore::open(dir.join("settings.json")).0),
            bus: bus.clone(),
            logs: LogBuffer::new(10, Some(bus)),
            service_name: "test".into(),
        })
    }

    fn office() -> ProfileEdit {
        ProfileEdit {
            name: "Office".into(),
            gateway: "vpn.example.com".into(),
            local_id: "laptop".into(),
            username: "alice".into(),
            psk: SecretUpdate::Set(SecretString::new("k")),
            ..Default::default()
        }
    }

    fn exec(ctx: &Arc<ServerCtx>, admin: bool, cmd: Cmd) -> (i32, String) {
        let mut out = Vec::new();
        let code = run(&cmd, &|| served(ctx, admin), &mut out);
        (code, String::from_utf8(out).unwrap())
    }

    #[test]
    fn enable_disable_by_name_needs_admin() {
        let ctx = ctx();
        ctx.store.create(&office()).unwrap();

        let (code, out) = exec(&ctx, false, Cmd::Enable("office".into()));
        assert_eq!(code, 5, "{out}");
        assert!(out.contains("Administrator rights are required"), "{out}");
        assert!(ctx.store.sign_in_profiles().is_empty());

        let (code, out) = exec(&ctx, true, Cmd::Enable("office".into()));
        assert_eq!(code, 0, "{out}");
        assert_eq!(ctx.store.sign_in_profiles().len(), 1);

        let (code, out) = exec(&ctx, true, Cmd::Enable("Nope".into()));
        assert_eq!(code, 1);
        assert!(out.contains("Office"), "lists the available names: {out}");

        let (code, _) = exec(&ctx, true, Cmd::Disable("Office".into()));
        assert_eq!(code, 0);
        assert!(ctx.store.sign_in_profiles().is_empty());
    }

    #[test]
    fn list_and_policy() {
        let ctx = ctx();
        let id = ctx.store.create(&office()).unwrap().id;
        ctx.store.set_sign_in(&id, true).unwrap();
        let (code, out) = exec(&ctx, false, Cmd::List);
        assert_eq!(code, 0);
        assert!(out.contains("Office") && out.contains("sign-in"), "{out}");
        assert!(out.contains("disconnect-on-signout"), "{out}");

        assert_eq!(
            exec(
                &ctx,
                false,
                Cmd::SetPolicy {
                    keep_on_signout: true
                }
            )
            .0,
            5
        );
        assert_eq!(
            exec(
                &ctx,
                true,
                Cmd::SetPolicy {
                    keep_on_signout: true
                }
            )
            .0,
            0
        );
        assert!(ctx.settings.get().keep_tunnel_on_signout);
        let (code, out) = exec(&ctx, false, Cmd::ShowPolicy);
        assert_eq!(code, 0);
        assert!(out.contains("keep-on-signout"), "{out}");
    }

    #[test]
    fn import_reports_each_profile() {
        let ctx = ctx();
        let file = std::env::temp_dir().join(format!("ipsec-import-{}.json", std::process::id()));
        std::fs::write(
            &file,
            r#"{ "profiles": [
                { "name": "Office", "gateway": "vpn.example.com", "local_id": "laptop",
                  "auth": "eap", "username": "alice", "psk": "k" },
                { "name": "Broken", "gateway": "", "local_id": "x", "auth": "psk", "psk": "k" }
            ] }"#,
        )
        .unwrap();
        let cmd = Cmd::Import {
            file: file.to_string_lossy().into_owned(),
            sign_in: true,
        };
        let (code, out) = exec(&ctx, true, cmd);
        assert_eq!(code, 1, "one profile failed validation: {out}");
        assert!(out.contains("Office") && out.contains("Broken"), "{out}");
        assert_eq!(ctx.store.sign_in_profiles().len(), 1);
        let _ = std::fs::remove_file(file);
    }

    #[test]
    fn service_not_running_is_exit_1() {
        let mut out = Vec::new();
        let code = run(
            &Cmd::List,
            &|| {
                Err(ClientError::Unavailable(std::io::Error::from(
                    std::io::ErrorKind::NotFound,
                )))
            },
            &mut out,
        );
        assert_eq!(code, 1);
        assert!(String::from_utf8(out).unwrap().contains("not running"));
    }
}
