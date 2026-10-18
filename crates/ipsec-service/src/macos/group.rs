//! The group whose members may control the VPN on macOS (004 US3,
//! data-model.md). `admin` by default; an administrator can choose another
//! with `ipsec-service access-group <name>`. Looked up with `dscl` through
//! the command runner, so the parsing is tested on every OS.

use crate::unix_cmd::CommandRunner;

/// The default group and its fixed gid on every macOS install.
pub const DEFAULT_GROUP: &str = "admin";
pub const ADMIN_GID: u32 = 80;

/// The effective group: its name and gid, and a warning to log when the
/// configured group could not be used.
#[derive(Debug, PartialEq, Eq)]
pub struct Resolved {
    pub name: String,
    pub gid: u32,
    pub warning: Option<String>,
}

/// 1 to 32 characters from `[A-Za-z0-9_.-]`, not starting with `-` or `.`.
pub fn valid_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && !name.starts_with(['-', '.'])
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// The gid in `dscl . -read /Groups/<name> PrimaryGroupID` output
/// (`PrimaryGroupID: 80`).
pub fn parse_primary_gid(out: &str) -> Option<u32> {
    out.lines()
        .find_map(|l| l.trim().strip_prefix("PrimaryGroupID:"))
        .and_then(|v| v.trim().parse().ok())
}

/// The gid of group `name`, or `None` if it does not exist (or the name is
/// not acceptable, so it never reaches the command line).
pub fn lookup(name: &str, runner: &dyn CommandRunner) -> Option<u32> {
    if !valid_name(name) {
        return None;
    }
    let path = format!("/Groups/{name}");
    let out = runner
        .run(&["dscl", ".", "-read", &path, "PrimaryGroupID"])
        .ok()?;
    if !out.status_ok {
        return None;
    }
    parse_primary_gid(&out.stdout)
}

/// The configured group if it resolves, otherwise `admin` with a warning.
pub fn resolve_or_admin(configured: Option<&str>, runner: &dyn CommandRunner) -> Resolved {
    let admin = |warning| Resolved {
        name: DEFAULT_GROUP.into(),
        gid: ADMIN_GID,
        warning,
    };
    match configured {
        None | Some(DEFAULT_GROUP) => admin(None),
        Some(name) => match lookup(name, runner) {
            Some(gid) => Resolved {
                name: name.into(),
                gid,
                warning: None,
            },
            None => admin(Some(format!(
                "access group '{name}' does not exist; only members of '{DEFAULT_GROUP}' may \
                 control the VPN until it is fixed with `sudo ipsec-service access-group`"
            ))),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unix_cmd::fake::{fail, ok, FakeRunner};

    #[test]
    fn names_follow_the_data_model() {
        for good in ["admin", "vpn-users", "staff_2", "a", "x.y", &"g".repeat(32)] {
            assert!(valid_name(good), "{good}");
        }
        for bad in [
            "",
            &"g".repeat(33),
            "-rf",
            ".hidden",
            "a b",
            "a/b",
            "grüne",
            "a;b",
            "a\nb",
        ] {
            assert!(!valid_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn parses_dscl_output() {
        assert_eq!(parse_primary_gid("PrimaryGroupID: 80\n"), Some(80));
        assert_eq!(parse_primary_gid("  PrimaryGroupID:   501  "), Some(501));
        assert_eq!(parse_primary_gid("PrimaryGroupID: x"), None);
        assert_eq!(
            parse_primary_gid("<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)"),
            None
        );
        assert_eq!(parse_primary_gid(""), None);
    }

    #[test]
    fn resolves_the_configured_group() {
        let r = FakeRunner::new();
        r.on(
            "dscl . -read /Groups/vpn-users",
            ok("PrimaryGroupID: 701\n"),
        );
        assert_eq!(
            resolve_or_admin(Some("vpn-users"), &r),
            Resolved {
                name: "vpn-users".into(),
                gid: 701,
                warning: None
            }
        );
        assert_eq!(r.calls(), ["dscl . -read /Groups/vpn-users PrimaryGroupID"]);
    }

    #[test]
    fn unknown_or_invalid_group_falls_back_to_admin() {
        let r = FakeRunner::new();
        r.on(
            "dscl",
            fail("<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)"),
        );
        let got = resolve_or_admin(Some("gone"), &r);
        assert_eq!((got.name.as_str(), got.gid), ("admin", 80));
        assert!(got.warning.unwrap().contains("'gone' does not exist"));
        // An unacceptable name is never passed to dscl.
        let r = FakeRunner::new();
        let got = resolve_or_admin(Some("../etc"), &r);
        assert_eq!(got.gid, ADMIN_GID);
        assert!(r.calls().is_empty());
    }

    #[test]
    fn default_needs_no_lookup() {
        let r = FakeRunner::new();
        for c in [None, Some("admin")] {
            assert_eq!(
                resolve_or_admin(c, &r),
                Resolved {
                    name: "admin".into(),
                    gid: 80,
                    warning: None
                }
            );
        }
        assert!(r.calls().is_empty());
    }
}
