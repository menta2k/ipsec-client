//! Looking up the `ipsec-client` group without libc (002 research R5).
//!
//! Under systemd the service already runs with `Group=ipsec-client`, so the
//! socket gets that group automatically. When the service is started by hand
//! as root, the socket would belong to group root and the group members could
//! not connect; the host then hands the socket to this group explicitly.

/// The group whose members may control the VPN.
pub const VPN_GROUP: &str = "ipsec-client";

/// The gid of `name` in `/etc/group`-formatted text (`name:x:gid:members`).
pub fn group_gid(etc_group: &str, name: &str) -> Option<u32> {
    etc_group
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .find_map(|l| {
            let mut f = l.split(':');
            (f.next()? == name).then(|| f.nth(1)?.parse().ok())?
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GROUPS: &str = "\
root:x:0:
# a comment
sudo:x:27:alice
ipsec-client:x:998:alice,bob
ipsec-client-old:x:997:
";

    #[test]
    fn finds_the_exact_group() {
        assert_eq!(group_gid(GROUPS, "ipsec-client"), Some(998));
        assert_eq!(group_gid(GROUPS, "root"), Some(0));
    }

    #[test]
    fn missing_or_malformed_entries_give_none() {
        assert_eq!(group_gid(GROUPS, "ipsec"), None);
        assert_eq!(
            group_gid("ipsec-client:x:notanumber:", "ipsec-client"),
            None
        );
        assert_eq!(group_gid("ipsec-client", "ipsec-client"), None);
        assert_eq!(group_gid("", "ipsec-client"), None);
    }
}
