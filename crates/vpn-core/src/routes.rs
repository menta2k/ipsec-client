//! Route planning from negotiated remote traffic selectors (FR-026).
//!
//! Full tunnel (a selector covering 0.0.0.0/0) is installed as the two halves
//! 0.0.0.0/1 + 128.0.0.0/1 so the original default route stays untouched, plus
//! a /32 to the gateway via the original next hop so tunnel traffic itself does
//! not loop.

use std::net::Ipv4Addr;

/// An IPv4 CIDR block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cidr {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl Cidr {
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix as u32)
        };
        (u32::from(ip) & mask) == (u32::from(self.addr) & mask)
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// Minimal set of CIDRs exactly covering the inclusive range `start..=end`.
pub fn range_to_cidrs(start: Ipv4Addr, end: Ipv4Addr) -> Vec<Cidr> {
    let (mut s, e) = (u32::from(start) as u64, u32::from(end) as u64);
    let mut out = Vec::new();
    if s > e {
        return out;
    }
    while s <= e {
        // Largest block aligned at `s`...
        let mut size: u64 = if s == 0 {
            1 << 32
        } else {
            1 << s.trailing_zeros()
        };
        // ...that does not overshoot `e`.
        while s + size - 1 > e {
            size >>= 1;
        }
        let prefix = 32 - size.trailing_zeros() as u8;
        out.push(Cidr {
            addr: Ipv4Addr::from(s as u32),
            prefix,
        });
        s += size;
    }
    out
}

/// The routing plan for one session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutePlan {
    /// Routes through the tunnel adapter.
    pub tunnel_routes: Vec<Cidr>,
    /// Whether a gateway host route via the original interface is needed.
    pub gateway_host_route: bool,
    pub full_tunnel: bool,
}

/// Build the plan from remote selector ranges and the gateway address.
pub fn plan(remote_ranges: &[(Ipv4Addr, Ipv4Addr)], gateway: Ipv4Addr) -> RoutePlan {
    let mut cidrs: Vec<Cidr> = remote_ranges
        .iter()
        .flat_map(|(s, e)| range_to_cidrs(*s, *e))
        .collect();
    cidrs.sort();
    cidrs.dedup();
    let full_tunnel = cidrs.iter().any(|c| c.prefix == 0);
    if full_tunnel {
        cidrs = vec![
            Cidr {
                addr: Ipv4Addr::new(0, 0, 0, 0),
                prefix: 1,
            },
            Cidr {
                addr: Ipv4Addr::new(128, 0, 0, 0),
                prefix: 1,
            },
        ];
    }
    let gateway_host_route = cidrs.iter().any(|c| c.contains(gateway));
    RoutePlan {
        tunnel_routes: cidrs,
        gateway_host_route,
        full_tunnel,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn strs(v: &[Cidr]) -> Vec<String> {
        v.iter().map(|c| c.to_string()).collect()
    }

    #[test]
    fn exact_subnet() {
        assert_eq!(
            strs(&range_to_cidrs(ip("10.0.0.0"), ip("10.0.255.255"))),
            vec!["10.0.0.0/16"]
        );
        assert_eq!(
            strs(&range_to_cidrs(ip("0.0.0.0"), ip("255.255.255.255"))),
            vec!["0.0.0.0/0"]
        );
        assert_eq!(
            strs(&range_to_cidrs(ip("10.1.1.1"), ip("10.1.1.1"))),
            vec!["10.1.1.1/32"]
        );
    }

    #[test]
    fn unaligned_range() {
        assert_eq!(
            strs(&range_to_cidrs(ip("10.0.0.5"), ip("10.0.0.20"))),
            vec![
                "10.0.0.5/32",
                "10.0.0.6/31",
                "10.0.0.8/29",
                "10.0.0.16/30",
                "10.0.0.20/32"
            ]
        );
        assert!(range_to_cidrs(ip("10.0.0.9"), ip("10.0.0.1")).is_empty());
    }

    #[test]
    fn full_tunnel_splits_and_protects_gateway() {
        let p = plan(
            &[(ip("0.0.0.0"), ip("255.255.255.255"))],
            ip("198.51.100.1"),
        );
        assert!(p.full_tunnel && p.gateway_host_route);
        assert_eq!(strs(&p.tunnel_routes), vec!["0.0.0.0/1", "128.0.0.0/1"]);
    }

    #[test]
    fn split_tunnel_without_gateway_overlap() {
        let p = plan(
            &[
                (ip("10.0.0.0"), ip("10.255.255.255")),
                (ip("10.0.0.0"), ip("10.255.255.255")),
            ],
            ip("198.51.100.1"),
        );
        assert!(!p.full_tunnel && !p.gateway_host_route);
        assert_eq!(strs(&p.tunnel_routes), vec!["10.0.0.0/8"]);
    }
}
