use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use sha2::{Digest, Sha256};

use crate::config::normalize_runtime_network_id;

pub const MESH_TUNNEL_IPV4_CIDR: &str = "10.44.0.0/16";

pub fn derive_mesh_tunnel_ip(network_id: &str, own_pubkey_hex: &str) -> Option<String> {
    let network_id = normalize_runtime_network_id(network_id);
    let network_id = network_id.trim();
    let own_pubkey_hex = own_pubkey_hex.trim();
    if network_id.is_empty() || own_pubkey_hex.is_empty() {
        return None;
    }

    let mut hasher = Sha256::new();
    hasher.update(network_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(own_pubkey_hex.as_bytes());
    let digest = hasher.finalize();

    let third_octet = (digest[0] % 254) + 1;
    let fourth_octet = (digest[1] % 254) + 1;
    Some(format!("10.44.{third_octet}.{fourth_octet}/32"))
}

/// Address space a network admin may assign as a member's tunnel address:
/// RFC 1918 private ranges and RFC 6598 shared space (`100.64.0.0/10`, which
/// Tailscale-style networks use). See `docs/assigned-addresses.md`.
pub fn is_assignable_tunnel_ipv4(address: Ipv4Addr) -> bool {
    let [first, second, ..] = address.octets();
    first == 10
        || (first == 172 && (16..=31).contains(&second))
        || (first == 192 && second == 168)
        || (first == 100 && (64..=127).contains(&second))
}

/// The one tunnel address each member uses for routing, DNS, packet admission
/// and forwarding: its assigned address when the roster assigns one, otherwise
/// the derived address. Assignments must name members, use assignable space,
/// and not reuse an address another member uses, assigned or derived.
///
/// Not called yet: consumers adopt it before rosters may carry assignments.
pub fn effective_mesh_tunnel_ipv4s(
    network_id: &str,
    members: &[String],
    assignments: &BTreeMap<String, Ipv4Addr>,
) -> anyhow::Result<BTreeMap<String, Ipv4Addr>> {
    let mut assigned_owner = BTreeMap::new();
    for (member, &address) in assignments {
        if !members.contains(member) {
            anyhow::bail!("tunnel address {address} is assigned to a non-member {member}");
        }
        if !is_assignable_tunnel_ipv4(address) {
            anyhow::bail!("tunnel address {address} for {member} is outside assignable space");
        }
        if let Some(owner) = assigned_owner.insert(address, member) {
            anyhow::bail!("tunnel address {address} is assigned to both {owner} and {member}");
        }
    }

    let mut effective = BTreeMap::new();
    for member in members {
        let address = match assignments.get(member) {
            Some(&address) => address,
            None => derive_mesh_tunnel_ip(network_id, member)
                .and_then(|address| strip_ipv4_host_prefix(&address))
                .ok_or_else(|| anyhow::anyhow!("no derived tunnel address for {member}"))?,
        };
        if let Some(owner) = assigned_owner.get(&address)
            && *owner != member
        {
            anyhow::bail!("tunnel address {address} assigned to {owner} is {member}'s address");
        }
        effective.insert(member.clone(), address);
    }
    Ok(effective)
}

fn strip_ipv4_host_prefix(address: &str) -> Option<Ipv4Addr> {
    address.strip_suffix("/32")?.parse().ok()
}

pub fn normalize_advertised_route(value: &str) -> Option<String> {
    let value = value.trim();
    let (addr, bits) = value.split_once('/')?;
    let addr: IpAddr = addr.trim().parse().ok()?;
    let bits: u8 = bits.trim().parse().ok()?;

    let max_bits = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if bits > max_bits {
        return None;
    }

    let network = match addr {
        IpAddr::V4(ip) => IpAddr::V4(mask_ipv4(ip, bits)),
        IpAddr::V6(ip) => IpAddr::V6(mask_ipv6(ip, bits)),
    };

    Some(format!("{network}/{bits}"))
}

pub fn route_is_ipv6(route: &str) -> bool {
    route
        .split_once('/')
        .map_or(route, |(address, _)| address)
        .trim()
        .parse::<Ipv6Addr>()
        .is_ok()
}

pub fn normalize_advertised_routes(routes: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();

    for route in routes {
        let Some(route) = normalize_advertised_route(route) else {
            continue;
        };
        if seen.insert(route.clone()) {
            normalized.push(route);
        }
    }

    normalized
}

pub fn effective_advertised_routes(routes: &[String], advertise_exit_node: bool) -> Vec<String> {
    let mut effective = normalize_advertised_routes(routes);
    let mut seen = effective.iter().cloned().collect::<HashSet<_>>();

    if advertise_exit_node {
        for route in exit_node_default_routes() {
            if seen.insert(route.clone()) {
                effective.push(route);
            }
        }
    }

    effective
}

pub fn exit_node_default_routes() -> Vec<String> {
    vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
}

pub(crate) fn is_exit_node_route(route: &str) -> bool {
    matches!(route, "0.0.0.0/0" | "::/0")
}

fn mask_ipv4(ip: Ipv4Addr, bits: u8) -> Ipv4Addr {
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    Ipv4Addr::from(u32::from(ip) & mask)
}

fn mask_ipv6(ip: Ipv6Addr, bits: u8) -> Ipv6Addr {
    let mask = if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits)
    };
    Ipv6Addr::from(u128::from_be_bytes(ip.octets()) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn members() -> Vec<String> {
        vec!["a".repeat(64), "b".repeat(64)]
    }

    fn derived(member: &str) -> Ipv4Addr {
        strip_ipv4_host_prefix(&derive_mesh_tunnel_ip("mesh", member).unwrap()).unwrap()
    }

    #[test]
    fn assignable_space_is_private_and_shared_ipv4_only() {
        for address in [
            "10.0.0.1",
            "10.44.0.1",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.254",
        ] {
            assert!(
                is_assignable_tunnel_ipv4(address.parse().unwrap()),
                "{address}"
            );
        }
        for address in [
            "0.0.0.0",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.15.255.255",
            "172.32.0.1",
            "192.169.0.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(
                !is_assignable_tunnel_ipv4(address.parse().unwrap()),
                "{address}"
            );
        }
    }

    #[test]
    fn effective_addresses_are_derived_without_assignments() {
        let members = members();
        let effective = effective_mesh_tunnel_ipv4s("mesh", &members, &BTreeMap::new()).unwrap();
        for member in &members {
            assert_eq!(effective[member], derived(member));
        }
    }

    #[test]
    fn assigned_address_replaces_the_derived_one_for_that_member_only() {
        // Migration case: keep a device's existing 100.64.0.0/10 tailnet address.
        let members = members();
        let assignments = BTreeMap::from([(members[0].clone(), Ipv4Addr::new(100, 64, 0, 13))]);
        let effective = effective_mesh_tunnel_ipv4s("mesh", &members, &assignments).unwrap();
        assert_eq!(effective[&members[0]], Ipv4Addr::new(100, 64, 0, 13));
        assert_eq!(effective[&members[1]], derived(&members[1]));
    }

    #[test]
    fn invalid_assignments_are_rejected() {
        let members = members();
        let outsider = "c".repeat(64);
        let cases = [
            (
                BTreeMap::from([(outsider, Ipv4Addr::new(100, 64, 0, 1))]),
                "non-member",
            ),
            (
                BTreeMap::from([(members[0].clone(), Ipv4Addr::new(8, 8, 8, 8))]),
                "outside assignable space",
            ),
            (
                BTreeMap::from([
                    (members[0].clone(), Ipv4Addr::new(100, 64, 0, 1)),
                    (members[1].clone(), Ipv4Addr::new(100, 64, 0, 1)),
                ]),
                "assigned to both",
            ),
            (
                BTreeMap::from([(members[0].clone(), derived(&members[1]))]),
                "address",
            ),
        ];
        for (assignments, expected) in cases {
            let error = effective_mesh_tunnel_ipv4s("mesh", &members, &assignments)
                .expect_err("invalid assignment");
            assert!(error.to_string().contains(expected), "{error}");
        }
    }
}
