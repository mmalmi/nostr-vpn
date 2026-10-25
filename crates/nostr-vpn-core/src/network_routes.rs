use std::collections::HashSet;
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
