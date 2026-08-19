#[cfg(target_os = "linux")]
use std::fs;
#[cfg(any(target_os = "linux", test))]
use std::net::IpAddr;
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use std::net::Ipv4Addr;
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use std::net::Ipv6Addr;
#[cfg(target_os = "linux")]
use std::net::ToSocketAddrs;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command as ProcessCommand;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use anyhow::Context;
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use anyhow::Result;
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use anyhow::anyhow;
#[cfg(target_os = "linux")]
use netdev::get_interfaces;
#[cfg(target_os = "linux")]
use netdev::interface::interface::Interface as NetworkInterface;
#[cfg(target_os = "linux")]
use nostr_vpn_core::config::AppConfig;

#[cfg(target_os = "macos")]
use crate::MacosRouteSpec;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::run_checked;
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use crate::strip_cidr;

include!("platform_routing/linux_routes.rs");
include!("platform_routing/forwarding_and_setup.rs");
include!("platform_routing/macos_routes_and_tests.rs");
