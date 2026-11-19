use super::*;

#[test]
fn direct_resolv_conf_crash_repair_only_restores_owned_content() {
    let previous = b"nameserver 192.0.2.53\n";
    assert!(!linux_direct_resolv_conf_needs_restore(previous, previous));
    assert!(linux_direct_resolv_conf_needs_restore(
        LINUX_DIRECT_RESOLV_CONF,
        previous
    ));
    let legacy =
        b"# Managed by nvpn secure DNS\nnameserver 127.0.0.1\noptions timeout:7 attempts:1\n";
    assert!(linux_direct_resolv_conf_needs_restore(legacy, previous));
    assert!(linux_direct_resolv_conf_needs_restore(
        &legacy[..legacy.len() - 5],
        previous
    ));
    assert!(linux_direct_resolv_conf_needs_restore(
        &LINUX_DIRECT_RESOLV_CONF[..12],
        previous
    ));
    assert!(!linux_direct_resolv_conf_needs_restore(
        &previous[..10],
        previous
    ));
    assert!(!linux_direct_resolv_conf_needs_restore(
        b"nameserver 203.0.113.53\n",
        previous
    ));
}

#[test]
fn direct_resolv_conf_waits_for_through_exit_upstream_failover() {
    let contents = std::str::from_utf8(LINUX_DIRECT_RESOLV_CONF).expect("UTF-8 resolv.conf");
    assert!(contents.contains(&format!("nameserver {LINUX_DNS_IP}\n")));
    assert!(contents.contains("options timeout:7 attempts:1"));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_secure_dns_does_not_share_the_native_loopback_address() {
    assert_eq!(SECURE_DNS_BIND.ip(), IpAddr::V4(LINUX_DNS_IP));
    let native_tcp = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let port = native_tcp.local_addr().unwrap().port();
    let native_udp = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let vpn_tcp = tokio::net::TcpListener::bind((SECURE_DNS_BIND.ip(), port))
        .await
        .unwrap();
    let vpn_udp = tokio::net::UdpSocket::bind((SECURE_DNS_BIND.ip(), port))
        .await
        .unwrap();
    assert_ne!(
        native_tcp.local_addr().unwrap(),
        vpn_tcp.local_addr().unwrap()
    );
    assert_ne!(
        native_udp.local_addr().unwrap(),
        vpn_udp.local_addr().unwrap()
    );
}
