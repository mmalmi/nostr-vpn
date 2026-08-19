#[cfg(target_os = "macos")]
use super::macos::{
    MACOS_SECURE_DNS_STORE_KEY, macos_magic_dns_resolver_config, macos_resolver_configs,
};
use super::*;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinEncodable as _, BinEncoder};
use nostr_vpn_core::secure_dns::SecureDnsResolver;
#[cfg(unix)]
use std::os::unix::fs::symlink;

struct FixtureResolver {
    fail: bool,
}

#[async_trait::async_trait]
impl SecureDnsLookup for FixtureResolver {
    async fn resolve(
        &self,
        query: &[u8],
    ) -> std::result::Result<Vec<u8>, nostr_vpn_core::secure_dns::SecureDnsError> {
        if self.fail {
            return Err(nostr_vpn_core::secure_dns::SecureDnsError::InvalidResponse);
        }
        let request = Message::from_vec(query).expect("fixture query");
        let mut response =
            Message::new(request.id, MessageType::Response, request.metadata.op_code);
        response.metadata.recursion_available = true;
        for query in request.queries {
            response.add_query(query);
        }
        let mut packet = Vec::new();
        response
            .emit(&mut BinEncoder::new(&mut packet))
            .expect("fixture response");
        Ok(packet)
    }
}

fn query_packet_with_type(name: &str, id: u16, record_type: RecordType) -> Vec<u8> {
    let mut query = Message::new(id, MessageType::Query, OpCode::Query);
    query.add_query(Query::query(
        Name::from_ascii(name).expect("query name"),
        record_type,
    ));
    let mut packet = Vec::new();
    query
        .emit(&mut BinEncoder::new(&mut packet))
        .expect("query packet");
    packet
}

fn query_packet(name: &str, id: u16) -> Vec<u8> {
    query_packet_with_type(name, id, RecordType::A)
}

#[cfg(target_os = "macos")]
#[test]
fn macos_secure_dns_uses_system_configuration_default_routing() {
    assert_eq!(
        SECURE_DNS_BIND,
        "127.0.0.1:1053".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(
        MACOS_SECURE_DNS_STORE_KEY,
        "State:/Network/Service/to.nostrvpn.nvpn-secure-dns/DNS"
    );
    assert_eq!(macos_resolver_configs().len(), 1);

    let magic_dns_resolver = macos_magic_dns_resolver_config();
    assert!(magic_dns_resolver.contains("nameserver 127.0.0.1\n"));
    assert!(magic_dns_resolver.contains("port 1053\n"));
    assert!(!magic_dns_resolver.contains("domain .\n"));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_failed_store_install_keeps_the_stub_for_owned_or_unknown_cleanup() {
    let absent: std::io::Result<bool> = Ok(false);
    let owned: std::io::Result<bool> = Ok(true);
    let unknown: std::io::Result<bool> = Err(std::io::Error::other("dynamic store unavailable"));

    assert!(!macos_secure_dns_store_cleanup_may_be_pending(&absent));
    assert!(macos_secure_dns_store_cleanup_may_be_pending(&owned));
    assert!(macos_secure_dns_store_cleanup_may_be_pending(&unknown));
}

#[test]
fn windows_policy_forces_all_dns_to_local_authenticated_stub() {
    let script = windows_secure_dns_install_script(42);
    assert!(script.contains("-InterfaceIndex 42"));
    assert!(script.contains("-Namespace '.'"));
    assert!(script.contains("-NameServers '127.0.0.1'"));
    assert!(!script.contains("1.1.1.1"));
    assert!(!script.contains("9.9.9.9"));
    let cleanup = windows_secure_dns_uninstall_script(42);
    assert!(cleanup.contains("-InterfaceIndex 42"));
    assert!(cleanup.contains("-ResetServerAddresses"));
    assert!(cleanup.contains("$servers.Count -eq 1"));
    assert!(cleanup.contains("$servers[0] -eq '127.0.0.1'"));
    let crash_repair = windows_secure_dns_repair_script();
    assert!(crash_repair.contains("Remove-DnsClientNrptRule"));
    assert!(!crash_repair.contains("Set-DnsClientServerAddress"));
    assert!(!crash_repair.contains("-InterfaceIndex"));
}

#[test]
fn direct_resolv_conf_crash_repair_only_restores_owned_content() {
    let previous = b"nameserver 192.0.2.53\n";
    assert!(!linux_direct_resolv_conf_needs_restore(previous, previous));
    assert!(linux_direct_resolv_conf_needs_restore(
        LINUX_DIRECT_RESOLV_CONF,
        previous
    ));
    assert!(linux_direct_resolv_conf_needs_restore(
        &LINUX_DIRECT_RESOLV_CONF[..12],
        previous
    ));
    assert!(linux_direct_resolv_conf_needs_restore(
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
    assert!(contents.contains("options timeout:7 attempts:1"));
}

#[cfg(unix)]
fn resolved_resolv_conf_fixture(
    name: &str,
) -> (
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let root = std::env::temp_dir().join(format!(
        "nvpn-resolved-resolv-conf-{name}-{}",
        std::process::id()
    ));
    if root.exists() {
        std::fs::remove_dir_all(&root).expect("remove stale resolver fixture");
    }
    let etc = root.join("etc");
    let run = root.join("run/systemd/resolve");
    std::fs::create_dir_all(&etc).expect("create fixture etc");
    std::fs::create_dir_all(&run).expect("create fixture resolved run directory");
    let uplink = run.join("resolv.conf");
    let stub = run.join("stub-resolv.conf");
    std::fs::write(&uplink, b"nameserver 192.0.2.53\n").expect("write uplink resolv.conf");
    std::fs::write(&stub, b"nameserver 127.0.0.53\n").expect("write stub resolv.conf");
    (root, etc.join("resolv.conf"), uplink, stub)
}

#[cfg(unix)]
fn resolved_paths(
    resolv_conf: &std::path::Path,
    cleanup: &linux::LinuxResolvedResolvConfCleanupState,
) -> LinuxResolvedPaths {
    linux_resolved_paths(resolv_conf, cleanup).expect("derive resolver ownership paths")
}

#[cfg(unix)]
fn resolved_marker_target(paths: &LinuxResolvedPaths) -> std::path::PathBuf {
    std::path::PathBuf::from(paths.marker.file_name().expect("resolver marker file name"))
}

#[cfg(unix)]
fn assert_resolver_path_missing(path: &std::path::Path) {
    let error = std::fs::symlink_metadata(path).expect_err("resolver path must be absent");
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}

#[cfg(unix)]
#[test]
fn resolved_uplink_symlink_is_switched_and_exactly_restored() {
    let (root, resolv_conf, uplink, stub) = resolved_resolv_conf_fixture("switch-and-restore");
    let prior_target = std::path::PathBuf::from("../run/systemd/resolve/resolv.conf");
    symlink(&prior_target, &resolv_conf).expect("install fixture uplink symlink");

    let cleanup = linux_resolved_resolv_conf_cleanup_intent(&resolv_conf, &uplink, &stub)
        .expect("read cleanup intent")
        .expect("uplink switch cleanup intent");
    let paths = resolved_paths(&resolv_conf, &cleanup);
    let marker_target = resolved_marker_target(&paths);
    assert_eq!(cleanup.ownership_token.len(), 32);
    assert!(
        cleanup
            .ownership_token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    );
    let mut invalid_token = cleanup.clone();
    invalid_token.ownership_token = "abcd-efgh".to_string();
    assert!(linux_resolved_paths(&resolv_conf, &invalid_token).is_err());
    assert_eq!(cleanup.previous_target, prior_target);
    install_linux_resolved_resolv_conf(&resolv_conf, &cleanup).expect("switch to resolved stub");
    assert_eq!(
        std::fs::read_link(&resolv_conf).expect("read installed symlink"),
        marker_target
    );
    assert_eq!(
        std::fs::read_link(&paths.marker).expect("read resolver marker"),
        stub
    );
    assert_eq!(
        std::fs::read_link(&paths.backup).expect("read resolver backup"),
        prior_target
    );

    restore_linux_resolved_resolv_conf(&resolv_conf, &cleanup)
        .expect("restore exact uplink target");
    assert_eq!(
        std::fs::read_link(&resolv_conf).expect("read restored symlink"),
        prior_target
    );
    assert_resolver_path_missing(&paths.marker);
    assert_resolver_path_missing(&paths.backup);
    assert_resolver_path_missing(&paths.candidate);
    assert_resolver_path_missing(&paths.active);
    std::fs::remove_dir_all(root).expect("remove resolver fixture");
}

#[cfg(unix)]
#[test]
fn resolved_stub_symlink_needs_no_nvpn_ownership() {
    let (root, resolv_conf, uplink, stub) = resolved_resolv_conf_fixture("already-stub");
    symlink(&stub, &resolv_conf).expect("install fixture stub symlink");

    assert_eq!(
        linux_resolved_resolv_conf_cleanup_intent(&resolv_conf, &uplink, &stub)
            .expect("classify stub symlink"),
        None
    );
    std::fs::remove_dir_all(root).expect("remove resolver fixture");
}

#[cfg(unix)]
#[test]
fn resolved_stub_noop_rejects_stale_reserved_paths() {
    let (root, resolv_conf, uplink, stub) = resolved_resolv_conf_fixture("stale-reserved");
    symlink(&stub, &resolv_conf).expect("install fixture stub symlink");
    let stale_path = resolv_conf
        .parent()
        .expect("resolver parent")
        .join(".nvpn-resolv-deadbeef.stub");
    symlink(&stub, &stale_path).expect("install stale resolver marker");
    let stale_marker = linux_resolved_resolv_conf_cleanup_intent(&resolv_conf, &uplink, &stub)
        .expect_err("stale marker must fail before native-stub classification");
    assert!(format!("{stale_marker:#}").contains("stale"));

    std::fs::remove_file(&stale_path).expect("remove stale marker");
    std::fs::remove_file(&resolv_conf).expect("remove native stub link");
    symlink(".nvpn-resolv-deadbeef.stub", &resolv_conf).expect("install stale main target");
    let stale_main = linux_resolved_resolv_conf_cleanup_intent(&resolv_conf, &uplink, &stub)
        .expect_err("raw reserved main target must fail closed");
    assert!(format!("{stale_main:#}").contains("reserved"));
    std::fs::remove_dir_all(root).expect("remove resolver fixture");
}

#[cfg(unix)]
#[test]
fn resolved_mode_rejects_resolv_conf_that_can_bypass_the_stub() {
    let (root, resolv_conf, uplink, stub) = resolved_resolv_conf_fixture("foreign");
    let foreign = root.join("foreign-resolv.conf");
    std::fs::write(&foreign, b"nameserver 203.0.113.53\n").expect("write foreign resolver");
    symlink(&foreign, &resolv_conf).expect("install foreign resolver symlink");

    let error = linux_resolved_resolv_conf_cleanup_intent(&resolv_conf, &uplink, &stub)
        .expect_err("foreign resolver must fail closed");
    assert!(format!("{error:#}").contains("unsupported"));
    std::fs::remove_dir_all(root).expect("remove resolver fixture");
}

#[cfg(unix)]
#[test]
fn resolved_mode_rejects_missing_or_regular_resolv_conf() {
    let (root, resolv_conf, uplink, stub) = resolved_resolv_conf_fixture("missing-or-regular");
    let missing = linux_resolved_resolv_conf_cleanup_intent(&resolv_conf, &uplink, &stub)
        .expect_err("missing resolv.conf must fail closed");
    assert!(format!("{missing:#}").contains("requires"));

    std::fs::write(&resolv_conf, b"nameserver 203.0.113.53\n").expect("write regular resolv.conf");
    let regular = linux_resolved_resolv_conf_cleanup_intent(&resolv_conf, &uplink, &stub)
        .expect_err("regular resolv.conf must fail closed");
    assert!(format!("{regular:#}").contains("requires"));
    std::fs::remove_dir_all(root).expect("remove resolver fixture");
}

#[cfg(unix)]
#[test]
fn resolved_cleanup_does_not_clobber_an_external_resolv_conf_change() {
    let (root, resolv_conf, uplink, stub) = resolved_resolv_conf_fixture("external-change");
    symlink(&uplink, &resolv_conf).expect("install fixture uplink symlink");
    let cleanup = linux_resolved_resolv_conf_cleanup_intent(&resolv_conf, &uplink, &stub)
        .expect("read cleanup intent")
        .expect("uplink switch cleanup intent");
    let paths = resolved_paths(&resolv_conf, &cleanup);
    install_linux_resolved_resolv_conf(&resolv_conf, &cleanup).expect("switch to resolved stub");

    std::fs::remove_file(&resolv_conf).expect("remove nVPN symlink");
    let external = root.join("external-resolv.conf");
    std::fs::write(&external, b"nameserver 198.51.100.53\n").expect("write external resolver");
    symlink(&external, &resolv_conf).expect("install external resolver symlink");
    restore_linux_resolved_resolv_conf(&resolv_conf, &cleanup)
        .expect("newer external resolver wins cleanup");
    assert_eq!(
        std::fs::read_link(&resolv_conf).expect("read external symlink"),
        external
    );
    assert_resolver_path_missing(&paths.backup);
    assert_resolver_path_missing(&paths.marker);
    assert_resolver_path_missing(&paths.candidate);
    assert_resolver_path_missing(&paths.active);
    std::fs::remove_dir_all(root).expect("remove resolver fixture");
}

#[cfg(unix)]
#[test]
fn resolved_cleanup_preserves_an_externally_changed_ownership_marker() {
    let (root, resolv_conf, uplink, stub) = resolved_resolv_conf_fixture("marker-takeover");
    symlink(&uplink, &resolv_conf).expect("install fixture uplink symlink");
    let cleanup = linux_resolved_resolv_conf_cleanup_intent(&resolv_conf, &uplink, &stub)
        .expect("read cleanup intent")
        .expect("uplink switch cleanup intent");
    let paths = resolved_paths(&resolv_conf, &cleanup);
    let marker_target = resolved_marker_target(&paths);
    install_linux_resolved_resolv_conf(&resolv_conf, &cleanup).expect("switch to resolved stub");

    let marker_path = paths.marker;
    std::fs::remove_file(&marker_path).expect("remove nVPN marker");
    let external = root.join("external-resolv.conf");
    std::fs::write(&external, b"nameserver 198.51.100.53\n").expect("write external resolver");
    symlink(&external, &marker_path).expect("take over resolver marker");
    let error = restore_linux_resolved_resolv_conf(&resolv_conf, &cleanup)
        .expect_err("external marker ownership must fail closed");
    assert!(format!("{error:#}").contains("preserving resolver state"));
    assert_eq!(
        std::fs::read_link(&resolv_conf).expect("read nVPN resolver link"),
        marker_target
    );
    assert_eq!(
        std::fs::read_link(&marker_path).expect("read external marker"),
        external
    );
    std::fs::remove_dir_all(root).expect("remove resolver fixture");
}

#[cfg(unix)]
#[test]
fn resolved_install_capture_preserves_a_preexisting_takeover() {
    let (root, resolv_conf, uplink, stub) = resolved_resolv_conf_fixture("pre-capture-takeover");
    symlink(&uplink, &resolv_conf).expect("install fixture uplink symlink");
    let cleanup = linux_resolved_resolv_conf_cleanup_intent(&resolv_conf, &uplink, &stub)
        .expect("read cleanup intent")
        .expect("uplink switch cleanup intent");
    let paths = resolved_paths(&resolv_conf, &cleanup);
    std::fs::remove_file(&resolv_conf).expect("remove original resolver symlink");
    let external = root.join("external-resolv.conf");
    std::fs::write(&external, b"nameserver 198.51.100.53\n").expect("write external resolver");
    symlink(&external, &resolv_conf).expect("install external resolver symlink");

    install_linux_resolved_resolv_conf(&resolv_conf, &cleanup)
        .expect_err("captured external resolver must be detected and restored");
    assert_eq!(
        std::fs::read_link(&resolv_conf).expect("read preserved external symlink"),
        external
    );
    restore_linux_resolved_resolv_conf(&resolv_conf, &cleanup).expect("remove only nVPN artifacts");
    assert_eq!(
        std::fs::read_link(&resolv_conf).expect("read preserved external symlink after cleanup"),
        external
    );
    assert_resolver_path_missing(&paths.marker);
    assert_resolver_path_missing(&paths.backup);
    assert_resolver_path_missing(&paths.candidate);
    assert_resolver_path_missing(&paths.active);
    std::fs::remove_dir_all(root).expect("remove resolver fixture");
}

#[cfg(unix)]
#[test]
fn resolved_install_noreplace_preserves_a_gap_takeover() {
    let (root, resolv_conf, uplink, stub) = resolved_resolv_conf_fixture("install-gap-takeover");
    symlink(&uplink, &resolv_conf).expect("install fixture uplink symlink");
    let cleanup = linux_resolved_resolv_conf_cleanup_intent(&resolv_conf, &uplink, &stub)
        .expect("read cleanup intent")
        .expect("uplink switch cleanup intent");
    let paths = resolved_paths(&resolv_conf, &cleanup);
    let external = root.join("external-resolv.conf");
    std::fs::write(&external, b"nameserver 198.51.100.53\n").expect("write external resolver");

    install_linux_resolved_resolv_conf_with_hook(&resolv_conf, &cleanup, || {
        symlink(&external, &resolv_conf).expect("claim resolver during install gap");
        Ok(())
    })
    .expect_err("gap takeover must win without replacement");
    assert_eq!(
        std::fs::read_link(&resolv_conf).expect("read preserved external symlink"),
        external
    );
    restore_linux_resolved_resolv_conf(&resolv_conf, &cleanup)
        .expect("external main wins and token-owned artifacts are removed");
    assert_eq!(
        std::fs::read_link(&resolv_conf).expect("read preserved external symlink after cleanup"),
        external
    );
    assert_resolver_path_missing(&paths.backup);
    assert_resolver_path_missing(&paths.candidate);
    assert_resolver_path_missing(&paths.marker);
    assert_resolver_path_missing(&paths.active);
    std::fs::remove_dir_all(root).expect("remove resolver fixture");
}

#[cfg(unix)]
#[test]
fn resolved_cleanup_noreplace_preserves_a_gap_takeover() {
    let (root, resolv_conf, uplink, stub) = resolved_resolv_conf_fixture("cleanup-takeover");
    symlink(&uplink, &resolv_conf).expect("install fixture uplink symlink");
    let cleanup = linux_resolved_resolv_conf_cleanup_intent(&resolv_conf, &uplink, &stub)
        .expect("read cleanup intent")
        .expect("uplink switch cleanup intent");
    let paths = resolved_paths(&resolv_conf, &cleanup);
    install_linux_resolved_resolv_conf(&resolv_conf, &cleanup).expect("switch to resolved stub");
    let external = root.join("external-resolv.conf");
    std::fs::write(&external, b"nameserver 198.51.100.53\n").expect("write external resolver");

    restore_linux_resolved_resolv_conf_with_hook(&resolv_conf, &cleanup, || {
        symlink(&external, &resolv_conf).expect("claim resolver during cleanup gap");
        Ok(())
    })
    .expect("cleanup gap takeover wins without being replaced");
    assert_eq!(
        std::fs::read_link(&resolv_conf).expect("read preserved external symlink"),
        external
    );
    assert_resolver_path_missing(&paths.backup);
    assert_resolver_path_missing(&paths.active);
    assert_resolver_path_missing(&paths.candidate);
    assert_resolver_path_missing(&paths.marker);
    restore_linux_resolved_resolv_conf(&resolv_conf, &cleanup)
        .expect("idempotent retry sees no owned artifacts");
    std::fs::remove_dir_all(root).expect("remove resolver fixture");
}

#[cfg(unix)]
#[test]
fn resolved_install_and_cleanup_preserve_regular_file_takeovers() {
    let (root, resolv_conf, uplink, stub) = resolved_resolv_conf_fixture("regular-takeover");
    symlink(&uplink, &resolv_conf).expect("install fixture uplink symlink");
    let cleanup = linux_resolved_resolv_conf_cleanup_intent(&resolv_conf, &uplink, &stub)
        .expect("read cleanup intent")
        .expect("uplink switch cleanup intent");
    let paths = resolved_paths(&resolv_conf, &cleanup);

    install_linux_resolved_resolv_conf_with_hook(&resolv_conf, &cleanup, || {
        std::fs::write(&resolv_conf, b"nameserver 198.51.100.53\n")
            .expect("claim install gap with regular resolver");
        Ok(())
    })
    .expect_err("regular install-gap takeover must win");
    restore_linux_resolved_resolv_conf(&resolv_conf, &cleanup)
        .expect("remove token artifacts around regular takeover");
    assert_eq!(
        std::fs::read(&resolv_conf).expect("read preserved regular resolver"),
        b"nameserver 198.51.100.53\n"
    );
    for path in [
        &paths.marker,
        &paths.backup,
        &paths.candidate,
        &paths.active,
    ] {
        assert_resolver_path_missing(path);
    }

    std::fs::remove_file(&resolv_conf).expect("remove first regular takeover");
    symlink(&uplink, &resolv_conf).expect("restore fixture uplink symlink");
    let second = linux_resolved_resolv_conf_cleanup_intent(&resolv_conf, &uplink, &stub)
        .expect("read second cleanup intent")
        .expect("second uplink switch cleanup intent");
    let second_paths = resolved_paths(&resolv_conf, &second);
    install_linux_resolved_resolv_conf(&resolv_conf, &second).expect("install second secure DNS");
    restore_linux_resolved_resolv_conf_with_hook(&resolv_conf, &second, || {
        std::fs::write(&resolv_conf, b"nameserver 203.0.113.53\n")
            .expect("claim cleanup gap with regular resolver");
        Ok(())
    })
    .expect("regular cleanup-gap takeover must win");
    assert_eq!(
        std::fs::read(&resolv_conf).expect("read second preserved regular resolver"),
        b"nameserver 203.0.113.53\n"
    );
    for path in [
        &second_paths.marker,
        &second_paths.backup,
        &second_paths.candidate,
        &second_paths.active,
    ] {
        assert_resolver_path_missing(path);
    }
    std::fs::remove_dir_all(root).expect("remove resolver fixture");
}

#[cfg(unix)]
#[test]
fn resolved_cleanup_rejects_reserved_main_without_artifacts() {
    let (root, resolv_conf, uplink, stub) = resolved_resolv_conf_fixture("reserved-main-only");
    symlink(&uplink, &resolv_conf).expect("install fixture uplink symlink");
    let cleanup = linux_resolved_resolv_conf_cleanup_intent(&resolv_conf, &uplink, &stub)
        .expect("read cleanup intent")
        .expect("uplink switch cleanup intent");
    let paths = resolved_paths(&resolv_conf, &cleanup);
    std::fs::remove_file(&resolv_conf).expect("remove fixture uplink");
    symlink(resolved_marker_target(&paths), &resolv_conf).expect("simulate dangling reserved main");

    let error = restore_linux_resolved_resolv_conf(&resolv_conf, &cleanup)
        .expect_err("reserved main cannot clear the journal");
    assert!(format!("{error:#}").contains("reserved nVPN path"));
    std::fs::remove_dir_all(root).expect("remove resolver fixture");
}

#[cfg(unix)]
#[test]
fn resolved_cleanup_retains_journal_when_main_is_missing_without_artifacts() {
    let (root, resolv_conf, uplink, stub) = resolved_resolv_conf_fixture("missing-main-only");
    symlink(&uplink, &resolv_conf).expect("install fixture uplink symlink");
    let cleanup = linux_resolved_resolv_conf_cleanup_intent(&resolv_conf, &uplink, &stub)
        .expect("read cleanup intent")
        .expect("uplink switch cleanup intent");
    std::fs::remove_file(&resolv_conf).expect("simulate external main removal");

    let error = restore_linux_resolved_resolv_conf(&resolv_conf, &cleanup)
        .expect_err("missing main cannot clear the journal");
    assert!(format!("{error:#}").contains("main resolver is missing"));
    std::fs::remove_dir_all(root).expect("remove resolver fixture");
}

#[cfg(unix)]
#[test]
fn resolved_cleanup_restores_main_missing_crash_phases() {
    let (root, resolv_conf, uplink, stub) = resolved_resolv_conf_fixture("missing-main-phases");
    symlink(&uplink, &resolv_conf).expect("install fixture uplink symlink");
    let cleanup = linux_resolved_resolv_conf_cleanup_intent(&resolv_conf, &uplink, &stub)
        .expect("read cleanup intent")
        .expect("uplink switch cleanup intent");
    let paths = resolved_paths(&resolv_conf, &cleanup);
    let marker_target = resolved_marker_target(&paths);
    symlink(&cleanup.stub_target, &paths.marker).expect("prepare marker");
    symlink(&marker_target, &paths.candidate).expect("prepare candidate");
    std::fs::rename(&resolv_conf, &paths.backup).expect("simulate crash after backup capture");

    restore_linux_resolved_resolv_conf(&resolv_conf, &cleanup)
        .expect("restore main after interrupted install");
    assert_eq!(
        std::fs::read_link(&resolv_conf).expect("restored main"),
        uplink
    );
    for path in [
        &paths.marker,
        &paths.backup,
        &paths.candidate,
        &paths.active,
    ] {
        assert_resolver_path_missing(path);
    }

    std::fs::remove_file(&resolv_conf).expect("remove first restored main");
    symlink(&uplink, &resolv_conf).expect("restore fixture uplink");
    let second = linux_resolved_resolv_conf_cleanup_intent(&resolv_conf, &uplink, &stub)
        .expect("read second cleanup intent")
        .expect("second uplink switch cleanup intent");
    let second_paths = resolved_paths(&resolv_conf, &second);
    install_linux_resolved_resolv_conf(&resolv_conf, &second).expect("install secure DNS");
    std::fs::rename(&resolv_conf, &second_paths.active)
        .expect("simulate crash after active capture");
    restore_linux_resolved_resolv_conf(&resolv_conf, &second)
        .expect("restore main after interrupted cleanup");
    assert_eq!(
        std::fs::read_link(&resolv_conf).expect("restored main"),
        uplink
    );
    for path in [
        &second_paths.marker,
        &second_paths.backup,
        &second_paths.candidate,
        &second_paths.active,
    ] {
        assert_resolver_path_missing(path);
    }
    std::fs::remove_dir_all(root).expect("remove resolver fixture");
}

#[cfg(unix)]
#[test]
fn resolved_crash_cleanup_removes_prepared_unique_links() {
    let (root, resolv_conf, uplink, stub) = resolved_resolv_conf_fixture("crash-window");
    symlink(&uplink, &resolv_conf).expect("install fixture uplink symlink");
    let cleanup = linux_resolved_resolv_conf_cleanup_intent(&resolv_conf, &uplink, &stub)
        .expect("read cleanup intent")
        .expect("uplink switch cleanup intent");
    let paths = resolved_paths(&resolv_conf, &cleanup);
    let marker_target = resolved_marker_target(&paths);
    symlink(&cleanup.stub_target, &paths.marker).expect("simulate prepared marker creation");
    symlink(&marker_target, &paths.candidate).expect("simulate prepared candidate creation");

    restore_linux_resolved_resolv_conf(&resolv_conf, &cleanup).expect("repair interrupted install");
    assert_eq!(
        std::fs::read_link(&resolv_conf).expect("read untouched uplink symlink"),
        uplink
    );
    assert_resolver_path_missing(&paths.marker);
    assert_resolver_path_missing(&paths.backup);
    assert_resolver_path_missing(&paths.candidate);
    assert_resolver_path_missing(&paths.active);
    std::fs::remove_dir_all(root).expect("remove resolver fixture");
}

#[test]
fn old_resolved_cleanup_journal_defaults_to_no_resolv_conf_ownership() {
    let cleanup: LinuxSecureDnsCleanupState =
        serde_json::from_str(r#"{"Resolved":{"interface":"nvpn0","interface_index":42}}"#)
            .expect("deserialize old cleanup journal");
    assert_eq!(
        cleanup,
        LinuxSecureDnsCleanupState::Resolved {
            interface: "nvpn0".to_string(),
            interface_index: Some(42),
            resolv_conf: None,
        }
    );
}

#[test]
fn resolved_cleanup_attempts_link_and_resolv_conf_rollback() {
    let order = std::cell::RefCell::new(Vec::new());
    let link_called = std::cell::Cell::new(false);
    let resolv_conf_called = std::cell::Cell::new(false);
    let error = restore_linux_resolved_components(
        || {
            order.borrow_mut().push("resolv_conf");
            resolv_conf_called.set(true);
            Err(anyhow!("resolv.conf rollback"))
        },
        || {
            order.borrow_mut().push("link");
            link_called.set(true);
            Err(anyhow!("link rollback"))
        },
    )
    .expect_err("both rollback failures");

    assert_eq!(&*order.borrow(), &["resolv_conf", "link"]);
    assert!(link_called.get());
    assert!(resolv_conf_called.get());
    let message = format!("{error:#}");
    assert!(message.contains("link rollback"));
    assert!(message.contains("resolv.conf rollback"));
}

#[test]
fn windows_wireguard_policy_uses_provider_dns_and_keeps_magic_dns_local() {
    let script = windows_wireguard_dns_script(
        "nvpn-wg-'exit",
        &["10.99.99.1".parse().expect("DNS address")],
    );
    assert!(script.contains("-Name 'nvpn-wg-''exit'"));
    assert!(script.contains("-ServerAddresses @('10.99.99.1')"));
    assert!(script.contains("-Namespace '.nvpn'"));
    assert!(script.contains("-Namespace '.fips'"));
    assert!(script.contains("-Namespace '.' -NameServers @('10.99.99.1')"));
    assert!(script.contains("try {"));
    assert!(script.contains("catch {"));
    assert!(script.contains("$originalError = $_"));
    assert!(script.contains("-Namespace '.' -NameServers '127.0.0.1'"));
    assert!(script.contains("throw $originalError"));
}

#[cfg(target_os = "windows")]
#[test]
fn windows_dns_command_budget_is_operation_specific() {
    assert_eq!(WINDOWS_DNS_COMMAND_TIMEOUT, Duration::from_secs(10));
    assert!(
        WINDOWS_DNS_COMMAND_TIMEOUT > crate::wg_upstream_runtime::WINDOWS_CHILD_COMMAND_TIMEOUT,
        "cold DnsClient PowerShell needs a larger bound than hot route/native commands"
    );
}

#[test]
fn direct_resolv_conf_is_limited_to_containers_and_openrc_hosts() {
    assert!(linux_direct_resolv_conf_allowed(true, false));
    assert!(linux_direct_resolv_conf_allowed(false, true));
    assert!(!linux_direct_resolv_conf_allowed(false, false));
}

#[cfg(target_os = "linux")]
#[test]
fn missing_openrc_resolv_conf_has_an_empty_restore_baseline() {
    let path = std::env::temp_dir().join(format!(
        "nvpn-missing-resolv-conf-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("unnamed")
    ));
    assert!(!path.exists());
    assert_eq!(
        read_linux_resolv_conf(&path).expect("missing baseline"),
        b""
    );
}

#[tokio::test]
async fn magic_dns_is_answered_locally_before_doh() {
    let packet = query_packet("peer.nvpn.", 55);
    let records = Arc::new(RwLock::new(HashMap::from([(
        "peer.nvpn".to_string(),
        Ipv4Addr::new(10, 44, 1, 9),
    )])));
    let resolver = SecureDnsResolver::new().expect("secure resolver");

    let response = resolve_or_servfail(&resolver, &records, None, &packet)
        .await
        .expect("local response");
    let response = Message::from_vec(&response).expect("DNS response");
    assert_eq!(response.id, 55);
    assert!(response.answers.iter().any(|answer| {
        matches!(
            &answer.data,
            RData::A(hickory_proto::rr::rdata::A(address))
                if *address == Ipv4Addr::new(10, 44, 1, 9)
        )
    }));
}

#[test]
fn direct_npub_fips_query_returns_ipv6_and_identity_without_doh() {
    let identity = fips_core::Identity::generate();
    let packet =
        query_packet_with_type(&format!("{}.fips.", identity.npub()), 77, RecordType::AAAA);

    let (response, resolved) = resolve_fips_dns_if_handled(&packet).expect("direct .fips response");
    let response = Message::from_vec(&response).expect("DNS response");
    assert_eq!(response.id, 77);
    assert!(response.answers.iter().any(|answer| {
        matches!(&answer.data, RData::AAAA(address) if address.0 == identity.address().to_ipv6())
    }));
    let resolved = resolved.expect("resolved identity");
    assert_eq!(resolved.node_addr, *identity.node_addr());
    let canonical_peer = PeerIdentity::from_npub(&identity.npub()).expect("canonical npub");
    assert_eq!(resolved.pubkey, canonical_peer.pubkey_full());
}

#[tokio::test]
async fn local_stub_serves_udp_and_fails_closed() {
    let server = Arc::new(
        tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("UDP server"),
    );
    let address = server.local_addr().expect("UDP address");
    let resolver: ResolverState = Arc::new(RwLock::new(Arc::new(FixtureResolver { fail: true })));
    let records = Arc::new(RwLock::new(HashMap::new()));
    let task = tokio::spawn(run_udp(server, resolver, records, None));
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("UDP client");
    client
        .send_to(&query_packet("example.com.", 81), address)
        .await
        .expect("UDP query");
    let mut response = [0_u8; 512];
    let (length, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut response))
        .await
        .expect("UDP timeout")
        .expect("UDP response");
    task.abort();

    let response = Message::from_vec(&response[..length]).expect("DNS response");
    assert_eq!(response.id, 81);
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
}

#[cfg(target_os = "windows")]
#[tokio::test]
async fn windows_udp_stub_survives_port_unreachable_from_expired_client() {
    let server = Arc::new(
        tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("UDP server"),
    );
    let address = server.local_addr().expect("UDP address");
    let resolver: ResolverState = Arc::new(RwLock::new(
        dns_resolver(&ExitDnsResolverConfig::FailClosed).expect("fail-closed resolver"),
    ));
    let records = Arc::new(RwLock::new(HashMap::from([(
        "alive.nvpn".to_string(),
        Ipv4Addr::new(10, 44, 1, 9),
    )])));
    let task = tokio::spawn(run_udp(Arc::clone(&server), resolver, records, None));

    // A DNS client can abandon its ephemeral UDP port before a delayed
    // response is sent. Windows reports the resulting local ICMP Port
    // Unreachable as WSAECONNRESET on the server's next receive.
    let expired_client = std::net::UdpSocket::bind("127.0.0.1:0").expect("expired UDP client");
    let expired_address = expired_client.local_addr().expect("expired client address");
    drop(expired_client);
    server
        .send_to(b"expired DNS response", expired_address)
        .await
        .expect("send to expired UDP client");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("live UDP client");
    client
        .send_to(&query_packet("alive.nvpn.", 83), address)
        .await
        .expect("live UDP query");
    let mut response = [0_u8; 512];
    let (length, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut response))
        .await
        .expect("UDP task stopped after transient Windows receive error")
        .expect("UDP response");
    task.abort();

    let response = Message::from_vec(&response[..length]).expect("DNS response");
    assert_eq!(response.id, 83);
    assert!(response.answers.iter().any(|answer| {
        matches!(
            &answer.data,
            RData::A(hickory_proto::rr::rdata::A(address))
                if *address == Ipv4Addr::new(10, 44, 1, 9)
        )
    }));
}

#[tokio::test]
async fn local_stub_serves_framed_tcp_dns() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("TCP server");
    let address = listener.local_addr().expect("TCP address");
    let resolver: ResolverState = Arc::new(RwLock::new(Arc::new(FixtureResolver { fail: false })));
    let records = Arc::new(RwLock::new(HashMap::new()));
    let task = tokio::spawn(run_tcp(listener, resolver, records, None));
    let mut client = tokio::net::TcpStream::connect(address)
        .await
        .expect("TCP client");
    let query = query_packet("example.com.", 82);
    client
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .expect("TCP query length");
    client.write_all(&query).await.expect("TCP query");
    let response_length = client.read_u16().await.expect("TCP response length") as usize;
    let mut response = vec![0_u8; response_length];
    client
        .read_exact(&mut response)
        .await
        .expect("TCP response");
    task.abort();

    let response = Message::from_vec(&response).expect("DNS response");
    assert_eq!(response.id, 82);
    assert_eq!(response.metadata.message_type, MessageType::Response);
}
