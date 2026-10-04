use std::collections::HashMap;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::fs;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
#[cfg(target_os = "macos")]
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{RwLock, mpsc};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

use crate::config::AppConfig;
use crate::network_routes::derive_mesh_tunnel_ip;

const DNS_TTL_SECS: u32 = 30;
const DNS_READ_TIMEOUT: Duration = Duration::from_millis(350);

#[derive(Debug, Clone)]
pub struct MagicDnsResolverConfig {
    pub suffix: String,
    pub nameserver: Ipv4Addr,
    pub port: u16,
    pub records: HashMap<String, Ipv4Addr>,
}

pub struct MagicDnsServer {
    local_addr: SocketAddr,
    records: Arc<RwLock<HashMap<String, Ipv4Addr>>>,
    stop_flag: Arc<AtomicBool>,
    finished_rx: mpsc::Receiver<()>,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl MagicDnsServer {
    pub fn start(bind_addr: SocketAddr, records: HashMap<String, Ipv4Addr>) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr)
            .with_context(|| format!("failed to bind magic dns on {bind_addr}"))?;
        socket
            .set_read_timeout(Some(DNS_READ_TIMEOUT))
            .context("failed to configure magic dns socket read timeout")?;

        let local_addr = socket
            .local_addr()
            .context("failed to get local magic dns socket address")?;
        let records = Arc::new(RwLock::new(records));
        let records_for_loop = Arc::clone(&records);
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_for_loop = Arc::clone(&stop_flag);
        let (finished_tx, finished_rx) = mpsc::channel();

        let join_handle = thread::spawn(move || {
            run_dns_loop(socket, records_for_loop, stop_for_loop);
            let _ = finished_tx.send(());
        });

        Ok(Self {
            local_addr,
            records,
            stop_flag,
            finished_rx,
            join_handle: Some(join_handle),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn update_records(&self, records: HashMap<String, Ipv4Addr>) {
        if let Ok(mut guard) = self.records.write() {
            *guard = records;
        }
    }

    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        let _ = self.finished_rx.recv_timeout(Duration::from_secs(1));
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for MagicDnsServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run_dns_loop(
    socket: UdpSocket,
    records: Arc<RwLock<HashMap<String, Ipv4Addr>>>,
    stop_flag: Arc<AtomicBool>,
) {
    let mut packet = [0_u8; 512];

    while !stop_flag.load(Ordering::Relaxed) {
        let Ok((len, peer_addr)) = socket.recv_from(&mut packet) else {
            continue;
        };
        let request = &packet[..len];
        let snapshot = records
            .read()
            .map(|guard| (*guard).clone())
            .unwrap_or_else(|_| HashMap::new());

        let Some(response) = resolve_fips_dns_if_handled(request)
            .map(|(response, _)| response)
            .or_else(|| build_dns_response(request, &snapshot, true))
        else {
            continue;
        };

        let _ = socket.send_to(&response, peer_addr);
    }
}

pub fn resolve_fips_dns_if_handled(
    query: &[u8],
) -> Option<(Vec<u8>, Option<fips_core::upper::dns::DnsResolvedIdentity>)> {
    let request = Message::from_vec(query).ok()?;
    let name = request.queries.first()?.name.to_utf8();
    if !name
        .trim_end_matches('.')
        .to_ascii_lowercase()
        .ends_with(".fips")
    {
        return None;
    }
    fips_core::upper::dns::handle_dns_packet(
        query,
        DNS_TTL_SECS,
        &fips_core::upper::hosts::HostMap::new(),
    )
}

pub fn build_magic_dns_response_if_handled(
    request: &[u8],
    records: &HashMap<String, Ipv4Addr>,
) -> Option<Vec<u8>> {
    build_dns_response(request, records, false)
}

pub fn build_magic_dns_server_failure_response(request: &[u8]) -> Option<Vec<u8>> {
    build_dns_error_response(request, ResponseCode::ServFail)
}

fn build_dns_response(
    request: &[u8],
    records: &HashMap<String, Ipv4Addr>,
    answer_name_errors: bool,
) -> Option<Vec<u8>> {
    let message = Message::from_vec(request).ok()?;
    let mut response = Message::new(message.id, MessageType::Response, OpCode::Query);
    response.metadata.recursion_desired = message.recursion_desired;
    response.metadata.recursion_available = false;
    response.metadata.authoritative = true;

    let mut answered = false;
    let mut matched_name = false;
    for query in &message.queries {
        response.add_query(query.clone());
        let mut qname = query.name().to_utf8().to_ascii_lowercase();
        qname = qname.trim_end_matches('.').to_string();
        if qname.is_empty() {
            continue;
        }

        let Some(ip) = records.get(&qname).copied() else {
            continue;
        };
        matched_name = true;
        if query.query_type() != RecordType::A {
            continue;
        }

        let answer = Record::from_rdata(query.name().clone(), DNS_TTL_SECS, RData::A(A(ip)));
        response.add_answer(answer);
        answered = true;
    }

    if !answered && !matched_name && !answer_name_errors {
        return None;
    }

    response.metadata.response_code = if answered || matched_name {
        ResponseCode::NoError
    } else {
        ResponseCode::NXDomain
    };

    let mut bytes = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut bytes);
    response.emit(&mut encoder).ok()?;
    Some(bytes)
}

fn build_dns_error_response(request: &[u8], code: ResponseCode) -> Option<Vec<u8>> {
    let message = Message::from_vec(request).ok()?;
    let mut response = Message::new(message.id, MessageType::Response, OpCode::Query);
    response.metadata.recursion_desired = message.recursion_desired;
    response.metadata.recursion_available = false;
    response.metadata.authoritative = true;
    response.metadata.response_code = code;
    for query in &message.queries {
        response.add_query(query.clone());
    }

    let mut bytes = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut bytes);
    response.emit(&mut encoder).ok()?;
    Some(bytes)
}

pub fn build_magic_dns_records(config: &AppConfig) -> HashMap<String, Ipv4Addr> {
    if !config.active_network_has_confirmed_local_identity() {
        return HashMap::new();
    }
    let suffix = config
        .magic_dns_suffix
        .trim()
        .trim_matches('.')
        .to_ascii_lowercase();
    let network_id = config.effective_network_id();
    let mut records = HashMap::new();

    if let (Some(alias), Ok(own_pubkey_hex)) =
        (config.self_magic_dns_label(), config.own_nostr_pubkey_hex())
        && let Some(tunnel_ip) = derive_mesh_tunnel_ip(&network_id, &own_pubkey_hex)
        && let Ok(ipv4) = strip_cidr(&tunnel_ip).parse::<Ipv4Addr>()
    {
        let alias = alias.to_ascii_lowercase();
        records.insert(alias.clone(), ipv4);
        if !suffix.is_empty() {
            records.insert(format!("{alias}.{suffix}"), ipv4);
        }
    }

    let own_pubkey_hex = config.own_nostr_pubkey_hex().ok();
    for participant in &config.active_network_signal_pubkeys_hex() {
        if own_pubkey_hex.as_deref() == Some(participant.as_str()) {
            continue;
        }
        let Some(alias) = config.peer_alias(participant) else {
            continue;
        };
        let Some(tunnel_ip) = derive_mesh_tunnel_ip(&network_id, participant) else {
            continue;
        };
        let Ok(ipv4) = strip_cidr(&tunnel_ip).parse::<Ipv4Addr>() else {
            continue;
        };

        let alias = alias.to_ascii_lowercase();
        records.insert(alias.clone(), ipv4);
        if !suffix.is_empty() {
            records.insert(format!("{alias}.{suffix}"), ipv4);
        }
    }

    records
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows", test))]
fn resolver_suffixes(suffix: &str) -> Vec<String> {
    let suffix = suffix.trim().trim_matches('.').to_ascii_lowercase();
    let mut suffixes = vec!["fips".to_string()];
    if !suffix.is_empty() && suffix != "fips" {
        suffixes.push(suffix);
    }
    suffixes
}

pub fn install_system_resolver(config: &MagicDnsResolverConfig) -> Result<()> {
    let suffix = config.suffix.trim().trim_matches('.').to_ascii_lowercase();

    #[cfg(target_os = "macos")]
    let (install, uninstall) = (install_macos_resolver, uninstall_macos_resolver);
    #[cfg(target_os = "windows")]
    let (install, uninstall) = (install_windows_resolver, uninstall_windows_resolver);

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        let suffixes = resolver_suffixes(&suffix);
        for (index, suffix) in suffixes.iter().enumerate() {
            if let Err(error) = install(suffix, config.nameserver, config.port) {
                for installed in &suffixes[..index] {
                    if let Err(cleanup) = uninstall(installed) {
                        eprintln!("magicdns: failed to roll back .{installed}: {cleanup}");
                    }
                }
                return Err(error);
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        install_linux_resolver(&suffix, config.nameserver, config.port, &config.records)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(anyhow!(
            "system magic dns is unsupported on this platform (suffix '{}')",
            suffix
        ))
    }
}

pub fn uninstall_system_resolver(suffix: &str) -> Result<()> {
    let suffix = suffix.trim().trim_matches('.').to_ascii_lowercase();

    #[cfg(target_os = "macos")]
    let uninstall = uninstall_macos_resolver;
    #[cfg(target_os = "windows")]
    let uninstall = uninstall_windows_resolver;
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        let failures: Vec<_> = resolver_suffixes(&suffix)
            .iter()
            .filter_map(|suffix| uninstall(suffix).err())
            .map(|error| error.to_string())
            .collect();
        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow!(failures.join("; ")))
        }
    }

    #[cfg(target_os = "linux")]
    {
        uninstall_linux_resolver(&suffix)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(anyhow!(
            "system magic dns uninstall is unsupported on this platform (suffix '{}')",
            suffix
        ))
    }
}

#[cfg(target_os = "macos")]
const MACOS_MAGIC_DNS_MARKER: &str = "# Managed by nvpn MagicDNS\n";

#[cfg(target_os = "macos")]
fn install_macos_resolver(suffix: &str, nameserver: Ipv4Addr, port: u16) -> Result<()> {
    let resolver_path = macos_resolver_path(suffix);
    write_macos_resolver(&resolver_path, nameserver, port)
}

#[cfg(target_os = "macos")]
fn write_macos_resolver(resolver_path: &Path, nameserver: Ipv4Addr, port: u16) -> Result<()> {
    if let Some(parent) = resolver_path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            if error.kind() == ErrorKind::PermissionDenied {
                anyhow!(
                    "permission denied creating {}; run with admin privileges",
                    parent.display()
                )
            } else {
                anyhow!(
                    "failed to create resolver directory {}: {error}",
                    parent.display()
                )
            }
        })?;
    }

    let legacy_body =
        format!("nameserver {nameserver}\nport {port}\noptions timeout:1 attempts:1\n");
    match fs::symlink_metadata(resolver_path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return Err(anyhow!(
                    "refusing to replace non-regular resolver {}",
                    resolver_path.display()
                ));
            }
            let current = fs::read_to_string(resolver_path)?;
            if current != legacy_body && !current.starts_with(MACOS_MAGIC_DNS_MARKER) {
                return Err(anyhow!(
                    "refusing to replace foreign resolver {}",
                    resolver_path.display()
                ));
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let body = format!("{MACOS_MAGIC_DNS_MARKER}{legacy_body}");
    fs::write(resolver_path, body).map_err(|error| {
        if error.kind() == ErrorKind::PermissionDenied {
            anyhow!(
                "permission denied writing {}; run with admin privileges",
                resolver_path.display()
            )
        } else {
            anyhow!(
                "failed to write resolver file {}: {error}",
                resolver_path.display()
            )
        }
    })?;

    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_macos_resolver(suffix: &str) -> Result<()> {
    let resolver_path = macos_resolver_path(suffix);
    remove_macos_resolver(&resolver_path)
}

#[cfg(target_os = "macos")]
fn remove_macos_resolver(resolver_path: &Path) -> Result<()> {
    match fs::symlink_metadata(resolver_path) {
        Ok(metadata) if !metadata.file_type().is_file() => return Ok(()),
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    if !fs::read_to_string(resolver_path)?.starts_with(MACOS_MAGIC_DNS_MARKER) {
        return Ok(());
    }

    fs::remove_file(resolver_path).map_err(|error| {
        if error.kind() == ErrorKind::PermissionDenied {
            anyhow!(
                "permission denied removing {}; run with admin privileges",
                resolver_path.display()
            )
        } else {
            anyhow!(
                "failed to remove resolver file {}: {error}",
                resolver_path.display()
            )
        }
    })?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_resolver_path(suffix: &str) -> PathBuf {
    PathBuf::from("/etc/resolver").join(suffix)
}

#[cfg(target_os = "linux")]
const LINUX_HOSTS_BEGIN: &str = "# BEGIN nostr-vpn MagicDNS";
#[cfg(target_os = "linux")]
const LINUX_HOSTS_END: &str = "# END nostr-vpn MagicDNS";
#[cfg(target_os = "linux")]
const LINUX_HOSTS_PATH: &str = "/etc/hosts";

#[cfg(target_os = "linux")]
fn install_linux_resolver(
    suffix: &str,
    nameserver: Ipv4Addr,
    port: u16,
    records: &HashMap<String, Ipv4Addr>,
) -> Result<()> {
    let resolver = if port == 53 {
        nameserver.to_string()
    } else {
        format!("{nameserver}:{port}")
    };

    let resolved_install = (|| -> Result<()> {
        run_linux_resolvectl(&["dns", "lo", &resolver])?;
        let domains: Vec<_> = resolver_suffixes(suffix)
            .iter()
            .map(|suffix| format!("~{suffix}"))
            .collect();
        let mut args = vec!["domain", "lo"];
        args.extend(domains.iter().map(String::as_str));
        run_linux_resolvectl(&args)?;
        let _ = run_linux_resolvectl(&["flush-caches"]);
        Ok(())
    })();

    match resolved_install {
        Ok(()) => {
            let _ = uninstall_linux_hosts_fallback();
            Ok(())
        }
        Err(resolved_error) => install_linux_hosts_fallback(suffix, records).with_context(|| {
            format!("systemd-resolved setup failed ({resolved_error}) and hosts fallback failed")
        }),
    }
}

#[cfg(target_os = "linux")]
fn uninstall_linux_resolver(_suffix: &str) -> Result<()> {
    let resolved_uninstall = run_linux_resolvectl(&["revert", "lo"]);
    let hosts_uninstall = uninstall_linux_hosts_fallback();

    match (resolved_uninstall, hosts_uninstall) {
        (Ok(()), Ok(_)) => Ok(()),
        (Err(_), Ok(true)) => Ok(()),
        (Err(resolved_error), Ok(false)) => Err(resolved_error),
        (Ok(()), Err(hosts_error)) => Err(hosts_error),
        (Err(resolved_error), Err(hosts_error)) => Err(anyhow!(
            "resolvectl cleanup failed ({resolved_error}); hosts cleanup failed ({hosts_error})"
        )),
    }
}

#[cfg(target_os = "linux")]
fn run_linux_resolvectl(args: &[&str]) -> Result<()> {
    let output = Command::new("resolvectl").args(args).output();
    let output = match output {
        Ok(output) => output,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Err(anyhow!(
                "resolvectl not found; install systemd-resolved tooling or configure DNS manually"
            ));
        }
        Err(error) => {
            return Err(anyhow!("failed to execute resolvectl: {error}"));
        }
    };

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    Err(anyhow!("resolvectl {} failed: {details}", args.join(" ")))
}

#[cfg(target_os = "linux")]
fn install_linux_hosts_fallback(suffix: &str, records: &HashMap<String, Ipv4Addr>) -> Result<()> {
    let suffix = suffix.trim().trim_matches('.').to_ascii_lowercase();
    let mut entries = records
        .iter()
        .filter_map(|(name, ip)| {
            let name = name.trim().trim_matches('.').to_ascii_lowercase();
            if name.ends_with(&format!(".{suffix}")) {
                Some((name, *ip))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries.dedup_by(|left, right| left.0 == right.0);

    if entries.is_empty() {
        return Err(anyhow!(
            "no .{suffix} MagicDNS records available for hosts fallback"
        ));
    }

    let current = read_linux_hosts_file()?;
    let mut next = remove_linux_hosts_magic_dns_block(&current);
    if !next.ends_with('\n') && !next.is_empty() {
        next.push('\n');
    }
    next.push_str(LINUX_HOSTS_BEGIN);
    next.push('\n');
    next.push_str("# Managed by nostr-vpn. Changes inside this block will be overwritten.\n");
    for (name, ip) in entries {
        next.push_str(&format!("{ip}\t{name}\n"));
    }
    next.push_str(LINUX_HOSTS_END);
    next.push('\n');

    write_linux_hosts_file(&next)
}

/// Rewrite the nostr-vpn block in `/etc/hosts` with `records` iff a block
/// is already present (i.e. the resolvectl path failed at install time and
/// we're on the hosts fallback). No-op otherwise so we don't litter
/// `/etc/hosts` on systems where resolvectl is the active path.
///
/// Called from the daemon after every config / roster reload so newly-added
/// peers become resolvable without restarting the daemon.
#[cfg(target_os = "linux")]
pub fn refresh_linux_hosts_fallback_if_active(
    suffix: &str,
    records: &HashMap<String, Ipv4Addr>,
) -> Result<()> {
    let current = read_linux_hosts_file()?;
    if !current.contains(LINUX_HOSTS_BEGIN) {
        return Ok(());
    }
    install_linux_hosts_fallback(suffix, records)
}

#[cfg(target_os = "linux")]
fn uninstall_linux_hosts_fallback() -> Result<bool> {
    let current = read_linux_hosts_file()?;
    let next = remove_linux_hosts_magic_dns_block(&current);
    if next == current {
        return Ok(false);
    }
    write_linux_hosts_file(&next)?;
    Ok(true)
}

#[cfg(target_os = "linux")]
fn read_linux_hosts_file() -> Result<String> {
    match fs::read_to_string(LINUX_HOSTS_PATH) {
        Ok(contents) => Ok(contents),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(String::new()),
        Err(error) if error.kind() == ErrorKind::PermissionDenied => Err(anyhow!(
            "permission denied reading {LINUX_HOSTS_PATH}; run with admin privileges"
        )),
        Err(error) => Err(anyhow!("failed to read {LINUX_HOSTS_PATH}: {error}")),
    }
}

#[cfg(target_os = "linux")]
fn write_linux_hosts_file(contents: &str) -> Result<()> {
    fs::write(LINUX_HOSTS_PATH, contents).map_err(|error| {
        if error.kind() == ErrorKind::PermissionDenied {
            anyhow!("permission denied writing {LINUX_HOSTS_PATH}; run with admin privileges")
        } else {
            anyhow!("failed to write {LINUX_HOSTS_PATH}: {error}")
        }
    })
}

#[cfg(target_os = "linux")]
fn remove_linux_hosts_magic_dns_block(contents: &str) -> String {
    let mut out = String::new();
    let mut in_block = false;
    for line in contents.lines() {
        if line.trim() == LINUX_HOSTS_BEGIN {
            in_block = true;
            continue;
        }
        if line.trim() == LINUX_HOSTS_END {
            in_block = false;
            continue;
        }
        if !in_block {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

#[cfg(any(target_os = "windows", test))]
fn windows_nameserver(nameserver: Ipv4Addr, port: u16) -> Result<String> {
    if port != 53 {
        return Err(anyhow!(
            "Windows split DNS requires the local MagicDNS server to listen on port 53"
        ));
    }
    Ok(nameserver.to_string())
}

#[cfg(any(target_os = "windows", test))]
fn windows_nrpt_display_name(suffix: &str) -> String {
    format!("nostr-vpn MagicDNS ({suffix})")
}

#[cfg(any(target_os = "windows", test))]
fn windows_nrpt_comment(suffix: &str) -> String {
    format!("nostr-vpn split DNS for {suffix}")
}

#[cfg(any(target_os = "windows", test))]
fn windows_powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(any(target_os = "windows", test))]
fn windows_install_nrpt_script(suffix: &str, nameserver: Ipv4Addr, port: u16) -> Result<String> {
    let namespace = suffix.trim().trim_matches('.').to_ascii_lowercase();
    let display_name = windows_nrpt_display_name(&namespace);
    let comment = windows_nrpt_comment(&namespace);
    let name_servers = windows_nameserver(nameserver, port)?;

    Ok(format!(
        concat!(
            "$ErrorActionPreference = 'Stop'\n",
            "$namespace = {}\n",
            "$displayName = {}\n",
            "$comment = {}\n",
            "$nameServers = {}\n",
            "Get-DnsClientNrptRule -ErrorAction SilentlyContinue |\n",
            "  Where-Object {{\n",
            "    $_.DisplayName -eq $displayName -or $_.Comment -eq $comment -or $_.Namespace -contains $namespace\n",
            "  }} |\n",
            "  ForEach-Object {{\n",
            "    $_ | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue | Out-Null\n",
            "  }}\n",
            "Add-DnsClientNrptRule -Namespace $namespace -NameServers $nameServers -DisplayName $displayName -Comment $comment -ErrorAction Stop | Out-Null\n",
        ),
        windows_powershell_quote(&namespace),
        windows_powershell_quote(&display_name),
        windows_powershell_quote(&comment),
        windows_powershell_quote(&name_servers),
    ))
}

#[cfg(any(target_os = "windows", test))]
fn windows_uninstall_nrpt_script(suffix: &str) -> String {
    let namespace = suffix.trim().trim_matches('.').to_ascii_lowercase();
    let display_name = windows_nrpt_display_name(&namespace);
    let comment = windows_nrpt_comment(&namespace);

    format!(
        concat!(
            "$namespace = {}\n",
            "$displayName = {}\n",
            "$comment = {}\n",
            "Get-DnsClientNrptRule -ErrorAction SilentlyContinue |\n",
            "  Where-Object {{\n",
            "    $_.DisplayName -eq $displayName -or $_.Comment -eq $comment -or $_.Namespace -contains $namespace\n",
            "  }} |\n",
            "  ForEach-Object {{\n",
            "    $_ | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue | Out-Null\n",
            "  }}\n",
        ),
        windows_powershell_quote(&namespace),
        windows_powershell_quote(&display_name),
        windows_powershell_quote(&comment),
    )
}

#[cfg(target_os = "windows")]
fn install_windows_resolver(suffix: &str, nameserver: Ipv4Addr, port: u16) -> Result<()> {
    let script = windows_install_nrpt_script(suffix, nameserver, port)?;
    run_windows_powershell(&script)
}

#[cfg(target_os = "windows")]
fn uninstall_windows_resolver(suffix: &str) -> Result<()> {
    run_windows_powershell(&windows_uninstall_nrpt_script(suffix))
}

#[cfg(target_os = "windows")]
fn run_windows_powershell(script: &str) -> Result<()> {
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output();
    let output = match output {
        Ok(output) => output,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Err(anyhow!(
                "powershell not found; configure Windows NRPT manually for split DNS"
            ));
        }
        Err(error) => {
            return Err(anyhow!("failed to execute powershell: {error}"));
        }
    };

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    Err(anyhow!("powershell NRPT update failed: {details}"))
}

fn strip_cidr(value: &str) -> &str {
    value.split('/').next().unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::{
        build_magic_dns_response_if_handled, windows_install_nrpt_script, windows_nameserver,
        windows_uninstall_nrpt_script,
    };
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    fn dns_query(name: &str) -> Vec<u8> {
        let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii(name).expect("query name"),
            RecordType::A,
        ));
        let mut bytes = Vec::new();
        let mut encoder = BinEncoder::new(&mut bytes);
        message.emit(&mut encoder).expect("encode query");
        bytes
    }

    #[test]
    fn split_dns_always_routes_fips_alongside_the_alias_suffix() {
        assert_eq!(super::resolver_suffixes("nvpn"), ["fips", "nvpn"]);
        assert_eq!(super::resolver_suffixes(" .Custom. "), ["fips", "custom"]);
        assert_eq!(super::resolver_suffixes(""), ["fips"]);
        assert_eq!(super::resolver_suffixes(".FIPS."), ["fips"]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_split_dns_installs_and_cleans_fips_without_replacing_foreign_files() {
        use super::{remove_macos_resolver, write_macos_resolver};
        use std::fs;

        let directory =
            std::env::temp_dir().join(format!("nvpn-split-dns-{}", uuid::Uuid::new_v4()));
        let path = directory.join("fips");
        write_macos_resolver(&path, Ipv4Addr::LOCALHOST, 1053).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("nameserver 127.0.0.1\nport 1053\n"));
        // A restart can update a resolver already owned by this listener.
        write_macos_resolver(&path, Ipv4Addr::LOCALHOST, 1054).unwrap();
        assert!(fs::read_to_string(&path).unwrap().contains("port 1054\n"));
        remove_macos_resolver(&path).unwrap();
        assert!(!path.exists());

        let foreign = "nameserver 192.0.2.53\n";
        fs::write(&path, foreign).unwrap();
        assert!(write_macos_resolver(&path, Ipv4Addr::LOCALHOST, 1053).is_err());
        remove_macos_resolver(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), foreign);
        fs::remove_file(&path).unwrap();
        let target = directory.join("foreign");
        fs::write(&target, foreign).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(write_macos_resolver(&path, Ipv4Addr::LOCALHOST, 1053).is_err());
        remove_macos_resolver(&path).unwrap();
        assert!(
            fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), foreign);
        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn magic_dns_response_if_answered_returns_matching_record() {
        let mut records = HashMap::new();
        records.insert("fixture-peer.nvpn".to_string(), Ipv4Addr::new(10, 44, 1, 2));

        let response =
            build_magic_dns_response_if_handled(&dns_query("fixture-peer.nvpn"), &records)
                .expect("response");
        let parsed = Message::from_vec(&response).expect("parse response");

        assert_eq!(parsed.answers.len(), 1);
        assert!(response.windows(4).any(|window| window == [10, 44, 1, 2]));
    }

    #[test]
    fn magic_dns_response_if_answered_lets_unknown_names_fall_through() {
        let records = HashMap::new();

        assert!(build_magic_dns_response_if_handled(&dns_query("example.com"), &records).is_none());
    }

    #[test]
    fn magic_dns_server_failure_response_returns_servfail() {
        let response = super::build_magic_dns_server_failure_response(&dns_query("example.com"))
            .expect("response");
        let parsed = Message::from_vec(&response).expect("parse response");

        assert_eq!(parsed.response_code, ResponseCode::ServFail);
        assert!(parsed.answers.is_empty());
    }

    #[test]
    fn windows_nrpt_install_script_targets_suffix_and_nameserver() {
        let script = windows_install_nrpt_script("mesh.example", Ipv4Addr::LOCALHOST, 53)
            .expect("build windows nrpt install script");
        assert!(script.contains("Add-DnsClientNrptRule"));
        assert!(script.contains("mesh.example"));
        assert!(script.contains("127.0.0.1"));
    }

    #[test]
    fn windows_nrpt_uninstall_script_matches_suffix() {
        let script = windows_uninstall_nrpt_script("mesh.example");
        assert!(script.contains("Get-DnsClientNrptRule"));
        assert!(script.contains("Remove-DnsClientNrptRule"));
        assert!(script.contains("mesh.example"));
    }

    #[test]
    fn windows_nrpt_requires_port_53() {
        let error = windows_nameserver(Ipv4Addr::LOCALHOST, 1053)
            .expect_err("non-53 port should be rejected");
        assert!(error.to_string().contains("port 53"));
    }
}
