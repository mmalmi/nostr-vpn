use std::collections::HashMap;
#[cfg(any(test, target_os = "windows"))]
use std::net::IpAddr;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(target_os = "windows")]
use std::process::Command;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use fips_endpoint::{FipsEndpoint, PeerIdentity};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinEncodable as _, BinEncoder};
use nostr_vpn_core::config::ExitDnsResolverConfig;
use nostr_vpn_core::secure_dns::{
    SECURE_DNS_MAX_MESSAGE_BYTES, SecureDnsLookup, build_servfail_response,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::Semaphore;
use tokio::task::{JoinHandle, JoinSet};

mod resolver;
use resolver::{current_resolver, dns_resolver, resolve_fips_dns_if_handled};
#[cfg(any(target_os = "linux", test))]
mod linux;
#[cfg(any(target_os = "linux", test))]
pub(crate) use linux::LinuxSecureDnsCleanupState;
#[cfg(all(test, target_os = "linux"))]
use linux::read_linux_resolv_conf;
#[cfg(target_os = "linux")]
pub(crate) use linux::repair_linux_secure_dns_cleanup_state;
#[cfg(test)]
use linux::{
    LINUX_DIRECT_RESOLV_CONF, linux_direct_resolv_conf_allowed,
    linux_direct_resolv_conf_needs_restore, restore_linux_resolved_components,
};
#[cfg(all(test, unix))]
use linux::{
    LinuxResolvedPaths, install_linux_resolved_resolv_conf,
    install_linux_resolved_resolv_conf_with_hook, linux_resolved_paths,
    linux_resolved_resolv_conf_cleanup_intent, restore_linux_resolved_resolv_conf,
    restore_linux_resolved_resolv_conf_with_hook,
};
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub(crate) use macos::cleanup_owned_macos_secure_dns_state;
#[cfg(target_os = "macos")]
use macos::{
    install_macos_secure_dns_store, macos_resolver_configs, macos_secure_dns_store_is_owned,
    remove_owned_macos_resolver_file, remove_owned_macos_secure_dns_store,
    write_macos_resolver_atomically,
};

#[cfg(target_os = "macos")]
const SECURE_DNS_PORT: u16 = 1053;
#[cfg(not(target_os = "macos"))]
const SECURE_DNS_PORT: u16 = 53;
const SECURE_DNS_BIND: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, SECURE_DNS_PORT));
const SECURE_DNS_MAX_IN_FLIGHT: usize = 64;
const SECURE_DNS_CLIENT_IDLE: Duration = Duration::from_secs(10);
#[cfg(target_os = "windows")]
const WINDOWS_DNS_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
type SharedResolver = Arc<dyn SecureDnsLookup>;
type ResolverState = Arc<RwLock<SharedResolver>>;
type FipsDnsEndpoint = Option<Arc<FipsEndpoint>>;
const FIPS_DNS_TTL_SECS: u32 = 30;
const PAID_EXIT_DNS_HEALTH_HOST: &str = "api.ipify.org.";

#[derive(Clone)]
pub(crate) struct SecureDnsHealthProbe {
    resolver: SharedResolver,
}

impl SecureDnsHealthProbe {
    pub(crate) async fn check_paid_exit(&self) -> Result<()> {
        let mut query = Message::new(0x4e56, MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(
            Name::from_ascii(PAID_EXIT_DNS_HEALTH_HOST)
                .expect("paid exit DNS health host is valid"),
            RecordType::A,
        ));
        let mut packet = Vec::with_capacity(64);
        query
            .emit(&mut BinEncoder::new(&mut packet))
            .context("encode paid exit DNS health query")?;
        let response = self
            .resolver
            .resolve(&packet)
            .await
            .context("secure DNS did not answer through the selected exit")?;
        let response = Message::from_vec(&response)
            .context("secure DNS returned an invalid paid exit health response")?;
        if response.metadata.response_code != ResponseCode::NoError
            || !response
                .answers
                .iter()
                .any(|answer| matches!(answer.data, RData::A(_)))
        {
            return Err(anyhow!(
                "secure DNS returned no IPv4 address through the selected exit"
            ));
        }
        Ok(())
    }
}

pub(crate) struct SecureDnsRuntime {
    udp_task: Option<JoinHandle<()>>,
    tcp_task: Option<JoinHandle<()>>,
    records: Arc<RwLock<HashMap<String, Ipv4Addr>>>,
    resolver: ResolverState,
    resolver_config: ExitDnsResolverConfig,
    system_dns: SystemDnsGuard,
}

impl SecureDnsRuntime {
    pub(crate) fn health_probe(&self) -> Result<SecureDnsHealthProbe> {
        let resolver = current_resolver(&self.resolver)
            .ok_or_else(|| anyhow!("secure DNS resolver lock poisoned"))?;
        Ok(SecureDnsHealthProbe { resolver })
    }

    pub(crate) async fn start_into(
        slot: &mut Option<Self>,
        interface: &str,
        interface_index: Option<u32>,
        records: HashMap<String, Ipv4Addr>,
        resolver_config: ExitDnsResolverConfig,
        fips_endpoint: FipsDnsEndpoint,
        persist_cleanup_intent: impl FnOnce(&SystemDnsCleanupIntent) -> Result<()>,
    ) -> Result<()> {
        let cleanup_intent = system_dns_cleanup_intent(interface, interface_index)?;
        let udp = Arc::new(
            tokio::net::UdpSocket::bind(SECURE_DNS_BIND)
                .await
                .with_context(|| format!("failed to bind secure DNS UDP on {SECURE_DNS_BIND}"))?,
        );
        let tcp = tokio::net::TcpListener::bind(SECURE_DNS_BIND)
            .await
            .with_context(|| format!("failed to bind secure DNS TCP on {SECURE_DNS_BIND}"))?;
        let resolver = Arc::new(RwLock::new(dns_resolver(&resolver_config)?));
        let records = Arc::new(RwLock::new(records));
        let udp_task = tokio::spawn(run_udp(
            udp,
            Arc::clone(&resolver),
            Arc::clone(&records),
            fips_endpoint.clone(),
        ));
        let tcp_task = tokio::spawn(run_tcp(
            tcp,
            Arc::clone(&resolver),
            Arc::clone(&records),
            fips_endpoint,
        ));
        if let Err(error) = persist_cleanup_intent(&cleanup_intent) {
            udp_task.abort();
            tcp_task.abort();
            return Err(error.context(
                "persist secure DNS cleanup ownership before changing the system resolver",
            ));
        }
        match SystemDnsGuard::install(cleanup_intent) {
            Ok(system_dns) => {
                *slot = Some(Self {
                    udp_task: Some(udp_task),
                    tcp_task: Some(tcp_task),
                    records,
                    resolver,
                    resolver_config,
                    system_dns,
                });
                Ok(())
            }
            Err(mut failure) => {
                if let Some(system_dns) = failure.cleanup_guard.take() {
                    // A platform DNS mutation could not be rolled back. Keep
                    // the localhost stub alive and retain exact cleanup
                    // ownership in the caller's runtime slot. The enclosing
                    // apply transaction journals that ownership before
                    // returning this error.
                    *slot = Some(Self {
                        udp_task: Some(udp_task),
                        tcp_task: Some(tcp_task),
                        records,
                        resolver,
                        resolver_config,
                        system_dns,
                    });
                } else {
                    // The install either made no system change or rolled it
                    // back completely, so the stub is no longer needed.
                    udp_task.abort();
                    tcp_task.abort();
                }
                Err(failure.error)
            }
        }
    }

    pub(crate) fn update_config(
        &mut self,
        records: HashMap<String, Ipv4Addr>,
        resolver_config: ExitDnsResolverConfig,
    ) -> Result<()> {
        if let Ok(mut current) = self.records.write() {
            *current = records;
        }
        if self.resolver_config != resolver_config {
            self.reset_resolver(resolver_config)?;
        }
        Ok(())
    }

    pub(crate) fn reset_resolver(&mut self, resolver_config: ExitDnsResolverConfig) -> Result<()> {
        let resolver = dns_resolver(&resolver_config)?;
        *self
            .resolver
            .write()
            .map_err(|_| anyhow!("secure DNS resolver lock poisoned"))? = resolver;
        self.resolver_config = resolver_config;
        Ok(())
    }

    pub(crate) fn update_records(&self, records: HashMap<String, Ipv4Addr>) {
        if let Ok(mut current) = self.records.write() {
            *current = records;
        }
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn update_windows_wireguard_dns(
        &mut self,
        interface: Option<&str>,
        servers: &[IpAddr],
    ) -> Result<()> {
        self.system_dns
            .update_windows_wireguard_dns(interface, servers)
    }

    pub(crate) async fn stop(&mut self) -> Result<()> {
        // Keep the local stub alive until the OS resolver is restored. If
        // resolver cleanup fails, callers retain this runtime and DNS keeps
        // working while the exact cleanup is retried.
        self.system_dns.cleanup()?;
        if let Some(task) = self.udp_task.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.tcp_task.take() {
            task.abort();
            let _ = task.await;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn linux_cleanup_state(&self) -> Option<LinuxSecureDnsCleanupState> {
        self.system_dns
            .active
            .then(|| self.system_dns.linux.clone())
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn windows_cleanup_interface_index(&self) -> Option<u32> {
        self.system_dns
            .active
            .then_some(self.system_dns.interface_index)
    }
}

impl Drop for SecureDnsRuntime {
    fn drop(&mut self) {
        if let Err(error) = self.system_dns.cleanup() {
            // Dropping JoinHandle detaches rather than cancels the tasks. Keep
            // the stub serving when the OS still points at it.
            eprintln!(
                "secure DNS: resolver cleanup failed during drop; keeping local stub alive: \
                 {error:#}"
            );
            return;
        }
        if let Some(task) = self.udp_task.take() {
            task.abort();
        }
        if let Some(task) = self.tcp_task.take() {
            task.abort();
        }
    }
}

async fn run_udp(
    socket: Arc<tokio::net::UdpSocket>,
    resolver: ResolverState,
    records: Arc<RwLock<HashMap<String, Ipv4Addr>>>,
    fips_endpoint: FipsDnsEndpoint,
) {
    let permits = Arc::new(Semaphore::new(SECURE_DNS_MAX_IN_FLIGHT));
    let mut requests = JoinSet::new();
    let mut packet = vec![0_u8; SECURE_DNS_MAX_MESSAGE_BYTES];
    loop {
        tokio::select! {
            completed = requests.join_next(), if !requests.is_empty() => {
                if let Some(Err(error)) = completed {
                    tracing::debug!(%error, "secure DNS UDP task failed");
                }
            }
            received = socket.recv_from(&mut packet) => {
                let (length, peer) = match received {
                    Ok(received) => received,
                    #[cfg(target_os = "windows")]
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {
                        tracing::debug!(%error, "secure DNS ignored expired UDP client");
                        continue;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "secure DNS UDP receive failed");
                        break;
                    }
                };
                let query = packet[..length].to_vec();
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    if let Some(response) = build_servfail_response(&query) {
                        let _ = socket.send_to(&response, peer).await;
                    }
                    continue;
                };
                let socket = Arc::clone(&socket);
                let resolver = current_resolver(&resolver);
                let records = Arc::clone(&records);
                let fips_endpoint = fips_endpoint.clone();
                requests.spawn(async move {
                    let _permit = permit;
                    if let Some(response) = match resolver {
                        Some(resolver) =>
                            resolve_or_servfail(
                                resolver.as_ref(),
                                &records,
                                fips_endpoint.as_deref(),
                                &query,
                            ).await,
                        None => build_servfail_response(&query),
                    }
                    {
                        let _ = socket.send_to(&response, peer).await;
                    }
                });
            }
        }
    }
    requests.abort_all();
}

async fn run_tcp(
    listener: tokio::net::TcpListener,
    resolver: ResolverState,
    records: Arc<RwLock<HashMap<String, Ipv4Addr>>>,
    fips_endpoint: FipsDnsEndpoint,
) {
    let permits = Arc::new(Semaphore::new(SECURE_DNS_MAX_IN_FLIGHT));
    let mut requests = JoinSet::new();
    loop {
        tokio::select! {
            completed = requests.join_next(), if !requests.is_empty() => {
                if let Some(Err(error)) = completed {
                    tracing::debug!(%error, "secure DNS TCP task failed");
                }
            }
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { break; };
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let resolver = Arc::clone(&resolver);
                let records = Arc::clone(&records);
                let fips_endpoint = fips_endpoint.clone();
                requests.spawn(async move {
                    let _permit = permit;
                    handle_tcp(stream, resolver, records, fips_endpoint).await;
                });
            }
        }
    }
    requests.abort_all();
}

async fn handle_tcp(
    mut stream: tokio::net::TcpStream,
    resolver: ResolverState,
    records: Arc<RwLock<HashMap<String, Ipv4Addr>>>,
    fips_endpoint: FipsDnsEndpoint,
) {
    loop {
        let Ok(Ok(length)) = tokio::time::timeout(SECURE_DNS_CLIENT_IDLE, stream.read_u16()).await
        else {
            return;
        };
        let length = usize::from(length);
        if !(12..=SECURE_DNS_MAX_MESSAGE_BYTES).contains(&length) {
            return;
        }
        let mut query = vec![0_u8; length];
        let Ok(Ok(_)) =
            tokio::time::timeout(SECURE_DNS_CLIENT_IDLE, stream.read_exact(&mut query)).await
        else {
            return;
        };
        let response = match current_resolver(&resolver) {
            Some(resolver) => {
                resolve_or_servfail(
                    resolver.as_ref(),
                    &records,
                    fips_endpoint.as_deref(),
                    &query,
                )
                .await
            }
            None => build_servfail_response(&query),
        };
        let Some(response) = response else {
            return;
        };
        let Ok(length) = u16::try_from(response.len()) else {
            return;
        };
        if stream.write_all(&length.to_be_bytes()).await.is_err()
            || stream.write_all(&response).await.is_err()
        {
            return;
        }
    }
}

async fn resolve_or_servfail(
    resolver: &dyn SecureDnsLookup,
    records: &Arc<RwLock<HashMap<String, Ipv4Addr>>>,
    fips_endpoint: Option<&FipsEndpoint>,
    query: &[u8],
) -> Option<Vec<u8>> {
    if let Ok(records) = records.read()
        && let Some(response) =
            nostr_vpn_core::magic_dns::build_magic_dns_response_if_handled(query, &records)
    {
        return Some(response);
    }
    if let Some(endpoint) = fips_endpoint
        && let Some((response, identity)) = resolve_fips_dns_if_handled(query)
    {
        if let Some(identity) = identity {
            let peer = PeerIdentity::from_pubkey_full(identity.pubkey);
            if peer.node_addr() != &identity.node_addr
                || !endpoint.register_peer_identity(peer).await.unwrap_or(false)
            {
                return build_servfail_response(query);
            }
        }
        return Some(response);
    }
    match resolver.resolve(query).await {
        Ok(response) => Some(response),
        Err(error) => {
            tracing::debug!(%error, "secure DNS resolution failed closed");
            build_servfail_response(query)
        }
    }
}

struct SystemDnsGuard {
    #[cfg(target_os = "linux")]
    linux: LinuxSecureDnsCleanupState,
    #[cfg(target_os = "macos")]
    resolver_paths: Vec<PathBuf>,
    #[cfg(target_os = "macos")]
    secure_dns_store: bool,
    #[cfg(target_os = "windows")]
    interface_index: u32,
    active: bool,
}

#[derive(Debug, Clone)]
pub(crate) enum SystemDnsCleanupIntent {
    #[cfg(target_os = "linux")]
    Linux(LinuxSecureDnsCleanupState),
    #[cfg(target_os = "macos")]
    MacosResolverFiles,
    #[cfg(target_os = "windows")]
    WindowsInterface(u32),
}

struct SystemDnsInstallFailure {
    error: anyhow::Error,
    cleanup_guard: Option<SystemDnsGuard>,
}

fn system_dns_cleanup_intent(
    interface: &str,
    interface_index: Option<u32>,
) -> Result<SystemDnsCleanupIntent> {
    #[cfg(target_os = "linux")]
    {
        let _ = interface_index;
        return Ok(SystemDnsCleanupIntent::Linux(linux::cleanup_intent(
            interface,
        )?));
    }

    #[cfg(target_os = "macos")]
    {
        let _ = (interface, interface_index);
        return Ok(SystemDnsCleanupIntent::MacosResolverFiles);
    }

    #[cfg(target_os = "windows")]
    {
        let _ = interface;
        return interface_index
            .map(SystemDnsCleanupIntent::WindowsInterface)
            .ok_or_else(|| anyhow!("Windows secure DNS requires a tunnel interface index"));
    }

    #[allow(unreachable_code)]
    Err(anyhow!("secure system DNS is unsupported on this platform"))
}

impl SystemDnsInstallFailure {
    fn rolled_back(error: anyhow::Error) -> Self {
        Self {
            error,
            cleanup_guard: None,
        }
    }

    fn cleanup_pending(error: anyhow::Error, cleanup_guard: SystemDnsGuard) -> Self {
        Self {
            error,
            cleanup_guard: Some(cleanup_guard),
        }
    }
}

#[cfg(target_os = "macos")]
fn macos_secure_dns_store_cleanup_may_be_pending(ownership: &std::io::Result<bool>) -> bool {
    match ownership {
        Ok(owned) => *owned,
        Err(_) => true,
    }
}

impl SystemDnsGuard {
    fn install(
        cleanup_intent: SystemDnsCleanupIntent,
    ) -> std::result::Result<Self, SystemDnsInstallFailure> {
        #[cfg(target_os = "linux")]
        {
            let SystemDnsCleanupIntent::Linux(cleanup_state) = cleanup_intent;
            let install = linux::install(&cleanup_state);
            if let Err(install_error) = install {
                let rollback = linux::restore(&cleanup_state);
                crate::fips_private_mesh::record_linux_secure_dns_cleanup(
                    cleanup_state.clone(),
                    &rollback,
                );
                return match rollback {
                    Ok(()) => Err(SystemDnsInstallFailure::rolled_back(install_error)),
                    Err(rollback_error) => Err(SystemDnsInstallFailure::cleanup_pending(
                        anyhow!(
                            "failed to install Linux secure DNS ({install_error:#}); \
                                 rollback also failed ({rollback_error:#})"
                        ),
                        Self {
                            linux: cleanup_state,
                            active: true,
                        },
                    )),
                };
            }
            linux::flush_caches();
            return Ok(Self {
                linux: cleanup_state,
                active: true,
            });
        }

        #[cfg(target_os = "macos")]
        {
            let SystemDnsCleanupIntent::MacosResolverFiles = cleanup_intent;
            let resolver_configs = macos_resolver_configs();
            if let Some(parent) = resolver_configs[0].0.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))
                    .map_err(SystemDnsInstallFailure::rolled_back)?;
            }
            let mut resolver_paths: Vec<PathBuf> = Vec::with_capacity(resolver_configs.len());
            for (resolver_path, config) in resolver_configs {
                if let Err(error) = write_macos_resolver_atomically(&resolver_path, &config) {
                    let mut rollback_failures = Vec::new();
                    for installed_path in &resolver_paths {
                        if let Err(rollback_error) =
                            remove_owned_macos_resolver_file(installed_path)
                        {
                            rollback_failures.push(format!(
                                "remove {}: {rollback_error}",
                                installed_path.display()
                            ));
                        }
                    }
                    if !rollback_failures.is_empty() {
                        return Err(SystemDnsInstallFailure::cleanup_pending(
                            anyhow!(
                                "failed to install {}: {error}; rollback failed: {}",
                                resolver_path.display(),
                                rollback_failures.join("; ")
                            ),
                            Self {
                                resolver_paths,
                                secure_dns_store: false,
                                active: true,
                            },
                        ));
                    }
                    return Err(SystemDnsInstallFailure::rolled_back(
                        anyhow!(error)
                            .context(format!("failed to install {}", resolver_path.display())),
                    ));
                }
                resolver_paths.push(resolver_path);
            }
            if let Err(error) = install_macos_secure_dns_store() {
                let install_error = anyhow!(error).context("failed to install macOS secure DNS");
                let mut rollback_failures = Vec::new();
                for installed_path in &resolver_paths {
                    if let Err(rollback_error) = remove_owned_macos_resolver_file(installed_path) {
                        rollback_failures.push(format!(
                            "remove {}: {rollback_error}",
                            installed_path.display()
                        ));
                    }
                }
                let store_ownership = macos_secure_dns_store_is_owned();
                let secure_dns_store =
                    macos_secure_dns_store_cleanup_may_be_pending(&store_ownership);
                match store_ownership {
                    Ok(true) => rollback_failures
                        .push("owned macOS secure DNS dynamic-store state remains".to_string()),
                    Ok(false) => {}
                    Err(ownership_error) => rollback_failures.push(format!(
                        "could not verify macOS secure DNS dynamic-store cleanup: \
                         {ownership_error}"
                    )),
                }
                if secure_dns_store || !rollback_failures.is_empty() {
                    return Err(SystemDnsInstallFailure::cleanup_pending(
                        anyhow!(
                            "{install_error:#}; rollback incomplete: {}",
                            rollback_failures.join("; ")
                        ),
                        Self {
                            resolver_paths,
                            secure_dns_store,
                            active: true,
                        },
                    ));
                }
                return Err(SystemDnsInstallFailure::rolled_back(install_error));
            }
            return Ok(Self {
                resolver_paths,
                secure_dns_store: true,
                active: true,
            });
        }

        #[cfg(target_os = "windows")]
        {
            let SystemDnsCleanupIntent::WindowsInterface(interface_index) = cleanup_intent;
            if let Err(install_error) =
                run_windows_powershell(&windows_secure_dns_install_script(interface_index))
                    .context("install Windows secure DNS policy")
            {
                let rollback =
                    run_windows_powershell(&windows_secure_dns_uninstall_script(interface_index))
                        .context("roll back Windows secure DNS policy");
                crate::fips_private_mesh::record_windows_secure_dns_cleanup(
                    interface_index,
                    &rollback,
                );
                return match rollback {
                    Ok(()) => Err(SystemDnsInstallFailure::rolled_back(install_error)),
                    Err(rollback_error) => Err(SystemDnsInstallFailure::cleanup_pending(
                        anyhow!(
                            "failed to install Windows secure DNS ({install_error:#}); \
                             rollback also failed ({rollback_error:#})"
                        ),
                        Self {
                            interface_index,
                            active: true,
                        },
                    )),
                };
            }
            return Ok(Self {
                interface_index,
                active: true,
            });
        }

        #[allow(unreachable_code)]
        Err(SystemDnsInstallFailure::rolled_back(anyhow!(
            "secure system DNS is unsupported on this platform"
        )))
    }

    #[cfg(target_os = "windows")]
    fn update_windows_wireguard_dns(
        &mut self,
        interface: Option<&str>,
        servers: &[IpAddr],
    ) -> Result<()> {
        match interface.filter(|_| !servers.is_empty()) {
            Some(interface) => {
                run_windows_powershell(&windows_wireguard_dns_script(interface, servers))
                    .context("set Windows WireGuard DNS policy")
            }
            None => {
                run_windows_powershell(&windows_secure_dns_install_script(self.interface_index))
                    .context("restore Windows secure DNS policy")
            }
        }
    }

    fn cleanup(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        {
            let result = linux::restore(&self.linux);
            if result.is_ok() {
                self.active = false;
                linux::flush_caches();
            }
            return result;
        }

        #[cfg(target_os = "macos")]
        {
            let mut failures = Vec::new();
            if self.secure_dns_store {
                match remove_owned_macos_secure_dns_store() {
                    Ok(_) => self.secure_dns_store = false,
                    Err(error) => failures.push(format!(
                        "remove macOS secure DNS dynamic-store state: {error}"
                    )),
                }
            }
            let mut remaining = Vec::new();
            for resolver_path in std::mem::take(&mut self.resolver_paths) {
                match remove_owned_macos_resolver_file(&resolver_path) {
                    Ok(_) => {}
                    Err(error) => {
                        failures.push(format!("remove {}: {error}", resolver_path.display()));
                        remaining.push(resolver_path);
                    }
                }
            }
            self.resolver_paths = remaining;
            self.active = self.secure_dns_store || !self.resolver_paths.is_empty();
            return if failures.is_empty() {
                Ok(())
            } else {
                Err(anyhow!(failures.join("; ")))
            };
        }

        #[cfg(target_os = "windows")]
        {
            let result =
                run_windows_powershell(&windows_secure_dns_uninstall_script(self.interface_index))
                    .context("remove Windows secure DNS policy");
            if result.is_ok() {
                self.active = false;
            }
            return result;
        }

        #[allow(unreachable_code)]
        Ok(())
    }
}

impl Drop for SystemDnsGuard {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("secure DNS: cleanup failed: {error:#}");
        }
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn repair_windows_secure_dns(_interface_index: u32) -> Result<()> {
    // The Wintun adapter is process-owned and normally disappears on a hard
    // crash. A saved interface index can be reused by an unrelated adapter,
    // so crash repair removes only nVPN's uniquely marked global NRPT rules.
    // Live cleanup uses `windows_secure_dns_uninstall_script` while the
    // runtime still owns the exact adapter.
    run_windows_powershell(&windows_secure_dns_repair_script())
        .context("repair Windows secure DNS policy")
}

#[cfg(any(target_os = "windows", test))]
fn windows_secure_dns_install_script(interface_index: u32) -> String {
    format!(
        concat!(
            "$ErrorActionPreference = 'Stop'\n",
            "$displayName = 'nostr-vpn secure DNS'\n",
            "$comment = 'nostr-vpn authenticated DNS-over-HTTPS stub'\n",
            "Get-DnsClientNrptRule -ErrorAction Stop | Where-Object {{ $_.DisplayName -eq $displayName -or $_.Comment -eq $comment }} | ForEach-Object {{ $_ | Remove-DnsClientNrptRule -Force -ErrorAction Stop | Out-Null }}\n",
            "Set-DnsClientServerAddress -InterfaceIndex {} -ServerAddresses @('127.0.0.1') -ErrorAction Stop\n",
            "Add-DnsClientNrptRule -Namespace '.' -NameServers '127.0.0.1' -DisplayName $displayName -Comment $comment -ErrorAction Stop | Out-Null\n",
            "Clear-DnsClientCache -ErrorAction SilentlyContinue\n",
        ),
        interface_index
    )
}

#[cfg(any(target_os = "windows", test))]
fn windows_secure_dns_uninstall_script(interface_index: u32) -> String {
    format!(
        concat!(
            "$ErrorActionPreference = 'Stop'\n",
            "$displayName = 'nostr-vpn secure DNS'\n",
            "$comment = 'nostr-vpn authenticated DNS-over-HTTPS stub'\n",
            "Get-DnsClientNrptRule -ErrorAction Stop | Where-Object {{ $_.DisplayName -eq $displayName -or $_.Comment -eq $comment }} | ForEach-Object {{ $_ | Remove-DnsClientNrptRule -Force -ErrorAction Stop | Out-Null }}\n",
            "$adapter = Get-NetAdapter -InterfaceIndex {} -ErrorAction SilentlyContinue\n",
            "if ($null -ne $adapter) {{\n",
            "  $servers = @((Get-DnsClientServerAddress -InterfaceIndex {} -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses | Where-Object {{ $_ }})\n",
            "  if ($servers.Count -eq 1 -and $servers[0] -eq '127.0.0.1') {{ Set-DnsClientServerAddress -InterfaceIndex {} -ResetServerAddresses -ErrorAction Stop }}\n",
            "}}\n",
            "Clear-DnsClientCache -ErrorAction SilentlyContinue\n",
        ),
        interface_index, interface_index, interface_index
    )
}

#[cfg(any(target_os = "windows", test))]
fn windows_secure_dns_repair_script() -> String {
    concat!(
        "$ErrorActionPreference = 'Stop'\n",
        "$displayName = 'nostr-vpn secure DNS'\n",
        "$comment = 'nostr-vpn authenticated DNS-over-HTTPS stub'\n",
        "Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { $_.DisplayName -eq $displayName -or $_.Comment -eq $comment } | ForEach-Object { $_ | Remove-DnsClientNrptRule -Force -ErrorAction Stop | Out-Null }\n",
        "Clear-DnsClientCache -ErrorAction SilentlyContinue\n",
    )
    .to_string()
}

#[cfg(any(target_os = "windows", test))]
fn windows_wireguard_dns_script(interface: &str, servers: &[IpAddr]) -> String {
    let interface = interface.replace('\'', "''");
    let servers = servers
        .iter()
        .map(|server| format!("'{server}'"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        concat!(
            "$ErrorActionPreference = 'Stop'\n",
            "$displayName = 'nostr-vpn secure DNS'\n",
            "$comment = 'nostr-vpn authenticated DNS-over-HTTPS stub'\n",
            "try {{\n",
            "  $wireGuard = Get-NetAdapter -Name '{}' -ErrorAction Stop\n",
            "  Set-DnsClientServerAddress -InterfaceIndex $wireGuard.ifIndex -ServerAddresses @({}) -ErrorAction Stop\n",
            "  Get-DnsClientNrptRule -ErrorAction Stop | Where-Object {{ $_.DisplayName -eq $displayName -or $_.Comment -eq $comment }} | ForEach-Object {{ $_ | Remove-DnsClientNrptRule -Force -ErrorAction Stop | Out-Null }}\n",
            "  Add-DnsClientNrptRule -Namespace '.nvpn' -NameServers '127.0.0.1' -DisplayName $displayName -Comment $comment -ErrorAction Stop | Out-Null\n",
            "  Add-DnsClientNrptRule -Namespace '.fips' -NameServers '127.0.0.1' -DisplayName $displayName -Comment $comment -ErrorAction Stop | Out-Null\n",
            "  Add-DnsClientNrptRule -Namespace '.' -NameServers @({}) -DisplayName $displayName -Comment $comment -ErrorAction Stop | Out-Null\n",
            "}} catch {{\n",
            "  $originalError = $_\n",
            "  Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object {{ $_.DisplayName -eq $displayName -or $_.Comment -eq $comment }} | ForEach-Object {{ $_ | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue | Out-Null }}\n",
            "  Add-DnsClientNrptRule -Namespace '.' -NameServers '127.0.0.1' -DisplayName $displayName -Comment $comment -ErrorAction SilentlyContinue | Out-Null\n",
            "  throw $originalError\n",
            "}}\n",
            "Clear-DnsClientCache -ErrorAction SilentlyContinue\n",
        ),
        interface, servers, servers
    )
}

#[cfg(target_os = "windows")]
fn run_windows_powershell(script: &str) -> Result<()> {
    let output = crate::wg_upstream_runtime::run_windows_command_with_timeout(
        Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", script]),
        "Windows DNS configuration command",
        WINDOWS_DNS_COMMAND_TIMEOUT,
    )?;
    if output.status.success() {
        return Ok(());
    }
    let details = if output.stderr.is_empty() {
        String::from_utf8_lossy(&output.stdout)
    } else {
        String::from_utf8_lossy(&output.stderr)
    };
    Err(anyhow!(
        "DNS configuration command failed: {}",
        details.trim()
    ))
}

#[cfg(test)]
#[path = "secure_dns_runtime/tests.rs"]
mod tests;
