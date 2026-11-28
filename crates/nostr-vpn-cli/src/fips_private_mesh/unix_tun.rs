#[cfg(any(target_os = "linux", test))]
const LINUX_CAP_NET_ADMIN_BIT: u32 = 12;
#[cfg(target_os = "linux")]
fn ensure_linux_tun_permissions(iface: &str) -> Result<()> {
    if std::fs::metadata("/dev/net/tun").is_err() {
        return Err(anyhow!(linux_tun_setup_error(
            iface,
            "missing /dev/net/tun device"
        )));
    }

    if let Ok(status) = std::fs::read_to_string("/proc/self/status")
        && linux_cap_eff_has_net_admin(&status) == Some(false)
    {
        return Err(anyhow!(linux_tun_setup_error(
            iface,
            "current process lacks CAP_NET_ADMIN"
        )));
    }

    Ok(())
}
#[cfg(any(target_os = "linux", test))]
fn linux_cap_eff_has_net_admin(status: &str) -> Option<bool> {
    let value = status
        .lines()
        .find_map(|line| line.trim_start().strip_prefix("CapEff:"))?
        .trim();
    let caps = u64::from_str_radix(value, 16).ok()?;
    Some((caps & (1_u64 << LINUX_CAP_NET_ADMIN_BIT)) != 0)
}
#[cfg(any(target_os = "linux", test))]
fn linux_tun_setup_error(iface: &str, reason: &str) -> String {
    format!(
        "Linux tunnel setup requires CAP_NET_ADMIN and /dev/net/tun before FIPS can create {iface}: {reason}. For a foreground session run `sudo nvpn start --connect` or `sudo nvpn connect`; for unattended use install/start the system service. In Docker add `--cap-add NET_ADMIN --device /dev/net/tun`."
    )
}

#[cfg(target_os = "linux")]
fn fips_tun_create_context(iface: &str) -> String {
    linux_tun_setup_error(iface, "kernel rejected TUN creation")
}

#[cfg(target_os = "macos")]
fn fips_tun_create_context(iface: &str) -> String {
    format!("failed to create FIPS tunnel {iface}")
}

#[cfg(target_os = "linux")]
struct SystemTun(LinuxVnetTun);
#[cfg(target_os = "macos")]
struct SystemTun(TunSocket);
#[cfg(target_os = "linux")]
impl SystemTun {
    fn new(iface: &str) -> Result<Self> {
        LinuxVnetTun::new(iface).map(Self)
    }

    fn set_non_blocking(self) -> Result<Self> {
        self.0.set_non_blocking().map(Self)
    }

    fn name(&self) -> Result<String> {
        Ok(self.0.name().to_string())
    }

    fn read_buffer_len(&self) -> usize {
        LINUX_VIRTIO_NET_HDR_LEN + 65_535
    }

    fn read_packets_into(
        &self,
        scratch: &mut [u8],
        batch: &mut TunPipelineBatch,
    ) -> io::Result<usize> {
        self.0.read_packets_into(scratch, batch)
    }
}

#[cfg(target_os = "linux")]
impl AsRawFd for SystemTun {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

#[cfg(target_os = "macos")]
impl SystemTun {
    fn new(iface: &str) -> Result<Self> {
        TunSocket::new(iface).map(Self).map_err(Into::into)
    }

    fn set_non_blocking(self) -> Result<Self> {
        self.0.set_non_blocking().map(Self).map_err(Into::into)
    }

    fn name(&self) -> Result<String> {
        self.0.name().map_err(Into::into)
    }

    fn read_buffer_len(&self) -> usize {
        65_535
    }

    fn read_packets_into(
        &self,
        scratch: &mut [u8],
        batch: &mut TunPipelineBatch,
    ) -> io::Result<usize> {
        read_plain_tun_packets_into(&self.0, scratch, batch)
    }
}

#[cfg(target_os = "macos")]
impl AsRawFd for SystemTun {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

#[cfg(target_os = "macos")]
fn read_plain_tun_packets_into(
    tun: &TunSocket,
    scratch: &mut [u8],
    batch: &mut TunPipelineBatch,
) -> io::Result<usize> {
    match tun.read(scratch) {
        Ok([]) => Ok(0),
        Ok(packet) => {
            let mut bytes = copy_with_fips_endpoint_headroom(packet);
            nostr_vpn_core::packet_checksums::finalize_transport_checksum(&mut bytes);
            push_tun_pipeline_packet_owned_finalized(batch, bytes);
            Ok(1)
        }
        Err(error) => Err(tun_error_to_io(error)),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn push_tun_pipeline_packet_owned_finalized(batch: &mut TunPipelineBatch, bytes: Vec<u8>) {
    if fips_unix_packet_debug_enabled() {
        eprintln!(
            "fips: TUN -> mesh {} bytes {}",
            bytes.len(),
            describe_ip_packet(&bytes)
        );
    }
    batch.push(TunPipelinePacket::new(bytes));
}

#[cfg(target_os = "macos")]
fn tun_error_to_io(error: boringtun::device::Error) -> io::Error {
    match error {
        boringtun::device::Error::IfaceRead(source) => source,
        error => io::Error::other(error),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]

include!("unix_tun_workers.rs");
include!("unix_tun_write.rs");
#[cfg(any(target_os = "linux", target_os = "macos"))]
include!("unix_tun_debug.rs");

#[cfg(target_os = "windows")]
include!("windows_runtime_type.rs");
