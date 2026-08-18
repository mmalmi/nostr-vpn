const LINUX_VIRTIO_NET_HDR_LEN: usize = 10;
const LINUX_VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 0x01;
const LINUX_VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
const LINUX_VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
const LINUX_VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;
const LINUX_VIRTIO_NET_HDR_GSO_UDP_L4: u8 = 5;
const LINUX_VIRTIO_NET_HDR_GSO_ECN: u8 = 0x80;
const LINUX_TCP_FLAGS_OFFSET: usize = 13;
const LINUX_TCP_FLAG_FIN: u8 = 0x01;
const LINUX_TCP_FLAG_PSH: u8 = 0x08;
const LINUX_TCP_FLAG_ACK: u8 = 0x10;
const LINUX_IPPROTO_TCP: u8 = 6;
const LINUX_IPPROTO_UDP: u8 = 17;
const LINUX_IPV4_SRC_ADDR_OFFSET: usize = 12;
const LINUX_IPV6_SRC_ADDR_OFFSET: usize = 8;
const LINUX_IOV_MAX: usize = 1024;
const LINUX_TCP_OPTIONS_MAX_LEN: usize = 40;
#[repr(C)]
union LinuxIfReqIfru {
    ifru_flags: libc::c_short,
    ifru_mtu: libc::c_int,
}
#[repr(C)]
struct LinuxIfReq {
    ifr_name: [libc::c_uchar; libc::IFNAMSIZ],
    ifr_ifru: LinuxIfReqIfru,
}

struct LinuxVnetTun {
    fd: RawFd,
    name: String,
}
impl Drop for LinuxVnetTun {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

impl AsRawFd for LinuxVnetTun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}
impl LinuxVnetTun {
    fn new(name: &str) -> Result<Self> {
        if name.parse::<i32>().is_ok() {
            return Err(anyhow!(
                "Linux vnet TUN cannot adopt a pre-opened fd; pass an interface name"
            ));
        }
        if name.len() >= libc::IFNAMSIZ {
            return Err(anyhow!("invalid Linux TUN interface name '{name}'"));
        }

        let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error()).context("open /dev/net/tun");
        }

        let result = Self::configure_fd(fd, name);
        if result.is_err() {
            unsafe {
                libc::close(fd);
            }
        }
        result
    }

    fn configure_fd(fd: RawFd, name: &str) -> Result<Self> {
        let mut ifr = LinuxIfReq {
            ifr_name: [0; libc::IFNAMSIZ],
            ifr_ifru: LinuxIfReqIfru {
                ifru_flags: (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_VNET_HDR)
                    as libc::c_short,
            },
        };
        let name_bytes = name.as_bytes();
        ifr.ifr_name[..name_bytes.len()].copy_from_slice(name_bytes);
        let rc = unsafe { libc::ioctl(fd, libc::TUNSETIFF as _, &ifr) };
        if rc < 0 {
            return Err(io::Error::last_os_error()).context("TUNSETIFF IFF_VNET_HDR");
        }

        let tcp_offloads = libc::TUN_F_CSUM | libc::TUN_F_TSO4 | libc::TUN_F_TSO6;
        let rc = unsafe { libc::ioctl(fd, libc::TUNSETOFFLOAD as _, tcp_offloads) };
        if rc < 0 {
            return Err(io::Error::last_os_error()).context("TUNSETOFFLOAD TCP offloads");
        }

        let udp_offloads = tcp_offloads | libc::TUN_F_USO4 | libc::TUN_F_USO6;
        let udp_gso = unsafe { libc::ioctl(fd, libc::TUNSETOFFLOAD as _, udp_offloads) } >= 0;
        eprintln!("fips: Linux vnet TUN enabled on {name}; udp_gso={udp_gso}");
        Ok(Self {
            fd,
            name: name.to_string(),
        })
    }

    fn set_non_blocking(self) -> Result<Self> {
        let flags = unsafe { libc::fcntl(self.fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error()).context("F_GETFL Linux vnet TUN");
        }
        let rc = unsafe { libc::fcntl(self.fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if rc < 0 {
            return Err(io::Error::last_os_error()).context("F_SETFL O_NONBLOCK Linux vnet TUN");
        }
        Ok(self)
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn read_packets_into(
        &self,
        scratch: &mut [u8],
        batch: &mut TunPipelineBatch,
    ) -> io::Result<usize> {
        let read_len = unsafe {
            libc::read(
                self.fd,
                scratch.as_mut_ptr().cast::<libc::c_void>(),
                scratch.len(),
            )
        };
        if read_len < 0 {
            return Err(io::Error::last_os_error());
        }
        if read_len == 0 {
            return Ok(0);
        }
        handle_linux_vnet_read(&mut scratch[..read_len as usize], batch)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LinuxVirtioNetHdr {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
}

impl LinuxVirtioNetHdr {
    fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < LINUX_VIRTIO_NET_HDR_LEN {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short virtio net header",
            ));
        }
        Ok(Self {
            flags: bytes[0],
            gso_type: bytes[1],
            hdr_len: u16::from_ne_bytes([bytes[2], bytes[3]]),
            gso_size: u16::from_ne_bytes([bytes[4], bytes[5]]),
            csum_start: u16::from_ne_bytes([bytes[6], bytes[7]]),
            csum_offset: u16::from_ne_bytes([bytes[8], bytes[9]]),
        })
    }

    fn encode(self, bytes: &mut [u8]) {
        bytes[0] = self.flags;
        bytes[1] = self.gso_type;
        bytes[2..4].copy_from_slice(&self.hdr_len.to_ne_bytes());
        bytes[4..6].copy_from_slice(&self.gso_size.to_ne_bytes());
        bytes[6..8].copy_from_slice(&self.csum_start.to_ne_bytes());
        bytes[8..10].copy_from_slice(&self.csum_offset.to_ne_bytes());
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LinuxVnetPayloadSegment {
    packet_index: usize,
    payload_offset: usize,
}

#[derive(Clone, Copy)]
struct LinuxVnetPacketRef {
    ptr: *const u8,
    len: usize,
}

impl LinuxVnetPacketRef {
    fn new(packet: &[u8]) -> Self {
        Self {
            ptr: packet.as_ptr(),
            len: packet.len(),
        }
    }

    fn with_slice<T>(self, f: impl FnOnce(&[u8]) -> T) -> T {
        // The preparer only stores these refs for the synchronous prepare/write
        // pass that borrowed the packet batch.
        let packet = unsafe { std::slice::from_raw_parts(self.ptr, self.len) };
        f(packet)
    }

    fn len_from_offset(self, offset: usize) -> usize {
        self.len
            .checked_sub(offset)
            .expect("prepared Linux vnet packet offset must be in bounds")
    }

    fn iovec_from_offset(self, offset: usize) -> libc::iovec {
        let len = self.len_from_offset(offset);
        libc::iovec {
            iov_base: unsafe { self.ptr.add(offset) } as *mut libc::c_void,
            iov_len: len,
        }
    }
}

struct LinuxVnetWriteFrame {
    virtio_header: [u8; LINUX_VIRTIO_NET_HDR_LEN],
    first_header: Vec<u8>,
    first_packet_index: usize,
    first_payload_offset: usize,
    payload_segments: Vec<LinuxVnetPayloadSegment>,
    tcp4_gro: Option<LinuxVnetTcp4GroState>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinuxVnetPreparedWriteFrame {
    RawPacket(usize),
    Vectored(usize),
}

#[derive(Clone, Debug)]
struct LinuxVnetTcp4GroState {
    ip_header_len: usize,
    tcp_header_len: usize,
    gso_size: usize,
    payload_len: usize,
    next_seq: u32,
    psh_set: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LinuxVnetTcp4GroFlow {
    tos: u8,
    df_reserved_flags: u8,
    ttl: u8,
    src_addr: [u8; 4],
    dst_addr: [u8; 4],
    src_port: u16,
    dst_port: u16,
    ack: u32,
    tcp_options_len: u8,
    tcp_options: [u8; LINUX_TCP_OPTIONS_MAX_LEN],
}
#[derive(Clone, Debug)]
struct LinuxVnetTcp4GroCandidate {
    ip_header_len: usize,
    tcp_header_len: usize,
    payload_len: usize,
    seq: u32,
    psh_set: bool,
    flow: LinuxVnetTcp4GroFlow,
}

struct LinuxVnetWritePreparer {
    gro_enabled: bool,
    frames: Vec<LinuxVnetPreparedWriteFrame>,
    vectored_frames: Vec<LinuxVnetWriteFrame>,
    vectored_frame_count: usize,
    packet_refs: Vec<LinuxVnetPacketRef>,
    write_iov: Vec<libc::iovec>,
    open_tcp4_flows: Vec<(LinuxVnetTcp4GroFlow, usize)>,
}

// The scratch iovec and packet-ref vectors are owned by one TUN writer task/thread
// and are only populated for a synchronous prepare/write pass.
unsafe impl Send for LinuxVnetWritePreparer {}

trait LinuxVnetPacketBatch {
    fn packet_count(&self) -> usize;
    fn append_packet_refs(&self, refs: &mut Vec<LinuxVnetPacketRef>);
}

impl<P: AsRef<[u8]>> LinuxVnetPacketBatch for [P] {
    fn packet_count(&self) -> usize {
        self.len()
    }

    fn append_packet_refs(&self, refs: &mut Vec<LinuxVnetPacketRef>) {
        refs.reserve(self.len());
        refs.extend(self.iter().map(|packet| LinuxVnetPacketRef::new(packet.as_ref())));
    }
}

impl<P: AsRef<[u8]>> LinuxVnetPacketBatch for Vec<P> {
    fn packet_count(&self) -> usize {
        self.len()
    }

    fn append_packet_refs(&self, refs: &mut Vec<LinuxVnetPacketRef>) {
        self.as_slice().append_packet_refs(refs);
    }
}

impl LinuxVnetPacketBatch for DirectTunWriteBatch {
    fn packet_count(&self) -> usize {
        self.len()
    }

    fn append_packet_refs(&self, refs: &mut Vec<LinuxVnetPacketRef>) {
        refs.reserve(self.len());
        for packet in self.run_slices() {
            refs.push(LinuxVnetPacketRef::new(packet));
        }
    }
}

impl LinuxVnetWritePreparer {
    fn new() -> Self {
        Self::with_gro(linux_vnet_tun_gro_enabled())
    }

    fn with_gro(gro_enabled: bool) -> Self {
        Self {
            gro_enabled,
            frames: Vec::new(),
            vectored_frames: Vec::new(),
            vectored_frame_count: 0,
            packet_refs: Vec::new(),
            write_iov: Vec::new(),
            open_tcp4_flows: Vec::new(),
        }
    }

    fn prepare<P: LinuxVnetPacketBatch + ?Sized>(&mut self, packets: &P) {
        self.frames.clear();
        self.open_tcp4_flows.clear();
        self.vectored_frame_count = 0;
        self.packet_refs.clear();
        packets.append_packet_refs(&mut self.packet_refs);
        debug_assert_eq!(self.packet_refs.len(), packets.packet_count());
        let packet_count = self.packet_refs.len();

        self.frames.reserve(packet_count);
        self.open_tcp4_flows.reserve(packet_count);
        for packet_index in 0..packet_count {
            if !self.gro_enabled {
                self.frames
                    .push(LinuxVnetPreparedWriteFrame::RawPacket(packet_index));
                continue;
            }
            if let Some(candidate) =
                self.packet_refs[packet_index].with_slice(linux_vnet_tcp4_gro_candidate)
            {
                if let Some((_, owned_index)) = self
                    .open_tcp4_flows
                    .iter()
                    .rfind(|(flow, _)| *flow == candidate.flow)
                    && linux_vnet_try_tcp4_gro_append_with_candidate(
                        &mut self.vectored_frames[*owned_index],
                        packet_index,
                        &candidate,
                    )
                {
                    continue;
                }

                let flow = candidate.flow.clone();
                let owned_index = self.start_tcp4_write_frame(packet_index, candidate);
                self.frames
                    .push(LinuxVnetPreparedWriteFrame::Vectored(owned_index));
                self.open_tcp4_flows.push((flow, owned_index));
                continue;
            }

            self.open_tcp4_flows.clear();
            self.frames
                .push(LinuxVnetPreparedWriteFrame::RawPacket(packet_index));
        }

        for frame in &mut self.vectored_frames[..self.vectored_frame_count] {
            linux_vnet_finish_write_frame(frame, &self.packet_refs);
        }
    }

    fn frames(&self) -> &[LinuxVnetPreparedWriteFrame] {
        &self.frames
    }

    fn packet_ref(&self, index: usize) -> LinuxVnetPacketRef {
        self.packet_refs[index]
    }

    fn write_vectored_frame_to_tun(
        &mut self,
        tun_fd: &BorrowedTunFd,
        frame_index: usize,
    ) -> io::Result<usize> {
        let Self {
            vectored_frames,
            packet_refs,
            write_iov,
            ..
        } = self;
        raw_write_linux_vnet_vectored_frame_to_tun(
            tun_fd,
            packet_refs,
            &vectored_frames[frame_index],
            write_iov,
        )
    }

    fn start_tcp4_write_frame(
        &mut self,
        packet_index: usize,
        candidate: LinuxVnetTcp4GroCandidate,
    ) -> usize {
        let index = self.vectored_frame_count;
        self.vectored_frame_count += 1;
        if index == self.vectored_frames.len() {
            self.vectored_frames.push(LinuxVnetWriteFrame {
                virtio_header: [0; LINUX_VIRTIO_NET_HDR_LEN],
                first_header: Vec::new(),
                first_packet_index: 0,
                first_payload_offset: 0,
                payload_segments: Vec::new(),
                tcp4_gro: None,
            });
        }
        linux_vnet_start_tcp4_write_frame_with_candidate(
            &mut self.vectored_frames[index],
            packet_index,
            candidate,
        );
        index
    }

}

fn linux_vnet_tun_gro_enabled() -> bool {
    std::env::var("NVPN_FIPS_LINUX_TUN_GRO")
        .ok()
        .is_none_or(|value| !matches!(value.trim(), "0" | "false" | "no" | "off"))
}

#[cfg(test)]
fn linux_vnet_prepare_write_frames<P: AsRef<[u8]> + Clone>(
    packets: &[P],
) -> Vec<(LinuxVnetPreparedWriteFrame, Vec<u8>)> {
    let packets = packets.to_vec();
    let mut preparer = LinuxVnetWritePreparer::new();
    linux_vnet_collect_prepared_write_frames(&mut preparer, packets)
}

#[cfg(test)]
fn linux_vnet_collect_prepared_write_frames<P: AsRef<[u8]> + Clone>(
    preparer: &mut LinuxVnetWritePreparer,
    packets: Vec<P>,
) -> Vec<(LinuxVnetPreparedWriteFrame, Vec<u8>)> {
    preparer.prepare(&packets);
    preparer
        .frames()
        .iter()
        .map(|frame| match frame {
            LinuxVnetPreparedWriteFrame::RawPacket(packet_index) => {
                let mut bytes = vec![0_u8; LINUX_VIRTIO_NET_HDR_LEN];
                bytes.extend_from_slice(packets[*packet_index].as_ref());
                (*frame, bytes)
            }
            LinuxVnetPreparedWriteFrame::Vectored(owned_index) => {
                let vectored = &preparer.vectored_frames[*owned_index];
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&vectored.virtio_header);
                let first_packet = packets[vectored.first_packet_index].as_ref();
                if vectored.first_header.is_empty() {
                    bytes.extend_from_slice(first_packet);
                } else {
                    bytes.extend_from_slice(&vectored.first_header);
                    bytes.extend_from_slice(&first_packet[vectored.first_payload_offset..]);
                }
                for segment in &vectored.payload_segments {
                    bytes.extend_from_slice(
                        &packets[segment.packet_index].as_ref()[segment.payload_offset..],
                    );
                }
                (*frame, bytes)
            }
        })
        .collect()
}

fn linux_vnet_start_tcp4_write_frame_with_candidate(
    frame: &mut LinuxVnetWriteFrame,
    packet_index: usize,
    candidate: LinuxVnetTcp4GroCandidate,
) {
    frame.virtio_header = [0; LINUX_VIRTIO_NET_HDR_LEN];
    frame.first_header.clear();
    frame.first_packet_index = packet_index;
    frame.first_payload_offset = 0;
    frame.payload_segments.clear();
    frame.tcp4_gro = Some(LinuxVnetTcp4GroState {
        ip_header_len: candidate.ip_header_len,
        tcp_header_len: candidate.tcp_header_len,
        gso_size: candidate.payload_len,
        payload_len: candidate.payload_len,
        next_seq: candidate.seq.wrapping_add(candidate.payload_len as u32),
        psh_set: candidate.psh_set,
    });
}

fn linux_vnet_try_tcp4_gro_append_with_candidate(
    frame: &mut LinuxVnetWriteFrame,
    packet_index: usize,
    candidate: &LinuxVnetTcp4GroCandidate,
) -> bool {
    let Some(state) = frame.tcp4_gro.as_mut() else {
        return false;
    };
    if state.psh_set || state.payload_len % state.gso_size != 0 {
        return false;
    }
    if candidate.ip_header_len != state.ip_header_len
        || candidate.tcp_header_len != state.tcp_header_len
        || candidate.seq != state.next_seq
        || candidate.payload_len > state.gso_size
    {
        return false;
    }

    let header_len = candidate.ip_header_len + candidate.tcp_header_len;
    let coalesced_packet_len =
        state.ip_header_len + state.tcp_header_len + state.payload_len + candidate.payload_len;
    if coalesced_packet_len > u16::MAX as usize {
        return false;
    }

    frame.payload_segments.push(LinuxVnetPayloadSegment {
        packet_index,
        payload_offset: header_len,
    });
    state.payload_len += candidate.payload_len;
    state.next_seq = state.next_seq.wrapping_add(candidate.payload_len as u32);
    if candidate.psh_set {
        state.psh_set = true;
    }
    true
}

fn linux_vnet_finish_write_frame(
    frame: &mut LinuxVnetWriteFrame,
    packet_refs: &[LinuxVnetPacketRef],
) {
    if let Some(state) = frame.tcp4_gro.take() {
        linux_vnet_finish_tcp4_write_frame(frame, packet_refs, state);
    }
}

fn linux_vnet_finish_tcp4_write_frame(
    frame: &mut LinuxVnetWriteFrame,
    packet_refs: &[LinuxVnetPacketRef],
    state: LinuxVnetTcp4GroState,
) {
    if state.payload_len <= state.gso_size {
        return;
    }

    let packet_len = state
        .ip_header_len
        .saturating_add(state.tcp_header_len)
        .saturating_add(state.payload_len);
    let ip_header_len = state.ip_header_len;
    let tcp_header_len = state.tcp_header_len;
    let transport_len = packet_len - ip_header_len;
    let header_len = ip_header_len + tcp_header_len;
    frame.first_header.clear();
    packet_refs[frame.first_packet_index].with_slice(|first_packet| {
        frame
            .first_header
            .extend_from_slice(&first_packet[..header_len]);
    });
    frame.first_payload_offset = header_len;
    let packet = &mut frame.first_header;

    packet[2..4].copy_from_slice(&(packet_len as u16).to_be_bytes());
    linux_vnet_finalize_ipv4_header_checksum(&mut packet[..ip_header_len]);
    if state.psh_set {
        packet[ip_header_len + LINUX_TCP_FLAGS_OFFSET] |= LINUX_TCP_FLAG_PSH;
    }

    let pseudo = linux_vnet_pseudo_header_sum(
        LINUX_IPPROTO_TCP,
        &packet[LINUX_IPV4_SRC_ADDR_OFFSET..LINUX_IPV4_SRC_ADDR_OFFSET + 4],
        &packet[LINUX_IPV4_SRC_ADDR_OFFSET + 4..LINUX_IPV4_SRC_ADDR_OFFSET + 8],
        transport_len as u16,
    );
    let partial = !linux_vnet_checksum(&[], pseudo);
    let checksum_at = ip_header_len + 16;
    packet[checksum_at..checksum_at + 2].copy_from_slice(&partial.to_be_bytes());

    LinuxVirtioNetHdr {
        flags: LINUX_VIRTIO_NET_HDR_F_NEEDS_CSUM,
        gso_type: LINUX_VIRTIO_NET_HDR_GSO_TCPV4,
        hdr_len: (ip_header_len + tcp_header_len) as u16,
        gso_size: state.gso_size as u16,
        csum_start: ip_header_len as u16,
        csum_offset: 16,
    }
    .encode(&mut frame.virtio_header);
}

fn linux_vnet_tcp4_gro_candidate(packet: &[u8]) -> Option<LinuxVnetTcp4GroCandidate> {
    if packet.len() < 40 || packet[0] >> 4 != 4 || packet[9] != LINUX_IPPROTO_TCP {
        return None;
    }
    let ip_header_len = usize::from(packet[0] & 0x0f) * 4;
    if !(20..=60).contains(&ip_header_len) || packet.len() < ip_header_len + 20 {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len != packet.len() {
        return None;
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        return None;
    }

    let tcp_header_len = usize::from(packet[ip_header_len + 12] >> 4) * 4;
    if !(20..=60).contains(&tcp_header_len) || packet.len() < ip_header_len + tcp_header_len {
        return None;
    }
    let flags = packet[ip_header_len + LINUX_TCP_FLAGS_OFFSET];
    let psh_set = match flags {
        LINUX_TCP_FLAG_ACK => false,
        flags if flags == (LINUX_TCP_FLAG_ACK | LINUX_TCP_FLAG_PSH) => true,
        _ => return None,
    };

    let payload_len = packet.len() - ip_header_len - tcp_header_len;
    if payload_len == 0 || payload_len > u16::MAX as usize {
        return None;
    }

    let mut src_addr = [0_u8; 4];
    src_addr.copy_from_slice(&packet[12..16]);
    let mut dst_addr = [0_u8; 4];
    dst_addr.copy_from_slice(&packet[16..20]);
    let tcp = &packet[ip_header_len..];
    let tcp_options_len =
        u8::try_from(tcp_header_len - 20).expect("TCP options length is at most 40 bytes");
    let mut tcp_options = [0_u8; LINUX_TCP_OPTIONS_MAX_LEN];
    tcp_options[..usize::from(tcp_options_len)].copy_from_slice(&tcp[20..tcp_header_len]);

    Some(LinuxVnetTcp4GroCandidate {
        ip_header_len,
        tcp_header_len,
        payload_len,
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        psh_set,
        flow: LinuxVnetTcp4GroFlow {
            tos: packet[1],
            df_reserved_flags: packet[6] >> 5,
            ttl: packet[8],
            src_addr,
            dst_addr,
            src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
            dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
            ack: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
            tcp_options_len,
            tcp_options,
        },
    })
}

fn linux_vnet_finalize_ipv4_header_checksum(header: &mut [u8]) {
    header[10] = 0;
    header[11] = 0;
    let checksum = !linux_vnet_checksum(header, 0);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());
}

fn handle_linux_vnet_read(frame: &mut [u8], batch: &mut TunPipelineBatch) -> io::Result<usize> {
    let hdr = LinuxVirtioNetHdr::decode(frame)?;
    let packet = &mut frame[LINUX_VIRTIO_NET_HDR_LEN..];
    let gso_type = hdr.gso_type & !LINUX_VIRTIO_NET_HDR_GSO_ECN;

    if gso_type == LINUX_VIRTIO_NET_HDR_GSO_NONE {
        if hdr.flags & LINUX_VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
            linux_vnet_gso_none_checksum(packet, hdr.csum_start, hdr.csum_offset)?;
        }
        push_tun_pipeline_packet(batch, packet);
        return Ok(1);
    }

    if hdr.gso_type & LINUX_VIRTIO_NET_HDR_GSO_ECN != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Linux vnet TUN GSO ECN packets are not supported yet",
        ));
    }
    if hdr.gso_size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Linux vnet TUN GSO packet has zero segment size",
        ));
    }

    match gso_type {
        LINUX_VIRTIO_NET_HDR_GSO_TCPV4
        | LINUX_VIRTIO_NET_HDR_GSO_TCPV6
        | LINUX_VIRTIO_NET_HDR_GSO_UDP_L4 => {}
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported Linux vnet TUN GSO type {gso_type}"),
            ));
        }
    }

    let Some((&version_byte, _)) = packet.split_first() else {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "empty Linux vnet TUN packet",
        ));
    };
    let is_v6 = match version_byte >> 4 {
        4 => {
            if gso_type != LINUX_VIRTIO_NET_HDR_GSO_TCPV4
                && gso_type != LINUX_VIRTIO_NET_HDR_GSO_UDP_L4
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "IPv4 packet has non-IPv4 GSO type",
                ));
            }
            false
        }
        6 => {
            if gso_type != LINUX_VIRTIO_NET_HDR_GSO_TCPV6
                && gso_type != LINUX_VIRTIO_NET_HDR_GSO_UDP_L4
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "IPv6 packet has non-IPv6 GSO type",
                ));
            }
            true
        }
        version => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid Linux vnet TUN packet IP version {version}"),
            ));
        }
    };

    let mut hdr = hdr;
    if gso_type == LINUX_VIRTIO_NET_HDR_GSO_UDP_L4 {
        hdr.hdr_len = hdr.csum_start.saturating_add(8);
    } else {
        let tcp_data_offset_at = usize::from(hdr.csum_start).saturating_add(12);
        let Some(&data_offset_byte) = packet.get(tcp_data_offset_at) else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Linux vnet TUN TCP GSO packet is too short",
            ));
        };
        let tcp_header_len = u16::from(data_offset_byte >> 4) * 4;
        if !(20..=60).contains(&tcp_header_len) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid Linux vnet TUN TCP header length {tcp_header_len}"),
            ));
        }
        hdr.hdr_len = hdr.csum_start.saturating_add(tcp_header_len);
    }

    let hdr_len = usize::from(hdr.hdr_len);
    let csum_start = usize::from(hdr.csum_start);
    let csum_at = csum_start.saturating_add(usize::from(hdr.csum_offset));
    if packet.len() < hdr_len || hdr_len < csum_start || csum_at + 1 >= packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Linux vnet TUN GSO header bounds",
        ));
    }

    let record_stats = crate::pipeline_profile::enabled();
    let split = linux_vnet_gso_split(packet, hdr, gso_type, is_v6, record_stats, batch)?;
    if record_stats {
        crate::pipeline_profile::record_tun_read_vnet_gso_split(split.count, split.bytes);
    }
    Ok(split.count)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LinuxVnetGsoSplitStats {
    count: usize,
    bytes: usize,
}

fn linux_vnet_gso_none_checksum(
    packet: &mut [u8],
    csum_start: u16,
    csum_offset: u16,
) -> io::Result<()> {
    let csum_start = usize::from(csum_start);
    let csum_at = csum_start.saturating_add(usize::from(csum_offset));
    if csum_start >= packet.len() || csum_at + 1 >= packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Linux vnet TUN checksum bounds",
        ));
    }
    let initial = u16::from_be_bytes([packet[csum_at], packet[csum_at + 1]]);
    packet[csum_at] = 0;
    packet[csum_at + 1] = 0;
    let checksum = !linux_vnet_checksum(&packet[csum_start..], u64::from(initial));
    packet[csum_at..csum_at + 2].copy_from_slice(&checksum.to_be_bytes());
    Ok(())
}

fn linux_vnet_gso_split(
    packet: &mut [u8],
    hdr: LinuxVirtioNetHdr,
    gso_type: u8,
    is_v6: bool,
    record_stats: bool,
    batch: &mut TunPipelineBatch,
) -> io::Result<LinuxVnetGsoSplitStats> {
    let ip_header_len = usize::from(hdr.csum_start);
    let transport_csum_at = usize::from(hdr.csum_start + hdr.csum_offset);
    if !is_v6 {
        packet[10] = 0;
        packet[11] = 0;
    }
    packet[transport_csum_at] = 0;
    packet[transport_csum_at + 1] = 0;

    let protocol = if gso_type == LINUX_VIRTIO_NET_HDR_GSO_TCPV4
        || gso_type == LINUX_VIRTIO_NET_HDR_GSO_TCPV6
    {
        LINUX_IPPROTO_TCP
    } else {
        LINUX_IPPROTO_UDP
    };
    let first_tcp_seq = if protocol == LINUX_IPPROTO_TCP {
        let seq_at = usize::from(hdr.csum_start).saturating_add(4);
        u32::from_be_bytes([
            packet[seq_at],
            packet[seq_at + 1],
            packet[seq_at + 2],
            packet[seq_at + 3],
        ])
    } else {
        0
    };

    let src_addr_offset = if is_v6 {
        LINUX_IPV6_SRC_ADDR_OFFSET
    } else {
        LINUX_IPV4_SRC_ADDR_OFFSET
    };
    let addr_len = if is_v6 { 16 } else { 4 };
    if src_addr_offset + addr_len * 2 > packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Linux vnet TUN GSO packet is too short for IP addresses",
        ));
    }
    let src = &packet[src_addr_offset..src_addr_offset + addr_len];
    let dst = &packet[src_addr_offset + addr_len..src_addr_offset + addr_len * 2];
    let pseudo_header_base_sum = linux_vnet_pseudo_header_base_sum(protocol, src, dst);
    let destination = if is_v6 {
        let mut octets = [0_u8; 16];
        octets.copy_from_slice(dst);
        Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
    } else {
        Some(IpAddr::V4(Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3])))
    };

    let csum_start = usize::from(hdr.csum_start);
    let hdr_len = usize::from(hdr.hdr_len);
    let payload_len = packet.len() - hdr_len;
    let gso_size = usize::from(hdr.gso_size);
    batch.reserve(payload_len.div_ceil(gso_size));

    let mut next_segment_data_at = hdr_len;
    let mut count = 0_usize;
    let mut segment_bytes = 0_usize;
    while next_segment_data_at < packet.len() {
        let next_segment_end = (next_segment_data_at + gso_size).min(packet.len());
        let segment_data_len = next_segment_end - next_segment_data_at;
        let total_len = hdr_len + segment_data_len;
        if total_len > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Linux vnet TUN GSO segment exceeds packet length limit",
            ));
        }

        let mut out = vec_with_fips_endpoint_headroom(total_len);
        out.extend_from_slice(&packet[..hdr_len]);
        out.extend_from_slice(&packet[next_segment_data_at..next_segment_end]);
        if !is_v6 {
            if count > 0 {
                let id = u16::from_be_bytes([out[4], out[5]]).wrapping_add(count as u16);
                out[4..6].copy_from_slice(&id.to_be_bytes());
            }
            out[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            let ip_checksum = !linux_vnet_checksum(&out[..ip_header_len], 0);
            out[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        } else {
            out[4..6].copy_from_slice(&((total_len - ip_header_len) as u16).to_be_bytes());
        }

        if protocol == LINUX_IPPROTO_TCP {
            let tcp_seq = first_tcp_seq.wrapping_add(u32::from(hdr.gso_size) * count as u32);
            out[csum_start + 4..csum_start + 8].copy_from_slice(&tcp_seq.to_be_bytes());
            if next_segment_end != packet.len() {
                out[csum_start + LINUX_TCP_FLAGS_OFFSET] &=
                    !(LINUX_TCP_FLAG_FIN | LINUX_TCP_FLAG_PSH);
            }
        } else {
            let udp_len = (hdr.hdr_len - hdr.csum_start) + segment_data_len as u16;
            out[csum_start + 4..csum_start + 6].copy_from_slice(&udp_len.to_be_bytes());
        }

        let transport_len = total_len - csum_start;
        let pseudo_sum = pseudo_header_base_sum + transport_len as u64;
        let transport_checksum = !linux_vnet_checksum(&out[csum_start..], pseudo_sum);
        let out_csum_at = csum_start + usize::from(hdr.csum_offset);
        out[out_csum_at..out_csum_at + 2].copy_from_slice(&transport_checksum.to_be_bytes());

        batch.push(TunPipelinePacket::from_destination(
            out,
            destination,
        ));
        if record_stats {
            segment_bytes = segment_bytes.saturating_add(total_len);
        }
        count += 1;
        next_segment_data_at = next_segment_end;
    }

    Ok(LinuxVnetGsoSplitStats {
        count,
        bytes: segment_bytes,
    })
}

fn linux_vnet_pseudo_header_sum(protocol: u8, src: &[u8], dst: &[u8], total_len: u16) -> u64 {
    linux_vnet_pseudo_header_base_sum(protocol, src, dst) + u64::from(total_len)
}

fn linux_vnet_pseudo_header_base_sum(protocol: u8, src: &[u8], dst: &[u8]) -> u64 {
    let mut sum = linux_vnet_add_words(0, src);
    sum = linux_vnet_add_words(sum, dst);
    sum += u64::from(protocol);
    sum
}

fn linux_vnet_checksum(bytes: &[u8], initial: u64) -> u16 {
    let mut sum = linux_vnet_add_words(initial, bytes);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

fn linux_vnet_add_words(mut sum: u64, bytes: &[u8]) -> u64 {
    let mut chunks = bytes.chunks_exact(8);
    for chunk in &mut chunks {
        let word = u64::from_be_bytes(chunk.try_into().expect("chunk is 8 bytes"));
        sum += (word >> 48)
            + ((word >> 32) & 0xffff)
            + ((word >> 16) & 0xffff)
            + (word & 0xffff);
    }

    let mut tail = chunks.remainder().chunks_exact(2);
    for chunk in &mut tail {
        sum += u64::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&byte) = tail.remainder().first() {
        sum += u64::from(byte) << 8;
    }
    sum
}

include!("linux_vnet_tun_tests.rs");
