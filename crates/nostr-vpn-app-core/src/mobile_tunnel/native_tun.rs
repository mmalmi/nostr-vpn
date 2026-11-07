const NATIVE_TUN_PACKET_HEADROOM: usize = 128;
const NATIVE_TUN_PACKET_MAX: usize = 65_535;
const NATIVE_TUN_POLL_TIMEOUT_MS: i32 = 100;

/// Moves packets between the Android VPN interface fd and the mesh runtime.
///
/// The interface can be replaced while the tunnel runs: Android keeps routing
/// through the old interface until a replacement is established, then sends
/// new outgoing packets to the replacement. `replace_fd` starts reading the
/// replacement, moves inbound writes to it, drains and closes the old fd.
struct NativeTunRuntime {
    /// Fd that inbound packets are written to. The write thread holds the
    /// read lock while it writes, so a replaced fd is closed only after the
    /// writer has moved off it.
    fd: Arc<RwLock<c_int>>,
    stop: Arc<AtomicBool>,
    reader: NativeTunReader,
    write_thread: Option<std::thread::JoinHandle<()>>,
    outbound_tx: tokio_mpsc::Sender<Vec<Vec<u8>>>,
    counters: Arc<MobileTunAtomicCounters>,
    packet_capacity: usize,
}

struct NativeTunReader {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl NativeTunReader {
    fn start(
        fd: c_int,
        outbound_tx: tokio_mpsc::Sender<Vec<Vec<u8>>>,
        counters: Arc<MobileTunAtomicCounters>,
        packet_capacity: usize,
    ) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let read_stop = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("nvpn-tun-read".to_string())
            .spawn(move || {
                native_tun_read_loop(fd, outbound_tx, read_stop, counters, packet_capacity);
            })
            .map_err(|error| anyhow!("failed to spawn native tun read thread: {error}"))?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }

    fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    fn join(&mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl NativeTunRuntime {
    fn start(
        fd: c_int,
        outbound_tx: tokio_mpsc::Sender<Vec<Vec<u8>>>,
        inbound_rx: tokio_mpsc::Receiver<Vec<Vec<u8>>>,
        packet_capacity: usize,
        counters: Arc<MobileTunAtomicCounters>,
    ) -> Result<Self> {
        let fd = prepare_mobile_tun_fd(fd)?;
        let reader = match NativeTunReader::start(
            fd,
            outbound_tx.clone(),
            Arc::clone(&counters),
            packet_capacity,
        ) {
            Ok(reader) => reader,
            Err(error) => {
                close_mobile_tun_fd(fd);
                return Err(error);
            }
        };

        let stop = Arc::new(AtomicBool::new(false));
        let write_fd = Arc::new(RwLock::new(fd));
        let mut runtime = Self {
            fd: Arc::clone(&write_fd),
            stop: Arc::clone(&stop),
            reader,
            write_thread: None,
            outbound_tx,
            counters: Arc::clone(&counters),
            packet_capacity,
        };
        match std::thread::Builder::new()
            .name("nvpn-tun-write".to_string())
            .spawn(move || native_tun_write_loop(&write_fd, inbound_rx, &stop, &counters))
        {
            Ok(thread) => {
                runtime.write_thread = Some(thread);
                Ok(runtime)
            }
            Err(error) => {
                runtime.shutdown();
                Err(anyhow!("failed to spawn native tun write thread: {error}"))
            }
        }
    }

    /// Switches the tunnel to a newly established interface fd. On error the
    /// replacement fd is closed and the current interface keeps running.
    fn replace_fd(&mut self, fd: c_int) -> Result<()> {
        let fd = prepare_mobile_tun_fd(fd)?;
        if self.stop.load(Ordering::Relaxed) {
            close_mobile_tun_fd(fd);
            return Err(anyhow!("native tun stopped"));
        }
        let reader = match NativeTunReader::start(
            fd,
            self.outbound_tx.clone(),
            Arc::clone(&self.counters),
            self.packet_capacity,
        ) {
            Ok(reader) => reader,
            Err(error) => {
                close_mobile_tun_fd(fd);
                return Err(error);
            }
        };
        let previous_fd = {
            let mut current = self
                .fd
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::replace(&mut *current, fd)
        };
        let mut previous_reader = std::mem::replace(&mut self.reader, reader);
        previous_reader.stop();
        previous_reader.join();
        close_mobile_tun_fd(previous_fd);
        Ok(())
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.reader.stop();
        let mut current = self
            .fd
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *current >= 0 {
            close_mobile_tun_fd(*current);
            *current = -1;
        }
    }

    fn join(&mut self) {
        self.reader.join();
        if let Some(thread) = self.write_thread.take() {
            let _ = thread.join();
        }
    }

    fn shutdown(&mut self) {
        self.stop();
        self.join();
    }
}

impl Drop for NativeTunRuntime {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn native_tun_packet_capacity(mtu: u16) -> usize {
    usize::from(mtu)
        .saturating_add(NATIVE_TUN_PACKET_HEADROOM)
        .clamp(1280, NATIVE_TUN_PACKET_MAX)
}

fn native_tun_read_loop(
    fd: c_int,
    outbound_tx: tokio_mpsc::Sender<Vec<Vec<u8>>>,
    stop: Arc<AtomicBool>,
    counters: Arc<MobileTunAtomicCounters>,
    packet_capacity: usize,
) {
    let mut packets = Vec::with_capacity(MOBILE_FIPS_SEND_BATCH);
    let mut read_packet = Vec::<u8>::with_capacity(packet_capacity);
    'read: loop {
        packets.clear();
        while packets.len() < MOBILE_FIPS_SEND_BATCH {
            match read_mobile_tun_packet(fd, &mut read_packet) {
                NativeTunRead::Packet(packet) => {
                    counters.note_read(packet.len());
                    packets.push(packet);
                }
                NativeTunRead::WouldBlock => {
                    if !packets.is_empty() {
                        break;
                    }
                    if !wait_mobile_tun_fd(fd, libc::POLLIN, &stop) {
                        break 'read;
                    }
                    continue;
                }
                NativeTunRead::Stopped => {
                    stop.store(true, Ordering::Relaxed);
                    return;
                }
            }
        }
        if !packets.is_empty() {
            let batch = std::mem::replace(&mut packets, Vec::with_capacity(MOBILE_FIPS_SEND_BATCH));
            let batch_len = batch.len();
            if stop.load(Ordering::Relaxed) || outbound_tx.blocking_send(batch).is_err() {
                for _ in 0..batch_len {
                    counters.note_drop();
                }
                stop.store(true, Ordering::Relaxed);
                return;
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
}

fn native_tun_write_loop(
    fd: &RwLock<c_int>,
    mut inbound_rx: tokio_mpsc::Receiver<Vec<Vec<u8>>>,
    stop: &AtomicBool,
    counters: &MobileTunAtomicCounters,
) {
    while !stop.load(Ordering::Relaxed) {
        let packets = match inbound_rx.blocking_recv() {
            Some(packets) => packets,
            None => break,
        };
        let fd = fd.read().unwrap_or_else(std::sync::PoisonError::into_inner);
        for packet in packets {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if !write_native_tun_inbound_packet(*fd, &packet, stop, counters) {
                stop.store(true, Ordering::Relaxed);
                return;
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
}

fn write_native_tun_inbound_packet(
    fd: c_int,
    packet: &[u8],
    stop: &AtomicBool,
    counters: &MobileTunAtomicCounters,
) -> bool {
    let packet_len = packet.len();
    match write_mobile_tun_packet(fd, packet, stop) {
        NativeTunWrite::Written => counters.note_write(packet_len),
        NativeTunWrite::Dropped => counters.note_drop(),
        NativeTunWrite::Stopped => {
            counters.note_drop();
            return false;
        }
    }
    true
}

enum NativeTunRead {
    Packet(Vec<u8>),
    WouldBlock,
    Stopped,
}

enum NativeTunWrite {
    Written,
    Dropped,
    Stopped,
}

fn read_mobile_tun_packet(fd: c_int, packet: &mut Vec<u8>) -> NativeTunRead {
    packet.clear();
    loop {
        let read = read_mobile_tun_payload(fd, packet);
        if read > 0 {
            let len = usize::try_from(read).unwrap_or(0);
            let Some(packet_len) = mobile_tun_payload_len(len) else {
                return NativeTunRead::Stopped;
            };
            unsafe {
                packet.set_len(packet_len);
            }
            let mut next_packet = Vec::with_capacity(packet.capacity());
            std::mem::swap(packet, &mut next_packet);
            return NativeTunRead::Packet(next_packet);
        }
        if read == 0 {
            return NativeTunRead::Stopped;
        }
        let error = std::io::Error::last_os_error();
        if mobile_tun_errno_is_interrupted(error.raw_os_error()) {
            continue;
        }
        if mobile_tun_errno_is_again(error.raw_os_error()) {
            return NativeTunRead::WouldBlock;
        }
        return NativeTunRead::Stopped;
    }
}

fn read_mobile_tun_payload(fd: c_int, packet: &mut Vec<u8>) -> isize {
    unsafe {
        libc::read(
            fd,
            packet.as_mut_ptr().cast::<libc::c_void>(),
            packet.capacity(),
        )
    }
}

fn mobile_tun_payload_len(read_len: usize) -> Option<usize> {
    Some(read_len)
}

fn write_mobile_tun_packet(fd: c_int, packet: &[u8], stop: &AtomicBool) -> NativeTunWrite {
    if packet.is_empty() {
        return NativeTunWrite::Dropped;
    }
    while !stop.load(Ordering::Relaxed) {
        let written =
            unsafe { libc::write(fd, packet.as_ptr().cast::<libc::c_void>(), packet.len()) };
        if written == isize::try_from(packet.len()).unwrap_or(-1) {
            return NativeTunWrite::Written;
        }
        if written >= 0 {
            return NativeTunWrite::Stopped;
        }
        let error = std::io::Error::last_os_error();
        if mobile_tun_errno_is_interrupted(error.raw_os_error()) {
            continue;
        }
        if mobile_tun_errno_is_again(error.raw_os_error())
            && wait_mobile_tun_fd(fd, libc::POLLOUT, stop)
        {
            continue;
        }
        return NativeTunWrite::Stopped;
    }
    NativeTunWrite::Stopped
}

fn wait_mobile_tun_fd(fd: c_int, events: i16, stop: &AtomicBool) -> bool {
    while !stop.load(Ordering::Relaxed) {
        let mut poll_fd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll_fd, 1, NATIVE_TUN_POLL_TIMEOUT_MS) };
        if ready > 0 {
            if poll_fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return false;
            }
            return poll_fd.revents & events != 0;
        }
        if ready == 0 {
            continue;
        }
        let error = std::io::Error::last_os_error();
        if mobile_tun_errno_is_interrupted(error.raw_os_error()) {
            continue;
        }
        return false;
    }
    false
}

fn prepare_mobile_tun_fd(fd: c_int) -> Result<c_int> {
    let fd = native_tun_owned_fd(fd)?;
    if let Err(error) = set_mobile_tun_nonblocking(fd) {
        close_mobile_tun_fd(fd);
        return Err(error);
    }
    Ok(fd)
}

fn native_tun_owned_fd(fd: c_int) -> Result<c_int> {
    Ok(fd)
}

fn set_mobile_tun_nonblocking(fd: c_int) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(anyhow!(
            "failed to read native tun fd flags: {}",
            std::io::Error::last_os_error()
        ));
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(anyhow!(
            "failed to set native tun fd nonblocking: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn close_mobile_tun_fd(fd: c_int) {
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
}

fn reject_unattached_mobile_tun_fd(fd: c_int) {
    close_mobile_tun_fd(fd);
}

fn mobile_tun_errno_is_interrupted(error: Option<i32>) -> bool {
    error == Some(libc::EINTR)
}

fn mobile_tun_errno_is_again(error: Option<i32>) -> bool {
    error == Some(libc::EAGAIN) || error == Some(libc::EWOULDBLOCK)
}
