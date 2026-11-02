const NATIVE_TUN_PACKET_HEADROOM: usize = 128;
const NATIVE_TUN_PACKET_MAX: usize = 65_535;
const NATIVE_TUN_POLL_TIMEOUT_MS: i32 = 100;

struct NativeTunRuntime {
    fd: c_int,
    stop: Arc<AtomicBool>,
    read_thread: Option<std::thread::JoinHandle<()>>,
    write_thread: Option<std::thread::JoinHandle<()>>,
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

        let stop = Arc::new(AtomicBool::new(false));
        let read_stop = Arc::clone(&stop);
        let read_counters = Arc::clone(&counters);
        let read_thread = match std::thread::Builder::new()
            .name("nvpn-tun-read".to_string())
            .spawn(move || {
                native_tun_read_loop(fd, outbound_tx, read_stop, read_counters, packet_capacity)
            })
        {
            Ok(thread) => thread,
            Err(error) => {
                close_mobile_tun_fd(fd);
                return Err(anyhow!("failed to spawn native tun read thread: {error}"));
            }
        };

        let write_stop = Arc::clone(&stop);
        let write_counters = Arc::clone(&counters);
        let write_thread = match std::thread::Builder::new()
            .name("nvpn-tun-write".to_string())
            .spawn(move || native_tun_write_loop(fd, inbound_rx, write_stop, write_counters))
        {
            Ok(thread) => thread,
            Err(error) => {
                let mut runtime = Self {
                    fd,
                    stop,
                    read_thread: Some(read_thread),
                    write_thread: None,
                };
                runtime.shutdown();
                return Err(anyhow!("failed to spawn native tun write thread: {error}"));
            }
        };

        Ok(Self {
            fd,
            stop,
            read_thread: Some(read_thread),
            write_thread: Some(write_thread),
        })
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    fn join(&mut self) {
        if let Some(thread) = self.read_thread.take() {
            let _ = thread.join();
        }
        if let Some(thread) = self.write_thread.take() {
            let _ = thread.join();
        }
    }

    fn shutdown(&mut self) {
        self.stop();
        self.join();
        // The threads hold their own copies of the fd number, so it must stay open until both have exited.
        if self.fd >= 0 {
            close_mobile_tun_fd(self.fd);
            self.fd = -1;
        }
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
    fd: c_int,
    mut inbound_rx: tokio_mpsc::Receiver<Vec<Vec<u8>>>,
    stop: Arc<AtomicBool>,
    counters: Arc<MobileTunAtomicCounters>,
) {
    while !stop.load(Ordering::Relaxed) {
        let packets = match inbound_rx.blocking_recv() {
            Some(packets) => packets,
            None => break,
        };
        for packet in packets {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if !write_native_tun_inbound_packet(fd, &packet, &stop, &counters) {
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
