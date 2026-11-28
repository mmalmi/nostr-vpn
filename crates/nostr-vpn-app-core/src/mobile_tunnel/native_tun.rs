use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const NATIVE_TUN_PACKET_HEADROOM: usize = 128;
const NATIVE_TUN_PACKET_MAX: usize = 65_535;

struct NativeTunStop {
    read_fd: OwnedFd,
    writer: tokio::sync::watch::Sender<Option<OwnedFd>>,
    running: tokio::sync::watch::Receiver<Option<OwnedFd>>,
    runtime: tokio::runtime::Handle,
}

impl NativeTunStop {
    fn new(runtime: &tokio::runtime::Handle) -> Result<Self> {
        let mut fds = [-1; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return Err(anyhow!(
                "failed to create native tun wake pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        // pipe2 returned two owned descriptors. Only the watch state owns the writer.
        let [read_fd, write_fd] = fds.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });
        let (writer, running) = tokio::sync::watch::channel(Some(write_fd));
        Ok(Self {
            read_fd,
            writer,
            running,
            runtime: runtime.clone(),
        })
    }

    fn request_stop(&self) {
        // Closing the sole writer leaves POLLHUP visible to both workers, even
        // if they begin polling later. The same transition wakes channel waits.
        self.writer
            .send_if_modified(|writer| writer.take().is_some());
    }

    fn is_stopped(&self) -> bool {
        // This receiver stays at the initial version. Stop is the only change.
        self.running.has_changed().unwrap_or(true)
    }

    fn wait_channel<F: std::future::Future>(&self, operation: F) -> Option<F::Output> {
        let mut stop = self.writer.subscribe();
        self.runtime.block_on(async {
            tokio::select! {
                biased;
                _ = stop.wait_for(Option::is_none) => None,
                result = operation => Some(result),
            }
        })
    }
}

struct StopOnWorkerExit<'a>(&'a NativeTunStop);

impl Drop for StopOnWorkerExit<'_> {
    fn drop(&mut self) {
        self.0.request_stop();
    }
}

struct NativeTunRuntime {
    // Both workers borrow this descriptor until join completes.
    _fd: OwnedFd,
    stop: Arc<NativeTunStop>,
    read_thread: Option<std::thread::JoinHandle<()>>,
    write_thread: Option<std::thread::JoinHandle<()>>,
}

impl NativeTunRuntime {
    fn start(
        fd: c_int,
        runtime: &tokio::runtime::Handle,
        outbound_tx: tokio_mpsc::Sender<Vec<Vec<u8>>>,
        inbound_rx: tokio_mpsc::Receiver<Vec<Vec<u8>>>,
        packet_capacity: usize,
        counters: Arc<MobileTunAtomicCounters>,
    ) -> Result<Self> {
        let owned_fd = unsafe { OwnedFd::from_raw_fd(prepare_mobile_tun_fd(fd)?) };
        let fd = owned_fd.as_raw_fd();
        let stop = Arc::new(NativeTunStop::new(runtime)?);
        let read_stop = Arc::clone(&stop);
        let read_counters = Arc::clone(&counters);
        let read_thread = std::thread::Builder::new()
            .name("nvpn-tun-read".to_string())
            .spawn(move || {
                native_tun_read_loop(fd, outbound_tx, &read_stop, read_counters, packet_capacity)
            })
            .map_err(|error| anyhow!("failed to spawn native tun read thread: {error}"))?;

        let write_stop = Arc::clone(&stop);
        let write_thread = match std::thread::Builder::new()
            .name("nvpn-tun-write".to_string())
            .spawn(move || native_tun_write_loop(fd, inbound_rx, &write_stop, counters))
        {
            Ok(thread) => thread,
            Err(error) => {
                stop.request_stop();
                let _ = read_thread.join();
                return Err(anyhow!("failed to spawn native tun write thread: {error}"));
            }
        };

        Ok(Self {
            _fd: owned_fd,
            stop,
            read_thread: Some(read_thread),
            write_thread: Some(write_thread),
        })
    }

    fn stop(&self) {
        self.stop.request_stop();
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
    stop: &NativeTunStop,
    counters: Arc<MobileTunAtomicCounters>,
    packet_capacity: usize,
) {
    let _stop_on_exit = StopOnWorkerExit(stop);
    let mut packets = Vec::with_capacity(MOBILE_FIPS_SEND_BATCH);
    let mut read_packet = Vec::<u8>::with_capacity(packet_capacity);
    'read: loop {
        packets.clear();
        let mut batch_bytes = 0usize;
        while packets.len() < MOBILE_FIPS_SEND_BATCH {
            match read_mobile_tun_packet(fd, &mut read_packet) {
                NativeTunRead::Packet(packet) => {
                    batch_bytes = batch_bytes.saturating_add(packet.len());
                    packets.push(packet);
                }
                NativeTunRead::WouldBlock => {
                    if !packets.is_empty() {
                        break;
                    }
                    if !wait_mobile_tun_fd(fd, libc::POLLIN, stop) {
                        break 'read;
                    }
                    continue;
                }
                NativeTunRead::Stopped => {
                    if !packets.is_empty() {
                        counters.note_read_batch(packets.len(), batch_bytes);
                        counters.note_drop_batch(packets.len());
                    }
                    break 'read;
                }
            }
        }
        if !packets.is_empty() {
            let batch = std::mem::replace(&mut packets, Vec::with_capacity(MOBILE_FIPS_SEND_BATCH));
            let batch_len = batch.len();
            counters.note_read_batch(batch_len, batch_bytes);
            let sent = !stop.is_stopped()
                && match outbound_tx.try_send(batch) {
                    Ok(()) => true,
                    Err(tokio_mpsc::error::TrySendError::Full(batch)) => {
                        matches!(stop.wait_channel(outbound_tx.send(batch)), Some(Ok(())))
                    }
                    Err(tokio_mpsc::error::TrySendError::Closed(_)) => false,
                };
            if !sent {
                counters.note_drop_batch(batch_len);
                break;
            }
        }
    }
}

fn native_tun_write_loop(
    fd: c_int,
    mut inbound_rx: tokio_mpsc::Receiver<Vec<Vec<u8>>>,
    stop: &NativeTunStop,
    counters: Arc<MobileTunAtomicCounters>,
) {
    let _stop_on_exit = StopOnWorkerExit(stop);
    'write: while !stop.is_stopped() {
        let packets = match inbound_rx.try_recv() {
            Ok(packets) => packets,
            Err(tokio_mpsc::error::TryRecvError::Empty) => {
                let Some(Some(packets)) = stop.wait_channel(inbound_rx.recv()) else {
                    break;
                };
                packets
            }
            Err(tokio_mpsc::error::TryRecvError::Disconnected) => break,
        };
        for packet in packets {
            if stop.is_stopped() || !write_native_tun_inbound_packet(fd, &packet, stop, &counters) {
                break 'write;
            }
        }
    }
}

fn write_native_tun_inbound_packet(
    fd: c_int,
    packet: &[u8],
    stop: &NativeTunStop,
    counters: &MobileTunAtomicCounters,
) -> bool {
    let packet_len = packet.len();
    match write_mobile_tun_packet(fd, packet, stop) {
        NativeTunWrite::Written => counters.note_write_batch(1, packet_len),
        NativeTunWrite::Dropped => counters.note_drop_batch(1),
        NativeTunWrite::Stopped => {
            counters.note_drop_batch(1);
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

fn write_mobile_tun_packet(fd: c_int, packet: &[u8], stop: &NativeTunStop) -> NativeTunWrite {
    if packet.is_empty() {
        return NativeTunWrite::Dropped;
    }
    while !stop.is_stopped() {
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

fn wait_mobile_tun_fd(fd: c_int, events: i16, stop: &NativeTunStop) -> bool {
    while !stop.is_stopped() {
        let mut poll_fds = [
            libc::pollfd {
                fd,
                events,
                revents: 0,
            },
            libc::pollfd {
                fd: stop.read_fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ready = unsafe { libc::poll(poll_fds.as_mut_ptr(), 2, -1) };
        if ready > 0 {
            if poll_fds[1].revents != 0 {
                return false;
            }
            if poll_fds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return false;
            }
            return poll_fds[0].revents & events != 0;
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

#[cfg(test)]
mod native_tun_stop_tests {
    use super::*;
    use std::net::Shutdown;
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    enum StopFrom {
        Reader,
        Writer,
        Owner,
    }

    #[test]
    fn partial_read_batch_at_eof_counts_reads_and_drops() {
        use std::io::Write;
        use std::os::fd::AsRawFd;

        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let stop = NativeTunStop::new(runtime.handle()).unwrap();
        let (tun, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(b"out").unwrap();
        peer.shutdown(Shutdown::Write).unwrap();
        let (sender, _receiver) = tokio_mpsc::channel(1);
        let counters = Arc::new(MobileTunAtomicCounters::default());
        native_tun_read_loop(tun.as_raw_fd(), sender, &stop, counters.clone(), 1280);
        let totals = counters.snapshot();
        assert_eq!((totals.packets_read, totals.bytes_read, totals.packets_dropped), (1, 3, 1));
    }

    fn check_worker_shutdown(from: StopFrom) {
        use std::io::{Read, Write};
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let (tun, mut peer) = UnixStream::pair().unwrap();
        let (outbound_tx, mut outbound_rx) = tokio_mpsc::channel(1);
        let (inbound_tx, inbound_rx) = tokio_mpsc::channel(1);
        let mut workers = NativeTunRuntime::start(
            tun.into_raw_fd(),
            runtime.handle(),
            outbound_tx,
            inbound_rx,
            1280,
            Arc::new(MobileTunAtomicCounters::default()),
        )
        .unwrap();
        // Exercise both workers before stopping either one. Leave the packet
        // channels and socket peer open unless they are the shutdown trigger.
        peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        peer.write_all(b"out").unwrap();
        let batch = runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(3), outbound_rx.recv())
                .await
                .unwrap()
                .unwrap()
        });
        assert_eq!(batch, [b"out".to_vec()]);
        inbound_tx.try_send(vec![b"in".to_vec()]).unwrap();
        let mut reply = [0; 2];
        peer.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"in");
        match from {
            StopFrom::Reader => peer.shutdown(Shutdown::Write).unwrap(),
            StopFrom::Writer => drop(inbound_tx),
            StopFrom::Owner => workers.stop(),
        }
        let (done, joined) = std::sync::mpsc::channel();
        let joiner = std::thread::spawn(move || {
            workers.read_thread.take().unwrap().join().unwrap();
            workers.write_thread.take().unwrap().join().unwrap();
            done.send(()).unwrap();
        });
        joined
            .recv_timeout(Duration::from_secs(3))
            .expect("native TUN workers did not stop");
        joiner.join().unwrap();
    }

    #[test]
    fn writer_channel_close_stops_idle_reader() {
        check_worker_shutdown(StopFrom::Writer);
    }

    #[test]
    fn reader_eof_stops_writer_with_open_channel() {
        check_worker_shutdown(StopFrom::Reader);
    }

    #[test]
    fn external_stop_wakes_idle_workers() {
        check_worker_shutdown(StopFrom::Owner);
    }
}
