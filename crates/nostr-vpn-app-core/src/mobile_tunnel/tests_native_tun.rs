    use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _, OwnedFd};

    // The Android service replaces the VPN interface from its main looper.
    // The old reader can be waiting for room in the outbound queue at that
    // moment, and nothing drains that queue while the mesh has no upstream.
    #[test]
    fn replacing_the_tun_fd_does_not_wait_for_a_saturated_outbound_queue() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .build()
            .expect("native tun test runtime");
        let (outbound_tx, mut outbound_rx) = tokio_mpsc::channel(1);
        let (inbound_tx, inbound_rx) = tokio_mpsc::channel(1);
        let counters = Arc::new(MobileTunAtomicCounters::default());
        let (old_interface, old_host) = native_tun_test_interface();
        let (new_interface, new_host) = native_tun_test_interface();
        let tun = NativeTunRuntime::start(
            old_interface.into_raw_fd(),
            runtime.handle().clone(),
            outbound_tx.clone(),
            inbound_rx,
            native_tun_packet_capacity(1150),
            Arc::clone(&counters),
        )
        .expect("start native tun");
        let tun = Arc::new(Mutex::new(tun));
        // Declared after `tun` so it is dropped first: the writer thread that
        // `tun` joins on drop ends when its queue closes.
        let inbound_tx = inbound_tx;

        // The first packet fills the queue; the second leaves the reader
        // waiting for room in it.
        native_tun_test_send(&old_host, b"first");
        native_tun_test_wait("the outbound queue to fill", || {
            outbound_tx.capacity() == 0
        });
        native_tun_test_send(&old_host, b"second");
        native_tun_test_wait("the reader to take the second packet", || {
            counters.snapshot().packets_read == 2
        });
        std::thread::sleep(Duration::from_millis(100));

        let (replaced_tx, replaced_rx) = std::sync::mpsc::channel();
        let replacement = new_interface.into_raw_fd();
        let replacing = Arc::clone(&tun);
        let replacer = std::thread::spawn(move || {
            let result = replacing
                .lock()
                .expect("native tun lock")
                .replace_fd(replacement);
            let _ = replaced_tx.send(result);
        });
        replaced_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("replacing the tun fd waited for the saturated outbound queue")
            .expect("replace native tun fd");
        replacer.join().expect("replacer thread");

        // The retired reader gives up its packet and closes the old
        // interface while the queue is still full.
        native_tun_test_wait("the old interface to close", || {
            native_tun_test_poll(&old_host) & libc::POLLHUP != 0
        });
        assert_eq!(outbound_tx.capacity(), 0);
        assert_eq!(counters.snapshot().packets_dropped, 1);

        // The tunnel carries packets on the replacement in both directions.
        assert_eq!(outbound_rx.blocking_recv(), Some(vec![b"first".to_vec()]));
        native_tun_test_send(&new_host, b"third");
        assert_eq!(outbound_rx.blocking_recv(), Some(vec![b"third".to_vec()]));
        inbound_tx
            .blocking_send(vec![b"reply".to_vec()])
            .expect("queue inbound packet");
        native_tun_test_wait("the inbound packet", || {
            native_tun_test_poll(&new_host) & libc::POLLIN != 0
        });
        let mut packet = [0_u8; 16];
        let len = unsafe {
            libc::read(
                new_host.as_raw_fd(),
                packet.as_mut_ptr().cast::<libc::c_void>(),
                packet.len(),
            )
        };
        assert_eq!(&packet[..usize::try_from(len).expect("read reply")], b"reply");
    }

    /// A packet-preserving socket pair in place of a VPN interface: the
    /// first end is handed to the tunnel, the second plays the host stack.
    fn native_tun_test_interface() -> (OwnedFd, OwnedFd) {
        let mut fds = [0; 2];
        let created =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr()) };
        assert_eq!(created, 0, "socketpair: {}", std::io::Error::last_os_error());
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    fn native_tun_test_send(host: &OwnedFd, packet: &[u8]) {
        let written = unsafe {
            libc::write(
                host.as_raw_fd(),
                packet.as_ptr().cast::<libc::c_void>(),
                packet.len(),
            )
        };
        assert_eq!(usize::try_from(written).ok(), Some(packet.len()));
    }

    fn native_tun_test_poll(host: &OwnedFd) -> i16 {
        let mut poll_fd = libc::pollfd {
            fd: host.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe { libc::poll(&raw mut poll_fd, 1, 0) };
        poll_fd.revents
    }

    fn native_tun_test_wait(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
