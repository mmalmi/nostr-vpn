fn spawn_tun_send_worker(
    tun: Arc<SystemTun>,
    mesh: Arc<FipsPrivateMeshRuntime>,
    fips_host_enabled: bool,
) -> Result<FipsTunSendWorker> {
    let stop = Arc::new(AtomicBool::new(false));
    let (wake_reader, wake_writer) = std::os::unix::net::UnixStream::pair()
        .context("failed to create TUN wake socket pair")?;
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::Builder::new()
        .name("nvpn-fips-tun-send".to_string())
        .spawn(move || {
            let tun_fd = BorrowedTunFd::new(tun.as_raw_fd());
            let wake_fd = wake_reader.as_raw_fd();
            let mut buf = vec![0_u8; tun.read_buffer_len()];
            let mut batch = Vec::with_capacity(FIPS_TUN_READ_BURST);
            let mut send_runs = Vec::new();
            let pipeline_profile_enabled = crate::pipeline_profile::enabled();
            while !thread_stop.load(Ordering::Acquire) {
                if !wait_fd_readable_blocking(tun_fd.as_raw_fd(), wake_fd, &thread_stop) {
                    break;
                }
                batch.clear();
                let mut drained = 0;
                let mut drained_bytes = 0usize;
                let mut sleep_after_error = false;
                loop {
                    let before_len = batch.len();
                    let read_result = {
                        let _t = crate::pipeline_profile::Timer::start(
                            crate::pipeline_profile::Stage::TunRead,
                        );
                        tun.read_packets_into(&mut buf, &mut batch)
                    };
                    match read_result {
                        Ok(0) => {
                            break;
                        }
                        Ok(packet_count) => {
                            debug_assert_eq!(batch.len(), before_len + packet_count);
                            if pipeline_profile_enabled {
                                for packet in &batch[before_len..] {
                                    drained_bytes =
                                        drained_bytes.saturating_add(packet.bytes.len());
                                }
                            }
                            drained += packet_count;
                            if drained >= FIPS_TUN_READ_BURST {
                                break;
                            }
                        }
                        Err(error) if temporary_tun_read_error(&error) => {
                            break;
                        }
                        Err(error) => {
                            eprintln!("fips: tunnel read failed: {error}");
                            sleep_after_error = true;
                            break;
                        }
                    }
                }

                if !batch.is_empty() {
                    if pipeline_profile_enabled {
                        crate::pipeline_profile::record_tun_read_batch(
                            batch.len(),
                            drained_bytes,
                            FIPS_TUN_READ_BURST,
                        );
                    }
                    send_mesh_packet_batch_blocking_or_log(
                        &mesh,
                        tun_fd,
                        &mut batch,
                        &mut send_runs,
                        &thread_stop,
                        fips_host_enabled,
                    );
                }

                if sleep_after_error {
                    std::thread::sleep(Duration::from_millis(100));
                }

                if drained >= FIPS_TUN_READ_BURST {
                    std::thread::yield_now();
                }
            }
        })
        .context("failed to spawn FIPS TUN send worker")?;
    Ok(FipsTunSendWorker { stop, wake_writer, thread })
}

async fn stop_tun_send_worker(worker: FipsTunSendWorker) {
    worker.stop.store(true, Ordering::Release);
    drop(worker.wake_writer);
    let _ = tokio::task::spawn_blocking(move || {
        let _ = worker.thread.join();
    })
    .await;
}
fn wait_fd_readable_blocking(fd: RawFd, wake_fd: RawFd, stop: &AtomicBool) -> bool {
    while !stop.load(Ordering::Acquire) {
        let mut poll_fds = [
            libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let result = unsafe { libc::poll(poll_fds.as_mut_ptr(), 2, -1) };
        if result > 0 {
            if poll_fds[1].revents != 0 {
                return false;
            }
            return poll_fds[0].revents & libc::POLLIN != 0
                && poll_fds[0].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) == 0;
        }
        if result == 0 {
            continue;
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        eprintln!("fips: tunnel read poll failed: {error}");
        return false;
    }
    false
}

fn send_mesh_packet_batch_blocking_or_log(
    mesh: &FipsPrivateMeshRuntime,
    tun_fd: BorrowedTunFd,
    packets: &mut TunPipelineBatch,
    send_runs: &mut Vec<FipsEndpointIdentitySendRun>,
    stop: &AtomicBool,
    fips_host_enabled: bool,
) {
    let packet_count = packets.len();
    crate::pipeline_profile::record_mesh_send_bulk_turn(0, packet_count);
    let _t = crate::pipeline_profile::Timer::start(crate::pipeline_profile::Stage::MeshSend);
    if !mesh.local_tunnel_ips.is_empty() {
        packets.retain(|packet| {
            if tun_pipeline_packet_targets_local_tunnel(&mesh.local_tunnel_ips, packet) {
                write_packet_to_tun_blocking(tun_fd, &packet.bytes, stop);
                false
            } else {
                true
            }
        });
    }
    if packets.is_empty() {
        return;
    }
    if fips_host_enabled {
        packets.retain_mut(|packet| {
            if !tun_pipeline_packet_targets_fips_host(packet) {
                return true;
            }
            let bytes = std::mem::take(&mut packet.bytes);
            if let Err(error) = mesh.endpoint().blocking_send_ip_packet(bytes) {
                eprintln!("fips-host: failed to enqueue outbound IPv6 packet: {error}");
            }
            false
        });
    }
    if packets.is_empty() {
        return;
    }
    let mesh_packet_count = packets.len();
    if let Err(error) = mesh.blocking_send_tun_pipeline_packet_turn(
        packets.drain(..),
        mesh_packet_count,
        send_runs,
    ) {
        eprintln!("fips: failed to send tunnel packet: {error}");
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn spawn_fips_host_recv_worker(
    endpoint: Arc<FipsEndpoint>,
    tun_fd: BorrowedTunFd,
) -> FipsHostRecvWorker {
    let task = tokio::spawn(async move {
        while let Some(delivered) = endpoint.recv_ip_packet().await {
            let address_family = match delivered.packet.first().map(|byte| byte >> 4) {
                Some(4) => libc::AF_INET as u8,
                Some(6) => libc::AF_INET6 as u8,
                _ => continue,
            };
            loop {
                match raw_write_packet_to_tun(&tun_fd, &delivered.packet, address_family) {
                    Ok(()) => {
                        crate::pipeline_profile::record_tun_write_packets(
                            1,
                            delivered.packet.len(),
                        );
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => {
                        eprintln!("fips-host: tunnel write failed: {error}");
                        break;
                    }
                }
            }
        }
    });
    FipsHostRecvWorker { task }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn stop_fips_host_recv_worker(worker: FipsHostRecvWorker) {
    let mut task = worker.task;
    task.abort();
    let _ = (&mut task).await;
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tun_pipeline_packet_targets_local_tunnel(
    local_tunnel_ips: &HashSet<IpAddr>,
    packet: &TunPipelinePacket,
) -> bool {
    packet
        .destination
        .is_some_and(|destination| local_tunnel_ips.contains(&destination))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn spawn_mesh_recv_worker(
    mesh: Arc<FipsPrivateMeshRuntime>,
    tun_fd: BorrowedTunFd,
    event_tx: mpsc::Sender<FipsPrivateMeshEvent>,
) -> Result<FipsMeshRecvWorker> {
    spawn_blocking_mesh_recv_worker(mesh, tun_fd, event_tx)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn stop_mesh_recv_worker(worker: FipsMeshRecvWorker, mesh: &FipsPrivateMeshRuntime) {
    worker.stop.store(true, Ordering::Release);
    mesh.wake_blocking_mesh_recv();
    let _ = tokio::task::spawn_blocking(move || {
        let _ = worker.thread.join();
    })
    .await;
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn spawn_blocking_mesh_recv_worker(
    mesh: Arc<FipsPrivateMeshRuntime>,
    tun_fd: BorrowedTunFd,
    event_tx: mpsc::Sender<FipsPrivateMeshEvent>,
) -> Result<FipsMeshRecvWorker> {
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let thread = std::thread::Builder::new()
        .name("nvpn-fips-mesh-recv".to_string())
        .spawn(move || {
            let recv_burst = FIPS_MESH_RECV_BURST;
            let mut packet_batch = DirectTunWriteBatch::with_capacity(recv_burst);
            #[cfg(target_os = "linux")]
            let mut vnet_write_preparer = LinuxVnetWritePreparer::new();
            let pipeline_profile_enabled = crate::pipeline_profile::enabled();
            while !thread_stop.load(Ordering::Acquire) {
                packet_batch.clear();
                let received = mesh.recv_direct_endpoint_tun_batch_blocking(
                    &thread_stop,
                    &mut packet_batch,
                    &event_tx,
                );
                match received {
                    Ok(Some(drained)) => {
                        if let Err(error) =
                            mesh.finalize_direct_endpoint_tun_batch_blocking(&packet_batch)
                        {
                            packet_batch.clear();
                            eprintln!("fips: failed to finalize tunnel packet batch: {error}");
                            std::thread::sleep(Duration::from_millis(100));
                            continue;
                        }
                        if pipeline_profile_enabled {
                            let packet_count = packet_batch.len();
                            let packet_bytes = packet_batch.bytes();
                            crate::pipeline_profile::record_mesh_recv_batch(
                                drained,
                                packet_count,
                                packet_bytes,
                                recv_burst,
                            );
                        }
                        if !packet_batch.is_empty() {
                            flush_direct_endpoint_packet_batch_to_tun_blocking(
                                tun_fd,
                                &mut packet_batch,
                                &thread_stop,
                                #[cfg(target_os = "linux")]
                                &mut vnet_write_preparer,
                            );
                        }
                        if drained >= recv_burst {
                            std::thread::yield_now();
                        }
                    }
                    Ok(None) => {
                        if let Err(error) =
                            mesh.finalize_direct_endpoint_tun_batch_blocking(&packet_batch)
                        {
                            packet_batch.clear();
                            eprintln!("fips: failed to finalize tunnel packet batch: {error}");
                        }
                        flush_direct_endpoint_packet_batch_to_tun_blocking(
                            tun_fd,
                            &mut packet_batch,
                            &thread_stop,
                            #[cfg(target_os = "linux")]
                            &mut vnet_write_preparer,
                        );
                        break;
                    }
                    Err(error) => {
                        if let Err(error) =
                            mesh.finalize_direct_endpoint_tun_batch_blocking(&packet_batch)
                        {
                            packet_batch.clear();
                            eprintln!("fips: failed to finalize tunnel packet batch: {error}");
                        }
                        flush_direct_endpoint_packet_batch_to_tun_blocking(
                            tun_fd,
                            &mut packet_batch,
                            &thread_stop,
                            #[cfg(target_os = "linux")]
                            &mut vnet_write_preparer,
                        );
                        eprintln!("fips: failed to receive tunnel packet: {error}");
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            }
        })
        .context("failed to spawn FIPS mesh receive worker")?;
    Ok(FipsMeshRecvWorker { stop, thread })
}
