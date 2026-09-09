const IOS_PACKET_FLOW_MAX_PACKET_BYTES: usize = 65_535;

pub(crate) type IosPacketFlowWriteCallback = unsafe extern "C" fn(
    context: *mut std::ffi::c_void,
    packets: *const *const u8,
    lengths: *const usize,
    packet_count: usize,
) -> bool;
pub(crate) type IosPacketFlowFailureCallback =
    unsafe extern "C" fn(context: *mut std::ffi::c_void, message: *const std::ffi::c_char);
pub(crate) type IosPacketFlowReleaseCallback = unsafe extern "C" fn(context: *mut std::ffi::c_void);

pub(crate) struct IosPacketFlowCallbacks {
    context: usize,
    write: IosPacketFlowWriteCallback,
    failure: IosPacketFlowFailureCallback,
    release: IosPacketFlowReleaseCallback,
}

impl IosPacketFlowCallbacks {
    pub(crate) fn new(
        context: *mut std::ffi::c_void,
        write: Option<IosPacketFlowWriteCallback>,
        failure: Option<IosPacketFlowFailureCallback>,
        release: Option<IosPacketFlowReleaseCallback>,
    ) -> Result<Self> {
        if context.is_null() {
            return Err(anyhow!("iOS packet flow callback context is null"));
        }
        Ok(Self {
            context: context as usize,
            write: write.ok_or_else(|| anyhow!("iOS packet flow write callback is null"))?,
            failure: failure.ok_or_else(|| anyhow!("iOS packet flow failure callback is null"))?,
            release: release.ok_or_else(|| anyhow!("iOS packet flow release callback is null"))?,
        })
    }

    fn write(&self, packets: &[Vec<u8>]) -> bool {
        let packet_pointers = packets.iter().map(Vec::as_ptr).collect::<Vec<_>>();
        let packet_lengths = packets.iter().map(Vec::len).collect::<Vec<_>>();
        unsafe {
            (self.write)(
                self.context as *mut std::ffi::c_void,
                packet_pointers.as_ptr(),
                packet_lengths.as_ptr(),
                packets.len(),
            )
        }
    }

    fn fail(&self, message: &str) {
        let message = std::ffi::CString::new(message)
            .expect("static iOS packet flow failure message must not contain NUL");
        unsafe {
            (self.failure)(self.context as *mut std::ffi::c_void, message.as_ptr());
        }
    }
}

impl Drop for IosPacketFlowCallbacks {
    fn drop(&mut self) {
        unsafe {
            (self.release)(self.context as *mut std::ffi::c_void);
        }
    }
}

pub(crate) struct IosPacketFlowRuntime {
    task: Option<JoinHandle<()>>,
}

impl IosPacketFlowRuntime {
    fn start(
        runtime: &Runtime,
        inbound_rx: tokio_mpsc::Receiver<Vec<Vec<u8>>>,
        callbacks: IosPacketFlowCallbacks,
        counters: Arc<MobileTunAtomicCounters>,
    ) -> Self {
        let task = runtime.spawn(run_ios_packet_flow_writer(inbound_rx, callbacks, counters));
        Self { task: Some(task) }
    }

    async fn shutdown(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for IosPacketFlowRuntime {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn run_ios_packet_flow_writer(
    mut inbound_rx: tokio_mpsc::Receiver<Vec<Vec<u8>>>,
    callbacks: IosPacketFlowCallbacks,
    counters: Arc<MobileTunAtomicCounters>,
) {
    while let Some(packets) = inbound_rx.recv().await {
        let mut valid_packets = Vec::with_capacity(packets.len());
        for packet in packets {
            if ios_packet_flow_packet_is_valid(&packet) {
                valid_packets.push(packet);
            } else {
                counters.note_drop();
            }
        }
        if valid_packets.is_empty() {
            continue;
        }
        if !callbacks.write(&valid_packets) {
            for _ in &valid_packets {
                counters.note_drop();
            }
            callbacks.fail("NEPacketTunnelFlow rejected an inbound packet batch");
            return;
        }
        for packet in &valid_packets {
            counters.note_write(packet.len());
        }
    }
    callbacks.fail("mobile tunnel inbound packet channel stopped");
}

fn ios_packet_flow_packet_is_valid(packet: &[u8]) -> bool {
    !packet.is_empty()
        && packet.len() <= IOS_PACKET_FLOW_MAX_PACKET_BYTES
        && matches!(packet[0] >> 4, 4 | 6)
}

fn send_ios_packet_flow_batch(
    outbound_tx: &tokio_mpsc::Sender<Vec<Vec<u8>>>,
    counters: &MobileTunAtomicCounters,
    bytes: &[u8],
    lengths: &[usize],
) -> Result<()> {
    if lengths.is_empty() {
        return Err(anyhow!("iOS packet flow returned an empty packet batch"));
    }
    if lengths.len() > TUNNEL_CHANNEL_CAPACITY {
        return Err(anyhow!(
            "iOS packet flow batch has too many packets: {}",
            lengths.len()
        ));
    }

    let mut offset = 0usize;
    let mut packets = Vec::with_capacity(lengths.len());
    for &length in lengths {
        if length == 0 || length > IOS_PACKET_FLOW_MAX_PACKET_BYTES {
            return Err(anyhow!(
                "iOS packet flow returned invalid packet length {length}"
            ));
        }
        let end = offset
            .checked_add(length)
            .ok_or_else(|| anyhow!("iOS packet flow batch length overflow"))?;
        let packet = bytes
            .get(offset..end)
            .ok_or_else(|| anyhow!("iOS packet flow batch is shorter than its packet lengths"))?;
        if !ios_packet_flow_packet_is_valid(packet) {
            return Err(anyhow!("iOS packet flow returned an invalid IP packet"));
        }
        packets.push(packet.to_vec());
        offset = end;
    }
    if offset != bytes.len() {
        return Err(anyhow!(
            "iOS packet flow batch has trailing bytes after its packet lengths"
        ));
    }

    let packet_lengths = packets.iter().map(Vec::len).collect::<Vec<_>>();
    if let Err(error) = outbound_tx.try_send(packets) {
        for _ in &packet_lengths {
            counters.note_drop();
        }
        return match error {
            tokio_mpsc::error::TrySendError::Full(_) => {
                // NEPacketTunnelFlow can deliver a startup burst faster than
                // the dispatcher drains it. Keep the queue bounded and count
                // the loss; temporary pressure must not tear down the VPN.
                Ok(())
            }
            tokio_mpsc::error::TrySendError::Closed(_) => {
                Err(anyhow!("mobile tunnel outbound packet channel stopped"))
            }
        };
    }
    for length in packet_lengths {
        counters.note_read(length);
    }
    Ok(())
}

#[cfg(test)]
mod ios_packet_flow_tests {
    use super::*;
    use std::ffi::{CStr, c_char, c_void};
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::{Arc, Condvar, Mutex, mpsc};
    use std::time::Duration;

    #[derive(Default)]
    struct CallbackState {
        writes: Mutex<Vec<Vec<Vec<u8>>>>,
        failures: Mutex<Vec<String>>,
        releases: AtomicUsize,
        in_write: AtomicBool,
        released_during_write: AtomicBool,
        reject_writes: AtomicBool,
        block_writes: AtomicBool,
        continue_write: Mutex<bool>,
        continue_write_changed: Condvar,
        write_entered_signal: Mutex<Option<mpsc::Sender<()>>>,
        write_signal: Mutex<Option<mpsc::Sender<()>>>,
        failure_signal: Mutex<Option<mpsc::Sender<()>>>,
    }

    struct CallbackContext {
        state: Arc<CallbackState>,
    }

    unsafe extern "C" fn test_write_callback(
        context: *mut c_void,
        packets: *const *const u8,
        lengths: *const usize,
        packet_count: usize,
    ) -> bool {
        let context = unsafe { &*(context.cast::<CallbackContext>()) };
        context.state.in_write.store(true, Ordering::SeqCst);
        if let Some(signal) = context.state.write_entered_signal.lock().unwrap().as_ref() {
            let _ = signal.send(());
        }
        if context.state.block_writes.load(Ordering::SeqCst) {
            let mut continue_write = context.state.continue_write.lock().unwrap();
            while !*continue_write {
                continue_write = context
                    .state
                    .continue_write_changed
                    .wait(continue_write)
                    .unwrap();
            }
        }
        let packet_pointers = unsafe { std::slice::from_raw_parts(packets, packet_count) };
        let packet_lengths = unsafe { std::slice::from_raw_parts(lengths, packet_count) };
        let copied = packet_pointers
            .iter()
            .zip(packet_lengths)
            .map(|(&packet, &length)| unsafe {
                std::slice::from_raw_parts(packet, length).to_vec()
            })
            .collect::<Vec<_>>();
        context.state.writes.lock().unwrap().push(copied);
        context.state.in_write.store(false, Ordering::SeqCst);
        if let Some(signal) = context.state.write_signal.lock().unwrap().as_ref() {
            let _ = signal.send(());
        }
        !context.state.reject_writes.load(Ordering::SeqCst)
    }

    unsafe extern "C" fn test_failure_callback(context: *mut c_void, message: *const c_char) {
        let context = unsafe { &*(context.cast::<CallbackContext>()) };
        let message = unsafe { CStr::from_ptr(message) }
            .to_string_lossy()
            .into_owned();
        context.state.failures.lock().unwrap().push(message);
        if let Some(signal) = context.state.failure_signal.lock().unwrap().as_ref() {
            let _ = signal.send(());
        }
    }

    unsafe extern "C" fn test_release_callback(context: *mut c_void) {
        let context = unsafe { Box::from_raw(context.cast::<CallbackContext>()) };
        if context.state.in_write.load(Ordering::SeqCst) {
            context
                .state
                .released_during_write
                .store(true, Ordering::SeqCst);
        }
        context.state.releases.fetch_add(1, Ordering::SeqCst);
    }

    fn test_callbacks(state: Arc<CallbackState>) -> IosPacketFlowCallbacks {
        let context = Box::into_raw(Box::new(CallbackContext { state })).cast::<c_void>();
        IosPacketFlowCallbacks::new(
            context,
            Some(test_write_callback),
            Some(test_failure_callback),
            Some(test_release_callback),
        )
        .unwrap()
    }

    fn test_runtime() -> Runtime {
        RuntimeBuilder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn ios_packet_flow_writes_batches_and_releases_context_after_shutdown() {
        let runtime = test_runtime();
        let counters = Arc::new(MobileTunAtomicCounters::default());
        let state = Arc::new(CallbackState::default());
        let (write_tx, write_rx) = mpsc::channel();
        *state.write_signal.lock().unwrap() = Some(write_tx);
        let (inbound_tx, inbound_rx) = tokio_mpsc::channel(1);
        let flow = IosPacketFlowRuntime::start(
            &runtime,
            inbound_rx,
            test_callbacks(Arc::clone(&state)),
            Arc::clone(&counters),
        );
        let ipv4 = vec![0x45, 0, 0, 20];
        let ipv6 = vec![0x60, 0, 0, 0];

        inbound_tx
            .blocking_send(vec![ipv4.clone(), ipv6.clone()])
            .unwrap();
        write_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(state.writes.lock().unwrap().as_slice(), &[vec![ipv4, ipv6]]);
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while counters.snapshot().packets_written != 2 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(counters.snapshot().packets_written, 2);

        runtime.block_on(flow.shutdown());
        assert_eq!(state.releases.load(Ordering::SeqCst), 1);
        assert!(!state.released_during_write.load(Ordering::SeqCst));
        assert!(state.failures.lock().unwrap().is_empty());
    }

    #[test]
    fn ios_packet_flow_write_rejection_is_fatal_and_counted() {
        let runtime = test_runtime();
        let counters = Arc::new(MobileTunAtomicCounters::default());
        let state = Arc::new(CallbackState::default());
        state.reject_writes.store(true, Ordering::SeqCst);
        let (failure_tx, failure_rx) = mpsc::channel();
        *state.failure_signal.lock().unwrap() = Some(failure_tx);
        let (inbound_tx, inbound_rx) = tokio_mpsc::channel(1);
        let flow = IosPacketFlowRuntime::start(
            &runtime,
            inbound_rx,
            test_callbacks(Arc::clone(&state)),
            Arc::clone(&counters),
        );

        inbound_tx
            .blocking_send(vec![vec![0x45, 0, 0, 20], vec![0x60, 0, 0, 0]])
            .unwrap();
        failure_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        runtime.block_on(flow.shutdown());

        assert_eq!(counters.snapshot().packets_written, 0);
        assert_eq!(counters.snapshot().packets_dropped, 2);
        assert_eq!(state.failures.lock().unwrap().len(), 1);
        assert_eq!(state.releases.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ios_packet_flow_shutdown_waits_for_an_active_callback_before_release() {
        let runtime = test_runtime();
        let counters = Arc::new(MobileTunAtomicCounters::default());
        let state = Arc::new(CallbackState::default());
        state.block_writes.store(true, Ordering::SeqCst);
        let (entered_tx, entered_rx) = mpsc::channel();
        *state.write_entered_signal.lock().unwrap() = Some(entered_tx);
        let (inbound_tx, inbound_rx) = tokio_mpsc::channel(1);
        let flow = IosPacketFlowRuntime::start(
            &runtime,
            inbound_rx,
            test_callbacks(Arc::clone(&state)),
            counters,
        );
        inbound_tx
            .blocking_send(vec![vec![0x45, 0, 0, 20]])
            .unwrap();
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let shutdown = std::thread::spawn(move || runtime.block_on(flow.shutdown()));
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(state.releases.load(Ordering::SeqCst), 0);
        assert!(state.in_write.load(Ordering::SeqCst));

        *state.continue_write.lock().unwrap() = true;
        state.continue_write_changed.notify_all();
        shutdown.join().unwrap();
        assert_eq!(state.releases.load(Ordering::SeqCst), 1);
        assert!(!state.released_during_write.load(Ordering::SeqCst));
    }

    #[test]
    fn ios_packet_flow_outbound_overload_drops_without_stopping_the_tunnel() {
        let runtime = test_runtime();
        let counters = Arc::new(MobileTunAtomicCounters::default());
        let (outbound_tx, mut outbound_rx) = tokio_mpsc::channel(1);
        send_ios_packet_flow_batch(&outbound_tx, &counters, &[0x45, 0, 0, 20], &[4]).unwrap();

        let started_at = std::time::Instant::now();
        send_ios_packet_flow_batch(&outbound_tx, &counters, &[0x60, 0, 0, 0], &[4]).unwrap();
        assert!(started_at.elapsed() < Duration::from_millis(250));

        assert_eq!(
            runtime.block_on(outbound_rx.recv()).unwrap(),
            vec![vec![0x45, 0, 0, 20]]
        );
        assert_eq!(counters.snapshot().packets_read, 1);
        assert_eq!(counters.snapshot().packets_dropped, 1);

        // Once the consumer catches up, the same live bridge accepts traffic.
        send_ios_packet_flow_batch(&outbound_tx, &counters, &[0x60, 0, 0, 0], &[4]).unwrap();
        assert_eq!(
            runtime.block_on(outbound_rx.recv()).unwrap(),
            vec![vec![0x60, 0, 0, 0]]
        );
        assert_eq!(counters.snapshot().packets_read, 2);

        // Actual shutdown remains a failure so the provider cancels its flow.
        drop(outbound_rx);
        let error = send_ios_packet_flow_batch(&outbound_tx, &counters, &[0x45, 0, 0, 20], &[4])
            .unwrap_err();
        assert!(error.to_string().contains("channel stopped"));
        assert_eq!(counters.snapshot().packets_dropped, 2);
    }

    #[test]
    fn ios_packet_flow_rejects_malformed_batches_before_enqueue() {
        let counters = MobileTunAtomicCounters::default();
        let (outbound_tx, mut outbound_rx) = tokio_mpsc::channel(1);
        assert!(
            send_ios_packet_flow_batch(&outbound_tx, &counters, &[0x45, 0, 0, 20], &[5],).is_err()
        );
        assert!(outbound_rx.try_recv().is_err());
        assert_eq!(counters.snapshot(), MobileTunCounters::default());
    }
}
