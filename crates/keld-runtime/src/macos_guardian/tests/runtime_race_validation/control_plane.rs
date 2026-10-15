// Test control custody only. The actual production host owner remains
// run_generation_host; the relay never mints or chooses authority.
struct ControlPlane {
    host: Option<JoinHandle<Result<(), RuntimeError>>>,
    relay: Option<JoinHandle<Result<(), RuntimeError>>>,
    commands: Sender<RelayCommand>,
    receipts: Receiver<RelayReceipt>,
    recovery: Arc<Mutex<RecoveryState>>,
    updates: Receiver<GuardedPrimaryUpdate>,
    consumption_probe: Option<UnixStream>,
    current: Arc<Mutex<Option<RegisteredPrimaryGeneration>>>,
    guardian_control: Option<UnixStream>,
}

impl ControlPlane {
    fn start(cut: DeliveryCut) -> Self {
        let (host_control, relay_host) = timed_pair();
        let (guardian_control, relay_guardian) = timed_pair();
        // This clone observes FIONREAD only, never consumes bytes.
        // It is dropped before cancellation/EOF to preserve custody.
        let consumption_probe = (cut == DeliveryCut::Partial).then(|| {
            guardian_control
                .try_clone()
                .expect("sole-consumer observation alias")
        });
        let (updates_tx, updates) = mpsc::channel();
        let current = Arc::new(Mutex::new(None));
        let recovery = Arc::new(Mutex::new(RecoveryState::new()));
        lock_recovery(&recovery).arm();
        let host_current = Arc::clone(&current);
        let host_recovery = Arc::clone(&recovery);
        let host = thread::spawn(move || {
            run_generation_host(
                host_control,
                &updates_tx,
                &host_current,
                &host_recovery,
                None,
            )
        });
        let (commands, commands_rx) = mpsc::channel();
        let (receipts_tx, receipts) = mpsc::channel();
        let relay = thread::spawn(move || {
            private_record_relay(relay_host, relay_guardian, &commands_rx, &receipts_tx)
        });
        Self {
            host: Some(host),
            relay: Some(relay),
            commands,
            receipts,
            recovery,
            updates,
            consumption_probe,
            current,
            guardian_control: Some(guardian_control),
        }
    }
}

impl Drop for ControlPlane {
    fn drop(&mut self) {
        lock_recovery(&self.recovery).deny();
        self.consumption_probe.take();
        if let Some(stream) = self.guardian_control.take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        for worker in [self.relay.take(), self.host.take()].into_iter().flatten() {
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => eprintln!("KEL143_RACE_RESCUE owner error: {error}"),
                Err(error) => eprintln!("KEL143_RACE_RESCUE thread panic: {error:?}"),
            }
        }
    }
}

fn await_initial_registration(
    supervisor: &Supervisor,
    current: &Mutex<Option<RegisteredPrimaryGeneration>>,
) -> u32 {
    let pid = match supervisor.recv_event(COLLECTION) {
        Some(crate::SupervisorEvent::Started { pid, attempt: 1 }) => pid,
        Some(event) => panic!("unexpected initial enrollment event: {event:?}"),
        None => panic!("actual initial group registration absent"),
    };
    assert_eq!(
        lock_generation(current).map(|generation| generation.group_pid),
        Some(pid)
    );
    pid
}
