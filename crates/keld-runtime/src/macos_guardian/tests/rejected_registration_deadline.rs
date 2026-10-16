// Pre-registration custody also needs bounded guardian retirement: there is
// no enrolled Bun group yet, so test only the owned guardian child here.
fn assert_guardian_cleanup_bounded<F>(guardian_pid: u32, operation: F) -> Option<String>
where
    F: FnOnce() -> Option<String> + Send + 'static,
{
    let (tx, rx) = mpsc::sync_channel(1);
    let owner = thread::spawn(move || {
        let _ = tx.send(operation());
    });
    let completed = rx.recv_timeout(GUARDIAN_SHUTDOWN_DEADLINE + Duration::from_secs(2));
    if completed.is_err() {
        // Safe red-phase kill switch for this exact test-owned guardian.
        let _ = kill(
            Pid::from_raw(i32::try_from(guardian_pid).expect("guardian pid fits")),
            Signal::SIGKILL,
        );
    }
    owner.join().expect("guardian cleanup worker joins");
    assert!(
        completed.is_ok(),
        "rejected/bootstrap guardian cleanup exceeded the five-second shutdown deadline"
    );
    assert_eq!(
        kill(
            Pid::from_raw(i32::try_from(guardian_pid).expect("guardian pid fits")),
            None,
        ),
        Err(Errno::ESRCH),
        "cleanup must reap the guardian, not merely signal it"
    );
    completed.expect("bounded worker result")
}

#[test]
fn rejected_registration_reaps_wedged_guardian_within_shutdown_deadline() {
    let mut command = long_running_command();
    command.stdin(Stdio::piped());
    let mut child = command.spawn().expect("isolated uncooperative guardian");
    let guardian_pid = child.id();
    let writer = child.stdin.take().expect("sole owned guardian writer");
    let error = super::lifecycle_error(
        "macOS guardian synthetic registration rejection",
        io::Error::new(io::ErrorKind::PermissionDenied, "refused registration"),
    );
    let rendered = assert_guardian_cleanup_bounded(guardian_pid, move || {
        Some(super::reject_host_registration(child, writer, None, error).to_string())
    })
    .expect("rejection is retained");
    assert!(rendered.contains("refused registration"), "{rendered}");
    assert!(
        rendered.contains("cleanup deadline"),
        "wedged guardian must report its bounded cleanup timeout: {rendered}"
    );
}

#[test]
fn dropping_unregistered_bootstrap_reaps_wedged_guardian_within_shutdown_deadline() {
    let guardian =
        GuardianBootstrap::spawn(long_running_command()).expect("spawn owned bootstrap guardian");
    let guardian_pid = guardian.guardian_pid().expect("bootstrap owns child");
    assert_guardian_cleanup_bounded(guardian_pid, move || {
        drop(guardian);
        None
    });
}
