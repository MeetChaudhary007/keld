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

// A guardian that exits zero is not proof its enrolled Bun group retired.
// The rejected-registration path must independently retire that registered
// group; the test fallback runs only if production fails to do so.
#[test]
fn rejected_writer_with_clean_guardian_exit_reaps_enrolled_group() {
    let mut group_command = long_running_command();
    group_command.process_group(0);
    let mut group = group_command.spawn().expect("isolated registered group");
    let group_pid = group.id();
    let raw_group = i32::try_from(group_pid).expect("group id fits i32");
    assert_eq!(
        nix::unistd::getpgid(Some(Pid::from_raw(raw_group)))
            .expect("registered group leader is alive")
            .as_raw(),
        raw_group,
        "never signal the test runner process group"
    );

    let mut guardian_command = Command::new("/bin/sh");
    guardian_command
        .args(["-c", "read ignored || exit 0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut guardian = guardian_command.spawn().expect("successful guardian stand-in");
    let writer = guardian.stdin.take().expect("sole liveness writer");
    fcntl(&writer, FcntlArg::F_SETFD(FdFlag::empty()))
        .expect("force registered-owner rejection");
    let error = HostGuardian::from_registered_parts(guardian, writer, None, group_pid)
        .expect_err("inheritable writer must be rejected");
    assert!(
        error.to_string().contains("require FD_CLOEXEC"),
        "unexpected rejected-registration error: {error}"
    );
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut observed = group.try_wait().expect("observe registered Bun group");
    while observed.is_none() && Instant::now() < deadline {
        thread::yield_now();
        observed = group.try_wait().expect("wait for group retirement");
    }
    let retired = observed.is_some();
    if !retired {
        terminate_registered_group(group_pid).expect("test-owned red-phase group kill");
        group.wait().expect("test-owned red-phase group reap");
    }
    assert!(retired, "rejected Guardian status zero stranded its enrolled Bun group");
}
