// Halt the registration writer after the child exists, but before its group
// record can reach the host. EOF must still revoke resources and reap the
// isolated group: registration is not a precondition for Guardian cleanup.
struct PausedGroupRegistration {
    entered: mpsc::Sender<u32>,
    release: mpsc::Receiver<()>,
}

impl io::Write for PausedGroupRegistration {
    fn write(&mut self, record: &[u8]) -> io::Result<usize> {
        if record.len() != super::REGISTRATION_LEN || record[..4] != super::REGISTRATION_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected group registration record",
            ));
        }
        let pid = u32::from_be_bytes(record[4..].try_into().map_err(io::Error::other)?);
        self.entered.send(pid).map_err(io::Error::other)?;
        self.release.recv().map_err(io::Error::other)?;
        Ok(record.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn host_eof_before_group_registration_reaps_spawned_child() {
    let (reader, writer) = liveness_pipe();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let revoked = Arc::new(AtomicBool::new(false));
    let revoke_for_guardian = Arc::clone(&revoked);
    let worker = thread::spawn(move || {
        let outcome = run_with_registration(
            long_running_command(),
            reader,
            PausedGroupRegistration {
                entered: entered_tx,
                release: release_rx,
            },
            |_| Ok(()),
            move || {
                revoke_for_guardian.store(true, Ordering::SeqCst);
                Ok(())
            },
        );
        done_tx.send(outcome).expect("send Guardian result");
    });

    let pid = entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("child spawned and Guardian blocked before registration write");
    let raw_pid = i32::try_from(pid).expect("group id fits signed PID");
    assert_eq!(
        nix::unistd::getpgid(Some(Pid::from_raw(raw_pid)))
            .expect("spawned group leader exists")
            .as_raw(),
        raw_pid,
        "child must be an isolated process-group leader before registration"
    );
    assert!(
        matches!(done_rx.try_recv(), Err(TryRecvError::Empty)),
        "Guardian must remain blocked while the host is still live"
    );

    // Simulates host SIGKILL's sole liveness effect: all host-owned writer
    // descriptors close before the Guardian reports the new group to its host.
    drop(writer);
    release_tx.send(()).expect("release held registration");
    let report = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("Guardian must observe pre-registration host EOF")
        .expect("Guardian must clean up a group despite pre-registration EOF");
    worker.join().expect("Guardian worker joins");
    assert_eq!(report.leader_pid(), pid);
    assert_eq!(report.leader_status().signal(), Some(9));
    assert!(revoked.load(Ordering::SeqCst), "registered resources revoked");
    assert_gone(Some(pid));
}
