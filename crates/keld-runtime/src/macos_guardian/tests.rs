use std::fs::File;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nix::sys::signal::{Signal, kill};
use nix::unistd::pipe;

use super::*;

mod generation_control_wire;

#[test]
fn guarded_primary_rejects_non_supervised_bootstrap_before_generation() {
    let registration = BootstrapListener::bind().expect("guarded registration");
    let app_link = registration.app_link();
    let peer = std::thread::spawn(move || {
        let (endpoint, token) = parse_app_link(&app_link).expect("parse registration link");
        let mut stream =
            std::os::unix::net::UnixStream::connect(endpoint).expect("connect registration link");
        handshake_client(&mut stream, &token).expect("authenticate registration link");
    });
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "read ignored || exit 0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn().expect("spawn guardian stand-in");
    let guardian_pid = child.id();
    let writer = child.stdin.take().expect("guardian liveness writer");
    require_close_on_exec(&writer).expect("test liveness CLOEXEC");
    let bootstrap = GuardianBootstrap {
        child: Some(child),
        liveness_writer: Some(writer),
        quit_ack_reader: None,
        registration,
    };
    let error = bootstrap
        .register_guarded_primary_until(Instant::now() + Duration::from_secs(5))
        .expect_err("plain bootstrap must not become guarded primary");
    peer.join().expect("registration peer joins");
    assert!(
        error.to_string().contains("requires the supervised"),
        "{error}"
    );
    let guardian_pid = i32::try_from(guardian_pid).expect("guardian pid fits i32");
    assert_eq!(kill(Pid::from_raw(guardian_pid), None), Err(Errno::ESRCH));
}

#[test]
fn recovery_release_requires_retired_clear_and_initial_arm_is_not_release() {
    let mut recovery = RecoveryState::new();
    assert!(recovery.permits(1));
    recovery.retire(1);
    recovery.arm();
    assert!(recovery.initial_ready);
    assert!(
        !recovery.permits(2),
        "late initial Ready released retirement"
    );
    recovery.arm();
    assert_eq!(recovery.release_attempt, Some(2));
    assert!(!recovery.permits(2), "None before Cleared released G2");
    recovery.cleared(1).expect("record completed G1 Clear");
    assert!(recovery.permits(2));
    assert!(
        !recovery.permits(3),
        "G1 release authorized a wrong attempt"
    );
    recovery.retire(2);
    assert!(!recovery.permits(3), "revocation retained native release");
    recovery.cleared(2).expect("record completed G2 Clear");
    assert!(!recovery.permits(3), "new Clear reused old release");
    recovery.arm();
    assert!(recovery.permits(3));
    recovery.deny();
    recovery.arm();
    assert!(!recovery.permits(3));
    assert!(recovery.release_attempt.is_none());
}

#[test]
fn unresolved_initial_ready_retains_its_deadline_after_native_wait_is_excluded() {
    let mut recovery = RecoveryState::new();
    let expired = Some(
        Instant::now()
            .checked_sub(GUARDIAN_SHUTDOWN_DEADLINE)
            .expect("test clock can represent one expired initial decision budget"),
    );
    let error = check_initial_recovery_decision(&recovery, expired)
        .expect_err("unresolved initial Ready remains bounded");
    assert_eq!(runtime_io_kind(&error), Some(io::ErrorKind::TimedOut));
    recovery.arm();
    check_initial_recovery_decision(&recovery, expired)
        .expect("decided eligibility does not time out legal native waiting");
    assert!(
        !recovery.permits(2),
        "eligibility alone released native waiting"
    );
}

#[test]
fn unclaimed_control_eof_explicitly_revokes_exact_lease_and_requires_attribution() {
    for acknowledged in [false, true] {
        let (events_tx, events_rx) = mpsc::channel();
        let mut owner = RoleGenerationOwner::new(
            RoleOwner::Primary,
            DEFAULT_ADMISSION_TIMEOUT,
            events_tx,
            None,
            None,
        );
        let provisioned = owner.provision(7).expect("own one unclaimed attempt");
        let (endpoint, _) = parse_app_link(&provisioned.app_link).expect("actual locator");
        let mut state = HostGenerationState {
            lease: Some(provisioned.lease),
            current_attempt: Some(7),
            ..HostGenerationState::default()
        };
        let recovery = Mutex::new(RecoveryState::new());
        if acknowledged {
            let mut recovery = lock_recovery(&recovery);
            recovery.deny();
            recovery.shutdown_acknowledged = true;
        }
        let result = finish_generation_control_eof(
            lifecycle_error("test EOF", io::Error::from(io::ErrorKind::UnexpectedEof)),
            0,
            &mut state,
            &Mutex::new(None),
            &recovery,
        );
        let events: Vec<_> = events_rx.try_iter().collect();
        let endpoint_closed = std::os::unix::net::UnixStream::connect(endpoint).is_err();
        assert!(state.lease.is_none() && state.current_attempt.is_none());
        assert!(
            endpoint_closed,
            "unclaimed listener survived explicit revoke"
        );
        assert!(
            events.iter().any(|event| matches!(
                event,
                RoleEvent::Revoked {
                    attempt: 7,
                    cause: crate::role::RoleRevocationCause::Shutdown,
                    ..
                }
            )),
            "exact owner emitted no Shutdown revocation: {events:?}"
        );
        assert_eq!(
            result.is_ok(),
            acknowledged,
            "denial/EOF fabricated attribution"
        );
    }
}

#[test]
fn attributed_control_eof_keeps_partial_and_registered_failures_fatal() {
    for (partial, registered) in [
        (1, None),
        (
            0,
            Some(RegisteredPrimaryGeneration {
                attempt: 2,
                group_pid: 42,
            }),
        ),
    ] {
        let recovery = Mutex::new(RecoveryState::new());
        {
            let mut recovery = lock_recovery(&recovery);
            recovery.deny();
            recovery.shutdown_acknowledged = true;
        }
        let mut state = HostGenerationState::default();
        let result = finish_generation_control_eof(
            lifecycle_error("test EOF", io::Error::from(io::ErrorKind::UnexpectedEof)),
            partial,
            &mut state,
            &Mutex::new(registered),
            &recovery,
        );
        assert_eq!(
            runtime_io_kind(&result.expect_err("partial/active EOF stays fatal")),
            Some(io::ErrorKind::UnexpectedEof)
        );
    }
}

#[test]
fn denied_recovery_cannot_be_rearmed_by_late_ready() {
    let mut child = Command::new("/bin/cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("owned liveness peer");
    let liveness_writer = child.stdin.take().expect("liveness writer");
    let quit_ack_reader = child.stdout.take().expect("ack reader");
    let (_updates_tx, updates_rx) = mpsc::channel();
    let mut primary = GuardedPrimary {
        child,
        liveness_writer: Some(liveness_writer),
        quit_ack_reader,
        current_generation: Arc::new(Mutex::new(None)),
        recovery_decision: Arc::new(Mutex::new(RecoveryState::new())),
        updates_rx,
        worker: None,
        shutdown_attributed: false,
    };
    primary.deny_recovery();
    primary.arm_recovery();
    primary.arm_recovery();
    let finally_denied = lock_recovery(&primary.recovery_decision).denied;
    primary.liveness_writer.take();
    primary.child.wait().expect("wait owned liveness peer");
    assert!(finally_denied, "late Ready reopened denial");
}

#[test]
fn generation_host_rejects_out_of_order_revoke_before_prepare() {
    let (host, mut guardian) = std::os::unix::net::UnixStream::pair().expect("KGC1 pair");
    let (updates_tx, _updates_rx) = mpsc::channel();
    let current = Mutex::new(None);
    write_generation_control(
        &mut guardian,
        &GenerationControlRecord::new(CONTROL_REVOKE, 1).with_cause(RevocationCause::ChildExited),
    )
    .expect("write out-of-order revoke");
    let error = run_generation_host(
        host,
        &updates_tx,
        &current,
        &Mutex::new(RecoveryState::new()),
        None,
    )
    .expect_err("revoke before prepare must fail");
    assert!(
        error.to_string().contains("invalid revoke transition"),
        "{error}"
    );
}

#[test]
fn generation_host_revokes_and_clears_before_preparing_successor() {
    use std::os::unix::net::UnixStream;

    let (host, mut guardian) = UnixStream::pair().expect("KGC1 pair");
    guardian
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("guardian control deadline");
    let (updates_tx, updates_rx) = mpsc::channel();
    let current = Arc::new(Mutex::new(None));
    let recovery_armed = Arc::new(Mutex::new(RecoveryState::new()));
    lock_recovery(&recovery_armed).arm();
    let host_current = Arc::clone(&current);
    let host_recovery = Arc::clone(&recovery_armed);
    let host_thread = std::thread::spawn(move || {
        run_generation_host(host, &updates_tx, &host_current, &host_recovery, None)
    });

    let prepared_one = guardian_exchange(
        &mut guardian,
        &GenerationControlRecord::new(CONTROL_PREPARE, 1),
        CONTROL_PREPARED,
    );
    let app_link = String::from_utf8(prepared_one.payload).expect("g1 app link UTF-8");
    let mut child_command = long_running_command();
    child_command.process_group(0);
    let mut child = child_command.spawn().expect("g1 group leader");
    let child_pid = child.id();
    guardian_exchange(
        &mut guardian,
        &GenerationControlRecord::new(CONTROL_SPAWNED, 1).with_pid(child_pid),
        CONTROL_REGISTERED,
    );
    let (endpoint, token) = parse_app_link(&app_link).expect("parse g1 app link");
    let mut app = UnixStream::connect(endpoint).expect("connect g1 app link");
    handshake_client(&mut app, &token).expect("authenticate g1 app link");
    let bound = loop {
        let update = updates_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("g1 bound update");
        if let GuardedPrimaryUpdate::Bound(bound) = update {
            break bound;
        }
    };
    assert_eq!(bound.attempt(), 1);

    guardian_exchange(
        &mut guardian,
        &GenerationControlRecord::new(CONTROL_REVOKE, 1).with_cause(RevocationCause::ChildExited),
        CONTROL_REVOKED,
    );
    terminate_registered_group(child_pid).expect("signal g1 group");
    let _ = child.wait().expect("wait g1 group leader");
    guardian_exchange(
        &mut guardian,
        &GenerationControlRecord::new(CONTROL_CLEAR, 1).with_pid(child_pid),
        CONTROL_CLEARED,
    );
    lock_recovery(&recovery_armed).arm();
    guardian_exchange(
        &mut guardian,
        &GenerationControlRecord::new(CONTROL_PREPARE, 2),
        CONTROL_PREPARED,
    );

    guardian_exchange(
        &mut guardian,
        &GenerationControlRecord::new(CONTROL_REVOKE, 2)
            .with_cause(RevocationCause::AdmissionFailed),
        CONTROL_REVOKED,
    );
    guardian_exchange(
        &mut guardian,
        &GenerationControlRecord::new(CONTROL_CLEAR, 2),
        CONTROL_CLEARED,
    );
    {
        let mut recovery = lock_recovery(&recovery_armed);
        recovery.deny();
        recovery.shutdown_acknowledged = true;
    }
    drop(guardian);
    host_thread
        .join()
        .expect("generation host joins")
        .expect("clean generation host EOF");

    let events: Vec<RoleEvent> = updates_rx
        .try_iter()
        .filter_map(|update| match update {
            GuardedPrimaryUpdate::Role(event) => Some(event),
            GuardedPrimaryUpdate::Bound(_) => None,
        })
        .collect();
    let revoked = events
        .iter()
        .position(|event| matches!(event, RoleEvent::Revoked { attempt: 1, .. }))
        .expect("g1 Revoked event");
    let provisioned = events
        .iter()
        .position(|event| matches!(event, RoleEvent::Provisioned { attempt: 2, .. }))
        .expect("g2 Provisioned event");
    assert!(revoked < provisioned, "g2 provisioned before g1 revocation");
}

#[test]
fn unmarked_successor_preparation_errors_preserve_failed_outcome() {
    use crate::SupervisorEvent;
    use PreparationAttribution::{Accepted, Requested, Unattributed};
    use io::ErrorKind::{Interrupted, InvalidData};

    const DIAGNOSTIC_PHASE: &str = "macOS guardian generation control transition";
    // Ordinary I/O kinds and public diagnostic phases do not mark an
    // intentional runtime cancellation, even after a stop fact is set.
    for attribution in [Accepted, Requested, Unattributed] {
        for (phase, kind) in [
            (DIAGNOSTIC_PHASE, Interrupted),
            (DIAGNOSTIC_PHASE, InvalidData),
            ("test unrelated preparation I/O", Interrupted),
            ("test unrelated preparation I/O", InvalidData),
        ] {
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let mut command = Command::new("/bin/sh");
            command.args([
                "-c",
                "printf KEL143_UNMARKED_G1_STDOUT; \
                 printf KEL143_UNMARKED_G1_STDERR >&2; exit 1",
            ]);
            let supervisor = Supervisor::start_prepared(
                RestartPolicy::default(),
                GatedUnmarkedFailurePreparer {
                    initial: Some(command),
                    entered_tx,
                    release_rx,
                    phase,
                    kind,
                    owned: false,
                },
            )
            .expect("initial real child must spawn");
            // Only attempt 2 reaches this fence, after actual G1 retirement.
            let entered = entered_rx.recv_timeout(Duration::from_secs(5));
            match attribution {
                Accepted => supervisor.accept_shutdown(),
                Requested => supervisor.shutdown(),
                Unattributed => {}
            }
            if entered.is_err() {
                supervisor.shutdown();
            }
            // Release before asserting so Drop cannot wait on our own gate.
            let released = release_tx.send(());
            drop(release_tx);
            entered.expect("successor preparation must reach the existing trait fence");
            released.expect("release the controlled preparation error");

            let deadline = Instant::now() + Duration::from_secs(5);
            let terminal = loop {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .expect("successor preparation terminal event deadline");
                match supervisor.recv_event(remaining) {
                    Some(SupervisorEvent::Started { attempt: 2, .. }) => {
                        panic!("failed successor preparation spawned G2");
                    }
                    Some(event @ (SupervisorEvent::Stopped | SupervisorEvent::Failed { .. })) => {
                        break event;
                    }
                    Some(_) => {}
                    None => panic!("no terminal successor event for {attribution:?}/{kind:?}"),
                }
            };
            let outcome = supervisor.wait_for_outcome();
            assert!(
                supervisor.current_pid().is_none(),
                "G2 must not remain live"
            );
            let ledger = supervisor.crash_ledger();
            assert_eq!(ledger.self_termination_count, 1);
            assert!(
                ledger
                    .last_self_termination
                    .is_some_and(|exit| exit.exit_code == Some(1)),
                "shutdown must preserve the already-observed G1 exit"
            );
            let output = supervisor.output();
            assert!(output.stdout.contains("KEL143_UNMARKED_G1_STDOUT"));
            assert!(output.stderr.contains("KEL143_UNMARKED_G1_STDERR"));
            assert!(
                matches!(terminal, SupervisorEvent::Failed { attempt: 2 }),
                "unmarked error became a stop: {attribution:?}/{phase}/{kind:?}: {terminal:?}"
            );
            match outcome {
                SupervisorOutcome::Failed(RuntimeError::Lifecycle {
                    phase: actual,
                    source,
                }) => {
                    assert_eq!(actual, phase);
                    assert_eq!(source.kind(), kind);
                    assert_eq!(
                        source.to_string(),
                        "controlled successor preparation failure"
                    );
                }
                other => panic!("unmarked preparation failure was hidden: {other:?}"),
            }
        }
    }
}

#[test]
fn owned_successor_interruption_requires_supervisor_stop_and_exact_attempt() {
    use crate::SupervisorEvent;
    for attribution in [
        PreparationAttribution::Accepted,
        PreparationAttribution::Requested,
        PreparationAttribution::Unattributed,
    ] {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 1"]);
        let supervisor = Supervisor::start_prepared(
            RestartPolicy::default(),
            GatedUnmarkedFailurePreparer {
                initial: Some(command),
                entered_tx,
                release_rx,
                phase: "unused marked phase",
                kind: io::ErrorKind::Interrupted,
                owned: true,
            },
        )
        .expect("initial real child");
        let entered = entered_rx.recv_timeout(Duration::from_secs(5));
        match attribution {
            PreparationAttribution::Accepted => supervisor.accept_shutdown(),
            PreparationAttribution::Requested => supervisor.shutdown(),
            PreparationAttribution::Unattributed => {}
        }
        if entered.is_err() {
            supervisor.shutdown();
        }
        let released = release_tx.send(());
        drop(release_tx);
        entered.expect("actual successor preparation fence");
        released.expect("release owned interruption");
        let deadline = Instant::now() + Duration::from_secs(5);
        let terminal = loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .expect("terminal event bound");
            match supervisor.recv_event(remaining) {
                Some(event @ (SupervisorEvent::Stopped | SupervisorEvent::Failed { .. })) => {
                    break event;
                }
                Some(SupervisorEvent::Started { attempt: 2, .. }) => {
                    panic!("cancelled G2 spawned")
                }
                Some(_) => {}
                None => panic!("missing owned preparation terminal"),
            }
        };
        let outcome = supervisor.wait_for_outcome();
        assert!(supervisor.current_pid().is_none());
        assert_eq!(supervisor.crash_ledger().self_termination_count, 1);
        match attribution {
            PreparationAttribution::Accepted | PreparationAttribution::Requested => {
                assert!(matches!(terminal, SupervisorEvent::Stopped));
                assert!(matches!(outcome, SupervisorOutcome::Stopped));
            }
            PreparationAttribution::Unattributed => {
                assert!(matches!(terminal, SupervisorEvent::Failed { attempt: 2 }));
                assert!(matches!(outcome, SupervisorOutcome::Failed(_)));
            }
        }
    }
    let marker = interrupted_successor_preparation(2);
    assert!(is_owned_preparation_interruption(&marker, 2));
    assert!(!is_owned_preparation_interruption(&marker, 1));
    assert!(!is_owned_preparation_interruption(&marker, 3));
}

#[derive(Debug, Clone, Copy)]
enum PreparationAttribution {
    Accepted,
    Requested,
    Unattributed,
}

struct GatedUnmarkedFailurePreparer {
    initial: Option<Command>,
    entered_tx: mpsc::Sender<()>,
    release_rx: mpsc::Receiver<()>,
    phase: &'static str,
    kind: io::ErrorKind,
    owned: bool,
}

impl ChildPreparer for GatedUnmarkedFailurePreparer {
    type Lease = crate::NoLease;

    fn prepare(&mut self, attempt: u32) -> Result<PreparedChild<Self::Lease>, RuntimeError> {
        if attempt == 1 {
            return Ok(PreparedChild {
                command: self.initial.take().expect("one initial command").into(),
                lease: crate::NoLease,
            });
        }
        assert_eq!(attempt, 2, "the failed preparation must not be retried");
        self.entered_tx.send(()).expect("observe successor prepare");
        self.release_rx
            .recv()
            .expect("controlled preparation release");
        if self.owned {
            return Err(interrupted_successor_preparation(attempt));
        }
        Err(RuntimeError::Lifecycle {
            phase: self.phase,
            source: io::Error::new(self.kind, "controlled successor preparation failure"),
        })
    }
}

fn guardian_exchange(
    guardian: &mut std::os::unix::net::UnixStream,
    request: &GenerationControlRecord,
    expected: u8,
) -> GenerationControlRecord {
    write_generation_control(guardian, request).expect("write guardian control request");
    let response = read_generation_control(guardian).expect("read guardian control response");
    assert_eq!(response.kind, expected);
    assert_eq!(response.attempt, request.attempt);
    response
}

#[test]
fn missing_private_registration_bootstrap_creates_no_child() {
    let temp = tempfile::tempdir().expect("temporary marker directory");
    let marker = temp.path().join("spawned");
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "printf spawned > \"$1\"", "keld-guardian-test"])
        .arg(&marker);
    let (reader, _writer) = liveness_pipe();
    let revoked = Arc::new(AtomicBool::new(false));
    let revoked_in_callback = Arc::clone(&revoked);
    let error = run(command, reader, move || {
        revoked_in_callback.store(true, Ordering::SeqCst);
        Ok(())
    })
    .expect_err("missing authenticated registration must fail before child spawn");
    assert!(error.to_string().contains(REGISTRATION_ENV), "{error}");
    assert!(!marker.exists(), "invalid bootstrap must create no child");
    assert!(revoked.load(Ordering::SeqCst));
}

#[test]
fn empty_program_is_rejected_before_spawn() {
    let (reader, _writer) = liveness_pipe();
    let error = run_with_registration(Command::new(""), reader, io::sink(), |_| Ok(()), || Ok(()))
        .expect_err("empty guardian command must fail");
    let rendered = error.to_string();
    assert!(rendered.contains("KELD-RUNTIME-003"), "{rendered}");
    assert!(rendered.contains("child program is empty"), "{rendered}");
}

#[test]
fn spawn_failure_revokes_prepared_resources() {
    let (reader, _writer) = liveness_pipe();
    let revoked = Arc::new(AtomicBool::new(false));
    let revoked_in_callback = Arc::clone(&revoked);
    let error = run_with_registration(
        Command::new("/definitely/missing/keld-bun"),
        reader,
        io::sink(),
        |_| Ok(()),
        move || {
            revoked_in_callback.store(true, Ordering::SeqCst);
            Ok(())
        },
    )
    .expect_err("spawn failure must fail closed");
    assert!(matches!(error, RuntimeError::Spawn(_)), "{error}");
    assert!(
        revoked.load(Ordering::SeqCst),
        "spawn failure must revoke every prepared resource"
    );
}

#[test]
fn private_registration_authority_is_not_inherited_by_the_child() {
    let (reader, writer) = liveness_pipe();
    let mut command = Command::new("/bin/sh");
    command
            .args([
                "-c",
                "if [ -z \"${KELD_INTERNAL_MACOS_GUARDIAN_REGISTRATION+x}\" ]; then exec /usr/bin/tail -f /dev/null; else exit 77; fi",
            ])
            .env(REGISTRATION_ENV, "must-not-reach-child");
    let report = run_with_registration(
        command,
        reader,
        io::sink(),
        move |_| {
            drop(writer);
            Ok(())
        },
        || Ok(()),
    )
    .expect("guardian cleanup with stripped private authority");
    assert_eq!(
        report.leader_status().signal(),
        Some(9),
        "a child that inherited the private registration value exits 77"
    );
}

#[test]
fn supervised_guardian_uses_one_supervisor_child_and_clean_host_shutdown() {
    let (reader, writer) = liveness_pipe();
    let registered = Arc::new(Mutex::new(None));
    let registered_in_callback = Arc::clone(&registered);
    let revoked = Arc::new(AtomicBool::new(false));
    let revoked_in_callback = Arc::clone(&revoked);
    let report = run_supervised_with_registration(
        reader,
        io::sink(),
        io::sink(),
        || Ok(long_running_command()),
        move |pid| {
            *registered_in_callback.lock().expect("pid lock") = Some(pid);
            drop(writer);
            Ok(())
        },
        move || {
            revoked_in_callback.store(true, Ordering::SeqCst);
            Ok(())
        },
    )
    .expect("host-driven supervised guardian cleanup");
    assert_eq!(report.0, registered.lock().expect("pid lock").expect("pid"));
    assert_eq!(report.1.self_termination_count, 0);
    assert!(revoked.load(Ordering::SeqCst));
    assert_gone(*registered.lock().expect("pid lock"));
}

#[test]
fn supervised_status_zero_is_retained_as_typed_self_termination() {
    let (reader, writer) = liveness_pipe();
    let revoked = Arc::new(AtomicBool::new(false));
    let revoked_in_callback = Arc::clone(&revoked);
    let error = run_supervised_with_registration(
        reader,
        io::sink(),
        io::sink(),
        || {
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", "exit 0"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            Ok(command)
        },
        move |_| {
            drop(writer);
            Ok(())
        },
        move || {
            revoked_in_callback.store(true, Ordering::SeqCst);
            Ok(())
        },
    )
    .expect_err("status-zero self-termination must not become host success");
    assert!(error.to_string().contains("KELD-RUNTIME-012"), "{error}");
    assert!(revoked.load(Ordering::SeqCst));
}

#[test]
fn supervised_command_preparation_failure_revokes_before_child() {
    let (reader, _writer) = liveness_pipe();
    let revoked = Arc::new(AtomicBool::new(false));
    let revoked_in_callback = Arc::clone(&revoked);
    let error = run_supervised_with_registration(
        reader,
        io::sink(),
        io::sink(),
        || {
            Err(lifecycle_error(
                "test supervised command preparation",
                io::Error::other("intentional preparation failure"),
            ))
        },
        |_| panic!("preparation failure must not spawn a child"),
        move || {
            revoked_in_callback.store(true, Ordering::SeqCst);
            Ok(())
        },
    )
    .expect_err("command preparation failure must fail closed");
    assert!(
        error
            .to_string()
            .contains("intentional preparation failure")
    );
    assert!(revoked.load(Ordering::SeqCst));
}

#[test]
fn dropping_unhanded_supervised_preparer_revokes_once() {
    let revoked = Arc::new(AtomicBool::new(false));
    let revoked_in_callback = Arc::clone(&revoked);
    let (pid_tx, _pid_rx) = mpsc::sync_channel(1);
    let preparer = SupervisedGuardianPreparer {
        command_factory: Some(|| Ok::<Command, RuntimeError>(Command::new("/usr/bin/true"))),
        registration: Some(io::sink()),
        child_spawned: Some(|_: u32| Ok::<(), io::Error>(())),
        revoke_registered_resources: Some(move || {
            assert!(
                !revoked_in_callback.swap(true, Ordering::SeqCst),
                "unhanded resources revoked more than once"
            );
            Ok(())
        }),
        pid_tx,
    };

    drop(preparer);
    assert!(revoked.load(Ordering::SeqCst));
}

#[test]
fn supervised_self_termination_returns_while_host_writer_is_still_live() {
    let (reader, writer) = liveness_pipe();
    let (pid_tx, pid_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let deadline = Instant::now() + Duration::from_secs(5);
    let worker = std::thread::spawn(move || {
        let result = run_supervised_with_registration(
            reader,
            io::sink(),
            io::sink(),
            || {
                let mut command = Command::new("/bin/sh");
                command.args(["-c", "kill -STOP $$; exit 0"]);
                Ok(command)
            },
            move |pid| pid_tx.send(pid).map_err(io::Error::other),
            || Ok(()),
        );
        done_tx.send(result).expect("report guardian result");
    });
    // Enrollment must precede the exit under test. Confirm the shell has
    // actually stopped so an early SIGCONT cannot race its SIGSTOP.
    let pid = pid_rx
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .expect("self-terminating child registered");
    await_stopped_child(pid, deadline);
    kill(
        Pid::from_raw(i32::try_from(pid).expect("pid fits i32")),
        Signal::SIGCONT,
    )
    .expect("let registered child exit zero");
    let result = done_rx.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    // The result must arrive with the writer live; close it before asserting
    // so a failed observation still lets the guardian clean up its child.
    drop(writer);
    worker.join().expect("guardian worker joins");
    let error = result
        .expect("self-termination must wake the guardian while host is live")
        .expect_err("unrequested status-zero exit is fatal");
    assert!(error.to_string().contains("KELD-RUNTIME-012"), "{error}");
}

#[test]
fn supervised_accepted_quit_does_not_record_status_zero_as_unrequested() {
    let (reader, mut writer) = liveness_pipe();
    let (pid_tx, pid_rx) = mpsc::channel();
    let (ack_tx, ack_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = run_supervised_with_registration(
            reader,
            io::sink(),
            AckSender(ack_tx),
            || {
                let mut command = Command::new("/bin/sh");
                command.args(["-c", "kill -STOP $$; exit 0"]);
                Ok(command)
            },
            move |pid| pid_tx.send(pid).map_err(io::Error::other),
            || Ok(()),
        );
        done_tx.send(result).expect("report guardian result");
    });
    let pid = pid_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("stopped child registered");

    let stopped_deadline = Instant::now() + Duration::from_secs(5);
    await_stopped_child(pid, stopped_deadline);

    writer.write_all(b"Q").expect("accept Quit before reply");
    assert_eq!(
        ack_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("guardian applied accepted-Quit attribution"),
        SUPERVISED_QUIT_ACK
    );
    kill(
        Pid::from_raw(i32::try_from(pid).expect("pid fits i32")),
        Signal::SIGCONT,
    )
    .expect("let accepted-Quit child exit zero");
    let deadline = Instant::now() + Duration::from_secs(5);
    while kill(
        Pid::from_raw(i32::try_from(pid).expect("pid fits i32")),
        None,
    )
    .is_ok()
    {
        assert!(Instant::now() < deadline, "accepted-Quit child stayed live");
        std::thread::yield_now();
    }
    drop(writer);

    let report = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("guardian finishes after host EOF")
        .expect("accepted Quit is a clean supervised shutdown");
    assert_eq!(report.1.self_termination_count, 0);
    worker.join().expect("guardian worker joins");
}

fn await_stopped_child(pid: u32, deadline: Instant) {
    loop {
        let output = Command::new("/bin/ps")
            .args(["-o", "state=", "-p", &pid.to_string()])
            .output()
            .expect("inspect stopped child state");
        if String::from_utf8(output.stdout)
            .expect("process state is UTF-8")
            .trim()
            .starts_with('T')
        {
            break;
        }
        assert!(Instant::now() < deadline, "child never stopped");
        std::thread::yield_now();
    }
}

struct AckSender(mpsc::Sender<[u8; SUPERVISED_QUIT_ACK.len()]>);

impl io::Write for AckSender {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let ack: [u8; SUPERVISED_QUIT_ACK.len()] = bytes.try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "unexpected acknowledgment size")
        })?;
        self.0.send(ack).map_err(io::Error::other)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn registration_failure_still_reaps_the_group() {
    let (reader, writer) = liveness_pipe();
    let pid = Arc::new(Mutex::new(None));
    let pid_for_registration = Arc::clone(&pid);
    let error = run_with_registration(
        long_running_command(),
        reader,
        io::sink(),
        move |child_pid| {
            drop(writer);
            *pid_for_registration.lock().expect("pid lock") = Some(child_pid);
            Err(io::Error::other("registration rejected"))
        },
        || Ok(()),
    )
    .expect_err("registration failure must fail guardian startup");
    assert!(
        error.to_string().contains("registration rejected"),
        "{error}"
    );
    assert_gone(*pid.lock().expect("pid lock"));
}

#[test]
fn pre_child_liveness_bytes_fail_and_revoke_prepared_resources() {
    let (reader, mut writer) = liveness_pipe();
    std::io::Write::write_all(&mut writer, &[1_u8]).expect("write invalid liveness byte");
    let spawned = Arc::new(AtomicBool::new(false));
    let spawned_in_callback = Arc::clone(&spawned);
    let revoked = Arc::new(AtomicBool::new(false));
    let revoked_in_callback = Arc::clone(&revoked);
    let error = run_with_registration(
        long_running_command(),
        reader,
        io::sink(),
        move |_| {
            spawned_in_callback.store(true, Ordering::SeqCst);
            Ok(())
        },
        move || {
            revoked_in_callback.store(true, Ordering::SeqCst);
            Ok(())
        },
    )
    .expect_err("liveness bytes must fail closed");
    assert!(
        error.to_string().contains("carried data instead of EOF"),
        "{error}"
    );
    assert!(!spawned.load(Ordering::SeqCst));
    assert!(revoked.load(Ordering::SeqCst));
}

#[test]
fn post_registration_liveness_bytes_still_revoke_and_reap() {
    let (reader, mut writer) = liveness_pipe();
    let pid = Arc::new(Mutex::new(None));
    let pid_for_registration = Arc::clone(&pid);
    let revoked = Arc::new(AtomicBool::new(false));
    let revoked_in_callback = Arc::clone(&revoked);
    let error = run_with_registration(
        long_running_command(),
        reader,
        io::sink(),
        move |child_pid| {
            *pid_for_registration.lock().expect("pid lock") = Some(child_pid);
            std::io::Write::write_all(&mut writer, &[1_u8])?;
            Ok(())
        },
        move || {
            revoked_in_callback.store(true, Ordering::SeqCst);
            Ok(())
        },
    )
    .expect_err("post-registration liveness bytes must fail closed");
    assert!(
        error.to_string().contains("carried data instead of EOF"),
        "{error}"
    );
    assert!(
        revoked.load(Ordering::SeqCst),
        "registered resources must be revoked on every fatal liveness result"
    );
    assert_gone(*pid.lock().expect("pid lock"));
}

#[test]
fn liveness_without_a_writer_fails_before_spawn() {
    let (reader, writer) = liveness_pipe();
    drop(writer);
    let spawned = Arc::new(AtomicBool::new(false));
    let spawned_in_callback = Arc::clone(&spawned);
    let error = run_with_registration(
        long_running_command(),
        reader,
        io::sink(),
        move |_| {
            spawned_in_callback.store(true, Ordering::SeqCst);
            Ok(())
        },
        || Ok(()),
    )
    .expect_err("a forged bootstrap without a host writer must fail");
    assert!(error.to_string().contains("no live writer"), "{error}");
    assert!(!spawned.load(Ordering::SeqCst));
}

#[test]
fn non_pipe_liveness_fails_before_spawn() {
    let file = tempfile::tempfile().expect("temporary regular file");
    let spawned = Arc::new(AtomicBool::new(false));
    let spawned_in_callback = Arc::clone(&spawned);
    let error = run_with_registration(
        long_running_command(),
        file,
        io::sink(),
        move |_| {
            spawned_in_callback.store(true, Ordering::SeqCst);
            Ok(())
        },
        || Ok(()),
    )
    .expect_err("a forged regular-file bootstrap must fail");
    assert!(error.to_string().contains("is not a pipe"), "{error}");
    assert!(!spawned.load(Ordering::SeqCst));
}

#[test]
fn initially_nonblocking_liveness_is_normalized_to_wait_for_eof() {
    let (reader, writer) = liveness_pipe();
    let flags = fcntl(&reader, FcntlArg::F_GETFL).expect("read liveness flags");
    fcntl(
        &reader,
        FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK),
    )
    .expect("make liveness reader initially nonblocking");
    let (spawned_tx, spawned_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = run_with_registration(
            long_running_command(),
            reader,
            io::sink(),
            move |_| {
                spawned_tx.send(()).map_err(io::Error::other)?;
                Ok(())
            },
            || Ok(()),
        );
        done_tx.send(result).expect("report guardian result");
    });
    spawned_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("guardian child registered");
    assert!(
        matches!(done_rx.try_recv(), Err(TryRecvError::Empty)),
        "guardian must still own the child while a live writer exists"
    );

    drop(writer);
    let report = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("guardian finishes after EOF")
        .expect("guardian EOF cleanup succeeds");
    assert_eq!(report.leader_status().signal(), Some(9));
    worker.join().expect("guardian worker joins");
}

#[test]
fn revocation_failure_still_reaps_the_group() {
    let (reader, writer) = liveness_pipe();
    let pid = Arc::new(Mutex::new(None));
    let pid_for_registration = Arc::clone(&pid);
    let error = run_with_registration(
        long_running_command(),
        reader,
        io::sink(),
        move |child_pid| {
            *pid_for_registration.lock().expect("pid lock") = Some(child_pid);
            drop(writer);
            Ok(())
        },
        || Err(io::Error::other("revocation rejected")),
    )
    .expect_err("revocation failure must block cleanup success");
    assert!(error.to_string().contains("revocation rejected"), "{error}");
    assert_gone(*pid.lock().expect("pid lock"));
}

#[test]
fn registered_group_fallback_terminates_a_live_leader() {
    let mut command = long_running_command();
    command.process_group(0);
    let mut child = command.spawn().expect("spawn fallback group leader");
    let pid = child.id();
    terminate_registered_group(pid).expect("terminate registered group");
    let status = child.wait().expect("wait fallback group leader");
    assert_eq!(status.signal(), Some(9));
}

#[test]
fn guardian_death_is_typed_and_cannot_leave_the_group() {
    let mut group_command = long_running_command();
    group_command.process_group(0);
    let mut group = group_command.spawn().expect("spawn registered group");
    let group_pid = group.id();

    let mut guardian_command = Command::new("/usr/bin/tail");
    guardian_command
        .args(["-f", "/dev/null"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut guardian = guardian_command.spawn().expect("spawn guardian stand-in");
    let writer = guardian.stdin.take().expect("guardian liveness writer");
    let mut owner = HostGuardian::from_registered_parts(guardian, writer, None, group_pid)
        .expect("register host guardian owner");
    kill(
        Pid::from_raw(i32::try_from(owner.guardian_pid()).expect("guardian pid fits i32")),
        Signal::SIGKILL,
    )
    .expect("kill guardian while host remains live");

    let error = owner
        .wait_fatal()
        .expect_err("guardian death must be a fatal session event");
    assert!(matches!(
        error,
        RuntimeError::GuardianExited {
            group_pid: observed,
            cleanup_error: None,
            ..
        } if observed == group_pid
    ));
    let status = group.wait().expect("wait fail-safe-killed group");
    assert_eq!(status.signal(), Some(9));
    assert_eq!(owner.group_pid(), None);
}

#[test]
fn orderly_shutdown_closes_the_same_liveness_writer() {
    let mut group_command = long_running_command();
    group_command.process_group(0);
    let mut group = group_command.spawn().expect("spawn registered group");
    let group_pid = group.id();
    let mut guardian_command = Command::new("/bin/sh");
    guardian_command
        .args(["-c", "read ignored || exit 0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut guardian = guardian_command.spawn().expect("spawn guardian stand-in");
    let writer = guardian.stdin.take().expect("guardian liveness writer");
    let mut owner = HostGuardian::from_registered_parts(guardian, writer, None, group_pid)
        .expect("register host guardian owner");
    let status = owner.shutdown().expect("orderly EOF shutdown");
    assert!(status.success());
    assert_eq!(owner.group_pid(), None);
    let error = owner
        .shutdown()
        .expect_err("terminal owner must not reuse its numeric group id");
    assert!(error.to_string().contains("already terminal"), "{error}");
    terminate_registered_group(group_pid).expect("remove orderly-shutdown test group");
    let group_status = group.wait().expect("wait orderly-shutdown test group");
    assert_eq!(group_status.signal(), Some(9));
}

#[test]
fn orderly_shutdown_deadline_kills_guardian_and_registered_group() {
    let mut group_command = long_running_command();
    group_command.process_group(0);
    let mut group = group_command.spawn().expect("spawn timeout group");
    let group_pid = group.id();
    let mut guardian_command = long_running_command();
    guardian_command.stdin(Stdio::piped());
    let mut guardian = guardian_command.spawn().expect("spawn wedged guardian");
    let guardian_pid = guardian.id();
    let writer = guardian.stdin.take().expect("guardian liveness writer");
    let mut owner = HostGuardian::from_registered_parts(guardian, writer, None, group_pid)
        .expect("register timeout owner");

    let error = owner
        .shutdown_until(Instant::now())
        .expect_err("wedged guardian must hit the shutdown deadline");
    assert!(error.to_string().contains("shutdown deadline"), "{error}");
    assert_eq!(owner.group_pid(), None);
    assert_eq!(
        kill(
            Pid::from_raw(i32::try_from(guardian_pid).expect("guardian pid fits i32")),
            None,
        ),
        Err(Errno::ESRCH)
    );
    let group_status = group.wait().expect("wait timeout-killed group");
    assert_eq!(group_status.signal(), Some(9));
}

#[test]
fn rejected_host_registration_waits_the_guardian() {
    let mut guardian_command = Command::new("/bin/sh");
    guardian_command
        .args(["-c", "read ignored || exit 0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut guardian = guardian_command.spawn().expect("spawn guardian stand-in");
    let guardian_pid = guardian.id();
    let writer = guardian.stdin.take().expect("guardian liveness writer");
    let error = HostGuardian::from_registered_parts(guardian, writer, None, 0)
        .expect_err("zero group must reject registration");
    assert!(
        error.to_string().contains("process group is zero"),
        "{error}"
    );
    let guardian_pid = i32::try_from(guardian_pid).expect("guardian pid fits i32");
    assert_eq!(kill(Pid::from_raw(guardian_pid), None), Err(Errno::ESRCH));
}

#[test]
fn unrepresentable_group_is_rejected_and_guardian_is_waited() {
    let mut guardian_command = Command::new("/bin/sh");
    guardian_command
        .args(["-c", "read ignored || exit 0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut guardian = guardian_command.spawn().expect("spawn guardian stand-in");
    let guardian_pid = guardian.id();
    let writer = guardian.stdin.take().expect("guardian liveness writer");
    let error = HostGuardian::from_registered_parts(guardian, writer, None, u32::MAX)
        .expect_err("unrepresentable group must reject registration");
    assert!(error.to_string().contains("exceeds c_int"), "{error}");
    let guardian_pid = i32::try_from(guardian_pid).expect("guardian pid fits i32");
    assert_eq!(kill(Pid::from_raw(guardian_pid), None), Err(Errno::ESRCH));
}

#[test]
fn inheritable_writer_rejection_waits_the_guardian() {
    let mut group_command = long_running_command();
    group_command.process_group(0);
    let mut group = group_command.spawn().expect("spawn registered group");
    let group_pid = group.id();
    let mut guardian_command = Command::new("/bin/sh");
    guardian_command
        .args(["-c", "read ignored || exit 0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut guardian = guardian_command.spawn().expect("spawn guardian stand-in");
    let guardian_pid = guardian.id();
    let writer = guardian.stdin.take().expect("guardian liveness writer");
    fcntl(&writer, FcntlArg::F_SETFD(FdFlag::empty())).expect("make test writer inheritable");
    let error = HostGuardian::from_registered_parts(guardian, writer, None, group_pid)
        .expect_err("inheritable writer must reject registration");
    assert!(error.to_string().contains("require FD_CLOEXEC"), "{error}");
    let guardian_pid = i32::try_from(guardian_pid).expect("guardian pid fits i32");
    assert_eq!(kill(Pid::from_raw(guardian_pid), None), Err(Errno::ESRCH));
    terminate_registered_group(group_pid).expect("remove writer-rejection test group");
    let group_status = group.wait().expect("wait writer-rejection test group");
    assert_eq!(group_status.signal(), Some(9));
}

// Root supplies an already-built Host artifact. Guardian stdout remains
// exclusively the existing Q/S ACK pipe, never a libtest output stream.
struct PersistentPrimaryFixture {
    primary: GuardedPrimary,
    stderr: File,
    stage_root: std::path::PathBuf,
}

impl PersistentPrimaryFixture {
    fn start() -> Self {
        use std::os::unix::fs::MetadataExt as _;
        // Host's existing fixture owner stages the public application and
        // keeps its ordinary HTTP observer alive. Runtime never stages it.
        let receipt = std::env::var_os("KELD_KEL143_FIXTURE_RECEIPT")
            .expect("Root supplies the existing Host fixture artifact JSON");
        let bytes = std::fs::read(receipt).expect("owned staged fixture receipt");
        assert!(
            !bytes.is_empty() && bytes.len() <= 8192,
            "bounded fixture data"
        );
        let data: serde_json::Value = serde_json::from_slice(&bytes).expect("fixture JSON");
        let host = data["stagedHost"]
            .as_str()
            .expect("exact staged Host artifact");
        let stage = std::path::PathBuf::from(data["stageRoot"].as_str().expect("stage root"));
        let entry = data["entryRelative"]
            .as_str()
            .expect("existing public app entry");
        let retained = File::open(stage.join(entry)).expect("retain exact entry identity");
        let identity = retained.metadata().expect("retained entry metadata");
        let stderr = tempfile::tempfile().expect("owned guardian diagnostics");
        let mut command = Command::new(host);
        command
            .arg(SUPERVISED_GUARDIAN_ARG)
            .arg(&stage)
            .arg(entry)
            .arg(identity.dev().to_string())
            .arg(identity.ino().to_string())
            .env_remove("KELD_DEV_LEASE")
            .process_group(0)
            .stderr(Stdio::from(
                stderr.try_clone().expect("diagnostic capture clone"),
            ));
        let bootstrap =
            GuardianBootstrap::spawn_supervised(command).expect("existing supervised bootstrap");
        drop(retained);
        let primary = bootstrap
            .register_guarded_primary_until(Instant::now() + GUARDIAN_SHUTDOWN_DEADLINE)
            .expect("real authenticated guardian registration");
        Self {
            primary,
            stderr,
            stage_root: stage,
        }
    }

    fn ready(&mut self) -> u32 {
        let deadline = Instant::now() + GUARDIAN_SHUTDOWN_DEADLINE;
        let bound = loop {
            self.primary
                .poll_fatal()
                .expect("healthy real guardian before Bound");
            if let Some(GuardedPrimaryUpdate::Bound(bound)) =
                self.primary.recv_update(GENERATION_CONTROL_POLL)
            {
                break bound;
            }
            assert!(Instant::now() < deadline, "actual G1 Bound deadline");
        };
        assert_eq!(bound.attempt(), 1);
        let pid = self
            .primary
            .group_pid()
            .expect("actual registered G1 group");
        let mut app = bound.into_stream();
        let ready = keld_ipc::codec::encode(&keld_ipc::lifecycle::LifecycleEvent::Ready)
            .expect("canonical lifecycle Ready payload");
        self.primary.arm_recovery();
        keld_ipc::link::write_frame(
            &mut app,
            keld_ipc::FrameKind::Event,
            0,
            keld_ipc::lifecycle::LIFECYCLE_CHANNEL,
            keld_ipc::CorrelationId(0),
            &ready,
        )
        .expect("existing actual Ready event");
        // The host lease also retains its stream; this alias mints no
        // process authority and no independent child/wait owner.
        pid
    }

    fn await_cleared(&mut self) {
        let deadline = Instant::now() + GUARDIAN_SHUTDOWN_DEADLINE;
        let mut revoked = false;
        loop {
            self.primary
                .poll_fatal()
                .expect("healthy guardian during real retirement");
            if let Some(update) = self.primary.recv_update(GENERATION_CONTROL_POLL) {
                match update {
                    GuardedPrimaryUpdate::Role(RoleEvent::Revoked { attempt: 1, .. }) => {
                        revoked = true;
                    }
                    GuardedPrimaryUpdate::Bound(bound) => {
                        panic!("closed permit bound G{}", bound.attempt())
                    }
                    GuardedPrimaryUpdate::Role(_) => {}
                }
            }
            let recovery = lock_recovery(&self.primary.recovery_decision);
            if revoked && recovery.cleared_attempt == Some(1) && recovery.expected_attempt == 2 {
                assert!(recovery.release_attempt.is_none());
                break;
            }
            drop(recovery);
            assert!(
                Instant::now() < deadline,
                "actual G1 revoke/Cleared deadline"
            );
        }
        assert!(self.primary.group_pid().is_none());
    }

    fn assert_live_for_budget(&mut self, phase: &str) {
        let guardian = self.primary.guardian_pid();
        let began = Instant::now();
        let deadline = Instant::now() + GUARDIAN_SHUTDOWN_DEADLINE + GENERATION_CONTROL_POLL;
        let mut observations = 0_u64;
        // This measures survival while an owned release/EOF is withheld;
        // it is the contract under test, not a synchronization sleep.
        while Instant::now() < deadline {
            self.primary
                .poll_fatal()
                .expect("persistent guardian remains healthy before host EOF");
            assert!(
                self.primary
                    .child
                    .try_wait()
                    .expect("owned guardian status")
                    .is_none()
            );
            assert_eq!(self.primary.guardian_pid(), guardian);
            assert!(self.primary.group_pid().is_none());
            observations += 1;
            if let Some(GuardedPrimaryUpdate::Bound(bound)) =
                self.primary.recv_update(Duration::ZERO)
            {
                panic!("closed native permit bound G{}", bound.attempt());
            }
            std::thread::yield_now();
        }
        println!(
            "KEL143_RUNTIME_LIVE phase={phase} guardian={guardian} observations={observations} elapsed_ns={} group=None",
            began.elapsed().as_nanos()
        );
    }

    fn diagnostics(&mut self) -> String {
        use std::io::Seek as _;
        self.stderr.rewind().expect("rewind owned diagnostics");
        let mut text = String::new();
        (&self.stderr)
            .take(65_536)
            .read_to_string(&mut text)
            .expect("bounded diagnostics");
        text
    }
}

#[test]
#[ignore = "explicit real macOS staged Host guardian shutdown proof"]
fn guarded_primary_attributed_stop_keeps_guardian_live_until_host_eof() {
    let mut fixture = PersistentPrimaryFixture::start();
    let group = fixture.ready();
    println!(
        "KEL143_RUNTIME_OWNED host={} guardian={} g1_group={group}",
        std::process::id(),
        fixture.primary.guardian_pid()
    );
    fixture
        .primary
        .fail_current_generation(1)
        .expect("only actual registered live G1");
    fixture.await_cleared();
    fixture.assert_live_for_budget("runtime-permit-held");
    fixture
        .primary
        .accept_shutdown()
        .expect("actual Q ACK before host tail");
    let deadline = Instant::now() + GUARDIAN_SHUTDOWN_DEADLINE;
    while fixture
        .primary
        .worker
        .as_ref()
        .is_some_and(|worker| !worker.is_finished())
    {
        fixture
            .primary
            .poll_fatal()
            .expect("Q-attributed guardian health");
        assert!(
            Instant::now() < deadline,
            "actual cancelled control EOF deadline"
        );
        std::thread::yield_now();
    }
    fixture
        .primary
        .join_worker()
        .expect("attributed resource-free control EOF");
    println!(
        "KEL143_RUNTIME_CONTROL_EOF guardian={} ack={}",
        fixture.primary.guardian_pid(),
        lock_recovery(&fixture.primary.recovery_decision).shutdown_acknowledged
    );
    fixture.assert_live_for_budget("q-stopped-before-host-eof");
    let status = fixture
        .primary
        .shutdown()
        .expect("host EOF and exact guardian reap");
    let diagnostics = fixture.diagnostics();
    println!(
        "KEL143_RUNTIME_REAP guardian={} raw_status={} group={:?}",
        fixture.primary.guardian_pid(),
        status.into_raw(),
        fixture.primary.group_pid()
    );
    assert!(
        status.success(),
        "attributed guardian final status: {status:?}; {diagnostics}"
    );
    assert!(fixture.primary.group_pid().is_none());
    assert!(
        fixture
            .primary
            .child
            .try_wait()
            .expect("retained terminal status")
            .is_some()
    );
    assert!(group > 1);
    assert!(
        !fixture.stage_root.exists(),
        "existing guardian completed its owned stage cleanup"
    );
}

#[test]
fn poll_fatal_rejects_owned_guardian_zero_even_after_shutdown_attribution() {
    let mut child = Command::new("/bin/sh")
        .args(["-c", "exit 0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("owned zero-status health fixture");
    let writer = child.stdin.take().expect("owned liveness writer");
    let ack = child.stdout.take().expect("owned acknowledgment reader");
    let (_tx, updates_rx) = mpsc::channel();
    let mut primary = GuardedPrimary {
        child,
        liveness_writer: Some(writer),
        quit_ack_reader: ack,
        current_generation: Arc::new(Mutex::new(None)),
        recovery_decision: Arc::new(Mutex::new(RecoveryState::new())),
        updates_rx,
        worker: None,
        shutdown_attributed: true,
    };
    let deadline = Instant::now() + GUARDIAN_SHUTDOWN_DEADLINE;
    let error = loop {
        if let Err(error) = primary.poll_fatal() {
            break error;
        }
        assert!(
            Instant::now() < deadline,
            "owned zero-status inspection deadline"
        );
        std::thread::yield_now();
    };
    assert!(
        matches!(
            error,
            RuntimeError::GuardianExited {
                exit_code: Some(0),
                ..
            }
        ),
        "attribution hid unexpected guardian zero: {error}"
    );
    assert!(primary.liveness_writer.is_none());
    assert!(
        primary
            .child
            .try_wait()
            .expect("already-reaped status retained")
            .is_some()
    );
}

fn owned_acknowledgment_primary() -> GuardedPrimary {
    // This owns a real ACK pipe peer, not a guardian/native mock claim.
    // The staged-Host case above separately proves the actual guardian.
    let script = r#"
const input = Bun.stdin.stream().getReader();
const first = await input.read();
if (first.done || first.value.byteLength !== 1 || first.value[0] !== 81) process.exit(2);
process.stdout.write("KQA");
while (!(await input.read()).done) {}
"#;
    let mut child = Command::new("bun")
        .args(["-e", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("owned Q ACK producer");
    let writer = child.stdin.take().expect("sole Q/liveness writer");
    let ack = child.stdout.take().expect("sole actual ACK reader");
    let (_tx, updates_rx) = mpsc::channel();
    GuardedPrimary {
        child,
        liveness_writer: Some(writer),
        quit_ack_reader: ack,
        current_generation: Arc::new(Mutex::new(None)),
        recovery_decision: Arc::new(Mutex::new(RecoveryState::new())),
        updates_rx,
        worker: None,
        shutdown_attributed: false,
    }
}

#[test]
fn control_eof_acknowledgment_is_order_independent_and_attributed() {
    for ack_first in [true, false] {
        let (mut host, peer) = std::os::unix::net::UnixStream::pair().expect("real EOF pair");
        let mut primary = owned_acknowledgment_primary();
        primary.deny_recovery();
        if ack_first {
            primary.accept_shutdown().expect("actual Q ACK before EOF");
        }
        let state_for_reader = Arc::clone(&primary.recovery_decision);
        let (observed_tx, observed_rx) = mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            let mut reader = GenerationControlReader::new();
            let eof = reader.poll(&mut host).expect_err("actual peer EOF");
            let ack_at_eof = lock_recovery(&state_for_reader).shutdown_acknowledged;
            observed_tx
                .send(ack_at_eof)
                .expect("record EOF before later ACK");
            finish_generation_control_eof(
                eof,
                reader.filled,
                &mut HostGenerationState::default(),
                &Mutex::new(None),
                &state_for_reader,
            )
        });
        drop(peer);
        let observed = observed_rx
            .recv_timeout(SUPERVISED_QUIT_ACK_DEADLINE)
            .expect("real EOF receipt");
        if !ack_first {
            primary
                .accept_shutdown()
                .expect("actual Q ACK after observed EOF");
        }
        let result = reader.join().expect("one owned EOF reader joins");
        let status = primary.shutdown().expect("ACK peer EOF and owned reap");
        println!(
            "KEL143_RUNTIME_ACK_EOF ack_first={ack_first} ack_at_eof={observed} peer_status={status:?}"
        );
        assert_eq!(observed, ack_first);
        result.expect("either ordered actual EOF/ACK completes cleanly");
        assert!(status.success());
    }
}

#[test]
fn control_eof_without_ack_cannot_succeed_from_denial() {
    let (mut host, peer) = std::os::unix::net::UnixStream::pair().expect("real EOF pair");
    drop(peer);
    let mut reader = GenerationControlReader::new();
    let eof = reader.poll(&mut host).expect_err("real peer EOF");
    let recovery = Mutex::new(RecoveryState::new());
    lock_recovery(&recovery).deny();
    let began = Instant::now();
    let error = finish_generation_control_eof(
        eof,
        reader.filled,
        &mut HostGenerationState::default(),
        &Mutex::new(None),
        &recovery,
    )
    .expect_err("denial alone cannot fabricate Q ACK");
    assert!(
        began.elapsed() >= SUPERVISED_QUIT_ACK_DEADLINE,
        "existing attribution budget was lost"
    );
    assert_eq!(runtime_io_kind(&error), Some(io::ErrorKind::UnexpectedEof));
}

#[test]
fn real_control_eof_preserves_partial_and_unattributed_failures() {
    for partial in [false, true] {
        let (mut host, mut peer) = std::os::unix::net::UnixStream::pair().expect("real EOF pair");
        if partial {
            let mut encoded = Vec::new();
            write_generation_control(
                &mut encoded,
                &GenerationControlRecord::new(CONTROL_CLEAR, 1),
            )
            .expect("canonical fixed record");
            peer.write_all(&encoded[..1]).expect("actual partial input");
        }
        drop(peer);
        let mut reader = GenerationControlReader::new();
        let eof = reader
            .poll(&mut host)
            .expect_err("actual partial/unattributed EOF");
        assert_eq!(reader.filled, usize::from(partial));
        let recovery = Mutex::new(RecoveryState::new());
        if partial {
            let mut recovery = lock_recovery(&recovery);
            recovery.deny();
            recovery.shutdown_acknowledged = true;
        }
        let error = finish_generation_control_eof(
            eof,
            reader.filled,
            &mut HostGenerationState::default(),
            &Mutex::new(None),
            &recovery,
        )
        .expect_err("unowned/partial closure remains fatal");
        assert_eq!(runtime_io_kind(&error), Some(io::ErrorKind::UnexpectedEof));
    }
}

#[test]
fn successor_prepare_zero_byte_reply_wait_outlives_transition_budget() {
    let (client, mut peer) = std::os::unix::net::UnixStream::pair().expect("real control pair");
    client
        .set_read_timeout(Some(GENERATION_CONTROL_POLL))
        .expect("existing read poll");
    client
        .set_write_timeout(Some(GENERATION_CONTROL_POLL))
        .expect("existing write poll");
    peer.set_read_timeout(Some(GUARDIAN_SHUTDOWN_DEADLINE))
        .expect("bounded request receipt");
    peer.set_write_timeout(Some(GENERATION_CONTROL_POLL))
        .expect("existing reply write poll");
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    let client_thread = std::thread::spawn(move || {
        let control = Arc::new(Mutex::new(GenerationControlPeer {
            stream: client,
            reader: GenerationControlReader::new(),
        }));
        let result = control_exchange(
            &control,
            &GenerationControlRecord::new(CONTROL_PREPARE, 2),
            CONTROL_PREPARED,
            2,
        );
        let _ = result_tx.send(result);
    });
    let request = read_generation_control(&mut peer);
    let began = Instant::now();
    let release_at = began + GUARDIAN_SHUTDOWN_DEADLINE + Duration::from_secs(1);
    let mut early = None;
    let mut disconnected = false;
    if request.is_ok() {
        // The request receipt, not a guessed startup delay, starts this
        // independent measured interval. No reply bytes exist before release.
        while Instant::now() < release_at {
            match result_rx.try_recv() {
                Ok(result) => {
                    early = Some(result);
                    break;
                }
                Err(mpsc::TryRecvError::Empty) => std::thread::yield_now(),
                Err(mpsc::TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
    }
    let held = began.elapsed();
    let reply = GenerationControlRecord::new(CONTROL_PREPARED, 2)
        .with_payload(b"test-prepared-reply".to_vec());
    let written = if request.is_ok() && early.is_none() && !disconnected {
        Some(write_generation_control(&mut peer, &reply))
    } else {
        None
    };
    let terminal = if written.as_ref().is_some_and(Result::is_ok) {
        Some(result_rx.recv_timeout(GUARDIAN_SHUTDOWN_DEADLINE))
    } else {
        None
    };
    // Closing the retained peer makes every unfinished read observe real
    // EOF. Join before the first assertion, including early-error schedules.
    drop(peer);
    let joined = client_thread.join();
    println!(
        "KEL143_ZERO_BYTE held_ns={} early={early:?} disconnected={disconnected} written={written:?} terminal={terminal:?}",
        held.as_nanos()
    );
    joined.expect("sole control reader joined");
    let request = request.expect("actual complete Prepare2 receipt");
    assert_eq!(request.kind, CONTROL_PREPARE);
    assert_eq!(request.attempt, 2);
    assert_eq!(request.pid, 0);
    assert_eq!(request.cause, 0);
    assert_eq!(request.payload, Vec::<u8>::new());
    assert!(
        early.is_none() && !disconnected,
        "zero-byte successor completed before owned reply release: {early:?}"
    );
    assert!(held >= GUARDIAN_SHUTDOWN_DEADLINE + Duration::from_secs(1));
    written
        .expect("one owned response release")
        .expect("complete canonical Prepared2 write");
    let response = terminal
        .expect("post-release result")
        .expect("bounded result collection")
        .expect("actual successor exchange succeeded");
    assert_eq!(response.kind, CONTROL_PREPARED);
    assert_eq!(response.attempt, 2);
    assert_eq!(response.pid, 0);
    assert_eq!(response.cause, 0);
    assert_eq!(response.payload, reply.payload);
}

struct TerminalLivenessReadProbe<'a> {
    reader: File,
    supervisor: &'a Supervisor,
    observed: mpsc::SyncSender<(bool, u32)>,
    terminal_reads: u32,
    reported: bool,
}

impl Read for TerminalLivenessReadProbe<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let flags = fcntl(self.reader.as_fd(), FcntlArg::F_GETFL).map_err(nix_io_error)?;
        let nonblocking = OFlag::from_bits_truncate(flags).contains(OFlag::O_NONBLOCK);
        if self
            .supervisor
            .thread
            .as_ref()
            .is_some_and(JoinHandle::is_finished)
        {
            self.terminal_reads = self.terminal_reads.saturating_add(1);
        }
        if !self.reported && (!nonblocking || self.terminal_reads >= 64) {
            let _ = self.observed.send((nonblocking, self.terminal_reads));
            self.reported = true;
        }
        self.reader.read(bytes)
    }
}

impl AsFd for TerminalLivenessReadProbe<'_> {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.reader.as_fd()
    }
}

fn run_terminal_liveness_probe(
    mut reader: File,
    mut acknowledgment: std::os::unix::net::UnixStream,
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
    observed: mpsc::SyncSender<(bool, u32)>,
    initialized: &mpsc::SyncSender<()>,
) -> (Result<(), RuntimeError>, bool, bool, SupervisorOutcome, u32) {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "exit 1"]);
    let supervisor = Supervisor::start_prepared(
        RestartPolicy::default(),
        GatedUnmarkedFailurePreparer {
            initial: Some(command),
            entered_tx: entered,
            release_rx: release,
            phase: "unused marked phase",
            kind: io::ErrorKind::Interrupted,
            owned: true,
        },
    )
    .expect("real controlled Supervisor child");
    validate_liveness_bootstrap(&mut reader).expect("actual live owned pipe");
    set_liveness_nonblocking(&reader, true).expect("existing active-loop descriptor mode");
    initialized
        .send(())
        .expect("descriptor validation precedes actual Q");
    let mut probe = TerminalLivenessReadProbe {
        reader,
        supervisor: &supervisor,
        observed,
        terminal_reads: 0,
        reported: false,
    };
    let (result, accepted, dead) = await_guarded_primary_liveness(
        &mut probe,
        &supervisor,
        &mut acknowledgment,
        &AtomicBool::new(false),
        &AtomicBool::new(false),
    );
    drop(probe);
    let outcome = supervisor.wait_for_outcome();
    let terminations = supervisor.crash_ledger().self_termination_count;
    (result, accepted, dead, outcome, terminations)
}

#[test]
fn attributed_stopped_liveness_wait_blocks_on_owned_descriptor() {
    let (reader, mut writer) = liveness_pipe();
    let (acknowledgment, mut ack_reader) =
        std::os::unix::net::UnixStream::pair().expect("actual Q ACK pair");
    ack_reader
        .set_read_timeout(Some(SUPERVISED_QUIT_ACK_DEADLINE))
        .expect("existing acknowledgment kill switch");
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (observed_tx, observed_rx) = mpsc::sync_channel(1);
    let (initialized_tx, initialized_rx) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        run_terminal_liveness_probe(
            reader,
            acknowledgment,
            entered_tx,
            release_rx,
            observed_tx,
            &initialized_tx,
        )
    });
    let initialized = initialized_rx.recv_timeout(GUARDIAN_SHUTDOWN_DEADLINE);
    let entered = entered_rx.recv_timeout(GUARDIAN_SHUTDOWN_DEADLINE);
    let write = if initialized.is_ok() && entered.is_ok() {
        writer.write_all(&[SUPERVISED_QUIT_ACCEPTED])
    } else {
        Err(io::Error::other(
            "controlled preparation did not reach attempt2",
        ))
    };
    let mut ack = [0_u8; 3];
    let acknowledged = if write.is_ok() {
        ack_reader.read_exact(&mut ack)
    } else {
        Err(io::Error::other("Q was not written"))
    };
    // Release only after the actual ACK cut; always release during failed
    // collection so no assertion strands the owned preparer or pipe read.
    let released = release_tx.send(());
    drop(release_tx);
    let observation = if acknowledged.is_ok() {
        observed_rx.recv_timeout(GUARDIAN_SHUTDOWN_DEADLINE)
    } else {
        Err(mpsc::RecvTimeoutError::Disconnected)
    };
    drop(writer);
    let joined = worker.join();
    println!(
        "KEL143_TERMINAL_WAIT acknowledged={acknowledged:?} ack={ack:?} observation={observation:?}"
    );
    initialized.expect("actual descriptor validation/mode setup");
    entered.expect("actual retired G1/attempt2 fence");
    write.expect("actual Q byte");
    acknowledged.expect("actual Q ACK bytes");
    released.expect("owned interruption release");
    let (nonblocking, terminal_reads) = observation.expect("bounded terminal wait witness");
    let (result, accepted, dead, outcome, terminations) = joined.expect("all owners joined");
    result.expect("actual host EOF completes liveness wait");
    assert_eq!(ack, SUPERVISED_QUIT_ACK);
    assert!(accepted && dead);
    assert!(matches!(outcome, SupervisorOutcome::Stopped));
    assert_eq!(terminations, 1, "retained actual G1 exit fact");
    assert!(
        !nonblocking,
        "terminal loop remained nonblocking after sender exit; reads={terminal_reads}"
    );
    assert!(
        terminal_reads < 64,
        "terminal disconnected-event loop repeated reads"
    );
}

// Existing approved KEL-143 §7 schedules. This test relay copies exact
// private records; run_generation_host remains the actual mint/lease owner.
mod runtime_race_validation {
    use super::*;
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    use std::sync::TryLockError;

    const COLLECTION: Duration = Duration::from_secs(7);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum DeliveryCut {
        Zero,
        Partial,
        FullBeforeLease,
        LeaseBeforeSpawn,
    }

    enum RelayCommand {
        Full,
        Prefix,
        AwaitClosure,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct ControlFields {
        kind: u8,
        cause: u8,
        attempt: u32,
        pid: u32,
        payload_len: usize,
    }

    impl ControlFields {
        fn capture(record: &GenerationControlRecord) -> Self {
            Self {
                kind: record.kind,
                cause: record.cause,
                attempt: record.attempt,
                pid: record.pid,
                payload_len: record.payload.len(),
            }
        }
    }

    enum RelayReceipt {
        ClearedOne,
        PreparedTwo(GenerationControlRecord),
        PrefixSent(Instant),
        NormalRevokeTwo {
            request: ControlFields,
            response: ControlFields,
        },
        NormalClearTwo {
            request: ControlFields,
            response: ControlFields,
        },
        GuardianControlEof,
    }

    struct PhaseGate {
        entered: Sender<()>,
        release: Receiver<()>,
    }

    impl PhaseGate {
        fn wait(&self) -> Result<(), RuntimeError> {
            self.entered.send(()).map_err(|_| {
                lifecycle_error(
                    "test Runtime phase receipt",
                    io::Error::other("custodian ended"),
                )
            })?;
            self.release.recv_timeout(COLLECTION).map_err(|source| {
                lifecycle_error("test Runtime phase release", io::Error::other(source))
            })
        }
    }

    struct ReturnedLeasePreparer<C> {
        inner: GuardedPrimaryPreparer<C>,
        gate: Option<PhaseGate>,
    }

    impl<C> ChildPreparer for ReturnedLeasePreparer<C>
    where
        C: FnMut(&str) -> Result<Command, RuntimeError> + Send + 'static,
    {
        type Lease = GuardedPrimaryLease;

        fn prepare(&mut self, attempt: u32) -> Result<PreparedChild<Self::Lease>, RuntimeError> {
            let prepared = self.inner.prepare(attempt)?;
            // This receipt follows actual GuardedPrimaryLease construction.
            // It does not replace that lease or call another spawn owner.
            if attempt == 2
                && let Some(gate) = &self.gate
            {
                gate.wait()?;
            }
            Ok(prepared)
        }
    }

    fn timed_pair() -> (UnixStream, UnixStream) {
        let (one, two) = UnixStream::pair().expect("existing private Unix pair");
        for stream in [&one, &two] {
            stream
                .set_read_timeout(Some(GENERATION_CONTROL_POLL))
                .expect("read poll");
            stream
                .set_write_timeout(Some(GENERATION_CONTROL_POLL))
                .expect("write poll");
        }
        (one, two)
    }

    fn receive_record(stream: &mut UnixStream) -> Result<GenerationControlRecord, RuntimeError> {
        let mut reader = GenerationControlReader::new();
        let deadline = Instant::now() + COLLECTION;
        loop {
            if let Some(record) = reader.poll(stream)? {
                return Ok(record);
            }
            if Instant::now() >= deadline {
                return Err(lifecycle_error(
                    "test Runtime record collection",
                    io::Error::from(io::ErrorKind::TimedOut),
                ));
            }
        }
    }

    fn private_record_relay(
        mut host: UnixStream,
        mut guardian: UnixStream,
        commands: &Receiver<RelayCommand>,
        receipts: &Sender<RelayReceipt>,
    ) -> Result<(), RuntimeError> {
        loop {
            let request = match receive_record(&mut guardian) {
                Ok(record) => record,
                Err(error) if runtime_io_kind(&error) == Some(io::ErrorKind::UnexpectedEof) => {
                    // Actual preparer/Supervisor control closure drives the
                    // real host owner EOF; the relay fabricates no record.
                    receipts
                        .send(RelayReceipt::GuardianControlEof)
                        .map_err(|_| {
                            lifecycle_error(
                                "test relay actual EOF receipt",
                                io::Error::other("custodian ended"),
                            )
                        })?;
                    return host.shutdown(Shutdown::Both).map_err(|source| {
                        lifecycle_error("test relay observed control closure", source)
                    });
                }
                Err(error) => return Err(error),
            };
            write_generation_control(&mut host, &request)?;
            let response = receive_record(&mut host)?;
            if response.kind == CONTROL_PREPARED && response.attempt == 2 {
                let mut encoded = Vec::new();
                write_generation_control(&mut encoded, &response)?;
                receipts
                    .send(RelayReceipt::PreparedTwo(response))
                    .map_err(|_| {
                        lifecycle_error(
                            "test relay Prepared receipt",
                            io::Error::other("custodian ended"),
                        )
                    })?;
                match commands.recv_timeout(COLLECTION).map_err(|source| {
                    lifecycle_error("test relay delivery release", io::Error::other(source))
                })? {
                    RelayCommand::Full => guardian.write_all(&encoded).map_err(|source| {
                        lifecycle_error("test relay complete Prepared write", source)
                    })?,
                    RelayCommand::Prefix => {
                        // One canonical byte is a valid prefix, not a
                        // malformed substitute response or model timeout.
                        let began = Instant::now();
                        guardian.write_all(&encoded[..1]).map_err(|source| {
                            lifecycle_error("test relay Prepared prefix write", source)
                        })?;
                        receipts
                            .send(RelayReceipt::PrefixSent(began))
                            .map_err(|_| {
                                lifecycle_error(
                                    "test relay prefix receipt",
                                    io::Error::other("custodian ended"),
                                )
                            })?;
                        match commands.recv_timeout(COLLECTION).map_err(|source| {
                            lifecycle_error(
                                "test relay partial outcome collection",
                                io::Error::other(source),
                            )
                        })? {
                            RelayCommand::AwaitClosure => {}
                            RelayCommand::Full | RelayCommand::Prefix => {
                                return Err(lifecycle_error(
                                    "test relay prefix command",
                                    io::Error::other("unexpected duplicate delivery"),
                                ));
                            }
                        }
                    }
                    RelayCommand::AwaitClosure => {}
                }
            } else {
                write_generation_control(&mut guardian, &response)?;
                // These facts come from the actual requests and actual
                // host replies, not the shared Revoked event that EOF can
                // also emit. Normal lease cleanup must earn its own oracle.
                let receipt = match (request.kind, request.attempt) {
                    (CONTROL_REVOKE, 2) => Some(RelayReceipt::NormalRevokeTwo {
                        request: ControlFields::capture(&request),
                        response: ControlFields::capture(&response),
                    }),
                    (CONTROL_CLEAR, 2) => Some(RelayReceipt::NormalClearTwo {
                        request: ControlFields::capture(&request),
                        response: ControlFields::capture(&response),
                    }),
                    _ => None,
                };
                if let Some(receipt) = receipt {
                    receipts.send(receipt).map_err(|_| {
                        lifecycle_error(
                            "test relay normal cleanup receipt",
                            io::Error::other("custodian ended"),
                        )
                    })?;
                }
                if response.kind == CONTROL_CLEARED && response.attempt == 1 {
                    receipts.send(RelayReceipt::ClearedOne).map_err(|_| {
                        lifecycle_error(
                            "test relay Clear receipt",
                            io::Error::other("custodian ended"),
                        )
                    })?;
                }
            }
        }
    }

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

    struct CutFixture {
        supervisor: Option<Supervisor>,
        plane: ControlPlane,
        phase_entered: Receiver<()>,
        phase_release: Sender<()>,
        cancelled: Arc<AtomicBool>,
        no_effect: tempfile::TempDir,
        initial_pid: u32,
    }

    impl CutFixture {
        fn start(cut: DeliveryCut) -> Self {
            let mut plane = ControlPlane::start(cut);
            let guardian_control = plane
                .guardian_control
                .take()
                .expect("one guardian private stream");
            let (phase_tx, phase_entered) = mpsc::channel();
            let (phase_release, phase_rx) = mpsc::channel();
            let mut factory_gate = None;
            let mut lease_gate = None;
            match cut {
                DeliveryCut::FullBeforeLease => {
                    factory_gate = Some(PhaseGate {
                        entered: phase_tx,
                        release: phase_rx,
                    });
                }
                DeliveryCut::LeaseBeforeSpawn => {
                    lease_gate = Some(PhaseGate {
                        entered: phase_tx,
                        release: phase_rx,
                    });
                }
                DeliveryCut::Zero | DeliveryCut::Partial => {}
            }
            let no_effect = tempfile::tempdir().expect("owned successor no-effect sentinel");
            let successor_effect = no_effect.path().join("unexpected-g2-effect");
            let initial_release = no_effect.path().join("g1-release");
            let initial_release_for_child = initial_release.clone();
            let mut calls = 0;
            let command_factory = move |_app_link: &str| {
                calls += 1;
                let mut command = Command::new("/bin/sh");
                if calls == 1 {
                    command.args([
                        "-c",
                        "printf KEL143_RACE_G1; while [ ! -e \"$1\" ]; do :; done; exit 1",
                        "keld-race",
                    ]);
                    command.arg(&initial_release_for_child);
                } else {
                    if let Some(gate) = &factory_gate {
                        gate.wait()?;
                    }
                    command.args([
                        "-c",
                        "printf KEL143_RACE_BAD_G2; printf bad > \"$1\"; exit 0",
                        "keld-race",
                    ]);
                    command.arg(&successor_effect);
                }
                Ok(command)
            };
            let cancelled = Arc::new(AtomicBool::new(false));
            let supervisor = Supervisor::start_prepared(
                RestartPolicy::default(),
                ReturnedLeasePreparer {
                    inner: GuardedPrimaryPreparer {
                        command_factory,
                        control: Arc::new(Mutex::new(GenerationControlPeer {
                            stream: guardian_control,
                            reader: GenerationControlReader::new(),
                        })),
                        host_unavailable: Arc::new(AtomicBool::new(false)),
                        preparation_cancelled: Arc::clone(&cancelled),
                    },
                    gate: lease_gate,
                },
            )
            .expect("real initial Supervisor child with actual guarded preparation");
            // Startup spawn precedes group enrollment. The production
            // Started receipt follows actual child_spawned/host enrollment.
            let initial_pid = await_initial_registration(&supervisor, &plane.current);
            std::fs::write(initial_release, b"release-g1").expect("release actual registered G1");
            Self {
                supervisor: Some(supervisor),
                plane,
                phase_entered,
                phase_release,
                cancelled,
                no_effect,
                initial_pid,
            }
        }

        fn release_after_clear(&self) -> GenerationControlRecord {
            assert!(matches!(
                self.plane
                    .receipts
                    .recv_timeout(COLLECTION)
                    .expect("actual Clear1"),
                RelayReceipt::ClearedOne
            ));
            assert!(lock_generation(&self.plane.current).is_none());
            lock_recovery(&self.plane.recovery).arm();
            match self
                .plane
                .receipts
                .recv_timeout(COLLECTION)
                .expect("actual host Prepared2 emission")
            {
                RelayReceipt::PreparedTwo(record) => record,
                _ => panic!("unexpected protocol receipt before Prepared2"),
            }
        }

        fn accept_actual_q(&self) {
            lock_recovery(&self.plane.recovery).deny();
            let (mut reader, mut writer) = liveness_pipe();
            validate_liveness_bootstrap(&mut reader).expect("owned validated liveness pipe");
            set_liveness_nonblocking(&reader, true).expect("active liveness poll");
            let (mut ack_writer, mut ack_reader) = timed_pair();
            writer
                .write_all(&[SUPERVISED_QUIT_ACCEPTED])
                .expect("actual Q byte");
            let mut quit = false;
            let mut orderly = false;
            assert!(
                !observe_guarded_liveness(
                    &mut reader,
                    self.supervisor.as_ref().expect("Supervisor owner"),
                    &mut quit,
                    &mut orderly,
                    &mut ack_writer,
                    &self.cancelled
                )
                .expect("existing guardian Q handling")
            );
            let mut bytes = [0; 3];
            ack_reader
                .read_exact(&mut bytes)
                .expect("actual KQA receipt");
            assert_eq!(bytes, *b"KQA");
            assert!(quit && !orderly);
            lock_recovery(&self.plane.recovery).shutdown_acknowledged = true;
        }

        fn collect(
            mut self,
            cut: DeliveryCut,
            response: &GenerationControlRecord,
            began: Option<Instant>,
        ) {
            // All releases/joins precede assertions. The fixture Drop also
            // releases every fence on failed collection or an unwind.
            let supervisor = self.supervisor.as_ref().expect("Supervisor owner");
            let (terminal, started_two) = collect_terminal_event(supervisor);
            let outcome = supervisor.wait_for_outcome();
            let current_pid = supervisor.current_pid();
            let ledger = supervisor.crash_ledger();
            let output = supervisor.output();
            // wait_for_outcome observes completion; dropping this sole
            // Supervisor joins its actual direct child/capture owner.
            drop(self.supervisor.take());
            let relay = self
                .plane
                .relay
                .take()
                .expect("one relay")
                .join()
                .expect("relay thread joins");
            let host = self
                .plane
                .host
                .take()
                .expect("one actual host owner")
                .join()
                .expect("host thread joins");
            let updates: Vec<_> = self.plane.updates.try_iter().collect();
            let cleanup_receipts: Vec<_> = self.plane.receipts.try_iter().collect();
            let (endpoint, _) = parse_app_link(
                std::str::from_utf8(&response.payload).expect("actual app link UTF8"),
            )
            .expect("actual minted locator");
            let endpoint_gone = UnixStream::connect(endpoint).is_err();
            let no_effect = !self.no_effect.path().join("unexpected-g2-effect").exists();
            relay.expect("real control EOF forwarded after guardian-side owner drop");
            host.expect("actual exact host lease cleanup completed before EOF success");
            assert!(!started_two && current_pid.is_none());
            assert!(lock_generation(&self.plane.current).is_none());
            assert_eq!(ledger.self_termination_count, 1);
            assert_eq!(
                ledger.last_self_termination.map(|entry| entry.pid),
                Some(self.initial_pid)
            );
            assert_gone(Some(self.initial_pid));
            assert!(
                ledger
                    .last_self_termination
                    .is_some_and(|entry| entry.exit_code == Some(1))
            );
            assert!(output.stdout.contains("KEL143_RACE_G1"));
            assert!(!output.stdout.contains("KEL143_RACE_BAD_G2") && no_effect);
            assert!(updates.iter().any(|update| matches!(
                update,
                GuardedPrimaryUpdate::Role(RoleEvent::Provisioned { attempt: 2, .. })
            )));
            assert!(updates.iter().any(|update| matches!(
                update,
                GuardedPrimaryUpdate::Role(RoleEvent::Revoked {
                    attempt: 2,
                    cause: crate::role::RoleRevocationCause::Shutdown,
                    ..
                })
            )));
            assert!(!updates.iter().any(|update| matches!(update, GuardedPrimaryUpdate::Bound(bound) if bound.attempt() == 2)));
            assert!(!updates.iter().any(|update| matches!(
                update,
                GuardedPrimaryUpdate::Role(
                    RoleEvent::Spawned { attempt: 2, .. } | RoleEvent::LinkBound { attempt: 2, .. }
                )
            )));
            assert!(endpoint_gone, "exact minted successor listener survived");
            assert_cleanup_route(cut, &cleanup_receipts);
            assert_cut_outcome(cut, &terminal, &outcome, began);
            println!(
                "KEL143_PREPARED_CUT cut={cut:?} actual_mint=true q_ack=true exact_revoked=2 listener_absent={endpoint_gone} g2_effect_absent={no_effect} direct_child_reaped=true"
            );
        }
    }

    fn assert_cleanup_route(cut: DeliveryCut, receipts: &[RelayReceipt]) {
        let revokes: Vec<_> = receipts
            .iter()
            .enumerate()
            .filter_map(|(index, receipt)| match receipt {
                RelayReceipt::NormalRevokeTwo { request, response } => {
                    Some((index, request, response))
                }
                _ => None,
            })
            .collect();
        let clears: Vec<_> = receipts
            .iter()
            .enumerate()
            .filter_map(|(index, receipt)| match receipt {
                RelayReceipt::NormalClearTwo { request, response } => {
                    Some((index, request, response))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            receipts
                .iter()
                .filter(|receipt| matches!(receipt, RelayReceipt::GuardianControlEof))
                .count(),
            1,
            "actual guardian control EOF absent/duplicated"
        );
        if matches!(
            cut,
            DeliveryCut::FullBeforeLease | DeliveryCut::LeaseBeforeSpawn
        ) {
            assert_eq!(
                revokes.len(),
                1,
                "normal lease Revoke2 request/ack missing or duplicated"
            );
            assert_eq!(
                clears.len(),
                1,
                "normal lease Clear2 request/ack missing or duplicated"
            );
            // Literal approved private wire fields are an independent
            // oracle; changing production constants cannot change these.
            let expected = [
                ControlFields {
                    kind: 5,
                    cause: 2,
                    attempt: 2,
                    pid: 0,
                    payload_len: 0,
                },
                ControlFields {
                    kind: 6,
                    cause: 0,
                    attempt: 2,
                    pid: 0,
                    payload_len: 0,
                },
                ControlFields {
                    kind: 7,
                    cause: 0,
                    attempt: 2,
                    pid: 0,
                    payload_len: 0,
                },
                ControlFields {
                    kind: 8,
                    cause: 0,
                    attempt: 2,
                    pid: 0,
                    payload_len: 0,
                },
            ];
            let actual = [revokes[0].1, revokes[0].2, clears[0].1, clears[0].2];
            assert_eq!(
                actual,
                [&expected[0], &expected[1], &expected[2], &expected[3]]
            );
            assert!(
                revokes[0].0 < clears[0].0,
                "normal Clear2 acknowledgment preceded Revoke2 acknowledgment"
            );
        } else {
            assert!(
                revokes.is_empty(),
                "unclaimed zero/partial cut acquired normal Revoke2 path"
            );
            assert!(
                clears.is_empty(),
                "unclaimed zero/partial cut acquired normal Clear2 path"
            );
            // Together with the separately asserted exact host-owned
            // Revoked2/Shutdown and successful host join, actual EOF plus
            // absent normal exchanges identifies the host EOF cleanup.
        }
    }

    fn collect_terminal_event(supervisor: &Supervisor) -> (crate::SupervisorEvent, bool) {
        let deadline = Instant::now() + COLLECTION;
        let mut started_two = false;
        let terminal = loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .expect("bounded terminal event collection");
            match supervisor.recv_event(remaining) {
                Some(crate::SupervisorEvent::Started { attempt: 2, .. }) => started_two = true,
                Some(
                    event @ (crate::SupervisorEvent::Stopped
                    | crate::SupervisorEvent::Failed { .. }),
                ) => break event,
                Some(_) => {}
                None => panic!("actual Supervisor terminal event absent"),
            }
        };
        (terminal, started_two)
    }

    fn assert_cut_outcome(
        cut: DeliveryCut,
        terminal: &crate::SupervisorEvent,
        outcome: &SupervisorOutcome,
        began: Option<Instant>,
    ) {
        if cut == DeliveryCut::Partial {
            assert!(
                began.expect("actual prefix write clock").elapsed() >= GUARDIAN_SHUTDOWN_DEADLINE
            );
            assert!(matches!(
                terminal,
                crate::SupervisorEvent::Failed { attempt: 2 }
            ));
            match outcome {
                SupervisorOutcome::Failed(error) => {
                    assert_eq!(runtime_io_kind(error), Some(io::ErrorKind::TimedOut));
                    assert!(!is_owned_preparation_interruption(error, 2));
                    assert!(error.to_string().contains("read deadline"));
                }
                other => panic!("partial Prepared timeout was hidden: {other:?}"),
            }
        } else {
            assert!(matches!(terminal, crate::SupervisorEvent::Stopped));
            assert!(matches!(outcome, SupervisorOutcome::Stopped));
        }
    }

    impl Drop for CutFixture {
        fn drop(&mut self) {
            lock_recovery(&self.plane.recovery).deny();
            self.plane.consumption_probe.take();
            if let Some(supervisor) = &self.supervisor {
                supervisor.shutdown();
            }
            self.cancelled.store(true, Ordering::Release);
            let _ = self.phase_release.send(());
            let _ = self.plane.commands.send(RelayCommand::AwaitClosure);
            drop(self.supervisor.take());
        }
    }

    fn run_delivery_cut(cut: DeliveryCut) {
        let mut fixture = CutFixture::start(cut);
        let response = fixture.release_after_clear();
        let mut began = None;
        match cut {
            DeliveryCut::Zero => {
                fixture.accept_actual_q();
                fixture
                    .plane
                    .commands
                    .send(RelayCommand::AwaitClosure)
                    .expect("zero-byte closure collection");
            }
            DeliveryCut::Partial => {
                fixture
                    .plane
                    .commands
                    .send(RelayCommand::Prefix)
                    .expect("one canonical prefix");
                began = match fixture
                    .plane
                    .receipts
                    .recv_timeout(COLLECTION)
                    .expect("actual prefix write receipt")
                {
                    RelayReceipt::PrefixSent(time) => Some(time),
                    _ => panic!("unexpected prefix receipt"),
                };
                let deadline = Instant::now() + COLLECTION;
                loop {
                    if rustix::io::ioctl_fionread(
                        fixture
                            .plane
                            .consumption_probe
                            .as_ref()
                            .expect("observation alias"),
                    )
                    .expect("existing safe available-byte primitive")
                        == 0
                    {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "valid prefix not consumed by sole control reader"
                    );
                    thread::yield_now();
                }
                drop(fixture.plane.consumption_probe.take());
                fixture.accept_actual_q();
                fixture
                    .plane
                    .commands
                    .send(RelayCommand::AwaitClosure)
                    .expect("partial suffix remains withheld until actual failure/EOF");
            }
            DeliveryCut::FullBeforeLease | DeliveryCut::LeaseBeforeSpawn => {
                fixture
                    .plane
                    .commands
                    .send(RelayCommand::Full)
                    .expect("full canonical Prepared2 release");
                fixture
                    .phase_entered
                    .recv_timeout(COLLECTION)
                    .expect("exact factory/returned-lease boundary");
                fixture.accept_actual_q();
                fixture
                    .phase_release
                    .send(())
                    .expect("release only after actual Q ACK");
            }
        }
        fixture.collect(cut, &response, began);
    }

    #[test]
    fn prepared_delivery_zero_bytes_retires_exact_unclaimed_host_lease() {
        run_delivery_cut(DeliveryCut::Zero);
    }

    #[test]
    fn prepared_delivery_partial_prefix_keeps_framing_clock_and_typed_timeout() {
        run_delivery_cut(DeliveryCut::Partial);
    }

    #[test]
    fn prepared_delivery_full_before_lease_uses_normal_supervisor_revoke() {
        run_delivery_cut(DeliveryCut::FullBeforeLease);
    }

    #[test]
    fn prepared_delivery_post_lease_pre_spawn_uses_normal_supervisor_revoke() {
        run_delivery_cut(DeliveryCut::LeaseBeforeSpawn);
    }

    struct RetiredOwner {
        guardian: Option<UnixStream>,
        recovery: Arc<Mutex<RecoveryState>>,
        updates: Receiver<GuardedPrimaryUpdate>,
        worker: Option<JoinHandle<Result<(), RuntimeError>>>,
    }

    impl RetiredOwner {
        fn stream(&mut self) -> &mut UnixStream {
            self.guardian.as_mut().expect("retained private peer")
        }

        fn join(&mut self) -> Result<Vec<GuardedPrimaryUpdate>, RuntimeError> {
            self.worker
                .take()
                .expect("one actual host owner")
                .join()
                .map_err(|_| {
                    lifecycle_error(
                        "test actual mint owner join",
                        io::Error::other("owner panicked"),
                    )
                })??;
            Ok(self.updates.try_iter().collect())
        }
    }

    impl Drop for RetiredOwner {
        fn drop(&mut self) {
            lock_recovery(&self.recovery).deny();
            self.guardian.take();
            if let Some(worker) = self.worker.take() {
                match worker.join() {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => eprintln!("KEL143_MINT_RESCUE owner error: {error}"),
                    Err(error) => eprintln!("KEL143_MINT_RESCUE panic: {error:?}"),
                }
            }
        }
    }

    fn prepare_retired_owner(fence: Option<GenerationProvisionFence>) -> RetiredOwner {
        let (host, guardian) = timed_pair();
        let (updates_tx, updates_rx) = mpsc::channel();
        let current = Arc::new(Mutex::new(None));
        let recovery = Arc::new(Mutex::new(RecoveryState::new()));
        lock_recovery(&recovery).arm();
        let state = Arc::clone(&recovery);
        let worker = thread::spawn(move || {
            run_generation_host(host, &updates_tx, &current, &state, fence.as_ref())
        });
        let mut owner = RetiredOwner {
            guardian: Some(guardian),
            recovery,
            updates: updates_rx,
            worker: Some(worker),
        };
        write_generation_control(
            owner.stream(),
            &GenerationControlRecord::new(CONTROL_PREPARE, 1),
        )
        .expect("actual Prepare1");
        assert_eq!(
            receive_record(owner.stream())
                .expect("actual Prepared1")
                .kind,
            CONTROL_PREPARED
        );
        for (kind, expected) in [
            (CONTROL_REVOKE, CONTROL_REVOKED),
            (CONTROL_CLEAR, CONTROL_CLEARED),
        ] {
            let record = if kind == CONTROL_REVOKE {
                GenerationControlRecord::new(kind, 1).with_cause(RevocationCause::AdmissionFailed)
            } else {
                GenerationControlRecord::new(kind, 1)
            };
            write_generation_control(owner.stream(), &record)
                .expect("actual retired predecessor transition");
            assert_eq!(
                receive_record(owner.stream())
                    .expect("actual predecessor acknowledgment")
                    .kind,
                expected
            );
        }
        owner
    }

    #[test]
    fn generation_host_provision_mutex_orders_actual_mint_and_denial() {
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::channel();
        let mut owner = prepare_retired_owner(Some(GenerationProvisionFence {
            attempt: 2,
            entered: entered_tx,
            release: release_rx,
        }));
        let recovery = Arc::clone(&owner.recovery);
        lock_recovery(&recovery).arm();
        write_generation_control(
            owner.stream(),
            &GenerationControlRecord::new(CONTROL_PREPARE, 2),
        )
        .expect("actual Prepare2");
        let entered = entered_rx.recv_timeout(COLLECTION);
        // This is an independent lock observable while actual host mint is
        // fenced. The fault releases the guard before this same fence.
        let denial_won_before_mint = match recovery.try_lock() {
            Ok(mut state) => {
                state.deny();
                true
            }
            Err(TryLockError::WouldBlock) => false,
            Err(TryLockError::Poisoned(error)) => {
                error.into_inner().deny();
                true
            }
        };
        let released = release_tx.send(());
        let response = receive_record(owner.stream());
        let events_at_mint: Vec<_> = owner.updates.try_iter().collect();
        lock_recovery(&recovery).deny();
        let mut listener_was_live = false;
        let mut listener_gone = false;
        if let Ok(response) = &response {
            let (endpoint, _) = parse_app_link(
                std::str::from_utf8(&response.payload).expect("actual app link UTF8"),
            )
            .expect("actual minted locator");
            listener_was_live = UnixStream::connect(endpoint).is_ok();
            for (kind, expected) in [
                (CONTROL_REVOKE, CONTROL_REVOKED),
                (CONTROL_CLEAR, CONTROL_CLEARED),
            ] {
                let record = if kind == CONTROL_REVOKE {
                    GenerationControlRecord::new(kind, 2).with_cause(RevocationCause::Shutdown)
                } else {
                    GenerationControlRecord::new(kind, 2)
                };
                write_generation_control(owner.stream(), &record)
                    .expect("actual successor cleanup transition");
                assert_eq!(
                    receive_record(owner.stream())
                        .expect("actual successor cleanup acknowledgment")
                        .kind,
                    expected
                );
            }
            listener_gone = UnixStream::connect(endpoint).is_err();
        }
        lock_recovery(&recovery).shutdown_acknowledged = true;
        owner.guardian.take();
        let joined = owner.join();
        entered.expect("actual pre-mint owner fence reached");
        released.expect("release actual mint fence before assertions");
        let response = response.expect("actual owner minted matching Prepared2");
        assert_eq!((response.kind, response.attempt), (CONTROL_PREPARED, 2));
        let after_cleanup =
            joined.expect("actual host owner joins after exact cleanup and attributed EOF");
        assert!(after_cleanup.iter().any(|update| matches!(
            update,
            GuardedPrimaryUpdate::Role(RoleEvent::Revoked {
                attempt: 2,
                cause: crate::role::RoleRevocationCause::Shutdown,
                ..
            })
        )));
        assert!(events_at_mint.iter().any(|update| matches!(
            update,
            GuardedPrimaryUpdate::Role(RoleEvent::Provisioned { attempt: 2, .. })
        )));
        assert!(listener_was_live && listener_gone);
        println!(
            "KEL143_MINT_FENCE denied_before_actual_mint={denial_won_before_mint} actual_provisioned=2 listener_was_live={listener_was_live} listener_absent={listener_gone}"
        );
        assert!(
            !denial_won_before_mint,
            "actual mint followed observed denial at the shared pre-mint fence"
        );
    }

    #[test]
    fn generation_host_denial_winner_has_no_successor_locator() {
        let mut owner = prepare_retired_owner(None);
        let recovery = Arc::clone(&owner.recovery);
        {
            let mut state = lock_recovery(&recovery);
            state.deny();
            state.arm();
            state.shutdown_acknowledged = true;
        }
        write_generation_control(
            owner.stream(),
            &GenerationControlRecord::new(CONTROL_PREPARE, 2),
        )
        .expect("actual denied Prepare2");
        // Draining EOF is the actual owner's final processing witness;
        // absence during a guessed timed interval would not establish it.
        owner
            .stream()
            .shutdown(Shutdown::Write)
            .expect("real private request EOF after complete Prepare2");
        let updates = owner
            .join()
            .expect("actual denied host owner joins after resource-free attributed completion");
        assert!(!updates.iter().any(|update| matches!(
            update,
            GuardedPrimaryUpdate::Role(RoleEvent::Provisioned { attempt: 2, .. })
        )));
        let closure =
            receive_record(owner.stream()).expect_err("denial fabricated Prepared2 locator");
        assert_eq!(
            runtime_io_kind(&closure),
            Some(io::ErrorKind::UnexpectedEof)
        );
        println!(
            "KEL143_MINT_FENCE denial_winner=true successor_locator=false actual_owner_eof=true"
        );
    }
}

fn long_running_command() -> Command {
    let mut command = Command::new("/usr/bin/tail");
    command
        .args(["-f", "/dev/null"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    command
}

fn liveness_pipe() -> (File, File) {
    let (reader, writer) = pipe().expect("create host-liveness pipe");
    fcntl(&reader, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
        .expect("make liveness reader non-inheritable");
    fcntl(&writer, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
        .expect("make liveness writer non-inheritable");
    (File::from(reader), File::from(writer))
}

fn assert_gone(pid: Option<u32>) {
    let pid = pid.expect("child registered");
    let pid = i32::try_from(pid).expect("pid fits i32");
    assert_eq!(kill(Pid::from_raw(pid), None), Err(Errno::ESRCH));
}
