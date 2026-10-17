// Pre-registration custody also needs bounded guardian retirement: there is
// no enrolled Bun group yet, so test only the owned guardian child here.
use std::io::{self, Read as _, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

use super::super::{
    CONTROL_PREPARE, CONTROL_PREPARED, CONTROL_SPAWNED, GUARDIAN_SHUTDOWN_DEADLINE,
    GenerationControlRecord, GuardianBootstrap, HostGuardian, REGISTRATION_ENV, handshake_client,
    lifecycle_error, parse_app_link, read_generation_control, reject_host_registration,
    terminate_registered_group, write_generation_control, write_group_registration,
};

mod witness;
use self::witness::await_denial_witness;

const FORGED_GROUP_ENV: &str = "KELD_TEST_KGR1_FOREIGN_GROUP";
const FORGED_GROUP_ROLE: &str =
    "macos_guardian::tests::rejected_registration_deadline::forged_kgr1_guardian_role";

#[test]
fn forged_kgr1_guardian_role() {
    let Some(group) = std::env::var_os(FORGED_GROUP_ENV) else {
        return;
    };
    let group: u32 = group
        .to_str()
        .expect("group pid UTF-8")
        .parse()
        .expect("group pid");
    let link = std::env::var(REGISTRATION_ENV).expect("one-use authenticated Guardian link");
    let (endpoint, token) = parse_app_link(&link).expect("actual private link");
    let mut stream = UnixStream::connect(endpoint).expect("connect own Guardian link");
    handshake_client(&mut stream, &token).expect("authenticate original private link");
    write_group_registration(&mut stream, group).expect("send forged complete KGR1 record");
    // The host must reject the reported outsider. Its sole liveness writer
    // closes during rejection; the rejected Guardian then exits normally.
    let mut control = [0_u8; 1];
    let count = io::stdin()
        .read(&mut control)
        .expect("read host-liveness EOF");
    assert_eq!(
        count, 0,
        "rejected Guardian must not receive a release byte"
    );
}

#[test]
fn authenticated_kgr1_cannot_claim_an_unrelated_live_process_group() {
    // A disposable, exactly owned outsider group. The test never probes or
    // signals an arbitrary OS process ID, including on unexpected acceptance.
    let mut outsider = Command::new("/bin/sleep")
        .arg("30")
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start independent test-owned process group");
    let group = outsider.id();
    let mut command = Command::new(std::env::current_exe().expect("test binary"));
    command
        .args(["--exact", FORGED_GROUP_ROLE, "--nocapture"])
        .env(FORGED_GROUP_ENV, group.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let outcome = GuardianBootstrap::spawn(command)
        .expect("spawn authenticated adversarial Guardian")
        .register_until(Instant::now() + GUARDIAN_SHUTDOWN_DEADLINE);
    let refusal = outcome.as_ref().err().map(ToString::to_string);
    drop(outcome); // All owned-Guardian resources are released, including red cases.
    let survives = outsider
        .try_wait()
        .expect("inspect exactly owned outsider")
        .is_none();
    let _ = outsider.kill();
    outsider.wait().expect("reap exactly owned outsider");
    assert!(
        refusal
            .as_ref()
            .is_some_and(|message| message.contains("direct child")),
        "forged KGR1 must be rejected before group retention ACK: {refusal:?}"
    );
    assert!(
        survives,
        "host cleanup killed a separate test-owned process group"
    );
}

// KGC1 has the same native lineage boundary as KGR1. An authenticated
// Guardian is not authority to enroll an arbitrary same-user process group
// into the host's later SIGKILL fail-safe.
const FORGED_KGC1_ENV: &str = "KELD_TEST_KGC1_FOREIGN_GROUP";
const FORGED_KGC1_WITNESS_ENV: &str = "KELD_TEST_KGC1_FOREIGN_WITNESS";
const FORGED_KGC1_ROLE: &str =
    "macos_guardian::tests::rejected_registration_deadline::forged_kgc1_guardian_role";

#[test]
fn forged_kgc1_guardian_role() {
    let Some(group) = std::env::var_os(FORGED_KGC1_ENV) else {
        return;
    };
    let group: u32 = group
        .to_str()
        .expect("group pid UTF-8")
        .parse()
        .expect("pid");
    let link = std::env::var(REGISTRATION_ENV).expect("authenticated KGC1 link");
    let (endpoint, token) = parse_app_link(&link).expect("one-use private link");
    let mut control = UnixStream::connect(endpoint).expect("connect private control");
    handshake_client(&mut control, &token).expect("authenticate genuine Guardian link");
    control
        .set_read_timeout(Some(GUARDIAN_SHUTDOWN_DEADLINE))
        .expect("bound rejection observation");
    write_generation_control(
        &mut control,
        &GenerationControlRecord::new(CONTROL_PREPARE, 1),
    )
    .expect("request genuine host generation");
    let prepared = read_generation_control(&mut control).expect("actual host prepare");
    assert_eq!((prepared.kind, prepared.attempt), (CONTROL_PREPARED, 1));
    assert!(
        !prepared.payload.is_empty(),
        "host minted real provisional lease"
    );
    write_generation_control(
        &mut control,
        &GenerationControlRecord::new(CONTROL_SPAWNED, 1).with_pid(group),
    )
    .expect("submit deliberately foreign group");
    let response = read_generation_control(&mut control);
    assert!(
        response.is_err(),
        "host must not send REGISTERED for an unrelated group: {:?}",
        response.map(|record| (record.kind, record.attempt))
    );
    let socket = std::env::var_os(FORGED_KGC1_WITNESS_ENV).expect("controller witness link");
    let mut witness = UnixStream::connect(socket).expect("connect host rejection witness");
    writeln!(witness, "DENIED {group}").expect("report actual failed REGISTERED read");
    // Stay alive until the host observes its control worker's denial.
    let mut byte = [0_u8; 1];
    assert_eq!(
        io::stdin().read(&mut byte).expect("read terminal host EOF"),
        0,
        "rejected KGC1 Guardian must never receive a release byte"
    );
}

struct TestOwnedOutsider(std::process::Child);

impl Drop for TestOwnedOutsider {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn authenticated_kgc1_cannot_enroll_or_kill_unrelated_live_process_group() {
    let temp = tempfile::tempdir().expect("owned KGC1 witness fixture");
    let witness_path = temp.path().join("denied.sock");
    let listener = UnixListener::bind(&witness_path).expect("private KGC1 witness socket");
    listener
        .set_nonblocking(true)
        .expect("bounded witness accept");
    let mut outsider = TestOwnedOutsider(
        Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn private test-owned outsider process group"),
    );
    let group = outsider.0.id();
    assert_eq!(
        nix::unistd::getpgid(Some(Pid::from_raw(i32::try_from(group).expect("pid fits")))),
        Ok(Pid::from_raw(i32::try_from(group).expect("pid fits"))),
        "native outsider must be its own group leader"
    );
    let mut command = Command::new(std::env::current_exe().expect("unit-test binary"));
    command
        .args(["--exact", FORGED_KGC1_ROLE, "--nocapture"])
        .env(FORGED_KGC1_ENV, group.to_string())
        .env(FORGED_KGC1_WITNESS_ENV, &witness_path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let mut primary = GuardianBootstrap::spawn_supervised(command)
        .expect("spawn authenticated adversarial Guardian")
        .register_guarded_primary_until(Instant::now() + GUARDIAN_SHUTDOWN_DEADLINE)
        .expect("retain genuine KGC1 Guardian before hostile SPAWNED");
    let deadline = Instant::now() + GUARDIAN_SHUTDOWN_DEADLINE;
    let refusal = loop {
        match primary.poll_fatal() {
            Ok(()) if Instant::now() < deadline => thread::yield_now(),
            Ok(()) => panic!("host accepted foreign KGC1 group without terminating the worker"),
            Err(error) => break error.to_string(),
        }
    };
    // First observe the product's effect. The test-owned rescue runs only
    // after this observation and cannot make a dead outsider count as alive.
    let outsider_survived = outsider
        .0
        .try_wait()
        .expect("inspect exactly owned outsider")
        .is_none();
    let no_registered_group = primary.group_pid().is_none();
    // The independent Guardian role must have observed the actual missing
    // REGISTERED wire response, not merely the host's own error string.
    let witness = await_denial_witness(&listener, deadline);
    primary.liveness_writer.take();
    let status = loop {
        match primary
            .child
            .try_wait()
            .expect("inspect authentic Guardian role")
        {
            Some(status) => break status,
            None if Instant::now() < deadline => thread::yield_now(),
            None => {
                let _ = primary.child.kill();
                let _ = primary.child.wait();
                panic!("authentic Guardian role failed to exit on host EOF");
            }
        }
    };
    assert!(
        refusal.contains("direct child"),
        "untrusted KGC1 group must fail native lineage validation: {refusal}"
    );
    assert!(
        no_registered_group,
        "foreign group was retained as kill authority"
    );
    assert_eq!(
        witness,
        format!("DENIED {group}\n"),
        "Guardian wire denial witness"
    );
    assert!(
        status.success(),
        "authentic Guardian role failed its exact --exact assertions"
    );
    assert!(
        outsider_survived,
        "fatal Guardian cleanup signaled an unrelated test-owned process group"
    );
}
use super::long_running_command;

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
    let error = lifecycle_error(
        "macOS guardian synthetic registration rejection",
        io::Error::new(io::ErrorKind::PermissionDenied, "refused registration"),
    );
    let rendered = assert_guardian_cleanup_bounded(guardian_pid, move || {
        Some(reject_host_registration(child, writer, error).to_string())
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
    let mut guardian = guardian_command
        .spawn()
        .expect("successful guardian stand-in");
    let writer = guardian.stdin.take().expect("sole liveness writer");
    fcntl(&writer, FcntlArg::F_SETFD(FdFlag::empty())).expect("force registered-owner rejection");
    let identity = super::super::process_group::observe_group_identity(group_pid)
        .expect("test-owned group identity before FD failure");
    let error = HostGuardian::from_registered_parts(guardian, writer, None, identity)
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
    assert!(
        retired,
        "rejected Guardian status zero stranded its enrolled Bun group"
    );
}
