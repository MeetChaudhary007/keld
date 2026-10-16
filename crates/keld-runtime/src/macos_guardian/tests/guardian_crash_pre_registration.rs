// Real macOS processes, using the shipping GuardedPrimary registration path.
// The separate Guardian dies from SIGKILL while Bun's pre-exec gate is held.
use std::io::{self, Read as _, Write as _};
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::{Pid, getpgid};

use super::super::{
    GUARDIAN_SHUTDOWN_DEADLINE, GuardedPrimary, GuardianBootstrap, run_guarded_primary,
};

const CRASH_ROLE_ENV: &str = "KELD_TEST_PREEXEC_GUARDIAN_ROLE";
const CRASH_MARKER_ENV: &str = "KELD_TEST_PREEXEC_BUN_MARKER";
const CRASH_GATE_ENV: &str = "KELD_TEST_GUARDIAN_PREEXEC_GATE";
const CRASH_BUN_ENV: &str = "KELD_TEST_GUARDIAN_BUN_BINARY";
const CRASH_ROLE_TEST: &str =
    "macos_guardian::tests::guardian_crash_pre_registration::guarded_preexec_guardian_role";

#[test]
fn guarded_preexec_guardian_role() {
    if std::env::var_os(CRASH_ROLE_ENV).is_none() {
        return;
    }
    let marker = std::env::var_os(CRASH_MARKER_ENV).expect("Bun marker path");
    let script = r#"
const { spawn } = require("node:child_process");
const { writeFileSync } = require("node:fs");
const descendant = spawn("/bin/sleep", ["60"], { stdio: "ignore" });
if (!descendant.pid) process.exit(70);
writeFileSync(process.env.KELD_TEST_PREEXEC_BUN_MARKER, `${process.pid} ${descendant.pid}`);
setInterval(() => {}, 1000);
"#;
    let bun = std::env::var_os(CRASH_BUN_ENV).expect("verified real Bun executable path");
    if let Err(error) = run_guarded_primary(
        io::stdin().lock(),
        move |_| {
            let mut command = Command::new(&bun);
            command
                .args(["-e", script])
                .env(CRASH_MARKER_ENV, &marker)
                .stdin(Stdio::null());
            Ok(command)
        },
        io::stdout(),
    ) {
        eprintln!("KELD_TEST_PREEXEC_GUARDIAN_FAILURE: {error}");
    }
}

fn verified_real_bun() -> std::path::PathBuf {
    let explicit = std::env::var_os("BUN_BIN").map(std::path::PathBuf::from);
    let on_path = std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join("bun"))
            .find(|candidate| candidate.is_file())
    });
    let installed = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .map(|home| home.join(".bun/bin/bun"))
        .filter(|candidate| candidate.is_file());
    let bun = explicit
        .or(on_path)
        .or(installed)
        .expect("real Bun binary required for macOS guardian crash proof");
    let version = Command::new(&bun)
        .arg("--version")
        .output()
        .expect("execute real Bun preflight");
    assert!(
        version.status.success(),
        "real Bun version preflight failed: {version:?}"
    );
    bun
}

struct GuardianCrashFixture {
    primary: GuardedPrimary,
    group_pid: Option<i32>,
}

impl Drop for GuardianCrashFixture {
    fn drop(&mut self) {
        // The failure cleanup is intentionally separate from assertions and
        // can only signal a verified, test-owned process group.
        let _ = self.primary.child.kill();
        let _ = self.primary.poll_fatal();
        if let Some(group) = self.group_pid {
            let pid = Pid::from_raw(group);
            if getpgid(Some(pid)) == Ok(pid) {
                let _ = nix::sys::signal::killpg(pid, Signal::SIGKILL);
            }
        }
    }
}

fn guard_crash_fixture(
    socket: &std::path::Path,
    marker: &std::path::Path,
    bun: &std::path::Path,
) -> GuardianCrashFixture {
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args(["--exact", CRASH_ROLE_TEST, "--nocapture"])
        .env(CRASH_ROLE_ENV, "guardian")
        .env(CRASH_GATE_ENV, socket)
        .env(CRASH_BUN_ENV, bun)
        .env(CRASH_MARKER_ENV, marker)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .process_group(0);
    let pending = GuardianBootstrap::spawn_supervised(command).expect("actual guardian bootstrap");
    let primary = pending
        .register_guarded_primary_until(Instant::now() + GUARDIAN_SHUTDOWN_DEADLINE)
        .expect("actual authenticated Guardian control bootstrap");
    GuardianCrashFixture {
        primary,
        group_pid: None,
    }
}

fn await_spawned_gate(
    listener: &std::os::unix::net::UnixListener,
) -> (std::os::unix::net::UnixStream, i32, u32) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(GUARDIAN_SHUTDOWN_DEADLINE))
                    .expect("bounded PID receipt");
                let mut bytes = [0_u8; 80];
                let count = stream.read(&mut bytes).expect("read gated PID");
                let receipt = std::str::from_utf8(&bytes[..count]).expect("UTF-8 PID receipt");
                let mut words = receipt.split_whitespace();
                assert_eq!(words.next(), Some("SPAWNED"), "{receipt}");
                let pid: i32 = words.next().expect("process group").parse().expect("PID");
                let guardian: u32 = words.next().expect("Guardian PID").parse().expect("PID");
                assert!(words.next().is_none(), "unexpected gate receipt: {receipt}");
                assert!(pid > 1 && pid != nix::unistd::getpgrp().as_raw());
                // Separate reporter authenticates its own PID; the controller
                // checks Guardian identity and process-group membership below.
                assert!(guardian > 1);
                return (stream, pid, guardian);
            }
            Err(source) if source.kind() == io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "Guardian never reached pre-exec gate"
                );
                thread::sleep(Duration::from_millis(3));
            }
            Err(source) => panic!("accept pre-exec PID: {source}"),
        }
    }
}

fn group_and_child_gone(group: i32, descendant: Option<i32>) {
    let deadline = Instant::now() + GUARDIAN_SHUTDOWN_DEADLINE;
    loop {
        let gone = matches!(
            kill(Pid::from_raw(-group), None),
            Err(nix::errno::Errno::ESRCH)
        ) && matches!(
            kill(Pid::from_raw(group), None),
            Err(nix::errno::Errno::ESRCH)
        ) && descendant.is_none_or(|pid| {
            matches!(
                kill(Pid::from_raw(pid), None),
                Err(nix::errno::Errno::ESRCH)
            )
        });
        if gone {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Bun group or descendant survived Guardian SIGKILL"
        );
        thread::sleep(Duration::from_millis(3));
    }
}

fn real_guardian_crash_at_gate(release_registration: bool) {
    let bun = verified_real_bun();
    let temp = tempfile::tempdir().expect("isolated crash fixture");
    let socket = temp.path().join("preexec.sock");
    let marker = temp.path().join("bun-and-descendant.pid");
    let listener = std::os::unix::net::UnixListener::bind(&socket).expect("test event socket");
    listener
        .set_nonblocking(true)
        .expect("bounded event accept");
    let mut fixture = guard_crash_fixture(&socket, &marker, &bun);
    let (mut gate, group, reported_guardian) = await_spawned_gate(&listener);
    assert_eq!(
        reported_guardian,
        fixture.primary.guardian_pid(),
        "unrelated PID cannot supply Guardian's gate receipt"
    );
    fixture.group_pid = Some(group);
    assert_eq!(
        getpgid(Some(Pid::from_raw(group))),
        Ok(Pid::from_raw(group)),
        "pre-exec child owns the isolated group"
    );
    assert_eq!(
        fixture.primary.group_pid(),
        None,
        "no premature registration"
    );
    assert!(
        !marker.exists(),
        "Bun executed before the host owned its group"
    );
    let mut descendant = None;
    if release_registration {
        gate.write_all(b"R").expect("permit host registration");
        let deadline = Instant::now() + GUARDIAN_SHUTDOWN_DEADLINE;
        while fixture.primary.group_pid() != Some(group.cast_unsigned()) {
            fixture
                .primary
                .poll_fatal()
                .expect("registered Guardian healthy");
            assert!(Instant::now() < deadline, "group was not registered");
            thread::yield_now();
        }
        let ids = loop {
            if let Ok(contents) = std::fs::read_to_string(&marker) {
                let ids: Vec<i32> = contents
                    .split_whitespace()
                    .filter_map(|part| part.parse().ok())
                    .collect();
                if ids.len() == 2 {
                    break ids;
                }
            }
            assert!(Instant::now() < deadline, "real Bun did not execute");
            thread::yield_now();
        };
        assert_eq!(ids[0], group);
        assert_eq!(
            getpgid(Some(Pid::from_raw(ids[1]))),
            Ok(Pid::from_raw(group))
        );
        descendant = Some(ids[1]);
    }
    // SIGKILL is directed only at the independently spawned Guardian. Before
    // registration, the permit pipe must close promptly through EOF, rather
    // than making this test pass after the separate five-second poll timeout.
    let killed_at = Instant::now();
    fixture.primary.child.kill().expect("SIGKILL real Guardian");
    let deadline = Instant::now() + GUARDIAN_SHUTDOWN_DEADLINE;
    let error = loop {
        match fixture.primary.poll_fatal() {
            Ok(()) => {
                assert!(Instant::now() < deadline, "host missed Guardian SIGKILL");
                thread::yield_now();
            }
            Err(error) => break error,
        }
    };
    assert!(error.to_string().contains("guardian"), "{error}");
    group_and_child_gone(group, descendant);
    if !release_registration {
        assert!(
            killed_at.elapsed() < Duration::from_secs(3),
            "pre-exec child survived Guardian SIGKILL until its polling deadline; permit writer leaked into child"
        );
        assert!(!marker.exists(), "unregistered Bun was allowed to execute");
    }
    fixture.group_pid = None;
}

#[test]
fn real_guardian_sigkill_before_registration_cannot_run_bun_or_descendants() {
    real_guardian_crash_at_gate(false);
}

#[test]
fn real_guardian_sigkill_after_registration_reaps_bun_and_descendants() {
    real_guardian_crash_at_gate(true);
}
