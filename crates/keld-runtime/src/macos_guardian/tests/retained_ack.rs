//! Real KGR1 host-retained-before-ACK cut through the shipping registration path.
//! A withheld host acknowledgment must never let Bun or its descendant exec.
use std::io::{self, Read as _, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, killpg};
use nix::unistd::{Pid, getpgid};

use super::super::process_group::validate_guardian_child_group;
use super::super::{GUARDIAN_SHUTDOWN_DEADLINE, GuardianBootstrap, run};
use super::test_support::{kernel_process_image, verified_real_bun};

mod dual_death;
mod escaped_descendant;
mod observers;
use self::observers::{group_gone, observe_pre_ack_image, read_marker, receive_event};

const ROLE_ENV: &str = "KELD_TEST_KGR1_RETAINED_ACK_ROLE";
const CUT_ENV: &str = "KELD_TEST_KGR1_RETAINED_ACK_SOCKET";
const MARKER_ENV: &str = "KELD_TEST_KGR1_RETAINED_ACK_MARKER";
const BUN_ENV: &str = "KELD_TEST_KGR1_RETAINED_ACK_BUN";
const ESCAPE_ENV: &str = "KELD_TEST_KGR1_DETACHED_DESCENDANT";
const ROLE_TEST: &str = "macos_guardian::tests::retained_ack::kgr1_retained_ack_process_role";

// Invoked ONLY in the Rust test build at bootstrap::register_until's real
// HostGuardian custody point. No alternate acknowledgment path or shipping
// environment feature exists. A disconnected controller denies the ACK.
pub(in crate::macos_guardian) fn hold_before_group_ack(
    group_pid: u32,
    guardian_pid: u32,
) -> io::Result<()> {
    let Some(socket) = std::env::var_os(CUT_ENV) else {
        return Ok(());
    };
    let mut stream = UnixStream::connect(socket)?;
    writeln!(
        stream,
        "RETAINED {group_pid} {guardian_pid} {}",
        std::process::id()
    )?;
    stream.set_nonblocking(true)?;
    let deadline = Instant::now() + GUARDIAN_SHUTDOWN_DEADLINE;
    loop {
        let mut release = [0_u8; 1];
        match stream.read(&mut release) {
            Ok(1) if release == *b"R" => return Ok(()),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "test custodian left",
                ));
            }
            Ok(1) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "test denied ACK",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
            Ok(_) => unreachable!("one-byte release buffer"),
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "test ACK fence exceeded deadline",
            ));
        }
        thread::yield_now();
    }
}

#[test]
fn kgr1_retained_ack_process_role() {
    let Some(role) = std::env::var_os(ROLE_ENV) else {
        return;
    };
    match role.to_str().expect("owned role is UTF-8") {
        "host" => {
            let mut command = process_role("guardian");
            command.stderr(Stdio::inherit());
            let bootstrap = GuardianBootstrap::spawn(command).expect("real private bootstrap");
            let _registered = bootstrap
                .register_until(Instant::now() + Duration::from_secs(10))
                .expect("complete real KGR1 ACK after controller release");
            thread::park(); // Only a real controller SIGKILL ends this host.
        }
        "guardian" => {
            let marker = std::env::var_os(MARKER_ENV).expect("Bun/descendant marker");
            let bun = std::env::var_os(BUN_ENV).expect("real Bun executable");
            let script = r#"
const { spawn } = require("node:child_process");
const { writeFileSync } = require("node:fs");
const descendant = spawn("/bin/sleep", ["60"], { stdio: "ignore" });
if (!descendant.pid) process.exit(70);
writeFileSync(process.env.KELD_TEST_KGR1_RETAINED_ACK_MARKER, `${process.pid} ${descendant.pid}`);
setInterval(() => {}, 1000);
"#;
            let escaped_script = r#"
const { spawn } = require("node:child_process");
const { writeFileSync } = require("node:fs");
const descendant = spawn("/bin/sleep", ["60"], { stdio: "ignore", detached: true });
if (!descendant.pid) process.exit(70);
writeFileSync(process.env.KELD_TEST_KGR1_RETAINED_ACK_MARKER, `${process.pid} ${descendant.pid}`);
setInterval(() => {}, 1000);
"#;
            let mut command = Command::new(bun);
            command
                .args([
                    "-e",
                    if std::env::var_os(ESCAPE_ENV).is_some() {
                        escaped_script
                    } else {
                        script
                    },
                ])
                .env(MARKER_ENV, marker);
            let result = run(command, io::stdin().lock(), || Ok(()));
            // A direct, native Guardian witness: success after a real ACK and
            // host EOF; rejection before ACK (no child image ever executed).
            let mut stream =
                UnixStream::connect(std::env::var_os(CUT_ENV).expect("controller event socket"))
                    .expect("notify controller of real Guardian completion");
            writeln!(
                stream,
                "GUARDIAN_DONE {} {}",
                std::process::id(),
                if result.is_ok() { "OK" } else { "ERR" }
            )
            .expect("publish Guardian completion");
        }
        other => panic!("unexpected test role {other}"),
    }
}

fn process_role(role: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("native libtest binary"));
    command
        .args(["--exact", ROLE_TEST, "--nocapture"])
        .env(ROLE_ENV, role)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    command
}

// Own test-created PIDs from their birth. Rescue never proves product success.
struct RetainedCut {
    host: Option<Child>,
    host_group: i32,
    guardian: Option<i32>,
    group: Option<i32>,
    descendant: Option<i32>,
}

impl Drop for RetainedCut {
    fn drop(&mut self) {
        if let Some(host) = self.host.as_mut() {
            let _ = host.kill();
            let _ = host.wait();
        }
        // The test host is the leader of its *own* isolated process group.
        // Its Guardian stays in that group, whereas Bun runs in a separate
        // group. Never SIGKILL a bare saved Guardian PID after its host died:
        // that numeric PID might have been recycled.
        let host_group = Pid::from_raw(self.host_group);
        if let Some(guardian) = self.guardian
            && host_group != nix::unistd::getpgrp()
            && getpgid(Some(Pid::from_raw(guardian))) == Ok(host_group)
        {
            let _ = killpg(host_group, Signal::SIGKILL);
        }
        if let Some(group) = self.group {
            let pid = Pid::from_raw(group);
            let actual_leader = getpgid(Some(pid)) == Ok(pid);
            let actual_descendant = self
                .descendant
                .is_some_and(|child| getpgid(Some(Pid::from_raw(child))) == Ok(pid));
            if (actual_leader || actual_descendant) && pid != nix::unistd::getpgrp() {
                let _ = killpg(pid, Signal::SIGKILL);
            }
        }
    }
}

fn native_retained_ack_cut(release_ack: bool) {
    let bun = verified_real_bun();
    let temp = tempfile::tempdir().expect("private retained-ACK fixture");
    let socket: PathBuf = temp.path().join("retained.sock");
    let marker: PathBuf = temp.path().join("bun-and-descendant.pid");
    let listener = UnixListener::bind(&socket).expect("owned test control socket");
    listener.set_nonblocking(true).expect("bounded accept loop");
    let mut host_command = process_role("host");
    host_command
        .env(CUT_ENV, &socket)
        .env(MARKER_ENV, &marker)
        .env(BUN_ENV, bun)
        .stderr(Stdio::inherit())
        .process_group(0);
    let host = host_command
        .spawn()
        .expect("start isolated real host subprocess");
    let host_group = i32::try_from(host.id()).expect("real host PGID fits");
    assert_eq!(
        getpgid(Some(Pid::from_raw(host_group))),
        Ok(Pid::from_raw(host_group)),
        "test host must own a separate cleanup process group"
    );
    let mut cut = RetainedCut {
        host: Some(host),
        host_group,
        guardian: None,
        group: None,
        descendant: None,
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    let (mut ack_fence, receipt) = receive_event(&listener, deadline);
    let parts: Vec<&str> = receipt.split_whitespace().collect();
    assert_eq!(parts.first().copied(), Some("RETAINED"), "{receipt}");
    assert_eq!(parts.len(), 4, "{receipt}");
    let group: u32 = parts[1].parse().expect("registered group");
    let guardian: u32 = parts[2].parse().expect("Guardian PID");
    let host: u32 = parts[3].parse().expect("host PID");
    assert_eq!(cut.host.as_ref().expect("host owner").id(), host);
    let group_i32 = i32::try_from(group).expect("native group PID");
    let guardian_i32 = i32::try_from(guardian).expect("native Guardian PID");
    cut.group = Some(group_i32);
    cut.guardian = Some(guardian_i32);
    assert_ne!(Pid::from_raw(group_i32), nix::unistd::getpgrp());
    validate_guardian_child_group(group, guardian)
        .expect("host-retained group is truly Guardian's live direct child");
    let original_image = observe_pre_ack_image(group_i32, &marker);

    if release_ack {
        ack_fence
            .write_all(b"R")
            .expect("release host's actual KGR1 ACK");
        let (bun_pid, descendant) = read_marker(&marker, deadline);
        cut.descendant = Some(descendant);
        assert_eq!(bun_pid, group_i32, "Bun is the registered group leader");
        assert_ne!(
            kernel_process_image(bun_pid),
            original_image,
            "the real ACK must permit the Bun executable image"
        );
        assert_eq!(
            getpgid(Some(Pid::from_raw(descendant))),
            Ok(Pid::from_raw(group_i32)),
            "real Bun descendant inherited the guarded native process group"
        );
    }
    let killed_at = Instant::now();
    let mut host = cut.host.take().expect("sole host subprocess owner");
    host.kill().expect("SIGKILL real host during held-ACK cut");
    assert_eq!(host.wait().expect("reap host child").signal(), Some(9));
    // Host death closes both its liveness writer and KGR1 stream. Before
    // ACK, the pre-exec child must deny and exit without any Bun code.
    let (_finished, witness) = receive_event(&listener, Instant::now() + Duration::from_secs(10));
    let expected = format!(
        "GUARDIAN_DONE {guardian} {}",
        if release_ack { "OK" } else { "ERR" }
    );
    assert_eq!(
        witness, expected,
        "real Guardian must finish its own shutdown"
    );
    group_gone(group_i32, cut.descendant, guardian_i32);
    if !release_ack {
        assert!(
            killed_at.elapsed() < Duration::from_secs(3),
            "host-death pre-exec denial waited for timeout, not KGR1 EOF"
        );
        assert!(!marker.exists(), "host died before ACK yet Bun executed");
    }
    cut.guardian = None;
    cut.group = None;
    cut.descendant = None;
}

#[test]
fn native_image_oracle_detects_bun_before_any_js_marker() {
    let bun = verified_real_bun();
    let temp = tempfile::tempdir().expect("owned empty marker fixture");
    let marker = temp.path().join("absent");
    let mut child = Command::new(bun)
        .args(["-e", "setInterval(() => {}, 1000)"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("actual unmarked Bun image");
    let pid = i32::try_from(child.id()).expect("Bun pid");
    let original_image = kernel_process_image(i32::try_from(std::process::id()).expect("PID"));
    let deadline = Instant::now() + GUARDIAN_SHUTDOWN_DEADLINE;
    let mut changed_image = false;
    while Instant::now() < deadline {
        if kernel_process_image(pid) != original_image {
            changed_image = true;
            break;
        }
        thread::yield_now();
    }
    let _ = child.kill();
    child.wait().expect("reap native Bun image probe");
    assert!(
        !marker.exists(),
        "image oracle test never asks Bun to write a JS marker"
    );
    assert!(
        changed_image,
        "native image oracle must catch exec without JS marker"
    );
}

#[test]
fn real_kgr1_host_sigkill_after_retention_before_ack_denies_bun_exec() {
    native_retained_ack_cut(false);
}

#[test]
fn real_kgr1_ack_release_permits_bun_descendant_then_host_death_reaps_group() {
    native_retained_ack_cut(true);
}
