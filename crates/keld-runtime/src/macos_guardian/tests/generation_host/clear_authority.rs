//! A forged/early authenticated KGC1 CLEAR cannot discard a live Bun group.
//! The host must exercise its own attested native fail-safe before CLEARED.
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::signal::{Signal, kill, killpg};
use nix::unistd::{Pid, getpgid};

use super::super::super::process_group::observe_group_identity;
use super::super::super::{handshake_client, parse_app_link};
use super::super::test_support::verified_real_bun;
use super::{
    CONTROL_CLEAR, CONTROL_CLEARED, CONTROL_PREPARE, CONTROL_PREPARED, CONTROL_REGISTERED,
    CONTROL_REVOKE, CONTROL_REVOKED, CONTROL_SPAWNED, GenerationControlRecord,
    GuardedPrimaryUpdate, RecoveryState, RevocationCause, guardian_exchange, lock_recovery,
    start_generation_host_fixture,
};

struct NativeBunGroup {
    leader: Child,
    descendant: Option<i32>,
}

impl Drop for NativeBunGroup {
    fn drop(&mut self) {
        let group = Pid::from_raw(i32::try_from(self.leader.id()).expect("native group ID"));
        let live_leader = getpgid(Some(group)) == Ok(group);
        let live_descendant = self
            .descendant
            .is_some_and(|pid| getpgid(Some(Pid::from_raw(pid))) == Ok(group));
        if group != nix::unistd::getpgrp() && (live_leader || live_descendant) {
            let _ = killpg(group, Signal::SIGKILL);
        }
        let _ = self.leader.kill();
        let _ = self.leader.wait();
    }
}

fn await_bun_descendant(marker: &std::path::Path) -> i32 {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(contents) = std::fs::read_to_string(marker)
            && let Ok(pid) = contents.trim().parse::<i32>()
        {
            return pid;
        }
        assert!(
            Instant::now() < deadline,
            "real Bun never spawned its group descendant"
        );
        std::thread::yield_now();
    }
}

fn start_real_bun_group(marker: &std::path::Path) -> NativeBunGroup {
    let bun = verified_real_bun();
    let script = r#"
const { spawn } = require("node:child_process");
const { writeFileSync } = require("node:fs");
const child = spawn("/bin/sleep", ["30"], { stdio: "ignore" });
if (!child.pid) process.exit(72);
writeFileSync(process.env.KELD_CLEAR_TEST_DESCENDANT, String(child.pid));
setInterval(() => {}, 1000);
"#;
    let mut command = Command::new(bun);
    command
        .args(["-e", script])
        .env("KELD_CLEAR_TEST_DESCENDANT", marker)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    NativeBunGroup {
        leader: command.spawn().expect("spawn real isolated Bun leader"),
        descendant: None,
    }
}

fn descendant_gone(pid: i32) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while kill(Pid::from_raw(pid), None) != Err(Errno::ESRCH) {
        assert!(
            Instant::now() < deadline,
            "Bun descendant escaped the host's CLEAR fail-safe"
        );
        std::thread::yield_now();
    }
}

#[test]
fn early_kgc1_clear_reaps_live_bun_and_same_group_descendant_before_cleared() {
    let root = tempfile::tempdir().expect("owned native Bun/CLEAR test root");
    let marker = root.path().join("descendant.pid");
    let mut owned = start_real_bun_group(&marker);
    let group_pid = owned.leader.id();
    let group = Pid::from_raw(i32::try_from(group_pid).expect("group pid fits"));
    let descendant = await_bun_descendant(&marker);
    owned.descendant = Some(descendant);
    assert_eq!(
        getpgid(Some(Pid::from_raw(descendant))),
        Ok(group),
        "real Bun descendant belongs to the exact registered process group"
    );
    observe_group_identity(group_pid).expect("kernel still holds original Bun leader birth");
    assert!(
        owned
            .leader
            .try_wait()
            .expect("inspect real Bun before CLEAR")
            .is_none(),
        "premature Bun exit cannot satisfy the forged CLEAR negative control"
    );

    let (host, mut guardian) = UnixStream::pair().expect("private KGC1 generation-control pair");
    guardian
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("bounded real Guardian read");
    let (updates_tx, updates_rx) = mpsc::channel::<GuardedPrimaryUpdate>();
    let current = Arc::new(Mutex::new(None));
    let recovery = Arc::new(Mutex::new(RecoveryState::new()));
    lock_recovery(&recovery).arm();
    let host_worker = start_generation_host_fixture(
        host,
        updates_tx,
        Arc::clone(&current),
        Arc::clone(&recovery),
    );
    let prepared = guardian_exchange(
        &mut guardian,
        &GenerationControlRecord::new(CONTROL_PREPARE, 1),
        CONTROL_PREPARED,
    );
    let app_link = String::from_utf8(prepared.payload).expect("actual host-minted link");
    guardian_exchange(
        &mut guardian,
        &GenerationControlRecord::new(CONTROL_SPAWNED, 1).with_pid(group_pid),
        CONTROL_REGISTERED,
    );
    let (endpoint, token) = parse_app_link(&app_link).expect("authenticated link contents");
    let mut app = UnixStream::connect(endpoint).expect("connect real generation app link");
    handshake_client(&mut app, &token).expect("authenticate actual generation before revoke");
    let bound = loop {
        match updates_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("receive actual bounded generation authentication")
        {
            GuardedPrimaryUpdate::Bound(bound) => break bound,
            GuardedPrimaryUpdate::Role(_) => {}
        }
    };
    assert_eq!(
        bound.attempt(),
        1,
        "host must really bind the admitted Bun generation"
    );
    guardian_exchange(
        &mut guardian,
        &GenerationControlRecord::new(CONTROL_REVOKE, 1)
            .with_cause(RevocationCause::AdmissionFailed),
        CONTROL_REVOKED,
    );
    assert!(
        owned
            .leader
            .try_wait()
            .expect("inspect live group after REVOKE")
            .is_none(),
        "REVOKED alone must not be miscounted as native group termination"
    );
    // Compromised/buggy Guardian falsely claims CLEAR despite still-live Bun
    // and descendant. Without the production CLEAR fail-safe, this receives
    // CLEARED while both continue to execute (failure-first negative oracle).
    guardian_exchange(
        &mut guardian,
        &GenerationControlRecord::new(CONTROL_CLEAR, 1).with_pid(group_pid),
        CONTROL_CLEARED,
    );
    let leader_status = owned.leader.wait().expect("host cleared native Bun group");
    descendant_gone(descendant);
    assert_eq!(
        leader_status.signal(),
        Some(9),
        "host must SIGKILL still-live Bun at CLEAR"
    );
    assert!(current.lock().expect("current generation mutex").is_none());
    lock_recovery(&recovery).deny();
    drop(bound);
    drop(app);
    drop(guardian);
    // This is a negative control; terminating authenticated control mid-run
    // may be an unattributed EOF. Do not count a failed worker as a clean exit.
    let _ = host_worker
        .join()
        .expect("host control worker joins after test shutdown");
}
