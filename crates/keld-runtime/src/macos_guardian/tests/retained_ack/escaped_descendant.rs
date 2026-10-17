//! Separate negative OS boundary: Bun can deliberately spawn a process in a
//! new session/group. A Guardian's verified original killpg cannot terminate
//! this new group without acquiring an independent kernel custody mechanism.
use std::io::Write as _;
use std::os::unix::net::UnixListener;
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use nix::sys::signal::kill;
use nix::unistd::{Pid, getpgid};

use super::super::super::process_group::{
    GroupIdentity, observe_group_identity, terminate_attested_group,
};
use super::{
    BUN_ENV, CUT_ENV, ESCAPE_ENV, MARKER_ENV, RetainedCut, group_gone, process_role, read_marker,
    receive_event, verified_real_bun,
};

struct EscapedTestGroup {
    marker: PathBuf,
    observed: Option<GroupIdentity>,
}

impl Drop for EscapedTestGroup {
    fn drop(&mut self) {
        // If a test fails before reading the marker, attempt ownership
        // recovery from the *private test-owned file*, not process-name grep.
        let group = self.observed.or_else(|| {
            std::fs::read_to_string(&self.marker)
                .ok()
                .and_then(|text| text.split_whitespace().nth(1)?.parse::<u32>().ok())
                .and_then(|pid| observe_group_identity(pid).ok())
        });
        if let Some(group) = group {
            let _ = terminate_attested_group(group);
        }
    }
}

#[test]
fn detached_bun_descendant_outlives_ordinary_guardian_group_reap() {
    let bun = verified_real_bun();
    let temp = tempfile::tempdir().expect("private detached-group fixture");
    let socket = temp.path().join("private-ack.sock");
    let marker = temp.path().join("actual-detached-child.pid");
    let mut escaped = EscapedTestGroup {
        marker: marker.clone(),
        observed: None,
    };
    let listener = UnixListener::bind(&socket).expect("owned control events");
    listener
        .set_nonblocking(true)
        .expect("bound event observation");
    let mut command = process_role("host");
    command
        .env(CUT_ENV, &socket)
        .env(MARKER_ENV, &marker)
        .env(BUN_ENV, bun)
        .env(ESCAPE_ENV, "1")
        .process_group(0)
        .stderr(Stdio::inherit());
    let host = command.spawn().expect("real host for native Guardian");
    let host_group = i32::try_from(host.id()).expect("test host PGID");
    assert_ne!(Pid::from_raw(host_group), nix::unistd::getpgrp());
    let mut cut = RetainedCut {
        host: Some(host),
        host_group,
        guardian: None,
        group: None,
        descendant: None, // Escaped descendant has a distinct owned cleanup guard.
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    let (mut gate, receipt) = receive_event(&listener, deadline);
    let parts: Vec<&str> = receipt.split_whitespace().collect();
    assert_eq!(parts.len(), 4, "{receipt}");
    assert_eq!(parts[0], "RETAINED");
    let group: u32 = parts[1].parse().expect("registered Bun group");
    let guardian: u32 = parts[2].parse().expect("actual Guardian PID");
    let host_pid: u32 = parts[3].parse().expect("actual host PID");
    assert_eq!(cut.host.as_ref().expect("owned host").id(), host_pid);
    let raw_group = i32::try_from(group).expect("Bun group ID");
    let raw_guardian = i32::try_from(guardian).expect("Guardian PID");
    cut.group = Some(raw_group);
    cut.guardian = Some(raw_guardian);
    gate.write_all(b"R")
        .expect("release authenticated host-retention ACK");
    let (bun_pid, detached_pid) = read_marker(&marker, deadline);
    assert_eq!(bun_pid, raw_group, "Bun leads its own registered group");
    assert_ne!(detached_pid, raw_group, "actual detached child identity");
    let independent_session = getpgid(Some(Pid::from_raw(detached_pid)))
        .expect("detached real Bun descendant still live");
    assert_eq!(
        independent_session,
        Pid::from_raw(detached_pid),
        "Bun created a new session/group rather than an ordinary descendant"
    );
    escaped.observed = Some(
        observe_group_identity(u32::try_from(detached_pid).expect("positive detached PID"))
            .expect("native kernel records the detached leader's birth"),
    );
    let mut host = cut.host.take().expect("own actual host Child");
    host.kill()
        .expect("SIGKILL real host while Guardian is live");
    assert_eq!(host.wait().expect("reap test host").signal(), Some(9));
    let (_completed, witness) = receive_event(&listener, Instant::now() + Duration::from_secs(10));
    assert_eq!(
        witness,
        format!("GUARDIAN_DONE {guardian} OK"),
        "the real Guardian still correctly reaps its registered Bun group"
    );
    group_gone(raw_group, None, raw_guardian);
    // The product must not claim this still-live escaped group was contained.
    // Inspect BEFORE EscapedTestGroup Drop sends its independent rescue.
    assert!(
        kill(Pid::from_raw(detached_pid), None).is_ok()
            && getpgid(Some(Pid::from_raw(detached_pid))) == Ok(independent_session),
        "a process that left Bun's PGID cannot be accounted for by the original killpg"
    );
    cut.guardian = None;
    cut.group = None;
}
