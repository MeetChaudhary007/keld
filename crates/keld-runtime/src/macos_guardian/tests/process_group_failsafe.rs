// Group-leader disappearance does not establish group disappearance. An
// unrelated process in the same private group can outlive the original leader.
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};

use nix::errno::Errno;
use nix::sys::signal::kill;
use nix::unistd::Pid;

use super::super::process_group::{
    finish_group_termination, terminate_registered_group, validate_guardian_child_group,
};

#[test]
fn foreign_group_is_not_a_guardian_owned_direct_child() {
    let mut group = Command::new("/bin/sleep")
        .arg("30")
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn private, test-owned foreign group");
    let group_pid = group.id();
    let actual_parent = std::process::id();
    let own_child = validate_guardian_child_group(group_pid, actual_parent);
    let forged_parent = validate_guardian_child_group(group_pid, u32::MAX);
    // Reap the test-owned process before any assertion, including red cases.
    group.kill().expect("kill exact test-owned child");
    group.wait().expect("reap exact test-owned child");
    own_child.expect("kernel identifies this actual direct child");
    let error = forged_parent.expect_err("an unrelated Guardian must not own this group");
    assert!(error.to_string().contains("direct child"), "{error}");
}

#[test]
fn reaped_leader_does_not_mask_live_process_group_when_signal_is_denied() {
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "sleep 25 >/dev/null 2>&1 & exit 0"])
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut leader = command.spawn().expect("private process group leader");
    let group_pid = leader.id();
    let raw_group = i32::try_from(group_pid).expect("group ID fits signed PID");
    assert!(leader.wait().expect("reap shell group leader").success());

    // Real macOS group state refutes the old getpgid(leader) heuristic.
    let leader_gone = nix::unistd::getpgid(Some(Pid::from_raw(raw_group)));
    let group_probe = kill(Pid::from_raw(-raw_group), None);
    let outcome = finish_group_termination(Err(Errno::EPERM), || group_probe);
    // Clean the isolated process group even if an assertion below fails.
    let cleanup = terminate_registered_group(group_pid);
    assert_eq!(leader_gone, Err(Errno::ESRCH));
    assert_eq!(group_probe, Ok(()), "descendant still owns group");
    assert!(
        outcome.is_err(),
        "EPERM cannot be suppressed for a live group"
    );
    cleanup.expect("reap isolated test process group");
}

#[test]
fn denied_group_signal_is_only_ignorable_after_group_absence_proof() {
    assert!(finish_group_termination(Err(Errno::EPERM), || Err(Errno::ESRCH)).is_ok());
    assert!(finish_group_termination(Err(Errno::EPERM), || Err(Errno::EPERM)).is_err());
    assert!(finish_group_termination(Err(Errno::EPERM), || Ok(())).is_err());
    assert!(finish_group_termination(Err(Errno::EIO), || Err(Errno::ESRCH)).is_err());
}
