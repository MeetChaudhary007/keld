// Group-leader disappearance does not establish group disappearance. An
// unrelated process in the same private group can outlive the original leader.
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
    assert!(outcome.is_err(), "EPERM cannot be suppressed for a live group");
    cleanup.expect("reap isolated test process group");
}

#[test]
fn denied_group_signal_is_only_ignorable_after_group_absence_proof() {
    assert!(finish_group_termination(Err(Errno::EPERM), || Err(Errno::ESRCH)).is_ok());
    assert!(finish_group_termination(Err(Errno::EPERM), || Err(Errno::EPERM)).is_err());
    assert!(finish_group_termination(Err(Errno::EPERM), || Ok(())).is_err());
    assert!(finish_group_termination(Err(Errno::EIO), || Err(Errno::ESRCH)).is_err());
}
