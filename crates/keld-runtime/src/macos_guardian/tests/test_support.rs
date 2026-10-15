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
