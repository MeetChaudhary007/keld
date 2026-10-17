use std::fs::File;
use std::io::{self, Read as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::sys::signal::kill;
use nix::unistd::{Pid, pipe};

pub(super) fn long_running_command() -> Command {
    let mut command = Command::new("/usr/bin/tail");
    command
        .args(["-f", "/dev/null"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    command
}

pub(super) fn liveness_pipe() -> (File, File) {
    let (reader, writer) = pipe().expect("create host-liveness pipe");
    fcntl(&reader, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
        .expect("make liveness reader non-inheritable");
    fcntl(&writer, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
        .expect("make liveness writer non-inheritable");
    (File::from(reader), File::from(writer))
}

pub(super) fn assert_gone(pid: Option<u32>) {
    let pid = pid.expect("child registered");
    let pid = i32::try_from(pid).expect("pid fits i32");
    assert_eq!(kill(Pid::from_raw(pid), None), Err(Errno::ESRCH));
}

/// Resolve the actual Bun executable for multiple native Guardian crash cuts.
/// No shell stand-in can prove the pre-exec/descendant security contract.
pub(super) fn verified_real_bun() -> std::path::PathBuf {
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

/// Actual test-only reporter receipt from `SpawnAdmission`, before the
/// authenticated KGR1/KGC1 registration exchange. Both crash scenarios use
/// this observer; the product still owns the pre-exec child and permit.
pub(super) fn await_spawned_gate(listener: &UnixListener) -> (UnixStream, i32, u32) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_nonblocking(true)
                    .expect("bounded record observer");
                let record_deadline = Instant::now() + Duration::from_secs(5);
                let mut bytes = Vec::with_capacity(80);
                loop {
                    let mut byte = [0_u8; 1];
                    match stream.read(&mut byte) {
                        Ok(1) if byte[0] == b'\n' => break,
                        Ok(1) => {
                            bytes.push(byte[0]);
                            assert!(bytes.len() <= 80, "bounded native PID record");
                        }
                        Ok(0) => panic!("truncated native pre-exec PID record"),
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                            ) => {}
                        Err(error) => panic!("read pre-exec PID receipt: {error}"),
                        Ok(_) => unreachable!("one-byte receipt read"),
                    }
                    assert!(
                        Instant::now() < record_deadline,
                        "pre-exec PID receipt exceeded its total deadline"
                    );
                    thread::yield_now();
                }
                let receipt = std::str::from_utf8(&bytes).expect("UTF-8 PID receipt");
                let mut words = receipt.split_whitespace();
                assert_eq!(words.next(), Some("SPAWNED"), "{receipt}");
                let pid: i32 = words.next().expect("process group").parse().expect("PID");
                let guardian: u32 = words.next().expect("Guardian PID").parse().expect("PID");
                assert!(words.next().is_none(), "unexpected gate receipt: {receipt}");
                assert!(pid > 1 && pid != nix::unistd::getpgrp().as_raw());
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

/// Native process-image oracle, independent of JS startup and marker writes.
/// Used only with a previously observed, test-owned live child PID.
pub(super) fn kernel_process_image(pid: i32) -> String {
    let output = Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
        .expect("read native process image");
    assert!(
        output.status.success(),
        "kernel could not inspect owned PID {pid}"
    );
    let image = String::from_utf8(output.stdout).expect("native image path is UTF-8");
    assert!(
        !image.trim().is_empty(),
        "owned PID {pid} has no process image"
    );
    image.trim().to_owned()
}
