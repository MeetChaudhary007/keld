//! Exact-self native child custody and independently calibrated object census.
use super::super::super::ReapedRouterProbe;
use nix::errno::Errno;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::{Pid, getpgid, getpgrp, getpid};
use std::fs::{self, File};
use std::io::{self, Read as _, Seek as _, SeekFrom};
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

pub(super) use super::sensor::{calibrate_object_sensor, object_handle_count};

const CHILD_ENV: &str = "KELD_CORE_AC7_NATIVE_CHILD";
const ROOT_ENV: &str = "KELD_CORE_AC7_NATIVE_TMP_ROOT";
const CHILD_BOUND: Duration = Duration::from_secs(45);

struct NativeChild {
    process: ReapedRouterProbe,
    group: Pid,
    armed: bool,
}

impl NativeChild {
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self.process.0.try_wait()?;
        if status.is_some() {
            self.armed = false;
        }
        Ok(status)
    }

    fn reap(&mut self) -> io::Result<ExitStatus> {
        // Disarm before every reaping wait, including its error path.
        self.armed = false;
        self.process.0.wait()
    }

    fn stop_unreaped_group(&mut self) -> io::Result<ExitStatus> {
        // Only the owned, unreaped leader reserves this numerical identity.
        // Reaping permanently removes group-signalling authority.
        if self.armed {
            let _ = killpg(self.group, Signal::SIGKILL);
        }
        self.reap()
    }
}

impl Drop for NativeChild {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.stop_unreaped_group();
        }
    }
}

pub(super) fn is_native_child(case: &str) -> bool {
    if std::env::var(CHILD_ENV).ok().as_deref() != Some(case) {
        return false;
    }
    assert_eq!(
        getpgrp(),
        getpid(),
        "native child must own its isolated group"
    );
    let expected =
        fs::canonicalize(std::env::var_os(ROOT_ENV).expect("exact test child's parent-owned root"))
            .expect("canonical parent-owned root");
    let actual = fs::canonicalize(std::env::temp_dir()).expect("canonical child temp_dir");
    assert_eq!(
        actual, expected,
        "child did not use its parent's controlled temp root"
    );
    println!(
        "KELD_AC7_CHILD_STARTED case={case} pid={} group={} temp_root={}",
        getpid(),
        getpgrp(),
        actual.display()
    );
    true
}

pub(super) fn record_owned_caller(case: &str, child: &std::process::Child) {
    let pid = Pid::from_raw(i32::try_from(child.id()).expect("owned Bun PID fits i32"));
    let group = getpgid(Some(pid)).expect("inspect owned Bun group");
    assert_eq!(
        group,
        getpgrp(),
        "owned caller left the native child's group"
    );
    println!("KELD_AC7_OWNED_BUN case={case} pid={pid} group={group}");
}

fn captured(file: &mut File) -> String {
    file.seek(SeekFrom::Start(0))
        .expect("rewind native child log");
    let mut value = String::new();
    file.read_to_string(&mut value)
        .expect("read native child log");
    value
}

fn spawn_native_child(
    case: &str,
    selector: &str,
    root: &Path,
    stdout: &File,
    stderr: &File,
) -> NativeChild {
    let child = Command::new(std::env::current_exe().expect("exact native test binary"))
        .args([
            "--exact",
            selector,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, case)
        .env(ROOT_ENV, root)
        .env("TMPDIR", root)
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            stdout.try_clone().expect("native stdout clone"),
        ))
        .stderr(Stdio::from(
            stderr.try_clone().expect("native stderr clone"),
        ))
        .process_group(0)
        .spawn()
        .expect("spawn exact native proof child");
    let group = Pid::from_raw(i32::try_from(child.id()).expect("native PID fits i32"));
    let child = NativeChild {
        process: ReapedRouterProbe(child),
        group,
        armed: true,
    };
    assert_ne!(group, getpgrp(), "never signal the parent's group");
    assert_eq!(
        getpgid(Some(group)).expect("verify exact spawned group"),
        group,
        "native child group differs from its owned identity"
    );
    child
}

fn await_native_child(child: &mut NativeChild) -> (ExitStatus, bool) {
    let deadline = Instant::now() + CHILD_BOUND;
    loop {
        if let Some(status) = child.try_wait().expect("observe native child exit") {
            return (status, false);
        }
        if Instant::now() >= deadline {
            return (
                child
                    .stop_unreaped_group()
                    .expect("reap watchdog-stopped native child"),
                true,
            );
        }
        // Completion polling only; this deadline is a failure kill switch.
        std::thread::park_timeout(Duration::from_millis(10));
    }
}

struct NativeReport {
    status: ExitStatus,
    timed_out: bool,
    group_diagnostic: Result<(), Errno>,
    output: String,
    detail: String,
}

fn finish_case(
    case: &str,
    selector: &str,
    root: tempfile::TempDir,
    canonical_root: &Path,
    report: &NativeReport,
) {
    let normal_root_empty = fs::read_dir(canonical_root)
        .and_then(|mut entries| entries.next().transpose().map(|entry| entry.is_none()));
    // Preserve this normal-cleanup oracle before recursive parent fallback.
    let close = root.close();
    let absent = matches!(
        fs::symlink_metadata(canonical_root),
        Err(error) if error.kind() == io::ErrorKind::NotFound
    );
    let normal = !report.timed_out
        && report.group_diagnostic == Err(Errno::ESRCH)
        && report.status.success()
        && report
            .output
            .contains(&format!("KELD_AC7_CHILD_STARTED case={case} "))
        && report
            .output
            .contains(&format!("KELD_AC7_CASE_DONE case={case} "))
        && report
            .output
            .contains("test result: ok. 1 passed; 0 failed;");
    println!(
        "KELD_AC7_CHILD_CAPTURE selector={selector} status={:?} watchdog={} group_diagnostic={:?} normal_root_empty={normal_root_empty:?} parent_close={close:?} root_absent={absent}\nstdout={}\nstderr={}",
        report.status, report.timed_out, report.group_diagnostic, report.output, report.detail
    );
    assert!(
        normal && matches!(normal_root_empty, Ok(true)) && close.is_ok() && absent,
        "native child failed: selector={selector} status={:?} watchdog={} group_diagnostic={:?} normal_root_empty={normal_root_empty:?} parent_close={close:?} root_absent={absent}\nstdout={}\nstderr={}",
        report.status,
        report.timed_out,
        report.group_diagnostic,
        report.output,
        report.detail
    );
}

pub(super) fn isolated_case(case: &str, selector: &str) {
    // Anonymous parent logs stay outside the root whose emptiness is observed.
    let mut stdout = tempfile::tempfile().expect("owned native stdout");
    let mut stderr = tempfile::tempfile().expect("owned native stderr");
    let root = tempfile::Builder::new()
        .prefix("k140c-")
        .tempdir_in("/tmp")
        .expect("parent-owned short native child root");
    let canonical_root = fs::canonicalize(root.path()).expect("canonical parent temp root");
    let mut child = spawn_native_child(case, selector, &canonical_root, &stdout, &stderr);
    let (status, timed_out) = await_native_child(&mut child);
    // The leader is reaped and signalling is disarmed. A residual/error group
    // is diagnostic FAILED, never a reason to signal a cached numerical PGID.
    // Abort-time residual Bun descendant cleanup remains explicitly unproved.
    let group_diagnostic = killpg(child.group, None::<Signal>);
    let report = NativeReport {
        status,
        timed_out,
        group_diagnostic,
        output: captured(&mut stdout),
        detail: captured(&mut stderr),
    };
    drop(child);
    finish_case(case, selector, root, &canonical_root, &report);
}
