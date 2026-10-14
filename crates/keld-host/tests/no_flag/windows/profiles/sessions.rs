//! Two consecutive application sessions in one host process (KEL-53 §7 row
//! "8, 20 (profile handover)", cell h5; KEL-270 T4d S6c, first commit).
//!
//! The host's session loop runs a second full application session on the main thread
//! after the first ended by the application's own `Quit`, with no update: the second
//! engine re-acquires the same persistent profile folder and reaches `Ready`. The
//! debug-only `KELD_TEST_WINDOWS_SECOND_SESSION=1` seam asks the loop for exactly one
//! more session; production never requests one, so the loop runs one session until the
//! S6c coordinator (or the rollback restore) starts the next.

use crate::PRODUCT_DEADLINE;
use crate::support::control::{accept_ready_generation, read_control_line};
use crate::support::installed::{INSTALLER_ENV, InstalledApp, SIGNED_HOST_A_P1, fixture_env};
use crate::support::process::{
    ProcessTimes, open_process_for_wait, process_exists, process_times, wait_child,
    wait_for_process_signal,
};
use crate::support::product::ProductFixture;
use crate::support::profile_run::{ProfileTestRoot, assert_profile_test_root_feature};
use crate::support::window::wait_for_host_window;
use serde_json::Value;
use std::fs;
use std::io::{BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::windows::io::{AsRawHandle as _, OwnedHandle};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::WAIT_OBJECT_0;

/// The debug-only S6c evidence trigger (the shape of `KELD_TEST_WINDOWS_LEASE_CENSUS`).
const SECOND_SESSION_SEAM: &str = "KELD_TEST_WINDOWS_SECOND_SESSION";
const RECORD_POLL: Duration = Duration::from_millis(5);

/// One observation of the persistent profile's lifecycle record, as the KEL-135
/// `profile.lifecycle.v1` document encodes it (`phase` and the owning `pid`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct LifecycleObservation {
    phase: String,
    owner_pid: Option<u64>,
}

impl LifecycleObservation {
    fn running_under(pid: u32) -> Self {
        Self {
            phase: "running".to_owned(),
            owner_pid: Some(u64::from(pid)),
        }
    }

    fn idle() -> Self {
        Self {
            phase: "idle".to_owned(),
            owner_pid: None,
        }
    }
}

/// One application session observed to `Ready`: its Bun generation, app link, window,
/// the profile record `running` under the host, and the host's thread census.
struct ObservedSession {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    bun_pid: u32,
    bun: OwnedHandle,
    link: String,
    window: Value,
    threads: u64,
}

impl ObservedSession {
    /// Accepts the next Bun generation on `control` and waits for the session's `Ready`,
    /// its titled window and the record `running` under `host_pid`.
    fn observe(control: &TcpListener, host: &mut Child, host_pid: u32, root: &Path) -> Self {
        let (reader, writer, bun_pid, link) = accept_ready_generation(control, host);
        let bun = open_process_for_wait(bun_pid, true);
        let window = wait_for_host_window(host_pid, Instant::now() + PRODUCT_DEADLINE);
        wait_for_record(
            root,
            &LifecycleObservation::running_under(host_pid),
            Instant::now() + PRODUCT_DEADLINE,
        );
        Self {
            reader,
            writer,
            bun_pid,
            bun,
            link,
            window,
            threads: host_thread_count(host_pid),
        }
    }

    /// Requests the application's `Quit` and observes the lifecycle-Quit cause: the host
    /// answers the correlated Quit, then closes the link (the forced tail never replies).
    fn quit(mut self, label: &str) -> OwnedHandle {
        self.writer
            .write_all(b"QUIT\n")
            .unwrap_or_else(|error| panic!("{label}: request lifecycle Quit: {error}"));
        self.writer
            .flush()
            .unwrap_or_else(|error| panic!("{label}: flush lifecycle Quit: {error}"));
        assert_eq!(read_control_line(&mut self.reader), "QUIT_REPLY", "{label}");
        assert_eq!(read_control_line(&mut self.reader), "LINK_EOF", "{label}");
        self.bun
    }
}

/// The signed installed host launched lease-less with the second-session seam set.
struct SeamedHost {
    host: Child,
    pid: u32,
    birth: u64,
}

impl SeamedHost {
    fn launch(installed: &InstalledApp, root: &Path, control: &TcpListener) -> Self {
        let control_port = control
            .local_addr()
            .expect("session control address")
            .port();
        let temp = root.parent().expect("test root parent");
        let host = installed
            .command()
            .env("KELD_T1B_CONTROL", control_port.to_string())
            .env("KELD_PROFILE_TEST_ROOT", root)
            .env("TEMP", temp)
            .env("TMP", temp)
            .env(SECOND_SESSION_SEAM, "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("launch the installed host without KELD_DEV_LEASE");
        let pid = host.id();
        let birth = process_times(host.as_raw_handle().cast()).creation;
        assert_ne!(birth, 0, "host creation time");
        Self { host, pid, birth }
    }

    /// The host is still the process that ran the first session: same creation time,
    /// not exited.
    fn assert_same_live_process(&mut self) {
        assert!(
            self.host.try_wait().expect("observe the host").is_none(),
            "the host must still be running its second session"
        );
        let times = process_times(self.host.as_raw_handle().cast());
        assert_eq!(
            (times.creation, times.exit),
            (self.birth, 0),
            "the second session runs in the same process (same creation time, not exited)"
        );
    }

    /// Waits for the orderly exit and returns its status with the drained output.
    fn finish(mut self) -> (std::process::ExitStatus, String, String) {
        let status = wait_child(&mut self.host, Instant::now() + PRODUCT_DEADLINE);
        let mut stdout = String::new();
        let mut stderr = String::new();
        self.host
            .stdout
            .take()
            .expect("captured host stdout")
            .read_to_string(&mut stdout)
            .expect("read host stdout");
        self.host
            .stderr
            .take()
            .expect("captured host stderr")
            .read_to_string(&mut stderr)
            .expect("read host stderr");
        (status, stdout, stderr)
    }
}

#[test]
#[ignore = "requires KELD_KEL254_SIGNED_HOST_A_P1 (a debug host built with kel135-profile-test-root) and KELD_KEL254_INSTALLER_FIXTURE (KEL-254 installed-host operator fixtures)"]
fn kel270_s6c_two_consecutive_sessions_in_one_host_process() {
    let fixture = ProductFixture::new();
    let root = ProfileTestRoot::new();
    let installed = InstalledApp::install(
        &fixture.project,
        &fixture_env(SIGNED_HOST_A_P1),
        &fixture_env(INSTALLER_ENV),
    );
    assert_profile_test_root_feature(installed.host(), root.path());
    let control = TcpListener::bind(("127.0.0.1", 0)).expect("bind session control");
    let mut seamed = SeamedHost::launch(&installed, root.path(), &control);
    let (host_pid, host_birth) = (seamed.pid, seamed.birth);

    // Independent record watcher: samples every distinct (phase, owner) transition of
    // the persistent profile record for the run's evidence. The assertions use bounded
    // waits on the record, never this sampled sequence.
    let stop_watcher = Arc::new(AtomicBool::new(false));
    let watcher = spawn_record_watcher(root.path().to_path_buf(), Arc::clone(&stop_watcher));

    let first = ObservedSession::observe(&control, &mut seamed.host, host_pid, root.path());
    let (bun_1, link_1, window_1, threads_1) = (
        first.bun_pid,
        first.link.clone(),
        first.window.clone(),
        first.threads,
    );
    let bun_1_handle = first.quit("first session");

    // Session 2 in the same process: a fresh Bun generation binds on the same control
    // listener. A host that exits after one session fails here with its exit status.
    let second = ObservedSession::observe(&control, &mut seamed.host, host_pid, root.path());
    seamed.assert_same_live_process();
    assert_ne!(
        bun_1, second.bun_pid,
        "the second session starts a new Bun primary"
    );
    assert_ne!(
        link_1, second.link,
        "the second session mints fresh app-link authority"
    );
    assert_eq!(
        wait_for_process_signal(&bun_1_handle, 0),
        WAIT_OBJECT_0,
        "the first Bun primary is reaped before the second session's generation binds"
    );
    let bun_1_times = process_times(bun_1_handle.as_raw_handle().cast());
    let bun_2_times = process_times(second.bun.as_raw_handle().cast());
    assert_first_exited_before_second(bun_1_times, bun_2_times);
    let (bun_2, window_2, threads_2) = (second.bun_pid, second.window.clone(), second.threads);
    let bun_2_handle = second.quit("second session");

    let (status, stdout, stderr) = seamed.finish();
    stop_watcher.store(true, Ordering::Release);
    let record_sequence = watcher.join().expect("record watcher thread");
    assert!(
        status.success(),
        "host exited with {status}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !process_exists(bun_2),
        "the second Bun primary survived the orderly host exit"
    );
    assert_eq!(
        wait_for_process_signal(&bun_2_handle, 0),
        WAIT_OBJECT_0,
        "the second Bun primary is reaped by the host exit"
    );
    wait_for_record(
        root.path(),
        &LifecycleObservation::idle(),
        Instant::now() + PRODUCT_DEADLINE,
    );
    let engine_constructions = count_engine_constructions(&stdout);
    assert_eq!(
        engine_constructions,
        (2, 2),
        "two engine constructions in one process\nstdout:\n{stdout}"
    );
    assert!(
        record_sequence.contains(&LifecycleObservation::running_under(host_pid))
            && record_sequence.last() == Some(&LifecycleObservation::idle()),
        "the sampled record sequence must include the asserted phases: {record_sequence:?}"
    );
    println!(
        "KELD_KEL270_H5 {}",
        serde_json::json!({
            "host_pid": host_pid,
            "host_birth": host_birth,
            "bun_pids": [bun_1, bun_2],
            "bun_1_exit": bun_1_times.exit,
            "bun_2_creation": bun_2_times.creation,
            "window_handles": [window_1["handle"], window_2["handle"]],
            "host_threads_at_ready": [threads_1, threads_2],
            "record_sequence": record_sequence.iter().map(|observation| {
                serde_json::json!({"phase": observation.phase, "owner_pid": observation.owner_pid})
            }).collect::<Vec<_>>(),
            "engine_constructions": engine_constructions.0,
        })
    );
    drop(installed);
    root.remove();
}

fn assert_first_exited_before_second(first: ProcessTimes, second: ProcessTimes) {
    assert_ne!(first.exit, 0, "the first Bun primary has exited");
    assert!(
        first.exit < second.creation,
        "the first Bun primary exited ({}) before the second was created ({})",
        first.exit,
        second.creation
    );
}

/// The debug profile fixture prints one `KELD_PROFILE_TEST_PREPARED` and one
/// `KELD_PROFILE_TEST_ENVIRONMENT_READY` line per `WebView2Engine::new`.
fn count_engine_constructions(stdout: &str) -> (usize, usize) {
    let prepared = stdout
        .lines()
        .filter(|line| line.starts_with("KELD_PROFILE_TEST_PREPARED "))
        .count();
    let environments = stdout
        .lines()
        .filter(|line| line.trim_end() == "KELD_PROFILE_TEST_ENVIRONMENT_READY")
        .count();
    (prepared, environments)
}

/// The one persistent profile's `profile.lifecycle.v1` beneath the isolated test root.
fn lifecycle_record_path(root: &Path) -> Option<PathBuf> {
    let namespaces = root.join("Keld").join("profiles").join("v1");
    let mut found = None;
    for entry in fs::read_dir(&namespaces).ok()? {
        let entry = entry.ok()?;
        if entry.file_type().ok()?.is_dir() {
            assert!(
                found.is_none(),
                "exactly one persistent profile namespace under {}",
                namespaces.display()
            );
            found = Some(entry.path().join("profile.lifecycle.v1"));
        }
    }
    found
}

/// Reads the record if it exists and is readable right now; a replace in flight
/// (rename or an exclusive writer) reads as `None` and is sampled again.
fn read_lifecycle_record(root: &Path) -> Option<LifecycleObservation> {
    let bytes = fs::read(lifecycle_record_path(root)?).ok()?;
    let document: Value = serde_json::from_slice(&bytes).ok()?;
    let phase = document["phase"].as_str()?.to_owned();
    let owner_pid = match &document["owner"] {
        Value::Null => None,
        owner => Some(owner["pid"].as_u64()?),
    };
    Some(LifecycleObservation { phase, owner_pid })
}

fn wait_for_record(root: &Path, expected: &LifecycleObservation, deadline: Instant) {
    loop {
        let observed = read_lifecycle_record(root);
        if observed.as_ref() == Some(expected) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "profile record did not reach {expected:?}; last observation {observed:?}"
        );
        thread::park_timeout(RECORD_POLL);
    }
}

fn spawn_record_watcher(
    root: PathBuf,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<Vec<LifecycleObservation>> {
    thread::spawn(move || {
        let mut sequence: Vec<LifecycleObservation> = Vec::new();
        loop {
            if let Some(observed) = read_lifecycle_record(&root)
                && sequence.last() != Some(&observed)
            {
                sequence.push(observed);
            }
            if stop.load(Ordering::Acquire) {
                return sequence;
            }
            thread::park_timeout(RECORD_POLL);
        }
    })
}

/// Thread census of the host (evidence only: tao parks one wait thread per event loop).
fn host_thread_count(pid: u32) -> u64 {
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!("(Get-Process -Id {pid} -ErrorAction Stop).Threads.Count"),
        ])
        .output()
        .expect("query host thread count");
    assert!(
        output.status.success(),
        "host thread census failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("numeric host thread count")
}
