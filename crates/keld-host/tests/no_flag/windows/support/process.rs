//! Native process wait, signal, identity and test-owned termination observers.

use std::io::Read;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{FILETIME, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_DUP_HANDLE, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
};

/// Kernel creation and exit times of one process, in `FILETIME` units (100 ns since
/// 1601). `exit` is zero while the process is still running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProcessTimes {
    pub(crate) creation: u64,
    pub(crate) exit: u64,
}

/// Reads the exact kernel process identity times through `process`, which needs at
/// least `PROCESS_QUERY_LIMITED_INFORMATION` (a `Child` handle or `open_process_for_wait`).
pub(crate) fn process_times(process: HANDLE) -> ProcessTimes {
    let empty = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut creation, mut exit, mut kernel, mut user) = (empty, empty, empty, empty);
    // SAFETY: `process` is a live handle the test owns with query rights; the four
    // FILETIME outputs live for this synchronous call, which neither retains nor
    // closes the handle. Contract:
    // https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes
    let ok = unsafe {
        GetProcessTimes(
            process,
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    };
    assert_ne!(
        ok,
        0,
        "GetProcessTimes on a test-owned process handle: {}",
        std::io::Error::last_os_error()
    );
    let filetime =
        |value: FILETIME| (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime);
    ProcessTimes {
        creation: filetime(creation),
        exit: filetime(exit),
    }
}

pub(crate) fn open_process_for_census(pid: u32) -> OwnedHandle {
    // SAFETY: numeric PID belongs to a live test-owned process; the returned
    // handle requests query/duplicate rights only and is converted once.
    let raw = unsafe {
        OpenProcess(
            PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        )
    };
    assert!(
        !raw.is_null(),
        "open PID {pid} for handle census: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: raw is the fresh non-null owning process handle returned above.
    unsafe { OwnedHandle::from_raw_handle(raw.cast()) }
}

pub(crate) fn open_process_for_wait(pid: u32, terminate: bool) -> OwnedHandle {
    let access = PROCESS_SYNCHRONIZE
        | PROCESS_QUERY_LIMITED_INFORMATION
        | if terminate { PROCESS_TERMINATE } else { 0 };
    // SAFETY: PID belongs to a live test-owned process. Access permits wait and
    // exit-status observation plus optional host-only termination. The returned
    // handle is converted once.
    let raw = unsafe { OpenProcess(access, 0, pid) };
    assert!(
        !raw.is_null(),
        "open PID {pid} for exact wait: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: raw is the fresh non-null owning process handle returned above.
    unsafe { OwnedHandle::from_raw_handle(raw.cast()) }
}

pub(crate) fn terminate_test_process(process: &OwnedHandle) {
    // SAFETY: this is the live test-owned host handle opened with terminate access.
    assert_ne!(
        unsafe { TerminateProcess(process.as_raw_handle().cast(), 1) },
        0,
        "terminate only the no-flag host: {}",
        std::io::Error::last_os_error()
    );
}

pub(crate) fn assert_process_signaled(process: &OwnedHandle, label: &str) {
    let result = wait_for_process_signal(process, 10_000);
    assert_eq!(result, WAIT_OBJECT_0, "{label} survived host death");
}

pub(crate) fn wait_for_process_signal(process: &OwnedHandle, timeout_ms: u32) -> u32 {
    // SAFETY: process is a live retained handle; signaling is the kernel's
    // exact process-termination oracle. Zero observes current state; a positive
    // timeout only bounds failure. This neither closes nor transfers the handle.
    unsafe { WaitForSingleObject(process.as_raw_handle().cast(), timeout_ms) }
}

/// Waits for `child` to exit until the kill switch `deadline`. At expiry the panic
/// carries [`process_tree_report`], taken while the host and its browser still live
/// (the caller's cleanup terminates them afterwards), so a stall can be classified.
pub(crate) fn wait_child(child: &mut Child, deadline: Instant) -> ExitStatus {
    loop {
        if let Some(status) = child.try_wait().expect("observe host exit") {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "host exit timed out; {}",
            process_tree_report(child.id())
        );
        thread::park_timeout(Duration::from_millis(10));
    }
}

/// Diagnostics for a kill switch's expiry: whether `root_pid` is alive and every live
/// descendant (`name:pid<parent`), with the `WebView2` browser processes
/// (`msedgewebview2.exe`) counted, so a stall separates a browser that never exited
/// (the shutdown hang guard's regime) from one that exited (the post-exit grace's) and
/// from a host that waits on neither. Parent links are as the OS reports them now; a
/// reused PID can add an unrelated process, which only widens the report.
pub(crate) fn process_tree_report(root_pid: u32) -> String {
    let script = format!(
        "$all=@(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name); \
         $tree=@{{}}; $tree[[uint32]{root_pid}]=$true; $grew=$true; \
         while ($grew) {{ $grew=$false; foreach ($p in $all) {{ \
           if ($p.ProcessId -ne {root_pid} -and -not $tree.ContainsKey([uint32]$p.ProcessId) -and $tree.ContainsKey([uint32]$p.ParentProcessId)) {{ $tree[[uint32]$p.ProcessId]=$true; $grew=$true }} }} }}; \
         $desc=@($all | Where-Object {{ $_.ProcessId -ne {root_pid} -and $tree.ContainsKey([uint32]$_.ProcessId) }}); \
         $browser=@($desc | Where-Object {{ $_.Name -eq 'msedgewebview2.exe' }}); \
         'host_alive=' + [bool]($all | Where-Object {{ $_.ProcessId -eq {root_pid} }}) + \
         ' browser_processes=' + $browser.Count + \
         ' descendants=' + (($desc | ForEach-Object {{ $_.Name + ':' + $_.ProcessId + '<' + $_.ParentProcessId }}) -join ',')"
    );
    match bounded_output(
        Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", &script]),
        Instant::now() + DIAGNOSTIC_QUERY_KILL_SWITCH,
    ) {
        Ok(output) => format!(
            "process tree of {root_pid}: {}{}",
            output.stdout.trim(),
            output.stderr.trim()
        ),
        Err(error) => format!("process tree of {root_pid}: query failed: {error}"),
    }
}

/// Kill switch for one diagnostic or cleanup helper process (a `PowerShell` query, a
/// `taskkill`): a cold `PowerShell` start with a CIM query takes seconds, never this long.
pub(crate) const DIAGNOSTIC_QUERY_KILL_SWITCH: Duration = Duration::from_secs(30);

/// What a helper process run by [`bounded_output`] wrote and how it exited.
pub(crate) struct BoundedOutput {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

/// Runs `command` with null input and piped output until the kill switch `deadline`:
/// a stalled helper (a hung CIM provider, a blocked console) is killed and reported,
/// so a diagnostic never hangs the cell it reports on. Each pipe is read on its own
/// thread, so neither can fill and stall the helper while the other is read.
pub(crate) fn bounded_output(
    command: &mut Command,
    deadline: Instant,
) -> Result<BoundedOutput, String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("start: {error}"))?;
    let stdout = child.stdout.take().map(read_pipe_on_thread);
    let stderr = child.stderr.take().map(read_pipe_on_thread);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                thread::park_timeout(Duration::from_millis(10));
            }
            outcome => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(match outcome {
                    Err(error) => format!("observe exit: {error}"),
                    _ => "still running at its kill switch; killed".to_owned(),
                });
            }
        }
    };
    // The helper exited; a grandchild that inherited a pipe could still hold it.
    let drained = Instant::now() + PIPE_DRAIN_KILL_SWITCH;
    Ok(BoundedOutput {
        status,
        stdout: stdout.map_or_else(String::new, |reader| pipe_text_by(&reader, drained)),
        stderr: stderr.map_or_else(String::new, |reader| pipe_text_by(&reader, drained)),
    })
}

/// Kill switch for reading a pipe to its end once its process has exited or been killed.
pub(crate) const PIPE_DRAIN_KILL_SWITCH: Duration = Duration::from_secs(10);

/// Reads `pipe` to its end on its own thread; the receiver yields the text then.
pub(crate) fn read_pipe_on_thread(mut pipe: impl Read + Send + 'static) -> Receiver<String> {
    let (text_tx, text_rx) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let read = pipe.read_to_end(&mut bytes);
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let text = match read {
            Ok(_) => text,
            Err(error) => format!("{text}\n<pipe read failed: {error}>"),
        };
        let _ = text_tx.send(text);
    });
    text_rx
}

/// The text of a pipe [`read_pipe_on_thread`] reads, or a marker when the pipe is still
/// open at `deadline` (a live process holds its write end). The reader thread is then
/// left blocked on the pipe; it ends when the last write end closes.
pub(crate) fn pipe_text_by(reader: &Receiver<String>, deadline: Instant) -> String {
    reader
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .unwrap_or_else(|_| "<pipe still open at its kill switch>".to_owned())
}

pub(crate) fn process_exists(pid: u32) -> bool {
    Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!("if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}"),
        ])
        .status()
        .expect("query process")
        .success()
}

pub(crate) fn wait_process_gone(pid: u32, deadline: Instant) {
    while process_exists(pid) {
        assert!(Instant::now() < deadline, "process {pid} remained live");
        thread::park_timeout(Duration::from_millis(20));
    }
}

pub(crate) fn wait_for_child_process(parent_pid: u32, name: &str, deadline: Instant) -> u32 {
    loop {
        let script = format!(
            "$p=Get-CimInstance Win32_Process -Filter \"ParentProcessId={parent_pid}\" | Where-Object {{$_.Name -eq '{name}' -and $_.CommandLine -notmatch 'keld-windows-dev-stage-cleanup'}} | Select-Object -First 1 -ExpandProperty ProcessId; if ($p) {{$p}}"
        );
        let output = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .expect("query delegated child process");
        if output.status.success()
            && let Ok(pid) = String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse::<u32>()
        {
            return pid;
        }
        if Instant::now() >= deadline {
            let dump = Command::new("powershell.exe")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &format!(
                        "Get-CimInstance Win32_Process -Filter \"ParentProcessId={parent_pid}\" | ForEach-Object {{ $_.Name + ' pid=' + $_.ProcessId + ' ' + $_.CommandLine }}"
                    ),
                ])
                .output()
                .expect("dump delegated children");
            panic!(
                "delegated child `{name}` did not appear under {parent_pid}; parent_alive={}; children:\n{}",
                process_exists(parent_pid),
                String::from_utf8_lossy(&dump.stdout)
            );
        }
        thread::park_timeout(Duration::from_millis(20));
    }
}

pub(crate) fn wait_for_cleanup_sentinel(parent_pid: u32, deadline: Instant) -> u32 {
    loop {
        let script = format!(
            "$p=Get-CimInstance Win32_Process -Filter \"ParentProcessId={parent_pid}\" | Where-Object {{$_.CommandLine -match 'keld-windows-dev-stage-cleanup-v1'}} | Select-Object -First 1 -ExpandProperty ProcessId; if ($p) {{$p}}"
        );
        let output = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .expect("query cleanup sentinel process");
        if output.status.success()
            && let Ok(pid) = String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse::<u32>()
        {
            return pid;
        }
        assert!(
            Instant::now() < deadline,
            "cleanup sentinel did not appear as a CLI-owned host sibling"
        );
        thread::park_timeout(Duration::from_millis(20));
    }
}
