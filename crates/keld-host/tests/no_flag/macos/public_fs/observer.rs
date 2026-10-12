use crate::support::EVENT_DEADLINE;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};

/// HTTP observes ordinary app/page data; the retained Quit stream owns no authority.
pub(super) struct Observation {
    pub(super) port: u16,
    pub(super) reports: mpsc::Receiver<Value>,
    pub(super) quit: mpsc::Sender<()>,
    recovery_commands: Option<mpsc::Sender<RecoveryCommand>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum RecoveryPhase {
    Pending,
    Before,
    After,
}

impl RecoveryPhase {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Before => "before",
            Self::After => "after",
        }
    }
}

pub(super) enum RecoveryCommand {
    Admit(u32),
    Invoke(RecoveryPhase),
    Quit(u32),
    RetirePending(u32),
}

/// Owns only ordinary fixture HTTP waits; two app generations, one real page.
struct RecoveryObserver {
    commands: mpsc::Receiver<RecoveryCommand>,
    admitted: BTreeSet<u32>,
    admissions: BTreeMap<u32, TcpStream>,
    page: Option<TcpStream>,
    invoke: Option<RecoveryPhase>,
    quits: BTreeMap<u32, TcpStream>,
    quitting: Option<u32>,
    pending: Option<(u32, TcpStream)>,
}

impl RecoveryObserver {
    fn new(commands: mpsc::Receiver<RecoveryCommand>) -> Self {
        Self {
            commands,
            admitted: BTreeSet::new(),
            admissions: BTreeMap::new(),
            page: None,
            invoke: None,
            quits: BTreeMap::new(),
            quitting: None,
            pending: None,
        }
    }

    fn poll(&mut self) {
        while let Ok(command) = self.commands.try_recv() {
            match command {
                RecoveryCommand::Admit(pid) => {
                    assert!(self.admitted.insert(pid), "one admission per owned app");
                    assert!(self.admitted.len() <= 2, "exactly two recovery apps");
                }
                RecoveryCommand::Invoke(phase) => {
                    assert!(self.invoke.replace(phase).is_none(), "one page command");
                }
                RecoveryCommand::RetirePending(pid) => {
                    let (held, stream) = self.pending.take().expect("one pending handler stream");
                    assert_eq!(held, pid, "retire only the observed old handler");
                    drop(stream);
                }
                RecoveryCommand::Quit(pid) => {
                    assert!(self.quitting.replace(pid).is_none(), "one recovery Quit");
                }
            }
        }
        self.respond_ready();
    }

    fn accept_wait(&mut self, path: &str, stream: TcpStream) -> Option<Value> {
        if let Some(identity) = path.strip_prefix("/recovery-pending/") {
            let (pid, nonce) = identity.split_once('/').expect("pending handler identity");
            let pid = pid.parse::<u32>().expect("owned pending handler PID");
            assert!(self.admitted.contains(&pid));
            assert_eq!(nonce.len(), 32);
            assert!(nonce.bytes().all(|byte| byte.is_ascii_hexdigit()));
            assert!(self.pending.replace((pid, stream)).is_none());
            return Some(serde_json::json!({"phase":"recovery-handler-pending",
                "pid":pid,"nonce":nonce,"barrier":"application-handler-only"}));
        }
        if path == "/recovery-page" {
            assert!(self.page.replace(stream).is_none(), "one real page wait");
        } else if let Some(pid) = path.strip_prefix("/recovery-admit/") {
            let pid = pid.parse::<u32>().expect("owned recovery admission PID");
            assert!(self.admissions.insert(pid, stream).is_none());
            assert!(self.admissions.len() <= 2);
        } else if let Some(pid) = path.strip_prefix("/recovery-quit/") {
            let pid = pid.parse::<u32>().expect("owned recovery Quit PID");
            assert!(self.quits.insert(pid, stream).is_none());
            assert!(self.quits.len() <= 2);
        } else {
            panic!("unexpected recovery fixture route {path}");
        }
        self.respond_ready();
        None
    }

    fn respond_ready(&mut self) {
        for pid in &self.admitted {
            if let Some(mut stream) = self.admissions.remove(pid) {
                respond(&mut stream, "admit");
            }
        }
        if self.page.is_some() && self.invoke.is_some() {
            let mut stream = self.page.take().expect("retained real page wait");
            let phase = self.invoke.take().expect("one page command");
            respond(&mut stream, phase.as_str());
        }
        if let Some(pid) = self.quitting
            && let Some(mut stream) = self.quits.remove(&pid)
        {
            // G1's dead HTTP wait is never answered or mistaken for G2.
            respond(&mut stream, "quit");
        }
    }
}

impl Observation {
    pub(super) fn await_page_result(&self, journal: &mut Vec<Value>) {
        let deadline = std::time::Instant::now() + EVENT_DEADLINE;
        let mut started = false;
        loop {
            let report = self
                .reports
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                .expect("actual page FS outcomes");
            eprintln!("KELD_KEL140_OBSERVATION {report}");
            let click_start = report["phase"] == "page-click-start";
            journal.push(report);
            if click_start && !started {
                started = true;
                continue;
            }
            // Existing exact page-result/effect assertions reject error,
            // duplicate click-start and every other unexpected final phase.
            return;
        }
    }

    pub(super) fn bind() -> Self {
        Self::bind_with_recovery(false)
    }

    pub(super) fn bind_recovery() -> Self {
        Self::bind_with_recovery(true)
    }

    pub(super) fn send_recovery_command(&self, command: RecoveryCommand) {
        self.recovery_commands
            .as_ref()
            .expect("recovery observer owns these fixture commands")
            .send(command)
            .expect("recovery observer remains live");
    }

    fn bind_with_recovery(recovery_mode: bool) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("prearm public FS observer");
        let port = listener.local_addr().expect("observer address").port();
        listener
            .set_nonblocking(true)
            .expect("responsive observer accept loop");
        let (send, reports) = mpsc::channel();
        let (quit, commands) = mpsc::channel();
        let (recovery_commands, mut recovery) = if recovery_mode {
            let (send, receive) = mpsc::channel();
            (Some(send), Some(RecoveryObserver::new(receive)))
        } else {
            (None, None)
        };
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let mut pending_quit = None;
            let mut released = false;
            while !stopping.load(Ordering::Acquire) {
                if let Some(recovery) = recovery.as_mut() {
                    recovery.poll();
                }
                released |= commands.try_recv().is_ok();
                if released && let Some(mut stream) = pending_quit.take() {
                    respond(&mut stream, "quit");
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        prepare_stream(&stream);
                        let (path, body) = read_observation(&mut stream);
                        match path.as_str() {
                            "/observe" => {
                                let report: Value =
                                    serde_json::from_slice(&body).expect("actual app/page JSON");
                                respond(&mut stream, "recorded");
                                send.send(report).expect("report observed data");
                            }
                            "/quit" => {
                                assert!(pending_quit.is_none(), "one public app Quit barrier");
                                if released {
                                    respond(&mut stream, "quit");
                                } else {
                                    pending_quit = Some(stream);
                                }
                            }
                            _ => match recovery.as_mut() {
                                Some(recovery) => {
                                    if let Some(report) = recovery.accept_wait(&path, stream) {
                                        send.send(report).expect("pending handler observation");
                                    }
                                }
                                None => panic!("unexpected public FS observation route {path}"),
                            },
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::yield_now();
                    }
                    Err(error) => panic!("public FS observer accept: {error}"),
                }
            }
        });
        Self {
            port,
            reports,
            quit,
            recovery_commands,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Observation {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            if !thread::panicking() {
                result.expect("observer owns/join its worker");
            }
        }
    }
}

fn prepare_stream(stream: &TcpStream) {
    // Darwin accept preserves listener flags. Only the accept loop is
    // nonblocking; each bounded HTTP request reader explicitly blocks.
    stream
        .set_nonblocking(false)
        .expect("normalize accepted observation stream");
    stream
        .set_read_timeout(Some(EVENT_DEADLINE))
        .expect("observer read kill switch");
    stream
        .set_write_timeout(Some(EVENT_DEADLINE))
        .expect("observer write kill switch");
}

fn read_observation(stream: &mut TcpStream) -> (String, Vec<u8>) {
    read_observation_observing(stream, |_| {})
}

fn read_observation_observing(
    stream: &mut TcpStream,
    mut observe: impl FnMut(usize),
) -> (String, Vec<u8>) {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
    let end = loop {
        if let Some(offset) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break offset + 4;
        }
        let read = stream.read(&mut chunk).expect("bounded observation header");
        assert_ne!(read, 0, "observer peer closed before headers");
        bytes.extend_from_slice(&chunk[..read]);
        assert!(bytes.len() <= 16 * 1024);
        observe(bytes.len());
    };
    let header = String::from_utf8(bytes[..end].to_vec()).expect("HTTP header UTF-8");
    let length = header
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map_or(0, |(_, value)| {
            value.trim().parse::<usize>().expect("body length")
        });
    assert!(end + length <= 16 * 1024);
    while bytes.len() < end + length {
        let read = stream.read(&mut chunk).expect("bounded observation body");
        assert_ne!(read, 0, "observer peer closed before body");
        bytes.extend_from_slice(&chunk[..read]);
        assert!(bytes.len() <= 16 * 1024);
        observe(bytes.len());
    }
    let path = header
        .lines()
        .next()
        .expect("request line")
        .split_whitespace()
        .nth(1)
        .expect("request target")
        .to_owned();
    (path, bytes[end..end + length].to_vec())
}

fn respond(stream: &mut TcpStream, body: &str) {
    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}", body.len()).expect("respond to observation");
}

#[test]
fn accepted_observation_stream_preserves_split_header_and_body() {
    const O_NONBLOCK: std::ffi::c_int = 4; // Darwin SDK 26.5 sys/fcntl.h.
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("real split-request listener");
    listener
        .set_nonblocking(true)
        .expect("same observer accept mode");
    let mut client = TcpStream::connect_timeout(
        &listener.local_addr().expect("listener address"),
        EVENT_DEADLINE,
    )
    .expect("real TCP client");
    let (mut accepted, _) = listener
        .accept()
        .expect("completed TCP connection is queued");
    // Force the failing starting state even on platforms that reset flags at accept.
    accepted
        .set_nonblocking(true)
        .expect("nonblocking accepted fixture");
    // Darwin SDK 26.5 sys/fcntl.h: O_NONBLOCK=4. Observe the kernel flag,
    // independently of the normalizer and before any scheduling/traffic race.
    assert_ne!(socket_file_flags(&accepted) & O_NONBLOCK, 0);
    prepare_stream(&accepted);
    assert_eq!(
        socket_file_flags(&accepted) & O_NONBLOCK,
        0,
        "accepted request reader stayed nonblocking"
    );
    prepare_stream(&client);
    let body = br#"{"phase":"split","bytes":[0,255]}"#;
    let prefix = b"POST /observe HTTP/1.1\r\nContent-Len";
    let remaining_header = format!("gth: {}\r\n\r\n", body.len());
    let (progress, observed) = mpsc::channel();
    thread::scope(|scope| {
        let writer = scope.spawn(move || {
            client
                .write_all(prefix)
                .expect("first real header fragment");
            await_byte_count(&observed, prefix.len());
            client
                .write_all(remaining_header.as_bytes())
                .expect("remaining header bytes");
            client
                .write_all(&body[..4])
                .expect("partial actual JSON body");
            await_byte_count(&observed, prefix.len() + remaining_header.len() + 4);
            client
                .write_all(&body[4..])
                .expect("remaining actual JSON body");
            await_byte_count(
                &observed,
                prefix.len() + remaining_header.len() + body.len(),
            );
        });
        let (path, actual) = read_observation_observing(&mut accepted, move |count| {
            progress
                .send(count)
                .expect("actual consumed TCP byte count");
        });
        assert_eq!(path, "/observe");
        assert_eq!(actual, body);
        writer.join().expect("split-request writer completes");
    });
}

fn socket_file_flags(stream: &TcpStream) -> std::ffi::c_int {
    use std::os::fd::AsRawFd as _;
    unsafe extern "C" {
        fn fcntl(fd: std::ffi::c_int, command: std::ffi::c_int, ...) -> std::ffi::c_int;
    }
    // Darwin SDK 26.5 sys/fcntl.h: F_GETFL=3, takes no variadic argument.
    const F_GETFL: std::ffi::c_int = 3;
    // SAFETY: stream retains the live socket for this entire shared borrow.
    // F_GETFL only reads descriptor status; no pointer, ownership transfer,
    // lifetime extension or status mutation occurs in this independent census.
    let flags = unsafe { fcntl(stream.as_raw_fd(), F_GETFL) };
    assert!(
        flags >= 0,
        "socket flag census: {}",
        std::io::Error::last_os_error()
    );
    flags
}

fn await_byte_count(observed: &mpsc::Receiver<usize>, expected: usize) {
    let deadline = std::time::Instant::now() + EVENT_DEADLINE;
    loop {
        let actual = observed
            .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            .expect("reader consumed the released fragment");
        assert!(actual <= expected, "unreleased fragment reached the reader");
        if actual == expected {
            return;
        }
    }
}
