//! Owns the responsive HTTP observation thread and its finite peer lifetimes.
use super::http::{PendingHttpRequest, RequestPoll};
use super::recovery::{RecoveryCommand, RecoveryObserver};
use super::respond;
use crate::support::EVENT_DEADLINE;
use serde_json::Value;
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};

/// HTTP observes ordinary app/page data; the retained Quit stream owns no authority.
pub(in crate::public_fs) struct Observation {
    pub(in crate::public_fs) port: u16,
    pub(in crate::public_fs) reports: mpsc::Receiver<Value>,
    pub(in crate::public_fs) quit: mpsc::Sender<()>,
    recovery_commands: Option<mpsc::Sender<RecoveryCommand>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Observation {
    pub(in crate::public_fs) fn await_page_result(&self, journal: &mut Vec<Value>) {
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

    pub(in crate::public_fs) fn bind() -> Self {
        Self::bind_with_recovery(false, false)
    }

    pub(in crate::public_fs) fn bind_recovery() -> Self {
        Self::bind_with_recovery(true, false)
    }

    pub(super) fn bind_with_accept_receipts() -> (Self, mpsc::Receiver<std::net::SocketAddr>) {
        let (send, receives) = mpsc::channel();
        (
            Self::bind_with_recovery_and_receipts(false, false, Some(send)),
            receives,
        )
    }

    /// Core/Runtime own Q/EOF; their G1/G2 ordinary app Quit waits park here.
    pub(in crate::public_fs) fn bind_staged_fixture() -> Self {
        Self::bind_with_recovery(false, true)
    }

    pub(in crate::public_fs) fn send_recovery_command(&self, command: RecoveryCommand) {
        self.recovery_commands
            .as_ref()
            .expect("recovery observer owns these fixture commands")
            .send(command)
            .expect("recovery observer remains live");
    }

    fn bind_with_recovery(recovery_mode: bool, retain_fixture_quits: bool) -> Self {
        Self::bind_with_recovery_and_receipts(recovery_mode, retain_fixture_quits, None)
    }

    fn bind_with_recovery_and_receipts(
        recovery_mode: bool,
        retain_fixture_quits: bool,
        accept_receipts: Option<mpsc::Sender<std::net::SocketAddr>>,
    ) -> Self {
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
            let mut fixture_quits = Vec::new();
            let mut released = false;
            let mut peers: Vec<PendingHttpRequest> = Vec::new();
            while !stopping.load(Ordering::Acquire) {
                if let Some(recovery) = recovery.as_mut() {
                    recovery.poll();
                }
                released |= commands.try_recv().is_ok();
                if released && let Some(mut stream) = pending_quit.take() {
                    respond(&mut stream, "quit");
                }
                // One silent keep-alive or split request must not prevent the
                // owner from observing Quit, other reports, or recovery signals.
                let mut index = 0;
                while index < peers.len() {
                    let (path, body) = match peers[index].poll() {
                        RequestPoll::Pending => {
                            index += 1;
                            continue;
                        }
                        RequestPoll::Closed => {
                            peers.remove(index);
                            continue;
                        }
                        RequestPoll::Ready(path, body) => (path, body),
                    };
                    // Preserve accept order when several complete requests
                    // become readable in the same pass.
                    let mut stream = peers.remove(index).into_stream();
                    match path.as_str() {
                        "/observe" => {
                            let report: Value =
                                serde_json::from_slice(&body).expect("actual app/page JSON");
                            respond(&mut stream, "recorded");
                            send.send(report).expect("report observed data");
                        }
                        "/quit" if retain_fixture_quits => {
                            assert!(fixture_quits.len() < 2, "only G1/G2 fixture Quit waits");
                            fixture_quits.push(stream);
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
                match listener.accept() {
                    Ok((stream, peer)) => {
                        if let Some(receipt) = &accept_receipts {
                            receipt
                                .send(peer)
                                .expect("native observer peer receipt owner");
                        }
                        assert!(
                            peers.len() < 32,
                            "native fixture cannot retain an unbounded number of HTTP peers"
                        );
                        peers.push(PendingHttpRequest::new(stream));
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

impl Observation {
    /// Stop and join the sole HTTP owner before observing its final report queue.
    pub(in crate::public_fs) fn stop_and_join(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.thread.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.expect("observer owns/join its worker");
            }
        }
    }
}

impl Drop for Observation {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}
