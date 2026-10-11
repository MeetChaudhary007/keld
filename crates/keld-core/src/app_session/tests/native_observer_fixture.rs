//! Native observer fixture/channel/worker/drain ownership for the AC7 scenarios.
use super::super::super::{
    FsDispatchSession, FsWorkerTestGate, GuardedFsTestSetup, GuardedTestRouter, app_detail,
};
use super::super::WorkerLinkRole;
use super::support;
use keld_native::fs::acceptance_observer::{Hold, Snapshot, install_current_thread};
use std::any::Any;
use std::fs;
use std::path::Path;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const OBSERVATION_BOUND: Duration = Duration::from_secs(5);
const NATIVE_HOLD_BOUND: Duration = Duration::from_secs(10);

pub(super) struct NativeSignals {
    initialized: Receiver<()>,
    pub(super) held: Receiver<Snapshot>,
    pub(super) returned: Receiver<Snapshot>,
    final_snapshot: Receiver<Snapshot>,
    pub(super) native_release: Option<Sender<()>>,
    pub(super) pre_entry: Option<Receiver<()>>,
    pub(super) pre_release: Option<Sender<()>>,
}

fn native_setup(hold_native: bool, pre_entry: bool) -> (GuardedFsTestSetup, NativeSignals) {
    let (initialized_tx, initialized) = mpsc::sync_channel(1);
    let (held_tx, held) = mpsc::sync_channel(1);
    let (returned_tx, returned) = mpsc::sync_channel(8);
    let (final_tx, final_snapshot) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::channel();
    let wait_control = hold_native.then(|| {
        Hold::new(held_tx, release_rx, NATIVE_HOLD_BOUND).expect("valid native fixture hold")
    });
    let (before_entry, pre_entry_rx, pre_release) = if pre_entry {
        let (taken, observed) = mpsc::sync_channel(1);
        let (release, receiver) = mpsc::channel();
        (
            Some(Arc::new(FsWorkerTestGate {
                taken,
                release: Mutex::new(receiver),
                before_entry: None,
                initializer: Mutex::new(None),
            })),
            Some(observed),
            Some(release),
        )
    } else {
        (None, None, None)
    };
    let setup: GuardedFsTestSetup = Box::new(move |gate| {
        gate.before_entry = before_entry;
        *gate.initializer.lock().expect("private initializer slot") = Some(Box::new(move || {
            assert_eq!(
                thread::current().name(),
                Some("keld-core-fs-worker"),
                "native scope installed on a different execution owner"
            );
            let guard =
                install_current_thread(wait_control, returned_tx, final_tx).ok_or_else(|| {
                    app_detail("native observer fixture", "scope installation refused")
                })?;
            println!(
                "KELD_AC7_OBSERVER_INSTALLED pid={} worker={:?}",
                std::process::id(),
                thread::current().id()
            );
            initialized_tx
                .send(())
                .map_err(|_| app_detail("native observer fixture", "setup witness disconnected"))?;
            Ok(Box::new(guard) as Box<dyn Any>)
        }));
    });
    (
        setup,
        NativeSignals {
            initialized,
            held,
            returned,
            final_snapshot,
            native_release: hold_native.then_some(release_tx),
            pre_entry: pre_entry_rx,
            pre_release,
        },
    )
}

/// Owns release controls before router/caller teardown, including failed assertions.
pub(super) struct NativeFixture {
    pub(super) signals: NativeSignals,
    role: Option<WorkerLinkRole>,
    router: Option<GuardedTestRouter>,
    pub(super) terminal_resume: Option<Sender<()>>,
}

impl NativeFixture {
    pub(super) fn start(case: &str, scenario: &str, hold_native: bool, pre_entry: bool) -> Self {
        Self::start_with_caller(case, hold_native, pre_entry, |setup| {
            WorkerLinkRole::start_public_fs_with_test_setup(scenario, Some(setup))
        })
    }

    pub(super) fn start_with_caller(
        case: &str,
        hold_native: bool,
        pre_entry: bool,
        caller: impl FnOnce(GuardedFsTestSetup) -> (WorkerLinkRole, GuardedTestRouter),
    ) -> Self {
        let (setup, signals) = native_setup(hold_native, pre_entry);
        let (role, router) = caller(setup);
        signals
            .initialized
            .recv_timeout(OBSERVATION_BOUND)
            .expect("observer actually installed on native worker");
        support::record_owned_caller(case, role.child.as_ref().expect("owned public caller"));
        Self {
            signals,
            role: Some(role),
            router: Some(router),
            terminal_resume: None,
        }
    }

    pub(super) fn router(&self) -> &GuardedTestRouter {
        self.router.as_ref().expect("owned native router")
    }

    pub(super) fn supply(&mut self, target: &Path, late: &Path) {
        self.role
            .as_mut()
            .expect("public caller custody")
            .supply_public_fs_targets(target, late);
    }

    pub(super) fn release_native(&mut self) {
        self.signals
            .native_release
            .take()
            .expect("one native release")
            .send(())
            .expect("native hold still owned");
    }

    pub(super) fn finish_caller(&mut self) -> std::collections::BTreeMap<String, String> {
        let role = self.role.take().expect("one public caller");
        let (report, pid, status) = role.finish_with_status();
        support::record_owned_caller_exit(pid, status);
        report
    }

    pub(super) fn assert_held_drain(&self, probe: &DrainProbe) {
        assert_eq!(
            self.router()
                .snapshot
                .fs
                .state
                .lock()
                .expect("held accounting")
                .in_flight,
            1,
            "lease accounting retired while independently observed native handle remains held"
        );
        assert!(
            matches!(probe.completed.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "drain returned before native release"
        );
        assert!(matches!(
            self.signals.returned.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }

    pub(super) fn finish_router(
        &mut self,
        target: &Path,
        late: &Path,
        expected_entries: usize,
        expected_bytes: &[u8],
    ) -> Snapshot {
        let router = self.router.take().expect("one router cleanup");
        router
            .router
            .shutdown()
            .expect("native router worker/readers join");
        let final_snapshot = self
            .signals
            .final_snapshot
            .recv_timeout(OBSERVATION_BOUND)
            .expect("required final native scope fence after worker join");
        assert!(
            !final_snapshot.fixture_fault,
            "invalid native evidence: {final_snapshot:?}"
        );
        assert_eq!(
            final_snapshot.request_entries, expected_entries,
            "native invocation census"
        );
        assert_eq!(
            final_snapshot.request_returns, expected_entries,
            "native normal-return census"
        );
        assert_eq!(
            support::object_handle_count(target),
            0,
            "native target handle survived cleanup"
        );
        assert_eq!(
            router
                .snapshot
                .fs
                .state
                .lock()
                .expect("joined native state")
                .in_flight,
            0,
            "owner lease survives joined worker"
        );
        assert_eq!(
            fs::read(target).expect("post-join independent bytes"),
            expected_bytes
        );
        assert!(!late.exists(), "late target changed before scope teardown");
        // The temporary scope is still present for every file/handle oracle.
        drop(router.snapshot);
        final_snapshot
    }
}

impl Drop for NativeFixture {
    fn drop(&mut self) {
        if let Some(release) = self.signals.native_release.take() {
            let _ = release.send(());
        }
        if let Some(release) = self.signals.pre_release.take() {
            let _ = release.send(());
        }
        if let Some(resume) = self.terminal_resume.take() {
            let _ = resume.send(());
        }
        if let Some(router) = &self.router {
            let _ = router.release.send(());
        }
        drop(self.role.take());
        drop(self.router.take());
    }
}

/// The real drain thread releases the held native operation before fallback join.
pub(super) struct DrainProbe {
    pub(super) completed: Receiver<()>,
    join: Option<JoinHandle<()>>,
    release_for_cleanup: Sender<()>,
}

impl DrainProbe {
    pub(super) fn start(session: Arc<FsDispatchSession>, release_for_cleanup: Sender<()>) -> Self {
        let (done, completed) = mpsc::sync_channel(1);
        let join = thread::spawn(move || {
            session.drain().expect("owning native lease drain");
            done.send(()).expect("drain completion witness");
        });
        Self {
            completed,
            join: Some(join),
            release_for_cleanup,
        }
    }

    pub(super) fn finish(mut self) {
        self.completed
            .recv_timeout(OBSERVATION_BOUND)
            .expect("native drain completes after release");
        self.join
            .take()
            .expect("owned drain thread")
            .join()
            .expect("drain thread joins");
    }
}

impl Drop for DrainProbe {
    fn drop(&mut self) {
        let _ = self.release_for_cleanup.send(());
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

pub(super) fn held_snapshot(fixture: &NativeFixture, case: &str, target: &Path) -> Snapshot {
    let held = fixture
        .signals
        .held
        .recv_timeout(OBSERVATION_BOUND)
        .expect("actual retained native hold");
    assert!(!held.fixture_fault, "invalid held evidence: {held:?}");
    assert_eq!(held.request_entries, 1);
    assert_eq!(
        held.request_returns, 0,
        "native return fabricated while object held"
    );
    assert!(
        held.walk_entries > 0 && held.target_opens > 0,
        "native retained walk absent: {held:?}"
    );
    assert_eq!(
        held.truncate_calls + held.create_calls + held.content_writes,
        0,
        "effect before release"
    );
    assert_eq!(
        support::object_handle_count(target),
        1,
        "native did not retain actual target handle"
    );
    assert!(matches!(
        fixture.signals.returned.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    let pending = fixture
        .router()
        .snapshot
        .fs
        .pending_call_for(1)
        .expect("actual admitted correlation");
    println!(
        "KELD_AC7_NATIVE_HELD case={case} pid={} attempt={} corr={:?} entries={} returns={} target_handles=1",
        std::process::id(),
        pending.attempt,
        pending.correlation,
        held.request_entries,
        held.request_returns
    );
    held
}
