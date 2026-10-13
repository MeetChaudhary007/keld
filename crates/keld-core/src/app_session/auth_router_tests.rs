//! Admission custody tests and actual socket/Native guard negative routes.
use std::fs::{self, File};

use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use keld_ipc::CallError;
use keld_ipc::codec::{decode, encode};
use keld_ipc::frame::{CorrelationId, FrameKind};
use keld_ipc::link::{AppLinkDeadlines as _, read_frame, write_frame};
use keld_native::auth::{AuthConfiguration, AuthProfileConfiguration, AuthRequest};
use sha2::{Digest as _, Sha256};

use super::super::{
    GuardianOwnerHandle, PrimaryRouter, PrimaryRouterHandle, SessionShutdownState,
    load_verified_manifest,
};
use super::{AUTH_CALL_CAPACITY, AuthSession, HashMap, Ordering, mpsc};

type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn logical_terminal_does_not_release_physical_leader_ticket() {
    let session = AuthSession::new();
    let leader = session
        .reserve(1, CorrelationId(11))
        .expect("reserve actual leader");
    let physical_lease = Arc::clone(&leader);
    assert!(session.take(&leader).expect("logical terminal"));
    drop(leader);
    assert_eq!(session.used.load(Ordering::Acquire), 1);
    drop(physical_lease); // models caller owner releasing only at Native Drained
    assert_eq!(session.used.load(Ordering::Acquire), 0);
}

#[test]
fn retired_ticket_cannot_remove_successor_with_reused_correlation() {
    let session = AuthSession::new();
    let old = session.reserve(1, CorrelationId(11)).expect("old caller");
    session.retire(1).expect("detach old caller");
    let new = session
        .reserve(2, CorrelationId(11))
        .expect("successor caller");
    assert!(!session.take(&old).expect("old terminal publication"));
    assert!(session.live(&new));
    assert_eq!(session.used.load(Ordering::Acquire), 2);
    session.take(&new).expect("new terminal");
    drop(old);
    drop(new);
    assert_eq!(session.used.load(Ordering::Acquire), 0);
}

#[test]
fn independent_auth_budget_supports_multiple_callers_and_rejects_duplicate() {
    let session = AuthSession::new();
    let tickets: Vec<_> = (1..=AUTH_CALL_CAPACITY)
        .map(|n| {
            session
                .reserve(1, CorrelationId(u32::try_from(n).expect("small capacity")))
                .expect("bounded caller")
        })
        .collect();
    assert!(session.unavailable(1, CorrelationId(100)));
    assert!(session.reserve(1, CorrelationId(100)).is_err());
    assert!(session.reserve(1, CorrelationId(1)).is_err());
    session.retire(1).expect("detach logical callers");
    assert_eq!(
        session.used.load(Ordering::Acquire),
        AUTH_CALL_CAPACITY,
        "leases still physically owned"
    );
    drop(tickets);
    assert_eq!(session.used.load(Ordering::Acquire), 0);
    assert!(!session.unavailable(2, CorrelationId(1)));
}

struct Fixture {
    router: PrimaryRouter,
    client: UnixStream,
    _temp: tempfile::TempDir,
    finished: bool,
    fs: Option<super::super::GuardSnapshot>,
    // Retain the actual routing owner channels through router teardown.
    guardian: std::sync::mpsc::Receiver<super::super::GuardianOwnerCommand>,
    window: std::sync::mpsc::Receiver<super::super::AppWindowCommand>,
}
impl Fixture {
    fn new(manifest: &str, configuration: AuthConfiguration) -> FixtureResult<Self> {
        Self::new_with_fs(manifest, configuration, false)
    }
    fn new_with_fs(
        manifest: &str,
        configuration: AuthConfiguration,
        fs_enabled: bool,
    ) -> FixtureResult<Self> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("keld.permissions.jsonc");
        fs::write(&path, manifest)?;
        let digest: [u8; 32] = Sha256::digest(manifest.as_bytes()).into();
        let verified = load_verified_manifest(File::open(&path)?, path, digest)?;
        let snapshot = if fs_enabled {
            Some(super::super::GuardSnapshot::prepare(verified.clone())?)
        } else {
            None
        };
        let (server, client) = UnixStream::pair()?;
        client.set_app_link_deadlines(Some(Duration::from_secs(5)))?;
        let (guardian_tx, guardian) = mpsc::channel();
        let (window_tx, window) = mpsc::channel();
        let handle = PrimaryRouterHandle {
            current: Arc::new(Mutex::new(None)),
            readers: Arc::new(Mutex::new(HashMap::new())),
            pending_echo: Arc::new(Mutex::new(None)),
            pending_echo_attempt: Arc::new(AtomicU32::new(0)),
            pending_echo_corr: Arc::new(AtomicU32::new(0)),
            next_host_corr: Arc::new(AtomicU32::new(1)),
            window_ready: Arc::new(AtomicBool::new(false)),
            last_window_closed: Arc::new(AtomicBool::new(false)),
            recovery_armed: Arc::new(AtomicBool::new(false)),
            last_revoked_attempt: Arc::new(AtomicU32::new(0)),
            shutdown: SessionShutdownState::new(),
            fs: snapshot.as_ref().map(super::super::GuardSnapshot::fs_weak),
            fs_worker_commands: None,
            auth: None,
            auth_commands: None,
            guardian: GuardianOwnerHandle {
                command_tx: guardian_tx,
            },
            window_commands: window_tx,
            quit_drain_hooks: Arc::default(),
        };
        let router = PrimaryRouter::finish_start(
            handle,
            snapshot
                .as_ref()
                .map(super::super::GuardSnapshot::take_initial_broker)
                .transpose()?,
            1,
            None,
            Some((verified, configuration)),
        )?;
        router
            .handle
            .install_prepared_generation(1, server)
            .map_err(|failure| failure.error)?;
        Ok(Self {
            router,
            client,
            _temp: temp,
            finished: false,
            fs: snapshot,
            guardian,
            window,
        })
    }
    fn call(&mut self, request: &AuthRequest, corr: u32) -> FixtureResult<CallError> {
        let channel = keld_ipc::channel_table::AUTH.id();
        write_frame(
            &mut self.client,
            FrameKind::Call,
            0,
            channel,
            CorrelationId(corr),
            &encode(request)?,
        )?;
        let (header, payload) = read_frame(&mut self.client)?;
        assert_eq!(
            (header.kind, header.channel, header.corr),
            (FrameKind::Err, channel, CorrelationId(corr))
        );
        Ok(decode(&payload)?)
    }
    fn finish(&mut self) -> Result<(), super::super::HostAppError> {
        self.finished = true;
        self.router.stop_and_join()
    }
    fn take_reader(
        &self,
        attempt: u32,
    ) -> FixtureResult<std::thread::JoinHandle<Result<(), super::super::HostAppError>>> {
        let mut readers = self
            .router
            .handle
            .readers
            .lock()
            .map_err(|_| "reader owner table poisoned")?;
        Ok(readers.remove(&attempt).ok_or("reader owner is absent")?)
    }
    fn retained_writer(&self) -> FixtureResult<UnixStream> {
        let current = self
            .router
            .handle
            .current
            .lock()
            .map_err(|_| "current generation lock poisoned")?;
        Ok(current
            .as_ref()
            .ok_or("current generation is absent")?
            .writer
            .try_clone()?)
    }
    fn acknowledge_prepare(&self) -> FixtureResult<()> {
        match self.guardian.recv_timeout(Duration::from_secs(5))? {
            super::super::GuardianOwnerCommand::PrepareAcceptedShutdown(reply) => {
                Ok(reply.send(Ok(()))?)
            }
            _ => Err("unexpected guardian prepare command".into()),
        }
    }
    fn acknowledge_tail_if_reached(&self) -> FixtureResult<bool> {
        match self.guardian.recv_timeout(Duration::from_secs(5)) {
            Ok(super::super::GuardianOwnerCommand::Shutdown(reply)) => {
                reply.send(Ok(()))?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if !self.finished {
            // An earlier test error/unwind still releases the real owner. Successful
            // paths check finish() in the test before this emergency fallback.
            if let Err(error) = self.router.stop_and_join() {
                eprintln!("emergency auth-fixture cleanup: {error}");
            }
        }
    }
}
fn begin(hint: Option<String>) -> AuthRequest {
    AuthRequest::Begin {
        provider: "entra-common".to_owned(),
        scopes: None,
        login_hint: hint,
    }
}

#[test]
fn actual_primary_auth_begin_not_granted_precedes_missing_client_and_bad_hint() -> FixtureResult<()>
{
    let mut fixture = Fixture::new("{}", AuthConfiguration::new())?;
    let error = fixture.call(&begin(Some("private\ninvalid".to_owned())), 41)?;
    assert_eq!(error.code, "KELD-GUARD001");
    assert!(!error.message.contains("private"));
    fixture.finish()?;
    Ok(())
}

#[test]
fn actual_primary_auth_begin_allow_without_client_returns_native_configuration_error()
-> FixtureResult<()> {
    let mut fixture = Fixture::new(
        r#"{"app":{"auth":{"begin":["https://login.microsoftonline.com/common"]}}}"#,
        AuthConfiguration::new(),
    )?;
    assert_eq!(fixture.call(&begin(None), 42)?.code, "KELD-AUTH-015");
    fixture.finish()?;
    Ok(())
}

#[test]
fn actual_primary_auth_begin_allow_with_client_validates_private_hint_before_effects()
-> FixtureResult<()> {
    let mut configuration = AuthConfiguration::new();
    configuration.insert(
        "entra-common".to_owned(),
        AuthProfileConfiguration {
            client_id: Some("literal-test-client".to_owned()),
            fixed_redirect: None,
        },
    );
    let mut fixture = Fixture::new(
        r#"{"app":{"auth":{"begin":["https://login.microsoftonline.com/common"]}}}"#,
        configuration,
    )?;
    let error = fixture.call(&begin(Some("private\ninvalid".to_owned())), 43)?;
    assert_eq!(error.code, "KELD-AUTH-010");
    assert!(!error.message.contains("private"));
    fixture.finish()?;
    Ok(())
}

#[test]
fn actual_primary_auth_token_unknown_account_uses_private_not_granted_constant() -> FixtureResult<()>
{
    let mut fixture = Fixture::new("{}", AuthConfiguration::new())?;
    let error = fixture.call(
        &AuthRequest::Token {
            account_id: "private-unknown-account".to_owned(),
            scopes: None,
        },
        44,
    )?;
    assert_eq!(error.code, "KELD-GUARD001");
    assert!(!error.message.contains("private-unknown-account"));
    assert!(!error.message.contains("unresolved"));
    assert!(!error.message.contains("https://"));
    fixture.finish()?;
    Ok(())
}

#[test]
fn accepted_quit_answers_auth_024_without_decoding_malformed_payload() -> FixtureResult<()> {
    use super::super::AppWindowCommand;
    let mut fixture = Fixture::new("{}", AuthConfiguration::new())?;
    write_frame(
        &mut fixture.client,
        FrameKind::Call,
        0,
        keld_ipc::LIFECYCLE_CHANNEL,
        CorrelationId(51),
        &encode(&keld_ipc::LifecycleRequest::Quit).expect("Quit payload"),
    )
    .expect("actual Quit CALL");
    fixture.acknowledge_prepare()?;
    let (quit, _) = read_frame(&mut fixture.client).expect("accepted Quit REPLY");
    assert_eq!(
        (quit.kind, quit.channel, quit.corr),
        (
            FrameKind::Reply,
            keld_ipc::LIFECYCLE_CHANNEL,
            CorrelationId(51)
        )
    );
    let auth = keld_ipc::channel_table::AUTH.id();
    write_frame(
        &mut fixture.client,
        FrameKind::Call,
        0,
        auth,
        CorrelationId(52),
        &[0xff],
    )
    .expect("post-Quit malformed auth CALL");
    fixture
        .client
        .shutdown(std::net::Shutdown::Write)
        .expect("peer ends its write direction");
    let (terminal, bytes) = read_frame(&mut fixture.client).expect("post-Quit auth terminal ERR");
    assert_eq!(
        (terminal.kind, terminal.channel, terminal.corr),
        (FrameKind::Err, auth, CorrelationId(52))
    );
    let error: CallError = decode(&bytes).expect("canonical terminal error");
    assert_eq!(
        error.code, "KELD-IPC-024",
        "malformed AUTH must never enter decoder/handler after accepted Quit"
    );
    match fixture
        .guardian
        .recv_timeout(Duration::from_secs(5))
        .expect("guardian tail")
    {
        super::super::GuardianOwnerCommand::Shutdown(reply) => {
            reply.send(Ok(())).expect("existing owner tail ack");
        }
        _ => panic!("unexpected guardian tail command"),
    }
    assert!(matches!(
        fixture
            .window
            .recv_timeout(Duration::from_secs(5))
            .expect("existing window Quit"),
        AppWindowCommand::Quit
    ));
    let session = fixture
        .router
        .handle
        .auth
        .as_ref()
        .expect("actual auth session");
    assert_eq!(
        session.used.load(Ordering::Acquire),
        0,
        "Quit must follow native all-drained + lease zero"
    );
    assert!(session.completion.lock().expect("drain observation").0);
    fixture.finish()?;
    Ok(())
}

fn poison_auth_pending(
    session: &Arc<AuthSession>,
    poison: impl FnOnce() + Send + 'static,
) -> FixtureResult<()> {
    let owner = Arc::clone(session);
    let joined = std::thread::spawn(move || -> Result<(), &'static str> {
        let _held = owner
            .pending
            .lock()
            .map_err(|_| "pending mutex was already poisoned")?;
        poison();
        Ok(())
    })
    .join();
    match joined {
        Err(_) if session.pending.is_poisoned() => Ok(()),
        Err(_) => Err("poison thread panicked without poisoning the pending mutex".into()),
        Ok(Err(error)) => Err(error.into()),
        Ok(Ok(())) => Err("poison callback returned without poisoning the pending mutex".into()),
    }
}

#[test]
fn auth_pending_poison_preserves_fs_echo_and_actual_link_retirement() -> FixtureResult<()> {
    use super::super::{PendingFsCall, PendingPrimaryEcho};
    use std::io::Read as _;
    let mut fixture = Fixture::new_with_fs("{}", AuthConfiguration::new(), true)?;
    let fs = Arc::clone(&fixture.fs.as_ref().expect("actual FS snapshot").fs);
    let lease = fs
        .begin_call(PendingFsCall {
            attempt: 1,
            correlation: CorrelationId(61),
        })
        .expect("actual FS pending lease");
    let (echo_tx, echo_rx) = mpsc::sync_channel(1);
    *fixture
        .router
        .handle
        .pending_echo
        .lock()
        .expect("actual echo slot") = Some(PendingPrimaryEcho {
        attempt: 1,
        correlation: CorrelationId(62),
        reply: echo_tx,
    });
    let session = Arc::clone(
        fixture
            .router
            .handle
            .auth
            .as_ref()
            .expect("actual auth owner"),
    );
    poison_auth_pending(&session, || {
        panic!("intentional actual auth pending poison")
    })?;
    assert!(session.pending.is_poisoned());
    let handle = fixture.router.handle.clone();
    let result;
    // A held duplicate prevents mere writer Drop from impersonating the required
    // explicit shutdown of the actual app link and all its duplicated descriptors.
    let writer_probe;
    {
        let _transition = handle.shutdown.transition_guard();
        let mut current = handle.current.lock().expect("current generation");
        writer_probe = current
            .as_ref()
            .expect("active writer")
            .writer
            .try_clone()
            .expect("actual descriptor duplicate");
        result = handle.retire_current_generation_locked(
            &mut current,
            1,
            "test retirement",
            "test link shutdown",
        );
    }
    let error = result.expect_err("preserve typed auth failure");
    assert!(error.to_string().contains("auth retirement"));
    let fs_retired = fs.pending_call_for(1).is_none();
    let echo_terminal = echo_rx
        .recv_timeout(Duration::from_secs(5))
        .is_ok_and(|reply| reply.is_err());
    fixture
        .client
        .set_app_link_read_deadline(Some(Duration::from_secs(5)))
        .expect("finite direct shutdown observation");
    let mut byte = [0];
    let link_shutdown = matches!(fixture.client.read(&mut byte), Ok(0));
    // Observe before all emergency harness cleanup: neither dropping lease nor
    // writer_probe may make the product oracle pass retroactively.
    assert_eq!(
        (fs_retired, echo_terminal, link_shutdown),
        (true, true, true),
        "auth poison short-circuited mandatory existing cleanup"
    );
    drop(writer_probe);
    drop(lease);
    if let Err(error) = fixture.finish() {
        eprintln!("expected poisoned-fixture cleanup: {error}");
    }
    Ok(())
}

#[test]
fn auth_and_fs_poison_are_both_carried_while_link_and_echo_still_retire() -> FixtureResult<()> {
    use super::super::PendingPrimaryEcho;
    use std::io::Read as _;
    let mut fixture = Fixture::new_with_fs("{}", AuthConfiguration::new(), true)?;
    let fs = Arc::clone(&fixture.fs.as_ref().expect("actual FS snapshot").fs);
    let fs_owner = Arc::clone(&fs);
    assert!(
        std::thread::spawn(move || {
            let _held = fs_owner.state.lock().expect("actual FS owner state");
            panic!("intentional actual FS state poison");
        })
        .join()
        .is_err()
    );
    let (echo_tx, echo_rx) = mpsc::sync_channel(1);
    *fixture
        .router
        .handle
        .pending_echo
        .lock()
        .expect("actual echo slot") = Some(PendingPrimaryEcho {
        attempt: 1,
        correlation: CorrelationId(63),
        reply: echo_tx,
    });
    poison_auth_pending(
        fixture.router.handle.auth.as_ref().expect("auth owner"),
        || panic!("intentional actual auth pending poison"),
    )?;
    let handle = fixture.router.handle.clone();
    let writer_probe;
    let error = {
        let _transition = handle.shutdown.transition_guard();
        let mut current = handle.current.lock().expect("actual current");
        writer_probe = current
            .as_ref()
            .expect("writer")
            .writer
            .try_clone()
            .expect("actual duplicate");
        handle
            .retire_current_generation_locked(
                &mut current,
                1,
                "test retirement",
                "test link shutdown",
            )
            .expect_err("independent typed cleanup failures")
    };
    let text = error.to_string();
    let echo_terminal = echo_rx
        .recv_timeout(Duration::from_secs(5))
        .is_ok_and(|reply| reply.is_err());
    fixture
        .client
        .set_app_link_read_deadline(Some(Duration::from_secs(5)))
        .expect("bounded actual close observation");
    let mut byte = [0];
    let closed = matches!(fixture.client.read(&mut byte), Ok(0));
    assert!(
        text.contains("auth retirement") && text.contains("filesystem retirement"),
        "lost independent cleanup error: {text}"
    );
    assert_eq!((echo_terminal, closed), (true, true));
    drop(writer_probe);
    if let Err(error) = fixture.finish() {
        eprintln!("expected poisoned-fixture cleanup: {error}");
    }
    Ok(())
}

#[test]
fn accepted_quit_auth_poison_still_quiesces_fs_and_reaches_guardian_tail() -> FixtureResult<()> {
    use std::io::Read as _;
    let mut fixture = Fixture::new_with_fs("{}", AuthConfiguration::new(), true)?;
    let fs = Arc::clone(&fixture.fs.as_ref().expect("actual FS snapshot").fs);
    let writer_probe = fixture.retained_writer()?;
    poison_auth_pending(
        fixture
            .router
            .handle
            .auth
            .as_ref()
            .expect("actual auth owner"),
        || panic!("intentional actual auth pending poison"),
    )?;
    write_frame(
        &mut fixture.client,
        FrameKind::Call,
        0,
        keld_ipc::LIFECYCLE_CHANNEL,
        CorrelationId(64),
        &encode(&keld_ipc::LifecycleRequest::Quit).expect("Quit literal"),
    )
    .expect("actual Quit CALL");
    fixture.acknowledge_prepare()?;
    let (reply, _) = read_frame(&mut fixture.client).expect("real accepted Quit REPLY");
    assert_eq!(
        (reply.kind, reply.channel, reply.corr),
        (
            FrameKind::Reply,
            keld_ipc::LIFECYCLE_CHANNEL,
            CorrelationId(64)
        )
    );
    let auth = keld_ipc::channel_table::AUTH.id();
    write_frame(
        &mut fixture.client,
        FrameKind::Call,
        0,
        auth,
        CorrelationId(65),
        &[0xff],
    )
    .expect("buffered post-Q malformed AUTH");
    fixture
        .client
        .shutdown(std::net::Shutdown::Write)
        .expect("role ends link after Quit reply");
    let buffered_024 = read_frame(&mut fixture.client).is_ok_and(|(header, payload)| {
        header.kind == FrameKind::Err
            && header.channel == auth
            && header.corr == CorrelationId(65)
            && decode::<CallError>(&payload).is_ok_and(|error| error.code == "KELD-IPC-024")
    });
    let reached_tail = fixture.acknowledge_tail_if_reached()?;
    let state = fs.state.lock().expect("existing FS observer");
    let quiesced = !state.accepting;
    let drained = state.in_flight == 0;
    drop(state);
    let reader = fixture.take_reader(1)?;
    let reader_error = reader
        .join()
        .expect("reader thread joined")
        .expect_err("auth poison remains a typed failure");
    assert!(reader_error.to_string().contains("auth retirement"));
    let generation_removed = fixture
        .router
        .handle
        .current
        .lock()
        .expect("current observer")
        .is_none();
    let mut byte = [0];
    let link_shutdown = matches!(fixture.client.read(&mut byte), Ok(0));
    assert_eq!(
        (
            quiesced,
            drained,
            reached_tail,
            buffered_024,
            generation_removed,
            link_shutdown
        ),
        (true, true, true, true, true, true),
        "auth poison after Q skipped existing cleanup"
    );
    drop(writer_probe);
    // Cleanup unproved is fatal: observe no successful existing window Quit.
    let commands: Vec<_> = fixture.window.try_iter().collect();
    assert!(
        !commands
            .iter()
            .any(|command| matches!(command, super::super::AppWindowCommand::Quit))
    );
    if let Err(error) = fixture.finish() {
        eprintln!("expected poisoned-fixture cleanup: {error}");
    }
    Ok(())
}

#[test]
fn cli_loss_auth_poison_preserves_echo_error_link_close_and_guardian_tail() -> FixtureResult<()> {
    use super::super::AppWindowCommand;
    use std::io::Read as _;
    let mut fixture = Fixture::new_with_fs("{}", AuthConfiguration::new(), true)?;
    let fs = Arc::clone(&fixture.fs.as_ref().expect("actual FS snapshot").fs);
    poison_auth_pending(
        fixture
            .router
            .handle
            .auth
            .as_ref()
            .expect("actual auth owner"),
        || panic!("intentional actual auth pending poison"),
    )?;
    let echo_owner = Arc::clone(&fixture.router.handle.pending_echo);
    assert!(
        std::thread::spawn(move || {
            let _held = echo_owner.lock().expect("actual Echo waiter lock");
            panic!("intentional actual Echo poison");
        })
        .join()
        .is_err()
    );
    let writer_probe = fixture.retained_writer()?;
    assert!(fixture.router.handle.shutdown.reserve_cli_lease_lost());
    let handle = fixture.router.handle.clone();
    let tail = std::thread::spawn(move || handle.cli_lease_lost());
    fixture.acknowledge_prepare()?;
    let reached_tail = fixture.acknowledge_tail_if_reached()?;
    let error = tail
        .join()
        .expect("actual CLI tail thread")
        .expect_err("retain independent cleanup errors");
    let detail = error.to_string();
    let current_removed = fixture
        .router
        .handle
        .current
        .lock()
        .expect("current observer")
        .is_none();
    let state = fs.state.lock().expect("FS actual cleanup observer");
    let fs_closed_and_drained = !state.accepting && state.in_flight == 0;
    drop(state);
    let mut byte = [0];
    let link_closed = matches!(fixture.client.read(&mut byte), Ok(0));
    assert!(
        detail.contains("auth retirement") && detail.contains("renderer Echo retirement"),
        "CLI loss discarded a cleanup error: {detail}"
    );
    assert_eq!(
        (
            reached_tail,
            current_removed,
            fs_closed_and_drained,
            link_closed
        ),
        (true, true, true, true)
    );
    assert!(
        !fixture
            .window
            .try_iter()
            .any(|command| matches!(command, AppWindowCommand::Quit)),
        "poisoned auth cleanup cannot publish successful Quit"
    );
    drop(writer_probe);
    if let Err(error) = fixture.finish() {
        eprintln!("expected poisoned-fixture cleanup: {error}");
    }
    Ok(())
}

#[test]
fn intentional_live_retirement_keeps_reader_inert_and_auth_owner_for_successor() -> FixtureResult<()>
{
    use super::super::AppWindowCommand;
    let mut fixture = Fixture::new("{}", AuthConfiguration::new())?;
    let auth_owner = Arc::clone(
        fixture
            .router
            .handle
            .auth
            .as_ref()
            .expect("host auth owner"),
    );
    fixture
        .router
        .handle
        .retire_generation(1)
        .expect("existing intentional recovery retirement");
    let reader = fixture.take_reader(1)?;
    reader
        .join()
        .expect("old reader joined")
        .expect("intentionally retired reader stays inert");
    assert!(fixture.router.handle.shutdown.is_running());
    assert!(
        !auth_owner.tail.load(Ordering::Acquire),
        "role retirement stopped host auth"
    );
    assert!(auth_owner.accepting.load(Ordering::Acquire));
    assert!(
        !fixture
            .window
            .try_iter()
            .any(|command| matches!(command, AppWindowCommand::Fatal))
    );
    let (server, client) = UnixStream::pair().expect("actual successor link");
    client
        .set_app_link_deadlines(Some(Duration::from_secs(5)))
        .expect("successor observer bound");
    fixture
        .router
        .handle
        .install_prepared_generation(2, server)
        .expect("existing successor publication");
    fixture.client = client;
    assert!(Arc::ptr_eq(
        &auth_owner,
        fixture.router.handle.auth.as_ref().expect("same owner")
    ));
    assert_eq!(
        fixture.call(&begin(None), 66)?.code,
        "KELD-GUARD001",
        "successor routes through actual retained auth worker"
    );
    fixture.finish()?;
    Ok(())
}
