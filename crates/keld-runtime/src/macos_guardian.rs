//! macOS host-death guardian for supervised Bun process groups.
//!
//! This is supervisor cleanup, not App Sandbox containment. The caller owns
//! the guardian process and the only liveness writer. The guardian process
//! calls [`run`] for the generic one-group API or [`run_guarded_primary`] for
//! KEL-96's persistent fresh-generation primary owner.

#![deny(unsafe_op_in_unsafe_fn)]

mod host_liveness;

mod generation_wire;

mod host_control;
#[cfg(test)]
use self::host_control::interrupted_successor_preparation;
pub(crate) use self::host_control::is_owned_preparation_interruption;
use self::host_control::{
    GenerationControlPeer, control_exchange, control_exchange_with_cancellation,
};

use self::generation_wire::{
    CONTROL_CLEAR, CONTROL_CLEARED, CONTROL_PREPARE, CONTROL_PREPARED, CONTROL_REGISTERED,
    CONTROL_REVOKE, CONTROL_REVOKED, CONTROL_SPAWNED, GenerationControlReader,
    GenerationControlRecord, decode_revocation_cause, validate_control_response,
    write_generation_control,
};
#[cfg(test)]
use self::generation_wire::{GENERATION_CONTROL_RECORD_LEN, read_generation_control};

use self::host_liveness::{
    await_host_death, observe_guarded_liveness, observe_supervised_liveness,
    set_liveness_nonblocking, validate_liveness_bootstrap,
};

use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::{Pid, getpgid};

use keld_ipc::link::handshake_client;
use keld_ipc::{
    BootstrapAdmission, BootstrapListener, BootstrapRejection, BootstrapRejectionObserver,
    parse_app_link,
};

use crate::role::{
    BoundRoleGeneration, DEFAULT_ADMISSION_TIMEOUT, RoleEvent, RoleGenerationLease,
    RoleGenerationOwner, RoleOwner,
};
use crate::{
    CapturedOutput, ChildPreparer, CrashLedger, GenerationLease, PreparedChild, RestartPolicy,
    RevocationCause, RuntimeError, Supervisor, SupervisorOutcome,
};

const REGISTRATION_ENV: &str = "KELD_INTERNAL_MACOS_GUARDIAN_REGISTRATION";
const REGISTRATION_MAGIC: [u8; 4] = *b"KGR1";
const REGISTRATION_LEN: usize = 8;
const SUPERVISED_QUIT_ACCEPTED: u8 = b'Q';
const SUPERVISED_QUIT_ACK: [u8; 3] = *b"KQA";
const SUPERVISED_ORDERLY_SHUTDOWN: u8 = b'S';
const SUPERVISED_ORDERLY_ACK: [u8; 3] = *b"KSA";
const SUPERVISED_QUIT_ACK_DEADLINE: Duration = Duration::from_secs(5);
const GUARDIAN_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);
const GENERATION_CONTROL_POLL: Duration = Duration::from_millis(20);

#[derive(Debug)]
struct RecoveryState {
    initial_ready: bool,
    denied: bool,
    retired_attempt: Option<u32>,
    cleared_attempt: Option<u32>,
    release_attempt: Option<u32>,
    expected_attempt: u32,
    shutdown_acknowledged: bool,
}

impl RecoveryState {
    const fn new() -> Self {
        Self {
            initial_ready: false,
            denied: false,
            retired_attempt: None,
            cleared_attempt: None,
            release_attempt: None,
            expected_attempt: 1,
            shutdown_acknowledged: false,
        }
    }

    fn arm(&mut self) {
        if self.denied {
            return;
        }
        if !self.initial_ready {
            self.initial_ready = true;
            return;
        }
        self.release_attempt = self
            .retired_attempt
            .and_then(|attempt| attempt.checked_add(1));
    }

    fn deny(&mut self) {
        self.denied = true;
        self.release_attempt = None;
    }

    fn retire(&mut self, attempt: u32) {
        self.retired_attempt = Some(attempt);
        self.cleared_attempt = None;
        self.release_attempt = None;
    }

    fn cleared(&mut self, attempt: u32) -> Result<(), RuntimeError> {
        self.expected_attempt = attempt.checked_add(1).ok_or_else(|| {
            lifecycle_error(
                "macOS guardian generation host transition",
                io::Error::other("supervisor attempt counter exhausted"),
            )
        })?;
        self.cleared_attempt = Some(attempt);
        Ok(())
    }

    fn permits(&self, attempt: u32) -> bool {
        !self.denied
            && self.expected_attempt == attempt
            && (attempt == 1
                || (self.initial_ready
                    && self.release_attempt == Some(attempt)
                    && self.cleared_attempt == self.retired_attempt
                    && self
                        .retired_attempt
                        .and_then(|retired| retired.checked_add(1))
                        == Some(attempt)))
    }
}

fn lock_recovery(state: &Mutex<RecoveryState>) -> std::sync::MutexGuard<'_, RecoveryState> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Private argv discriminator for the KEL-96 supervised guardian re-exec.
///
/// It carries no authority: authenticated registration and the inherited
/// liveness descriptor must still validate before Bun can spawn.
pub const SUPERVISED_GUARDIAN_ARG: &str = "--keld-internal-macos-guardian-v1";

/// Observable completion of one guardian-owned Bun process group.
#[derive(Debug)]
pub struct GuardianReport {
    leader_pid: u32,
    leader_status: ExitStatus,
}

struct SupervisedGuardianPreparer<C, W, S, F: FnOnce() -> io::Result<()>> {
    command_factory: Option<C>,
    registration: Option<W>,
    child_spawned: Option<S>,
    revoke_registered_resources: Option<F>,
    pid_tx: std::sync::mpsc::SyncSender<u32>,
}

impl<C, W, S, F> Drop for SupervisedGuardianPreparer<C, W, S, F>
where
    F: FnOnce() -> io::Result<()>,
{
    fn drop(&mut self) {
        if let Some(revoke) = self.revoke_registered_resources.take() {
            let _ = revoke();
        }
    }
}

struct SupervisedGuardianLease<W, S, F> {
    registration: W,
    child_spawned: Option<S>,
    revoke_registered_resources: Option<F>,
    pid_tx: std::sync::mpsc::SyncSender<u32>,
    group_pid: Option<u32>,
}

impl<C, W, S, F> ChildPreparer for SupervisedGuardianPreparer<C, W, S, F>
where
    C: FnOnce() -> Result<Command, RuntimeError> + Send + 'static,
    W: Write + Send + 'static,
    S: FnOnce(u32) -> io::Result<()> + Send + 'static,
    F: FnOnce() -> io::Result<()> + Send + 'static,
{
    type Lease = SupervisedGuardianLease<W, S, F>;

    fn prepare(&mut self, attempt: u32) -> Result<PreparedChild<Self::Lease>, RuntimeError> {
        if attempt != 1 {
            return Err(lifecycle_error(
                "macOS guardian supervisor policy",
                io::Error::other("KEL-96/T1b forbids a successor before KEL-96/T3"),
            ));
        }
        let factory = self.command_factory.take().ok_or_else(|| {
            lifecycle_error(
                "macOS guardian supervisor preparation",
                io::Error::other("Bun command factory was already consumed"),
            )
        })?;
        let mut command = match factory() {
            Ok(command) => command,
            Err(error) => {
                let mut failures = vec![error];
                if let Some(revoke) = self.revoke_registered_resources.take()
                    && let Err(source) = revoke()
                {
                    failures.push(lifecycle_error(
                        "macOS guardian pre-child registered-resource revocation",
                        source,
                    ));
                }
                return Err(collapse_failures(failures));
            }
        };
        command
            .env_remove(REGISTRATION_ENV)
            .process_group(0)
            .stdin(Stdio::null());
        Ok(PreparedChild {
            command: command.into(),
            lease: SupervisedGuardianLease {
                registration: self.registration.take().ok_or_else(|| {
                    lifecycle_error(
                        "macOS guardian supervisor preparation",
                        io::Error::other("authenticated registration writer is missing"),
                    )
                })?,
                child_spawned: self.child_spawned.take(),
                revoke_registered_resources: self.revoke_registered_resources.take(),
                pid_tx: self.pid_tx.clone(),
                group_pid: None,
            },
        })
    }
}

impl<W, S, F> GenerationLease for SupervisedGuardianLease<W, S, F>
where
    W: Write + Send + 'static,
    S: FnOnce(u32) -> io::Result<()> + Send + 'static,
    F: FnOnce() -> io::Result<()> + Send + 'static,
{
    fn child_spawned(&mut self, pid: u32, _attempt: u32) -> Result<(), RuntimeError> {
        validate_group_leader(pid)?;
        self.group_pid = Some(pid);
        write_group_registration(&mut self.registration, pid)?;
        if let Some(observer) = self.child_spawned.take() {
            observer(pid).map_err(|source| {
                lifecycle_error("macOS guardian supervised-child observer", source)
            })?;
        }
        self.pid_tx.send(pid).map_err(|_| {
            lifecycle_error(
                "macOS guardian supervised-child registration",
                io::Error::other("guardian owner stopped before child registration"),
            )
        })
    }

    fn revoke(mut self, _cause: RevocationCause) -> Result<(), RuntimeError> {
        let mut failures = Vec::new();
        if let Some(revoke) = self.revoke_registered_resources.take()
            && let Err(source) = revoke()
        {
            failures.push(lifecycle_error(
                "macOS guardian registered-resource revocation",
                source,
            ));
        }
        if let Some(group_pid) = self.group_pid.take()
            && let Err(error) = terminate_registered_group(group_pid)
        {
            failures.push(error);
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(collapse_failures(failures))
        }
    }
}

/// Host-side authenticated bootstrap for one private guardian process.
///
/// The bootstrap mints a one-use owner-only registration link, overrides the
/// private environment value, and owns the guardian child plus sole liveness
/// writer until [`Self::register_until`] consumes the guardian-emitted group
/// record. Callers never supply a numeric process-group id.
#[derive(Debug)]
pub struct GuardianBootstrap {
    child: Option<Child>,
    liveness_writer: Option<ChildStdin>,
    quit_ack_reader: Option<ChildStdout>,
    registration: BootstrapListener,
}

impl GuardianBootstrap {
    /// Spawns one private guardian command with authenticated registration and
    /// a non-inheritable host-liveness writer.
    ///
    /// # Errors
    ///
    /// Returns a typed [`RuntimeError`] if the private command is empty, the
    /// registration link cannot be provisioned, the guardian cannot spawn, or
    /// its piped stdin cannot be retained.
    pub fn spawn(mut command: Command) -> Result<Self, RuntimeError> {
        Self::spawn_inner(&mut command, false)
    }

    /// Spawns the private guardian with stdout reserved for the fixed
    /// accepted-Quit acknowledgment used by [`run_supervised`].
    ///
    /// # Errors
    ///
    /// Returns the same typed bootstrap failures as [`Self::spawn`], plus a
    /// missing acknowledgment-pipe failure.
    pub fn spawn_supervised(mut command: Command) -> Result<Self, RuntimeError> {
        Self::spawn_inner(&mut command, true)
    }

    fn spawn_inner(command: &mut Command, supervised: bool) -> Result<Self, RuntimeError> {
        if command.get_program().is_empty() {
            return Err(lifecycle_error(
                "macOS guardian private bootstrap",
                io::Error::new(io::ErrorKind::InvalidInput, "guardian program is empty"),
            ));
        }
        let registration = BootstrapListener::bind().map_err(|source| {
            lifecycle_error("macOS guardian registration-link provisioning", source)
        })?;
        command
            .env(REGISTRATION_ENV, registration.app_link())
            .stdin(Stdio::piped());
        if supervised {
            command.stdout(Stdio::piped());
        }
        let mut child = command.spawn().map_err(RuntimeError::Spawn)?;
        let Some(liveness_writer) = child.stdin.take() else {
            let mut failures = vec![lifecycle_error(
                "macOS guardian host-liveness writer provisioning",
                io::Error::other("spawned guardian has no piped stdin"),
            )];
            if let Err(source) = child.kill()
                && source.kind() != io::ErrorKind::InvalidInput
            {
                failures.push(lifecycle_error(
                    "macOS guardian bootstrap process kill",
                    source,
                ));
            }
            if let Err(source) = child.wait() {
                failures.push(lifecycle_error(
                    "macOS guardian bootstrap process wait",
                    source,
                ));
            }
            return Err(collapse_failures(failures));
        };
        let quit_ack_reader = if supervised {
            match child.stdout.take() {
                Some(reader) => Some(reader),
                None => {
                    return Err(reject_host_registration(
                        child,
                        liveness_writer,
                        None,
                        lifecycle_error(
                            "macOS guardian supervised-Quit acknowledgment",
                            io::Error::other("spawned guardian has no acknowledgment reader"),
                        ),
                    ));
                }
            }
        } else {
            None
        };
        if let Err(error) = require_close_on_exec(&liveness_writer) {
            return Err(reject_host_registration(
                child,
                liveness_writer,
                None,
                error,
            ));
        }
        Ok(Self {
            child: Some(child),
            liveness_writer: Some(liveness_writer),
            quit_ack_reader,
            registration,
        })
    }

    /// OS process id of the private guardian while registration is pending.
    #[must_use]
    pub fn guardian_pid(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// Authenticates and consumes the guardian-owned process-group record.
    ///
    /// # Errors
    ///
    /// Returns a typed [`RuntimeError`] when the deadline elapses, registration
    /// is cancelled or malformed, the group is not representable by macOS, or
    /// the guardian exits before registration completes. Every rejected path
    /// closes the liveness writer and waits the guardian before returning.
    pub fn register_until(mut self, deadline: Instant) -> Result<HostGuardian, RuntimeError> {
        let admission = self
            .registration
            .accept_authenticated_until(deadline, &NoopRegistrationObserver)
            .map_err(|source| lifecycle_error("macOS guardian registration admission", source));
        let mut stream = match admission {
            Ok(BootstrapAdmission::Authenticated(stream)) => stream,
            Ok(BootstrapAdmission::Cancelled) => {
                return Err(self.reject_registration(lifecycle_error(
                    "macOS guardian registration admission",
                    io::Error::new(io::ErrorKind::Interrupted, "registration was cancelled"),
                )));
            }
            Ok(BootstrapAdmission::DeadlineElapsed) => {
                return Err(self.reject_registration(lifecycle_error(
                    "macOS guardian registration admission",
                    io::Error::new(io::ErrorKind::TimedOut, "registration deadline elapsed"),
                )));
            }
            Err(error) => return Err(self.reject_registration(error)),
        };
        let mut record = [0_u8; REGISTRATION_LEN];
        if let Err(source) = stream.read_exact(&mut record) {
            return Err(self.reject_registration(lifecycle_error(
                "macOS guardian registration record",
                source,
            )));
        }
        if record[..4] != REGISTRATION_MAGIC {
            return Err(self.reject_registration(lifecycle_error(
                "macOS guardian registration record",
                io::Error::new(io::ErrorKind::InvalidData, "registration magic is not KGR1"),
            )));
        }
        let group_pid = u32::from_be_bytes(record[4..].try_into().map_err(|_| {
            lifecycle_error(
                "macOS guardian registration record",
                io::Error::new(io::ErrorKind::InvalidData, "registration pid is truncated"),
            )
        })?);
        validate_group_leader(group_pid).map_err(|error| self.reject_registration(error))?;

        let child = self.child.take().ok_or_else(|| {
            lifecycle_error(
                "macOS guardian registration owner",
                io::Error::new(io::ErrorKind::NotConnected, "guardian child is missing"),
            )
        })?;
        let liveness_writer = self.liveness_writer.take().ok_or_else(|| {
            lifecycle_error(
                "macOS guardian registration owner",
                io::Error::new(io::ErrorKind::NotConnected, "liveness writer is missing"),
            )
        })?;
        HostGuardian::from_registered_parts(
            child,
            liveness_writer,
            self.quit_ack_reader.take(),
            group_pid,
        )
    }

    /// Authenticates the private guardian as a persistent primary-generation
    /// owner and starts the host half of the KEL-75 generation driver.
    ///
    /// Unlike [`Self::register_until`], the authenticated registration stream
    /// remains open as the bounded `KGC1` generation-control channel. The
    /// separate stdin pipe retains its existing host-death/accepted-Quit
    /// contract.
    ///
    /// # Errors
    ///
    /// Returns a typed lifecycle failure if guardian authentication, handle
    /// extraction, control-channel setup, or host-worker creation fails.
    pub fn register_guarded_primary_until(
        mut self,
        deadline: Instant,
    ) -> Result<GuardedPrimary, RuntimeError> {
        let admission = self
            .registration
            .accept_authenticated_until(deadline, &NoopRegistrationObserver)
            .map_err(|source| lifecycle_error("macOS guardian registration admission", source));
        let control = match admission {
            Ok(BootstrapAdmission::Authenticated(stream)) => stream,
            Ok(BootstrapAdmission::Cancelled) => {
                return Err(self.reject_registration(lifecycle_error(
                    "macOS guardian registration admission",
                    io::Error::new(io::ErrorKind::Interrupted, "registration was cancelled"),
                )));
            }
            Ok(BootstrapAdmission::DeadlineElapsed) => {
                return Err(self.reject_registration(lifecycle_error(
                    "macOS guardian registration admission",
                    io::Error::new(io::ErrorKind::TimedOut, "registration deadline elapsed"),
                )));
            }
            Err(error) => return Err(self.reject_registration(error)),
        };
        let child = self.child.take().ok_or_else(|| {
            lifecycle_error(
                "macOS guardian generation owner",
                io::Error::new(io::ErrorKind::NotConnected, "guardian child is missing"),
            )
        })?;
        let liveness_writer = self.liveness_writer.take().ok_or_else(|| {
            lifecycle_error(
                "macOS guardian generation owner",
                io::Error::new(io::ErrorKind::NotConnected, "liveness writer is missing"),
            )
        })?;
        if let Err(error) = require_close_on_exec(&liveness_writer) {
            return Err(reject_host_registration(
                child,
                liveness_writer,
                None,
                error,
            ));
        }
        let Some(quit_ack_reader) = self.quit_ack_reader.take() else {
            return Err(reject_host_registration(
                child,
                liveness_writer,
                None,
                lifecycle_error(
                    "macOS guardian generation acknowledgment",
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "guarded primary requires the supervised acknowledgment pipe",
                    ),
                ),
            ));
        };
        GuardedPrimary::start(child, liveness_writer, quit_ack_reader, control)
    }

    fn reject_registration(&mut self, error: RuntimeError) -> RuntimeError {
        let Some(child) = self.child.take() else {
            return error;
        };
        let Some(liveness_writer) = self.liveness_writer.take() else {
            return error;
        };
        reject_host_registration(child, liveness_writer, None, error)
    }
}

/// One host-visible update from the guarded primary-generation owner.
#[derive(Debug)]
pub enum GuardedPrimaryUpdate {
    /// Existing KEL-75 lifecycle event.
    Role(RoleEvent),
    /// Newly authenticated stream for one generation.
    Bound(BoundRoleGeneration),
}

/// Host-owned handle for one persistent guardian and its primary generations.
///
/// The value owns the guardian process, sole liveness writer, current-group
/// fail-safe and host half of KEL-75 generation admission. It exposes no raw
/// control records and no child/process-group mutation API.
#[derive(Debug)]
pub struct GuardedPrimary {
    child: Child,
    liveness_writer: Option<ChildStdin>,
    quit_ack_reader: ChildStdout,
    current_generation: Arc<Mutex<Option<RegisteredPrimaryGeneration>>>,
    recovery_decision: Arc<Mutex<RecoveryState>>,
    updates_rx: Receiver<GuardedPrimaryUpdate>,
    worker: Option<JoinHandle<Result<(), RuntimeError>>>,
    shutdown_attributed: bool,
}

#[derive(Debug, Clone, Copy)]
struct RegisteredPrimaryGeneration {
    attempt: u32,
    group_pid: u32,
}

impl GuardedPrimary {
    fn start(
        mut child: Child,
        liveness_writer: ChildStdin,
        quit_ack_reader: ChildStdout,
        control: std::os::unix::net::UnixStream,
    ) -> Result<Self, RuntimeError> {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Err(RuntimeError::GuardianExited {
                    group_pid: 0,
                    exit_code: status.code(),
                    cleanup_error: None,
                });
            }
            Ok(None) => {}
            Err(source) => {
                return Err(reject_host_registration(
                    child,
                    liveness_writer,
                    None,
                    lifecycle_error("macOS guardian generation process inspection", source),
                ));
            }
        }
        let current_generation = Arc::new(Mutex::new(None));
        let recovery_decision = Arc::new(Mutex::new(RecoveryState::new()));
        let (updates_tx, updates_rx) = mpsc::channel();
        let generation_for_worker = Arc::clone(&current_generation);
        let recovery_for_worker = Arc::clone(&recovery_decision);
        let worker = match thread::Builder::new()
            .name("keld-runtime-guardian-generation-host".to_owned())
            .spawn(move || {
                run_generation_host(
                    control,
                    &updates_tx,
                    &generation_for_worker,
                    &recovery_for_worker,
                    #[cfg(test)]
                    None,
                )
            }) {
            Ok(worker) => worker,
            Err(source) => {
                return Err(reject_host_registration(
                    child,
                    liveness_writer,
                    None,
                    lifecycle_error("macOS guardian generation host worker", source),
                ));
            }
        };
        Ok(Self {
            child,
            liveness_writer: Some(liveness_writer),
            quit_ack_reader,
            current_generation,
            recovery_decision,
            updates_rx,
            worker: Some(worker),
            shutdown_attributed: false,
        })
    }

    /// OS process id of the persistent guardian.
    #[must_use]
    pub fn guardian_pid(&self) -> u32 {
        self.child.id()
    }

    /// Current registered Bun process-group leader, when a generation is live.
    #[must_use]
    pub fn group_pid(&self) -> Option<u32> {
        lock_generation(&self.current_generation).map(|generation| generation.group_pid)
    }

    /// Arms initial Ready, then releases the current retired successor.
    pub fn arm_recovery(&self) {
        lock_recovery(&self.recovery_decision).arm();
    }

    /// Permanently rejects successor preparation for a failed startup.
    pub fn deny_recovery(&self) {
        lock_recovery(&self.recovery_decision).deny();
    }

    /// Reports app-link failure for the named current generation.
    ///
    /// A stale reader is ignored. For the current attempt, runtime signals the
    /// enrolled group; the existing guardian-side Supervisor observes that
    /// process failure, performs KEL-75 revocation, and applies its one restart
    /// policy. Core never signals or restarts a process itself.
    ///
    /// # Errors
    ///
    /// Returns the owning group-signal failure.
    pub fn fail_current_generation(&self, attempt: u32) -> Result<(), RuntimeError> {
        let current = lock_generation(&self.current_generation);
        let Some(generation) = *current else {
            return Ok(());
        };
        if generation.attempt != attempt {
            return Ok(());
        }
        terminate_registered_group(generation.group_pid)
    }

    /// Waits for one generation update up to `timeout`.
    #[must_use]
    pub fn recv_update(&self, timeout: Duration) -> Option<GuardedPrimaryUpdate> {
        self.updates_rx.recv_timeout(timeout).ok()
    }

    /// Records accepted host shutdown before a correlated reply is published.
    ///
    /// # Errors
    ///
    /// Returns a typed lifecycle error when the guardian cannot acknowledge
    /// attribution while the host still owns the session.
    pub fn accept_shutdown(&mut self) -> Result<(), RuntimeError> {
        // The same guard covers the actual locator/token mint. Release it
        // before Q I/O so the generation owner can finish cleanup concurrently.
        self.deny_recovery();
        let ack_reader = &mut self.quit_ack_reader;
        let writer = self.liveness_writer.as_mut().ok_or_else(|| {
            lifecycle_error(
                "macOS guardian supervised-Quit control",
                io::Error::new(io::ErrorKind::NotConnected, "liveness writer is missing"),
            )
        })?;
        set_liveness_nonblocking(writer, true)?;
        writer
            .write_all(&[SUPERVISED_QUIT_ACCEPTED])
            .and_then(|()| writer.flush())
            .map_err(|source| lifecycle_error("macOS guardian supervised-Quit control", source))?;
        read_supervised_quit_ack(ack_reader)?;
        self.shutdown_attributed = true;
        lock_recovery(&self.recovery_decision).shutdown_acknowledged = true;
        Ok(())
    }

    /// Polls guardian/control health and invokes the current-group fail-safe
    /// before returning a terminal error.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::GuardianExited`] for guardian death or the
    /// host-worker's exact typed control/admission failure.
    pub fn poll_fatal(&mut self) -> Result<(), RuntimeError> {
        match self.child.try_wait() {
            Ok(None) => {}
            Ok(Some(status)) => {
                self.liveness_writer.take();
                let group_pid = take_generation(&self.current_generation)
                    .map_or(0, |generation| generation.group_pid);
                let cleanup_error = (group_pid != 0)
                    .then(|| terminate_registered_group(group_pid).err())
                    .flatten()
                    .map(|error| io::Error::other(error.to_string()));
                Err(RuntimeError::GuardianExited {
                    group_pid,
                    exit_code: status.code(),
                    cleanup_error,
                })?;
            }
            Err(source) => {
                return Err(lifecycle_error(
                    "macOS guardian generation process inspection",
                    source,
                ));
            }
        }
        if self.worker.as_ref().is_some_and(JoinHandle::is_finished) {
            let result = self.join_worker();
            if let Err(error) = result {
                let cleanup = self.fail_safe_current_group().err();
                return match cleanup {
                    Some(cleanup_error) => Err(collapse_failures(vec![error, cleanup_error])),
                    None => Err(error),
                };
            }
        }
        Ok(())
    }

    /// Closes the liveness writer, waits the guardian, and joins generation
    /// control after the guardian has revoked/cleared the current generation.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for timeout, unexpected guardian exit, current
    /// group cleanup failure, or generation worker failure.
    pub fn shutdown(&mut self) -> Result<ExitStatus, RuntimeError> {
        let mut failures = Vec::new();
        if let Err(error) = self.prepare_orderly_shutdown() {
            failures.push(error);
        }
        self.liveness_writer.take();
        let deadline = Instant::now() + GUARDIAN_SHUTDOWN_DEADLINE;
        let mut status = None;
        loop {
            match self.child.try_wait() {
                Ok(Some(observed)) => {
                    status = Some(observed);
                    break;
                }
                Ok(None) if Instant::now() < deadline => thread::yield_now(),
                Ok(None) => {
                    failures.push(lifecycle_error(
                        "macOS guardian generation shutdown deadline",
                        io::Error::new(io::ErrorKind::TimedOut, "guardian did not exit"),
                    ));
                    if let Err(error) = self.fail_safe_current_group() {
                        failures.push(error);
                    }
                    if let Err(source) = self.child.kill()
                        && source.kind() != io::ErrorKind::InvalidInput
                    {
                        failures.push(lifecycle_error(
                            "macOS guardian generation process kill",
                            source,
                        ));
                    }
                    match self.child.wait() {
                        Ok(observed) => status = Some(observed),
                        Err(source) => failures.push(lifecycle_error(
                            "macOS guardian generation process wait",
                            source,
                        )),
                    }
                    break;
                }
                Err(source) => {
                    failures.push(lifecycle_error(
                        "macOS guardian generation shutdown wait",
                        source,
                    ));
                    if let Err(error) = self.fail_safe_current_group() {
                        failures.push(error);
                    }
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
            }
        }
        if let Err(error) = self.join_worker() {
            failures.push(error);
        }
        if let Some(observed) = status
            && !observed.success()
        {
            let group_pid = take_generation(&self.current_generation)
                .map_or(0, |generation| generation.group_pid);
            let cleanup_error = (group_pid != 0)
                .then(|| terminate_registered_group(group_pid).err())
                .flatten()
                .map(|error| io::Error::other(error.to_string()));
            failures.push(RuntimeError::GuardianExited {
                group_pid,
                exit_code: observed.code(),
                cleanup_error,
            });
        }
        if failures.is_empty() {
            status.ok_or_else(|| {
                lifecycle_error(
                    "macOS guardian generation shutdown wait",
                    io::Error::other("guardian ended without an observable status"),
                )
            })
        } else {
            Err(collapse_failures(failures))
        }
    }

    fn prepare_orderly_shutdown(&mut self) -> Result<(), RuntimeError> {
        self.deny_recovery();
        if self.shutdown_attributed {
            return Ok(());
        }
        let writer = self.liveness_writer.as_mut().ok_or_else(|| {
            lifecycle_error(
                "macOS guardian orderly-shutdown control",
                io::Error::new(io::ErrorKind::NotConnected, "liveness writer is missing"),
            )
        })?;
        let ack_reader = &mut self.quit_ack_reader;
        set_liveness_nonblocking(writer, true)?;
        writer
            .write_all(&[SUPERVISED_ORDERLY_SHUTDOWN])
            .and_then(|()| writer.flush())
            .map_err(|source| lifecycle_error("macOS guardian orderly-shutdown control", source))?;
        read_supervised_orderly_ack(ack_reader)?;
        self.shutdown_attributed = true;
        lock_recovery(&self.recovery_decision).shutdown_acknowledged = true;
        Ok(())
    }

    fn join_worker(&mut self) -> Result<(), RuntimeError> {
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };
        worker.join().map_err(|_| {
            lifecycle_error(
                "macOS guardian generation host worker",
                io::Error::other("generation host worker panicked"),
            )
        })?
    }

    fn fail_safe_current_group(&self) -> Result<(), RuntimeError> {
        take_generation(&self.current_generation).map_or(Ok(()), |generation| {
            terminate_registered_group(generation.group_pid)
        })
    }
}

fn lock_generation(
    generation: &Mutex<Option<RegisteredPrimaryGeneration>>,
) -> std::sync::MutexGuard<'_, Option<RegisteredPrimaryGeneration>> {
    match generation.lock() {
        Ok(generation) => generation,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn take_generation(
    generation: &Mutex<Option<RegisteredPrimaryGeneration>>,
) -> Option<RegisteredPrimaryGeneration> {
    lock_generation(generation).take()
}

impl Drop for GuardedPrimary {
    fn drop(&mut self) {
        if self.liveness_writer.is_none() {
            return;
        }
        let _ = self.shutdown();
    }
}

impl Drop for GuardianBootstrap {
    fn drop(&mut self) {
        let (Some(mut child), Some(liveness_writer)) =
            (self.child.take(), self.liveness_writer.take())
        else {
            return;
        };
        drop(liveness_writer);
        let _ = child.wait();
    }
}

struct NoopRegistrationObserver;

impl BootstrapRejectionObserver for NoopRegistrationObserver {
    fn rejected(&self, _rejection: BootstrapRejection) {}
}

/// Host-owned handle for one registered private guardian.
///
/// This value owns the guardian process handle and the sole liveness writer.
/// Dropping or calling [`Self::shutdown`] closes that writer so the guardian
/// follows the same EOF cleanup path used for abnormal host death.
#[derive(Debug)]
pub struct HostGuardian {
    child: Child,
    liveness_writer: Option<ChildStdin>,
    quit_ack_reader: Option<ChildStdout>,
    group_pid: Option<u32>,
}

impl HostGuardian {
    fn from_registered_parts(
        mut child: Child,
        liveness_writer: ChildStdin,
        quit_ack_reader: Option<ChildStdout>,
        group_pid: u32,
    ) -> Result<Self, RuntimeError> {
        if let Err(error) = validate_group_leader(group_pid) {
            return Err(reject_host_registration(
                child,
                liveness_writer,
                (group_pid != 0).then_some(group_pid),
                error,
            ));
        }
        if let Err(error) = require_close_on_exec(&liveness_writer) {
            return Err(reject_host_registration(
                child,
                liveness_writer,
                Some(group_pid),
                error,
            ));
        }
        match child.try_wait() {
            Ok(Some(status)) => return Err(unexpected_guardian_exit(group_pid, status)),
            Ok(None) => {}
            Err(source) => {
                let error = lifecycle_error("macOS guardian process-handle inspection", source);
                return Err(reject_host_registration(
                    child,
                    liveness_writer,
                    Some(group_pid),
                    error,
                ));
            }
        }
        Ok(Self {
            child,
            liveness_writer: Some(liveness_writer),
            quit_ack_reader,
            group_pid: Some(group_pid),
        })
    }

    /// OS process id of the private guardian.
    #[must_use]
    pub fn guardian_pid(&self) -> u32 {
        self.child.id()
    }

    /// Registered Bun process-group leader.
    #[must_use]
    pub const fn group_pid(&self) -> Option<u32> {
        self.group_pid
    }

    /// Polls for an unexpected guardian exit while the host remains live.
    ///
    /// # Errors
    ///
    /// Returns a typed lifecycle error when process inspection fails. A
    /// guardian exit invokes the group fail-safe and returns
    /// [`RuntimeError::GuardianExited`].
    pub fn poll_fatal(&mut self) -> Result<(), RuntimeError> {
        self.require_active()?;
        let status = match self.child.try_wait() {
            Ok(status) => status,
            Err(source) => {
                return Err(
                    self.fail_observation("macOS guardian process-handle inspection", source)
                );
            }
        };
        if let Some(status) = status {
            self.liveness_writer.take();
            let group_pid = self.take_registered_group()?;
            return Err(unexpected_guardian_exit(group_pid, status));
        }
        Ok(())
    }

    /// Blocks until the guardian exits while the host still owns its writer.
    ///
    /// A host watcher may use this to turn guardian death into one typed fatal
    /// session event. The registered group fail-safe runs before the event is
    /// returned.
    ///
    /// # Errors
    ///
    /// Always returns [`RuntimeError::GuardianExited`] after the process wait,
    /// or a typed lifecycle error if the wait itself fails.
    pub fn wait_fatal(&mut self) -> Result<(), RuntimeError> {
        self.require_active()?;
        let status = match self.child.wait() {
            Ok(status) => status,
            Err(source) => {
                return Err(self.fail_observation("macOS guardian process-handle wait", source));
            }
        };
        self.liveness_writer.take();
        let group_pid = self.take_registered_group()?;
        Err(unexpected_guardian_exit(group_pid, status))
    }

    /// Records an accepted KEL-96 Quit before its correlated reply can let
    /// Bun exit cooperatively. This writes one non-authority control byte to
    /// the host-exclusive liveness pipe; only [`run_supervised`] accepts it.
    /// Group termination still begins only when [`Self::shutdown`] closes the
    /// writer, so the Quit reply can be published first.
    ///
    /// # Errors
    ///
    /// Returns a typed lifecycle error if the guardian is already terminal or
    /// the private control byte cannot be written and flushed.
    pub fn accept_supervised_quit(&mut self) -> Result<(), RuntimeError> {
        self.require_active()?;
        let ack_reader = self.quit_ack_reader.as_mut().ok_or_else(|| {
            lifecycle_error(
                "macOS guardian supervised-Quit acknowledgment",
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "guardian was not spawned through the supervised bootstrap",
                ),
            )
        })?;
        let writer = self.liveness_writer.as_mut().ok_or_else(|| {
            lifecycle_error(
                "macOS guardian supervised-Quit control",
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "guardian liveness writer is unavailable",
                ),
            )
        })?;
        set_liveness_nonblocking(writer, true)?;
        writer
            .write_all(&[SUPERVISED_QUIT_ACCEPTED])
            .and_then(|()| writer.flush())
            .map_err(|source| lifecycle_error("macOS guardian supervised-Quit control", source))?;
        read_supervised_quit_ack(ack_reader)
    }

    /// Performs orderly shutdown through the same EOF cleanup owner.
    ///
    /// # Errors
    ///
    /// Returns a typed lifecycle error if the guardian cannot be waited. A
    /// non-success guardian exit invokes the group fail-safe and returns
    /// [`RuntimeError::GuardianExited`].
    pub fn shutdown(&mut self) -> Result<ExitStatus, RuntimeError> {
        self.shutdown_until(Instant::now() + GUARDIAN_SHUTDOWN_DEADLINE)
    }

    fn shutdown_until(&mut self, deadline: Instant) -> Result<ExitStatus, RuntimeError> {
        self.require_active()?;
        self.liveness_writer.take();
        let status = loop {
            match self.child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => std::thread::yield_now(),
                Ok(None) => {
                    let mut failures = vec![lifecycle_error(
                        "macOS guardian orderly-shutdown deadline",
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "guardian did not exit before the shutdown deadline",
                        ),
                    )];
                    if let Some(group_pid) = self.group_pid.take()
                        && let Err(error) = terminate_registered_group(group_pid)
                    {
                        failures.push(error);
                    }
                    if let Err(source) = self.child.kill()
                        && source.kind() != io::ErrorKind::InvalidInput
                    {
                        failures.push(lifecycle_error(
                            "macOS guardian shutdown-timeout process kill",
                            source,
                        ));
                    }
                    if let Err(source) = self.child.wait() {
                        failures.push(lifecycle_error(
                            "macOS guardian shutdown-timeout process wait",
                            source,
                        ));
                    }
                    return Err(collapse_failures(failures));
                }
                Err(source) => {
                    return Err(
                        self.fail_observation("macOS guardian orderly-shutdown wait", source)
                    );
                }
            }
        };
        let group_pid = self.take_registered_group()?;
        if status.success() {
            Ok(status)
        } else {
            Err(unexpected_guardian_exit(group_pid, status))
        }
    }

    fn require_active(&self) -> Result<u32, RuntimeError> {
        self.group_pid.ok_or_else(|| {
            lifecycle_error(
                "macOS guardian terminal owner reuse",
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "guardian owner is already terminal; start a fresh session",
                ),
            )
        })
    }

    fn take_registered_group(&mut self) -> Result<u32, RuntimeError> {
        self.group_pid.take().ok_or_else(|| {
            lifecycle_error(
                "macOS guardian terminal owner reuse",
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "guardian owner is already terminal; start a fresh session",
                ),
            )
        })
    }

    fn fail_observation(&mut self, phase: &'static str, source: io::Error) -> RuntimeError {
        self.liveness_writer.take();
        let mut failures = vec![lifecycle_error(phase, source)];
        if let Some(group_pid) = self.group_pid.take()
            && let Err(error) = terminate_registered_group(group_pid)
        {
            failures.push(error);
        }
        if let Err(source) = self.child.kill()
            && source.kind() != io::ErrorKind::InvalidInput
        {
            failures.push(lifecycle_error(
                "macOS guardian fail-safe process kill",
                source,
            ));
        }
        if let Err(source) = self.child.wait() {
            failures.push(lifecycle_error(
                "macOS guardian fail-safe process wait",
                source,
            ));
        }
        collapse_failures(failures)
    }
}

impl Drop for HostGuardian {
    fn drop(&mut self) {
        if self.liveness_writer.take().is_none() {
            return;
        }
        match self.child.wait() {
            Ok(status) if status.success() => {
                self.group_pid.take();
            }
            Ok(_) | Err(_) => {
                if let Some(group_pid) = self.group_pid.take() {
                    let _ = terminate_registered_group(group_pid);
                }
            }
        }
    }
}

impl GuardianReport {
    /// OS process id of the direct Bun child and process-group leader.
    #[must_use]
    pub const fn leader_pid(&self) -> u32 {
        self.leader_pid
    }

    /// Exit status observed by waiting the direct Bun child.
    #[must_use]
    pub const fn leader_status(&self) -> ExitStatus {
        self.leader_status
    }
}

/// Runs one guardian-owned child group until the host-liveness reader reaches
/// EOF, then revokes registered link resources, signals the enrolled process
/// group, and waits the direct child.
///
/// `command` is placed in a new process group before spawn. Descendants inherit
/// that group unless they explicitly break away; a strict-profile consumer
/// must separately prove that attempted `setpgid`/`setsid` escape fails.
/// `liveness` must carry no bytes: EOF is the only accepted host-death signal.
/// The revocation callback runs before group termination, and an error from it
/// blocks successful cleanup even though the group is still terminated and
/// waited.
/// The module authenticates to the host-minted private registration link before
/// child creation and emits the fixed `KGR1` group record after spawn. Callers
/// cannot substitute a numeric group id.
///
/// # Errors
///
/// Returns a typed [`RuntimeError`] when the command is empty, spawning fails,
/// the liveness reader carries bytes or errors, revocation fails, the group
/// cannot be signaled, or the direct child cannot be waited.
pub fn run<R, F>(
    command: Command,
    liveness: R,
    revoke_registered_resources: F,
) -> Result<GuardianReport, RuntimeError>
where
    R: Read + AsFd,
    F: FnOnce() -> io::Result<()>,
{
    let registration = match connect_guardian_registration() {
        Ok(registration) => registration,
        Err(error) => return Err(fail_before_child(error, revoke_registered_resources)),
    };
    run_with_registration(
        command,
        liveness,
        registration,
        |_| Ok(()),
        revoke_registered_resources,
    )
}

/// Runs one non-restarting guardian-owned [`Supervisor`] until host EOF.
///
/// The guardian authenticates its private group-registration link and validates
/// the live host-liveness pipe before starting the supervisor. The supervisor
/// remains the sole Bun spawn/capture/KEL-116-ledger/wait owner. Its prepared
/// generation lease registers the exact Bun group and revokes resources plus
/// signals that group before supervisor kill/wait. A first unrequested child
/// termination is fatal; [`run_guarded_primary`] owns the KEL-96/T3
/// multi-generation path.
/// `quit_ack` is a private dedicated writer: after the guardian reads the
/// accepted-Quit control and updates Supervisor attribution, it writes fixed
/// `KQA`. The host must observe that ack before publishing the Quit reply.
///
/// # Errors
///
/// Returns [`RuntimeError`] for invalid private bootstrap, initial spawn or
/// registration failure, host-liveness failure, revocation/group cleanup
/// failure, or any unrequested Bun self-termination.
pub fn run_supervised<R, C, A, F>(
    liveness: R,
    command_factory: C,
    quit_ack: A,
    revoke_registered_resources: F,
) -> Result<CapturedOutput, RuntimeError>
where
    R: Read + AsFd,
    C: FnOnce() -> Result<Command, RuntimeError> + Send + 'static,
    A: Write,
    F: FnOnce() -> io::Result<()> + Send + 'static,
{
    let registration = match connect_guardian_registration() {
        Ok(registration) => registration,
        Err(error) => return Err(fail_before_child(error, revoke_registered_resources)),
    };
    run_supervised_with_registration(
        liveness,
        registration,
        quit_ack,
        command_factory,
        |_| Ok(()),
        revoke_registered_resources,
    )
    .map(|(_, _, output)| output)
}

struct GuardedPrimaryPreparer<C> {
    command_factory: C,
    control: Arc<Mutex<GenerationControlPeer>>,
    host_unavailable: Arc<AtomicBool>,
    preparation_cancelled: Arc<AtomicBool>,
}

impl<C> ChildPreparer for GuardedPrimaryPreparer<C>
where
    C: FnMut(&str) -> Result<Command, RuntimeError> + Send + 'static,
{
    type Lease = GuardedPrimaryLease;

    fn prepare(&mut self, attempt: u32) -> Result<PreparedChild<Self::Lease>, RuntimeError> {
        let response = control_exchange_with_cancellation(
            &self.control,
            &GenerationControlRecord::new(CONTROL_PREPARE, attempt),
            CONTROL_PREPARED,
            attempt,
            Some((&self.preparation_cancelled, &self.host_unavailable)),
        )?;
        let app_link = match String::from_utf8(response.payload) {
            Ok(app_link) if !app_link.is_empty() => app_link,
            Ok(_) => {
                let primary = lifecycle_error(
                    "macOS guardian generation preparation",
                    io::Error::new(io::ErrorKind::InvalidData, "prepared app link is empty"),
                );
                return Err(collapse_guarded_preparation_failure(
                    &self.control,
                    attempt,
                    primary,
                ));
            }
            Err(source) => {
                let primary = lifecycle_error(
                    "macOS guardian generation preparation",
                    io::Error::new(io::ErrorKind::InvalidData, source),
                );
                return Err(collapse_guarded_preparation_failure(
                    &self.control,
                    attempt,
                    primary,
                ));
            }
        };
        let mut command = match (self.command_factory)(&app_link) {
            Ok(command) => command,
            Err(primary) => {
                return Err(collapse_guarded_preparation_failure(
                    &self.control,
                    attempt,
                    primary,
                ));
            }
        };
        command
            .env_remove(REGISTRATION_ENV)
            .process_group(0)
            .stdin(Stdio::null());
        Ok(PreparedChild {
            command: command.into(),
            lease: GuardedPrimaryLease {
                attempt,
                control: Arc::clone(&self.control),
                host_unavailable: Arc::clone(&self.host_unavailable),
                group_pid: None,
            },
        })
    }
}

fn collapse_guarded_preparation_failure(
    control: &Arc<Mutex<GenerationControlPeer>>,
    attempt: u32,
    primary: RuntimeError,
) -> RuntimeError {
    let revoke = control_exchange(
        control,
        &GenerationControlRecord::new(CONTROL_REVOKE, attempt)
            .with_cause(RevocationCause::AdmissionFailed),
        CONTROL_REVOKED,
        attempt,
    );
    let clear = revoke.and_then(|_| {
        control_exchange(
            control,
            &GenerationControlRecord::new(CONTROL_CLEAR, attempt),
            CONTROL_CLEARED,
            attempt,
        )
    });
    match clear {
        Ok(_) => primary,
        Err(cleanup) => collapse_failures(vec![primary, cleanup]),
    }
}

struct GuardedPrimaryLease {
    attempt: u32,
    control: Arc<Mutex<GenerationControlPeer>>,
    host_unavailable: Arc<AtomicBool>,
    group_pid: Option<u32>,
}

impl GenerationLease for GuardedPrimaryLease {
    fn child_spawned(&mut self, pid: u32, attempt: u32) -> Result<(), RuntimeError> {
        if attempt != self.attempt {
            return Err(lifecycle_error(
                "macOS guardian generation registration",
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "supervisor attempt differs from prepared generation",
                ),
            ));
        }
        validate_group_leader(pid)?;
        control_exchange(
            &self.control,
            &GenerationControlRecord::new(CONTROL_SPAWNED, attempt).with_pid(pid),
            CONTROL_REGISTERED,
            attempt,
        )?;
        self.group_pid = Some(pid);
        Ok(())
    }

    fn revoke(mut self, cause: RevocationCause) -> Result<(), RuntimeError> {
        let group_pid = self.group_pid.take();
        let host_available = !self.host_unavailable.load(Ordering::Acquire);
        let mut failures = Vec::new();
        if host_available
            && let Err(error) = control_exchange(
                &self.control,
                &GenerationControlRecord::new(CONTROL_REVOKE, self.attempt).with_cause(cause),
                CONTROL_REVOKED,
                self.attempt,
            )
        {
            failures.push(error);
        }
        if let Some(pid) = group_pid
            && let Err(error) = terminate_registered_group(pid)
        {
            failures.push(error);
        }
        if host_available
            && failures.is_empty()
            && let Err(error) = control_exchange(
                &self.control,
                &GenerationControlRecord::new(CONTROL_CLEAR, self.attempt)
                    .with_pid(group_pid.unwrap_or(0)),
                CONTROL_CLEARED,
                self.attempt,
            )
        {
            failures.push(error);
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(collapse_failures(failures))
        }
    }
}

/// Runs a persistent macOS guardian whose single [`Supervisor`] requests a
/// fresh host-owned primary generation before every Bun spawn.
///
/// The authenticated guardian-registration stream becomes a bounded private
/// generation-control channel. The host remains the endpoint/token/stream
/// owner; the guardian remains the only Bun child, process-group, restart and
/// reap owner. Public kipc frame bytes are unchanged.
///
/// # Errors
///
/// Returns [`RuntimeError`] when either private bootstrap is invalid, the host
/// rejects a generation transition, the supervisor reaches a terminal
/// failure, or an unrequested status-zero termination stops supervision.
pub fn run_guarded_primary<R, C, A>(
    mut liveness: R,
    command_factory: C,
    mut quit_ack: A,
) -> Result<CapturedOutput, RuntimeError>
where
    R: Read + AsFd,
    C: FnMut(&str) -> Result<Command, RuntimeError> + Send + 'static,
    A: Write,
{
    let control = connect_guardian_registration()?;
    control
        .set_read_timeout(Some(GENERATION_CONTROL_POLL))
        .map_err(|source| lifecycle_error("macOS guardian generation control deadline", source))?;
    control
        .set_write_timeout(Some(GENERATION_CONTROL_POLL))
        .map_err(|source| lifecycle_error("macOS guardian generation control deadline", source))?;
    validate_liveness_bootstrap(&mut liveness)?;
    let host_unavailable = Arc::new(AtomicBool::new(false));
    let preparation_cancelled = Arc::new(AtomicBool::new(false));
    let supervisor = Supervisor::start_prepared(
        RestartPolicy::default(),
        GuardedPrimaryPreparer {
            command_factory,
            control: Arc::new(Mutex::new(GenerationControlPeer {
                stream: control,
                reader: GenerationControlReader::new(),
            })),
            host_unavailable: Arc::clone(&host_unavailable),
            preparation_cancelled: Arc::clone(&preparation_cancelled),
        },
    )?;

    set_liveness_nonblocking(&liveness, true)?;
    let (liveness_result, quit_accepted, host_dead) = await_guarded_primary_liveness(
        &mut liveness,
        &supervisor,
        &mut quit_ack,
        &host_unavailable,
        &preparation_cancelled,
    );

    let outcome = supervisor.wait_for_outcome();
    let crash_ledger = supervisor.crash_ledger();
    let output = supervisor.output();
    let mut failures = Vec::new();
    if let Err(error) = liveness_result {
        failures.push(error);
    }
    match outcome {
        SupervisorOutcome::CrashLoop(error) | SupervisorOutcome::Failed(error) => {
            failures.push(error);
        }
        SupervisorOutcome::Stopped if !quit_accepted && !host_dead => {
            if let Some(termination) = crash_ledger.last_self_termination {
                failures.push(RuntimeError::ChildCrashed {
                    pid: termination.pid,
                    exit_code: termination.exit_code,
                    stderr_tail: output.stderr_tail(2_000),
                });
            } else {
                failures.push(lifecycle_error(
                    "macOS guardian generation supervisor stop",
                    io::Error::other("supervisor stopped without owned shutdown attribution"),
                ));
            }
        }
        SupervisorOutcome::Stopped => {}
    }
    if failures.is_empty() {
        Ok(output)
    } else {
        Err(collapse_failures(failures))
    }
}

fn await_guarded_primary_liveness(
    liveness: &mut (impl Read + AsFd),
    supervisor: &Supervisor,
    quit_ack: &mut impl Write,
    host_unavailable: &AtomicBool,
    preparation_cancelled: &AtomicBool,
) -> (Result<(), RuntimeError>, bool, bool) {
    let mut liveness_result = Ok(());
    let mut quit_accepted = false;
    let mut orderly_requested = false;
    let mut host_dead = false;
    loop {
        match observe_guarded_liveness(
            liveness,
            supervisor,
            &mut quit_accepted,
            &mut orderly_requested,
            quit_ack,
            preparation_cancelled,
        ) {
            Ok(true) => {
                host_dead = true;
                if !quit_accepted && !orderly_requested {
                    host_unavailable.store(true, Ordering::Release);
                }
                supervisor.shutdown();
                break;
            }
            Ok(false) => {}
            Err(error) => {
                liveness_result = Err(error);
                // A liveness fault interrupts a pending read as a fatal error,
                // never as the privately attributed stop marker.
                host_unavailable.store(true, Ordering::Release);
                supervisor.shutdown();
                break;
            }
        }
        match supervisor.recv_event(GENERATION_CONTROL_POLL) {
            Some(crate::SupervisorEvent::Stopped) if quit_accepted => {
                // Supervisor stop does not terminate this persistent guardian.
                // Core may still own real native retirement before host EOF.
                if let Err(error) = set_liveness_nonblocking(liveness, false) {
                    liveness_result = Err(error);
                    break;
                }
            }
            Some(
                crate::SupervisorEvent::RespawnFailed
                | crate::SupervisorEvent::Failed { .. }
                | crate::SupervisorEvent::CrashLoopTripped
                | crate::SupervisorEvent::Stopped,
            ) => break,
            None => thread::yield_now(),
            Some(_) => {}
        }
    }

    (liveness_result, quit_accepted, host_dead)
}

fn run_supervised_with_registration<R, W, C, A, S, F>(
    mut liveness: R,
    registration: W,
    mut quit_ack: A,
    command_factory: C,
    child_spawned: S,
    revoke_registered_resources: F,
) -> Result<(u32, CrashLedger, CapturedOutput), RuntimeError>
where
    R: Read + AsFd,
    W: Write + Send + 'static,
    C: FnOnce() -> Result<Command, RuntimeError> + Send + 'static,
    A: Write,
    S: FnOnce(u32) -> io::Result<()> + Send + 'static,
    F: FnOnce() -> io::Result<()> + Send + 'static,
{
    if let Err(error) = validate_liveness_bootstrap(&mut liveness) {
        return Err(fail_before_child(error, revoke_registered_resources));
    }
    let (pid_tx, pid_rx) = std::sync::mpsc::sync_channel(1);
    let preparer = SupervisedGuardianPreparer {
        command_factory: Some(command_factory),
        registration: Some(registration),
        child_spawned: Some(child_spawned),
        revoke_registered_resources: Some(revoke_registered_resources),
        pid_tx,
    };
    let supervisor = Supervisor::start_prepared(
        RestartPolicy {
            max_crashes: 1,
            window_secs: 30,
        },
        preparer,
    )?;
    let leader_pid = pid_rx.recv().map_err(|_| {
        lifecycle_error(
            "macOS guardian supervised-child registration",
            io::Error::other("supervisor ended before registering its initial child"),
        )
    })?;

    set_liveness_nonblocking(&liveness, true)?;
    let mut liveness_result = Ok(());
    let mut quit_accepted = false;
    loop {
        match observe_supervised_liveness(
            &mut liveness,
            &supervisor,
            &mut quit_accepted,
            &mut quit_ack,
        ) {
            Ok(true) => break,
            Ok(false) => {}
            Err(error) => {
                liveness_result = Err(error);
                supervisor.shutdown();
                break;
            }
        }
        if let Some(event) = supervisor.recv_event(Duration::from_millis(20))
            && matches!(
                event,
                crate::SupervisorEvent::Exited { .. }
                    | crate::SupervisorEvent::RespawnFailed
                    | crate::SupervisorEvent::Failed { .. }
                    | crate::SupervisorEvent::CrashLoopTripped
                    | crate::SupervisorEvent::Stopped
            )
        {
            if let Err(error) = observe_supervised_liveness(
                &mut liveness,
                &supervisor,
                &mut quit_accepted,
                &mut quit_ack,
            ) {
                liveness_result = Err(error);
                supervisor.shutdown();
            }
            break;
        }
    }
    let outcome = supervisor.wait_for_outcome();
    let crash_ledger = supervisor.crash_ledger();
    let output = supervisor.output();
    drop(supervisor);

    let mut failures = Vec::new();
    if let Err(error) = liveness_result {
        failures.push(error);
    }
    match outcome {
        SupervisorOutcome::CrashLoop(error) | SupervisorOutcome::Failed(error) => {
            failures.push(error);
        }
        SupervisorOutcome::Stopped => {
            if let Some(termination) = crash_ledger.last_self_termination {
                failures.push(RuntimeError::ChildCrashed {
                    pid: termination.pid,
                    exit_code: termination.exit_code,
                    stderr_tail: output.stderr_tail(2_000),
                });
            }
        }
    }
    if !failures.is_empty() {
        return Err(collapse_failures(failures));
    }
    Ok((leader_pid, crash_ledger, output))
}

fn run_with_registration<R, W, S, F>(
    mut command: Command,
    mut liveness: R,
    mut registration: W,
    child_spawned: S,
    revoke_registered_resources: F,
) -> Result<GuardianReport, RuntimeError>
where
    R: Read + AsFd,
    W: Write,
    S: FnOnce(u32) -> io::Result<()>,
    F: FnOnce() -> io::Result<()>,
{
    if command.get_program().is_empty() {
        let error = lifecycle_error(
            "macOS guardian bootstrap",
            io::Error::new(io::ErrorKind::InvalidInput, "child program is empty"),
        );
        return Err(fail_before_child(error, revoke_registered_resources));
    }

    if let Err(error) = validate_liveness_bootstrap(&mut liveness) {
        return Err(fail_before_child(error, revoke_registered_resources));
    }

    command
        .env_remove(REGISTRATION_ENV)
        .process_group(0)
        .stdin(Stdio::null());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(source) => {
            return Err(fail_before_child(
                RuntimeError::Spawn(source),
                revoke_registered_resources,
            ));
        }
    };
    let leader_pid = child.id();

    let registration_result = validate_group_pid(leader_pid)
        .map(|_| ())
        .and_then(|()| write_group_registration(&mut registration, leader_pid));
    if let Err(error) = registration_result {
        let mut failures = vec![error];
        if let Err(source) = revoke_registered_resources() {
            failures.push(lifecycle_error(
                "macOS guardian registered-resource revocation",
                source,
            ));
        }
        if let Err(error) = terminate_registered_group(leader_pid) {
            failures.push(error);
        }
        if let Err(source) = child.wait() {
            failures.push(lifecycle_error("macOS guardian direct-child wait", source));
        }
        return Err(collapse_failures(failures));
    }

    if let Err(source) = child_spawned(leader_pid) {
        let mut failures = vec![lifecycle_error(
            "macOS guardian local registration observer",
            source,
        )];
        if let Err(source) = revoke_registered_resources() {
            failures.push(lifecycle_error(
                "macOS guardian registered-resource revocation",
                source,
            ));
        }
        if let Err(error) = terminate_registered_group(leader_pid) {
            failures.push(error);
        }
        if let Err(source) = child.wait() {
            failures.push(lifecycle_error("macOS guardian direct-child wait", source));
        }
        return Err(collapse_failures(failures));
    }

    let liveness_result = await_host_death(&mut liveness);
    let revocation_result = revoke_registered_resources()
        .map_err(|source| lifecycle_error("macOS guardian registered-resource revocation", source));
    let signal_result = terminate_registered_group(leader_pid);
    let wait_result = child.wait();
    let mut failures = Vec::new();
    if let Err(error) = liveness_result {
        failures.push(error);
    }
    if let Err(error) = revocation_result {
        failures.push(error);
    }
    if let Err(error) = signal_result {
        failures.push(error);
    }
    let leader_status = match wait_result {
        Ok(status) => status,
        Err(source) => {
            failures.push(lifecycle_error("macOS guardian direct-child wait", source));
            return Err(collapse_failures(failures));
        }
    };
    if !failures.is_empty() {
        return Err(collapse_failures(failures));
    }
    Ok(GuardianReport {
        leader_pid,
        leader_status,
    })
}

fn connect_guardian_registration() -> Result<std::os::unix::net::UnixStream, RuntimeError> {
    let link = std::env::var(REGISTRATION_ENV).map_err(|source| {
        lifecycle_error(
            "macOS guardian private registration bootstrap",
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{REGISTRATION_ENV} is unavailable: {source}"),
            ),
        )
    })?;
    let (endpoint, token) = parse_app_link(&link).map_err(|source| {
        lifecycle_error(
            "macOS guardian private registration bootstrap",
            io::Error::new(io::ErrorKind::InvalidInput, source.to_string()),
        )
    })?;
    let mut stream = std::os::unix::net::UnixStream::connect(endpoint)
        .map_err(|source| lifecycle_error("macOS guardian private registration connect", source))?;
    handshake_client(&mut stream, &token).map_err(|source| {
        lifecycle_error(
            "macOS guardian private registration authentication",
            io::Error::other(source.to_string()),
        )
    })?;
    Ok(stream)
}

fn write_group_registration(writer: &mut impl Write, group_pid: u32) -> Result<(), RuntimeError> {
    let mut record = [0_u8; REGISTRATION_LEN];
    record[..4].copy_from_slice(&REGISTRATION_MAGIC);
    record[4..].copy_from_slice(&group_pid.to_be_bytes());
    writer.write_all(&record).map_err(|source| {
        lifecycle_error("macOS guardian authenticated group registration", source)
    })?;
    writer.flush().map_err(|source| {
        lifecycle_error(
            "macOS guardian authenticated group registration flush",
            source,
        )
    })
}

#[cfg(test)]
struct GenerationProvisionFence {
    attempt: u32,
    entered: mpsc::SyncSender<()>,
    release: Receiver<()>,
}

#[derive(Default)]
struct HostGenerationState {
    lease: Option<RoleGenerationLease>,
    current_attempt: Option<u32>,
    revoked_attempt: Option<u32>,
    pending_prepare: Option<GenerationControlRecord>,
    initial_decision_deadline: Option<Instant>,
}

#[allow(clippy::too_many_lines)] // one owner keeps every private protocol transition contiguous
fn run_generation_host(
    mut control: std::os::unix::net::UnixStream,
    updates_tx: &Sender<GuardedPrimaryUpdate>,
    current_generation: &Mutex<Option<RegisteredPrimaryGeneration>>,
    recovery_decision: &Mutex<RecoveryState>,
    #[cfg(test)] provision_fence: Option<&GenerationProvisionFence>,
) -> Result<(), RuntimeError> {
    control
        .set_read_timeout(Some(GENERATION_CONTROL_POLL))
        .map_err(|source| lifecycle_error("macOS guardian generation host deadline", source))?;
    control
        .set_write_timeout(Some(GENERATION_CONTROL_POLL))
        .map_err(|source| lifecycle_error("macOS guardian generation host deadline", source))?;
    let (events_tx, events_rx) = mpsc::channel();
    let (bound_tx, bound_rx) = mpsc::channel();
    let mut owner = RoleGenerationOwner::new(
        RoleOwner::Primary,
        DEFAULT_ADMISSION_TIMEOUT,
        events_tx,
        Some(bound_tx),
        #[cfg(test)]
        #[cfg(unix)]
        None,
    );
    let mut state = HostGenerationState::default();
    let mut control_reader = GenerationControlReader::new();
    loop {
        if let Some(lease) = state.lease.as_mut() {
            lease.poll()?;
        }
        forward_generation_updates(updates_tx, &bound_rx, &events_rx)?;
        let record = match control_reader.poll(&mut control) {
            Ok(record) => record,
            Err(error) if runtime_io_kind(&error) == Some(io::ErrorKind::UnexpectedEof) => {
                let result = finish_generation_control_eof(
                    error,
                    control_reader.filled,
                    &mut state,
                    current_generation,
                    recovery_decision,
                );
                forward_generation_updates(updates_tx, &bound_rx, &events_rx)?;
                return result;
            }
            Err(error) => return Err(error),
        };
        let expected_attempt = lock_recovery(recovery_decision).expected_attempt;
        if let Some(record) = record {
            if state.pending_prepare.is_some() {
                return Err(invalid_control_transition(
                    "pending prepare",
                    record.attempt,
                    expected_attempt,
                ));
            }
            match record.kind {
                CONTROL_PREPARE => {
                    if record.attempt != expected_attempt
                        || state.current_attempt.is_some()
                        || state.lease.is_some()
                        || state.revoked_attempt.is_some()
                        || lock_generation(current_generation).is_some()
                        || record.pid != 0
                        || record.cause != 0
                        || !record.payload.is_empty()
                    {
                        return Err(invalid_control_transition(
                            "prepare",
                            record.attempt,
                            expected_attempt,
                        ));
                    }
                    if record.attempt > 1 && !lock_recovery(recovery_decision).initial_ready {
                        state.initial_decision_deadline =
                            Some(Instant::now() + GUARDIAN_SHUTDOWN_DEADLINE);
                    }
                    state.pending_prepare = Some(record);
                }
                CONTROL_SPAWNED => {
                    if state.current_attempt != Some(record.attempt)
                        || record.pid == 0
                        || record.cause != 0
                        || !record.payload.is_empty()
                        || lock_generation(current_generation).is_some()
                    {
                        return Err(invalid_control_transition(
                            "spawned",
                            record.attempt,
                            expected_attempt,
                        ));
                    }
                    let current = state.lease.as_mut().ok_or_else(|| {
                        invalid_control_transition("spawned", record.attempt, expected_attempt)
                    })?;
                    current.child_spawned(record.pid, record.attempt)?;
                    *lock_generation(current_generation) = Some(RegisteredPrimaryGeneration {
                        attempt: record.attempt,
                        group_pid: record.pid,
                    });
                    forward_generation_updates(updates_tx, &bound_rx, &events_rx)?;
                    write_generation_control(
                        &mut control,
                        &GenerationControlRecord::new(CONTROL_REGISTERED, record.attempt)
                            .with_pid(record.pid),
                    )?;
                }
                CONTROL_REVOKE => {
                    if state.current_attempt != Some(record.attempt)
                        || state.revoked_attempt.is_some()
                        || record.pid != 0
                        || !record.payload.is_empty()
                    {
                        return Err(invalid_control_transition(
                            "revoke",
                            record.attempt,
                            expected_attempt,
                        ));
                    }
                    let cause = decode_revocation_cause(record.cause)?;
                    let current = state.lease.take().ok_or_else(|| {
                        invalid_control_transition("revoke", record.attempt, expected_attempt)
                    })?;
                    // Close native release before the lease emits Revoked.
                    lock_recovery(recovery_decision).retire(record.attempt);
                    current.revoke(cause)?;
                    state.revoked_attempt = Some(record.attempt);
                    forward_generation_updates(updates_tx, &bound_rx, &events_rx)?;
                    write_generation_control(
                        &mut control,
                        &GenerationControlRecord::new(CONTROL_REVOKED, record.attempt),
                    )?;
                }
                CONTROL_CLEAR => {
                    let registered = lock_generation(current_generation)
                        .map_or(0, |generation| generation.group_pid);
                    if state.current_attempt != Some(record.attempt)
                        || state.revoked_attempt != Some(record.attempt)
                        || record.cause != 0
                        || !record.payload.is_empty()
                        || record.pid != registered
                    {
                        return Err(invalid_control_transition(
                            "clear",
                            record.attempt,
                            expected_attempt,
                        ));
                    }
                    take_generation(current_generation);
                    write_generation_control(
                        &mut control,
                        &GenerationControlRecord::new(CONTROL_CLEARED, record.attempt)
                            .with_pid(record.pid),
                    )?;
                    state.current_attempt = None;
                    state.revoked_attempt = None;
                    // None alone is not Clear: only the completed acknowledgment
                    // advances the attempt and permits a pending release request.
                    lock_recovery(recovery_decision).cleared(record.attempt)?;
                }
                _ => {
                    return Err(lifecycle_error(
                        "macOS guardian generation host transition",
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unexpected control kind {}", record.kind),
                        ),
                    ));
                }
            }
        }
        if control_reader.filled != 0 {
            continue;
        }
        let Some(pending) = state.pending_prepare.as_ref() else {
            continue;
        };
        let provisioned = {
            let mut recovery = lock_recovery(recovery_decision);
            check_initial_recovery_decision(&recovery, state.initial_decision_deadline)?;
            if pending.attempt == 1 && recovery.denied {
                return Err(rejected_recovery());
            }
            if !recovery.permits(pending.attempt) {
                continue;
            }
            recovery.release_attempt = None;
            // This actual bind/token mint is ordered against permanent denial.
            // Do not release the recovery guard between the check and provision.
            #[cfg(test)]
            if let Some(fence) = provision_fence.filter(|fence| fence.attempt == pending.attempt) {
                // Scoped unit-test custody only: shipping code has no fence,
                // callback, global, extra owner, or branch here. The real host
                // owner retains its recovery guard through the actual mint.
                fence.entered.send(()).map_err(|_| {
                    lifecycle_error(
                        "test generation pre-mint receipt",
                        io::Error::other("test custodian ended"),
                    )
                })?;
                fence
                    .release
                    .recv_timeout(GUARDIAN_SHUTDOWN_DEADLINE)
                    .map_err(|source| {
                        lifecycle_error(
                            "test generation pre-mint release",
                            io::Error::other(source),
                        )
                    })?;
            }
            owner.provision(pending.attempt)?
        };
        let response = GenerationControlRecord::new(CONTROL_PREPARED, pending.attempt)
            .with_payload(provisioned.app_link.as_bytes().to_vec());
        state.current_attempt = Some(pending.attempt);
        state.lease = Some(provisioned.lease);
        state.pending_prepare = None;
        state.initial_decision_deadline = None;
        forward_generation_updates(updates_tx, &bound_rx, &events_rx)?;
        if let Err(error) = write_generation_control(&mut control, &response) {
            if matches!(
                runtime_io_kind(&error),
                Some(io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset)
            ) {
                let result = finish_generation_control_eof(
                    error,
                    control_reader.filled,
                    &mut state,
                    current_generation,
                    recovery_decision,
                );
                forward_generation_updates(updates_tx, &bound_rx, &events_rx)?;
                return result;
            }
            return Err(error);
        }
    }
}

fn rejected_recovery() -> RuntimeError {
    lifecycle_error(
        "macOS guardian generation host transition",
        io::Error::new(
            io::ErrorKind::InvalidData,
            "successor preparation was rejected before initial Ready",
        ),
    )
}

fn check_initial_recovery_decision(
    recovery: &RecoveryState,
    deadline: Option<Instant>,
) -> Result<(), RuntimeError> {
    if recovery.initial_ready || deadline.is_none() {
        return Ok(());
    }
    if recovery.denied {
        return Err(rejected_recovery());
    }
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err(lifecycle_error(
            "macOS guardian generation host transition",
            io::Error::new(
                io::ErrorKind::TimedOut,
                "initial Ready did not decide recovery before the deadline",
            ),
        ));
    }
    Ok(())
}

fn finish_generation_control_eof(
    primary: RuntimeError,
    partial_bytes: usize,
    state: &mut HostGenerationState,
    current_generation: &Mutex<Option<RegisteredPrimaryGeneration>>,
    recovery: &Mutex<RecoveryState>,
) -> Result<(), RuntimeError> {
    if partial_bytes != 0 || lock_generation(current_generation).is_some() {
        return Err(primary);
    }
    if let Some(lease) = state.lease.take() {
        let Some(attempt) = state.current_attempt.take() else {
            return Err(primary);
        };
        if state.revoked_attempt.is_some() {
            return Err(primary);
        }
        lock_recovery(recovery).retire(attempt);
        if let Err(cleanup) = lease.revoke(RevocationCause::Shutdown) {
            return Err(collapse_failures(vec![primary, cleanup]));
        }
    }
    if state.current_attempt.is_some() || state.revoked_attempt.is_some() {
        return Err(primary);
    }
    // EOF can precede the host's Q/S ACK read by one scheduling turn. Retain
    // the EOF fact and its one existing attribution budget; never reread EOF.
    let deadline = Instant::now() + SUPERVISED_QUIT_ACK_DEADLINE;
    loop {
        let recovery = lock_recovery(recovery);
        if !recovery.denied {
            return Err(primary);
        }
        if recovery.shutdown_acknowledged {
            return Ok(());
        }
        drop(recovery);
        if Instant::now() >= deadline {
            return Err(primary);
        }
        thread::yield_now();
    }
}

fn forward_generation_updates(
    updates_tx: &Sender<GuardedPrimaryUpdate>,
    bound_rx: &Receiver<BoundRoleGeneration>,
    events_rx: &Receiver<RoleEvent>,
) -> Result<(), RuntimeError> {
    while let Ok(bound) = bound_rx.try_recv() {
        updates_tx
            .send(GuardedPrimaryUpdate::Bound(bound))
            .map_err(|_| generation_consumer_gone())?;
    }
    while let Ok(event) = events_rx.try_recv() {
        updates_tx
            .send(GuardedPrimaryUpdate::Role(event))
            .map_err(|_| generation_consumer_gone())?;
    }
    Ok(())
}

fn generation_consumer_gone() -> RuntimeError {
    lifecycle_error(
        "macOS guardian generation update delivery",
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "host generation consumer ended before shutdown",
        ),
    )
}

fn invalid_control_transition(phase: &str, attempt: u32, expected: u32) -> RuntimeError {
    lifecycle_error(
        "macOS guardian generation host transition",
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid {phase} transition for attempt {attempt}; expected {expected}"),
        ),
    )
}

fn runtime_io_kind(error: &RuntimeError) -> Option<io::ErrorKind> {
    match error {
        RuntimeError::Spawn(source) | RuntimeError::Lifecycle { source, .. } => Some(source.kind()),
        RuntimeError::CrashLoop { .. }
        | RuntimeError::ChildCrashed { .. }
        | RuntimeError::GuardianExited { .. } => None,
    }
}

fn fail_before_child(
    error: RuntimeError,
    revoke_registered_resources: impl FnOnce() -> io::Result<()>,
) -> RuntimeError {
    let mut failures = vec![error];
    if let Err(source) = revoke_registered_resources() {
        failures.push(lifecycle_error(
            "macOS guardian pre-child registered-resource revocation",
            source,
        ));
    }
    collapse_failures(failures)
}

fn validate_group_pid(group: u32) -> Result<i32, RuntimeError> {
    if group == 0 {
        return Err(lifecycle_error(
            "macOS guardian host registration",
            io::Error::new(io::ErrorKind::InvalidInput, "process group is zero"),
        ));
    }
    i32::try_from(group).map_err(|_| {
        lifecycle_error(
            "macOS guardian host registration",
            io::Error::new(io::ErrorKind::InvalidInput, "process group exceeds c_int"),
        )
    })
}

fn validate_group_leader(group: u32) -> Result<i32, RuntimeError> {
    let raw = validate_group_pid(group)?;
    let observed = getpgid(Some(Pid::from_raw(raw))).map_err(|source| {
        lifecycle_error(
            "macOS guardian group-leader validation",
            nix_io_error(source),
        )
    })?;
    if observed.as_raw() == raw {
        Ok(raw)
    } else {
        Err(lifecycle_error(
            "macOS guardian group-leader validation",
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("reported pid {group} belongs to process group {observed}"),
            ),
        ))
    }
}

fn terminate_registered_group(group: u32) -> Result<(), RuntimeError> {
    let group = validate_group_pid(group)?;
    match killpg(Pid::from_raw(group), Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(Errno::EPERM) if matches!(getpgid(Some(Pid::from_raw(group))), Err(Errno::ESRCH)) => {
            // A post-Ready link failure may have already signalled the group
            // while the direct child was exiting. Darwin can report EPERM for
            // the now-retired numeric group. Require getpgid to prove the
            // leader gone; never suppress EPERM while that leader resolves.
            Ok(())
        }
        Err(error) => Err(lifecycle_error(
            "macOS guardian process-group signal",
            io::Error::from_raw_os_error(error as i32),
        )),
    }
}

fn reject_host_registration(
    mut child: Child,
    liveness_writer: ChildStdin,
    group_pid: Option<u32>,
    error: RuntimeError,
) -> RuntimeError {
    drop(liveness_writer);
    let mut failures = vec![error];
    match child.wait() {
        Ok(status) if status.success() => {}
        Ok(status) => {
            failures.push(lifecycle_error(
                "macOS guardian rejected-registration wait",
                io::Error::other(format!(
                    "guardian exited unsuccessfully during registration cleanup: {status}"
                )),
            ));
            if let Some(group_pid) = group_pid
                && let Err(error) = terminate_registered_group(group_pid)
            {
                failures.push(error);
            }
        }
        Err(source) => {
            failures.push(lifecycle_error(
                "macOS guardian rejected-registration wait",
                source,
            ));
            if let Some(group_pid) = group_pid
                && let Err(error) = terminate_registered_group(group_pid)
            {
                failures.push(error);
            }
        }
    }
    collapse_failures(failures)
}

fn require_close_on_exec(writer: &impl AsFd) -> Result<(), RuntimeError> {
    let raw = fcntl(writer.as_fd(), FcntlArg::F_GETFD).map_err(|source| {
        lifecycle_error(
            "macOS guardian host-liveness writer flags",
            nix_io_error(source),
        )
    })?;
    let flags = FdFlag::from_bits_truncate(raw);
    if flags.contains(FdFlag::FD_CLOEXEC) {
        Ok(())
    } else {
        Err(lifecycle_error(
            "macOS guardian host-liveness writer validation",
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "host-liveness writer is inheritable; require FD_CLOEXEC",
            ),
        ))
    }
}

fn read_supervised_quit_ack(reader: &mut ChildStdout) -> Result<(), RuntimeError> {
    read_supervised_ack(
        reader,
        SUPERVISED_QUIT_ACK,
        "macOS guardian supervised-Quit acknowledgment",
        "accepted Quit",
    )
}

fn read_supervised_orderly_ack(reader: &mut ChildStdout) -> Result<(), RuntimeError> {
    read_supervised_ack(
        reader,
        SUPERVISED_ORDERLY_ACK,
        "macOS guardian orderly-shutdown acknowledgment",
        "orderly shutdown",
    )
}

fn read_supervised_ack(
    reader: &mut ChildStdout,
    expected: [u8; 3],
    phase: &'static str,
    action: &'static str,
) -> Result<(), RuntimeError> {
    let raw_flags = fcntl(reader.as_fd(), FcntlArg::F_GETFL)
        .map_err(|source| lifecycle_error(phase, nix_io_error(source)))?;
    fcntl(
        reader.as_fd(),
        FcntlArg::F_SETFL(OFlag::from_bits_truncate(raw_flags) | OFlag::O_NONBLOCK),
    )
    .map_err(|source| lifecycle_error(phase, nix_io_error(source)))?;
    let deadline = Instant::now() + SUPERVISED_QUIT_ACK_DEADLINE;
    let mut ack = [0_u8; 3];
    let mut filled = 0;
    while filled < ack.len() {
        match reader.read(&mut ack[filled..]) {
            Ok(0) => {
                return Err(lifecycle_error(
                    phase,
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("guardian exited before acknowledging {action}"),
                    ),
                ));
            }
            Ok(read) => filled += read,
            Err(source) if source.kind() == io::ErrorKind::Interrupted => {}
            Err(source) if source.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(lifecycle_error(
                        phase,
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("guardian did not acknowledge {action} before the deadline"),
                        ),
                    ));
                }
                std::thread::yield_now();
            }
            Err(source) => {
                return Err(lifecycle_error(phase, source));
            }
        }
    }
    if ack == expected {
        Ok(())
    } else {
        Err(lifecycle_error(
            phase,
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("guardian returned an invalid {action} acknowledgment"),
            ),
        ))
    }
}

fn unexpected_guardian_exit(group_pid: u32, status: ExitStatus) -> RuntimeError {
    let cleanup_error = terminate_registered_group(group_pid)
        .err()
        .map(|error| io::Error::other(error.to_string()));
    RuntimeError::GuardianExited {
        group_pid,
        exit_code: status.code(),
        cleanup_error,
    }
}

fn nix_io_error(source: Errno) -> io::Error {
    io::Error::from_raw_os_error(source as i32)
}

fn lifecycle_error(phase: &'static str, source: io::Error) -> RuntimeError {
    RuntimeError::Lifecycle { phase, source }
}

fn collapse_failures(mut failures: Vec<RuntimeError>) -> RuntimeError {
    if failures.len() == 1
        && let Some(error) = failures.pop()
    {
        return error;
    }
    let details = failures
        .into_iter()
        .map(|error| error.to_string())
        .collect::<Vec<_>>()
        .join("; ");
    lifecycle_error("macOS guardian cleanup", io::Error::other(details))
}

#[cfg(test)]
mod tests;
