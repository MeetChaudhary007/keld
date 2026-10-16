//! macOS host-death guardian for supervised Bun process groups.
//!
//! This is supervisor cleanup, not App Sandbox containment. The caller owns
//! the guardian process and the only liveness writer. The guardian process
//! calls [`run`] for the generic one-group API or [`run_guarded_primary`] for
//! KEL-96's persistent fresh-generation primary owner.

#![deny(unsafe_op_in_unsafe_fn)]

mod guarded_primary;
pub use self::guarded_primary::{GuardedPrimary, GuardedPrimaryUpdate};
use self::guarded_primary::{RegisteredPrimaryGeneration, lock_generation, take_generation};

mod recovery_state;
use self::recovery_state::{RecoveryState, lock_recovery};

mod host_liveness;
#[cfg(test)]
use self::host_liveness::observe_guarded_liveness;

mod generation_wire;

mod host_control;

mod process_group;
use self::process_group::{
    reject_host_registration, terminate_registered_group, validate_group_leader, validate_group_pid,
};

mod guarded_lease;
#[cfg(test)]
use self::guarded_lease::GuardedPrimaryLease;
use self::guarded_lease::GuardedPrimaryPreparer;

mod supervised_lease;
use self::supervised_lease::SupervisedGuardianPreparer;

mod registered_guardian;
pub use self::registered_guardian::HostGuardian;

mod bootstrap;
pub use self::bootstrap::GuardianBootstrap;

mod supervision_runner;
use self::supervision_runner::{
    connect_guardian_registration, run_supervised_with_registration, run_with_registration,
    write_group_registration,
};

mod generation_host;
use self::generation_host::run_generation_host;
#[cfg(test)]
use self::generation_host::{
    GenerationProvisionFence, HostGenerationState, check_initial_recovery_decision,
    finish_generation_control_eof, runtime_io_kind,
};

mod supervised_ack;
use self::supervised_ack::{
    SUPERVISED_ORDERLY_ACK, SUPERVISED_ORDERLY_SHUTDOWN, SUPERVISED_QUIT_ACCEPTED,
    SUPERVISED_QUIT_ACK, SUPERVISED_QUIT_ACK_DEADLINE, read_supervised_orderly_ack,
    read_supervised_quit_ack,
};

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
    await_guarded_primary_liveness, await_host_death, observe_supervised_liveness,
    require_close_on_exec, set_liveness_nonblocking, validate_liveness_bootstrap,
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
const GUARDIAN_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);
const GENERATION_CONTROL_POLL: Duration = Duration::from_millis(20);

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
