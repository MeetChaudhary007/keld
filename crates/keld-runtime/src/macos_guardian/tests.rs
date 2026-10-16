use std::fs::File;
use std::io::Write as _;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use nix::unistd::pipe;

use super::{
    AsFd, CONTROL_CLEAR, CONTROL_CLEARED, CONTROL_PREPARE, CONTROL_PREPARED, CONTROL_REGISTERED,
    CONTROL_REVOKE, CONTROL_REVOKED, CONTROL_SPAWNED, ChildPreparer, Command, Errno,
    GENERATION_CONTROL_POLL, GUARDIAN_SHUTDOWN_DEADLINE, GenerationControlPeer,
    GenerationControlReader, GenerationControlRecord, GenerationProvisionFence, GuardedPrimary,
    GuardedPrimaryLease, GuardedPrimaryPreparer, GuardedPrimaryUpdate, GuardianBootstrap,
    HostGenerationState, HostGuardian, Instant, JoinHandle, PreparedChild, REGISTRATION_ENV, Read,
    Receiver, RecoveryState, RegisteredPrimaryGeneration, RestartPolicy, RevocationCause,
    RoleEvent, RuntimeError, SUPERVISED_GUARDIAN_ARG, SUPERVISED_QUIT_ACCEPTED,
    SUPERVISED_QUIT_ACK, SUPERVISED_QUIT_ACK_DEADLINE, Sender, SupervisedGuardianPreparer,
    Supervisor, SupervisorOutcome, await_guarded_primary_liveness, control_exchange,
    finish_generation_control_eof, handshake_client, interrupted_successor_preparation, io,
    is_owned_preparation_interruption, lifecycle_error, lock_generation, lock_recovery,
    nix_io_error, observe_guarded_liveness, parse_app_link, read_generation_control, run,
    run_generation_host, run_supervised_with_registration, run_with_registration, runtime_io_kind,
    set_liveness_nonblocking, terminate_registered_group, thread, validate_liveness_bootstrap,
    write_generation_control,
};

mod generation_control_wire;

mod recovery_and_revocation;

include!("tests/generation_host.rs");

include!("tests/supervised_bootstrap.rs");

include!("tests/liveness_and_shutdown.rs");
mod rejected_registration_deadline;
include!("tests/pre_registration_host_death.rs");
include!("tests/guardian_crash_pre_registration.rs");
mod process_group_failsafe;

include!("tests/guarded_primary_shutdown.rs");
mod worker_outcome;

include!("tests/control_acknowledgement.rs");

include!("tests/terminal_liveness.rs");

// Existing approved KEL-143 §7 schedules. This test relay copies exact
// private records; run_generation_host remains the actual mint/lease owner.
mod runtime_race_validation {
    use super::{
        Arc, AtomicBool, CONTROL_CLEAR, CONTROL_CLEARED, CONTROL_PREPARE, CONTROL_PREPARED,
        CONTROL_REVOKE, CONTROL_REVOKED, ChildPreparer, Command, Duration, GENERATION_CONTROL_POLL,
        GUARDIAN_SHUTDOWN_DEADLINE, GenerationControlPeer, GenerationControlReader,
        GenerationControlRecord, GenerationProvisionFence, GuardedPrimaryLease,
        GuardedPrimaryPreparer, GuardedPrimaryUpdate, Instant, JoinHandle, Mutex, Ordering,
        PreparedChild, Read, Receiver, RecoveryState, RegisteredPrimaryGeneration, RestartPolicy,
        RevocationCause, RoleEvent, RuntimeError, SUPERVISED_QUIT_ACCEPTED, Sender, Supervisor,
        SupervisorOutcome, assert_gone, io, is_owned_preparation_interruption, lifecycle_error,
        liveness_pipe, lock_generation, lock_recovery, mpsc, observe_guarded_liveness,
        parse_app_link, run_generation_host, runtime_io_kind, set_liveness_nonblocking, thread,
        validate_liveness_bootstrap, write_generation_control,
    };
    use std::io::Write as _;
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    use std::sync::TryLockError;

    include!("tests/runtime_race_validation/records_and_cut_types.rs");
    include!("tests/runtime_race_validation/private_record_relay.rs");
    include!("tests/runtime_race_validation/control_plane.rs");
    include!("tests/runtime_race_validation/delivery_fixture.rs");
    include!("tests/runtime_race_validation/delivery_assertions.rs");
    include!("tests/runtime_race_validation/ownership_races.rs");
}

include!("tests/test_support.rs");
