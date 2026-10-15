use std::fs::File;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nix::sys::signal::{Signal, kill};
use nix::unistd::pipe;

use super::*;

mod generation_control_wire;

include!("tests/recovery_and_revocation.rs");

include!("tests/generation_host.rs");

include!("tests/supervised_bootstrap.rs");

include!("tests/liveness_and_shutdown.rs");

include!("tests/guarded_primary_shutdown.rs");

include!("tests/control_acknowledgement.rs");

include!("tests/terminal_liveness.rs");

// Existing approved KEL-143 §7 schedules. This test relay copies exact
// private records; run_generation_host remains the actual mint/lease owner.
mod runtime_race_validation {
    use super::*;
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
