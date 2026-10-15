//! Private macOS process-group validation and rejected-registration cleanup.
use std::io;
use std::process::{Child, ChildStdin};

use nix::errno::Errno;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::{Pid, getpgid};

use super::{RuntimeError, collapse_failures, lifecycle_error, nix_io_error};

pub(super) fn validate_group_pid(group: u32) -> Result<i32, RuntimeError> {
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

pub(super) fn validate_group_leader(group: u32) -> Result<i32, RuntimeError> {
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

pub(super) fn terminate_registered_group(group: u32) -> Result<(), RuntimeError> {
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

pub(super) fn reject_host_registration(
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
