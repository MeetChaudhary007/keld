//! Registered guardian host-side lifecycle and owned shutdown handling.
use super::{
    Child, ChildStdin, ChildStdout, ExitStatus, GUARDIAN_SHUTDOWN_DEADLINE, GuardianReport,
    Instant, RuntimeError, SUPERVISED_QUIT_ACCEPTED, Write, collapse_failures, io, lifecycle_error,
    read_supervised_quit_ack, reject_host_registration, require_close_on_exec,
    set_liveness_nonblocking, terminate_registered_group, unexpected_guardian_exit,
    validate_group_leader,
};

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
    pub(super) fn from_registered_parts(
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

    pub(super) fn shutdown_until(&mut self, deadline: Instant) -> Result<ExitStatus, RuntimeError> {
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
