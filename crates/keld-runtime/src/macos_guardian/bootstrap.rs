//! Authenticated macOS guardian bootstrap and registration ownership.
use super::{
    BootstrapAdmission, BootstrapListener, BootstrapRejection, BootstrapRejectionObserver, Child,
    ChildStdin, ChildStdout, Command, GuardedPrimary, HostGuardian, Instant, REGISTRATION_ENV,
    REGISTRATION_LEN, REGISTRATION_MAGIC, Read, RuntimeError, Stdio, collapse_failures, io,
    lifecycle_error, reject_host_registration, require_close_on_exec, validate_group_leader,
};

/// Host-side authenticated bootstrap for one private guardian process.
///
/// The bootstrap mints a one-use owner-only registration link, overrides the
/// private environment value, and owns the guardian child plus sole liveness
/// writer until [`Self::register_until`] consumes the guardian-emitted group
/// record. Callers never supply a numeric process-group id.
#[derive(Debug)]
pub struct GuardianBootstrap {
    pub(super) child: Option<Child>,
    pub(super) liveness_writer: Option<ChildStdin>,
    pub(super) quit_ack_reader: Option<ChildStdout>,
    pub(super) registration: BootstrapListener,
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
