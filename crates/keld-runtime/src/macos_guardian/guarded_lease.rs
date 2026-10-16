//! Fresh-generation child preparation and the exact revocation lease.
use super::{
    Arc, AtomicBool, CONTROL_CLEAR, CONTROL_CLEARED, CONTROL_PREPARE, CONTROL_PREPARED,
    CONTROL_REGISTERED, CONTROL_REVOKE, CONTROL_REVOKED, CONTROL_SPAWNED, ChildPreparer, Command,
    CommandExt, GenerationControlPeer, GenerationControlRecord, GenerationLease, Mutex, Ordering,
    PreparedChild, REGISTRATION_ENV, RevocationCause, RuntimeError, Stdio, collapse_failures,
    control_exchange, control_exchange_with_cancellation, io, lifecycle_error,
    terminate_registered_group, validate_group_leader,
};

pub(super) struct GuardedPrimaryPreparer<C> {
    pub(super) command_factory: C,
    pub(super) control: Arc<Mutex<GenerationControlPeer>>,
    pub(super) host_unavailable: Arc<AtomicBool>,
    pub(super) preparation_cancelled: Arc<AtomicBool>,
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

pub(super) struct GuardedPrimaryLease {
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
