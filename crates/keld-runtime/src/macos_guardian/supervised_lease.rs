//! Single-group supervised preparation and resource revocation.
use super::{
    ChildPreparer, Command, CommandExt, GenerationLease, PreparedChild, REGISTRATION_ENV,
    RevocationCause, RuntimeError, Stdio, Write, collapse_failures, io, lifecycle_error,
    terminate_registered_group, validate_group_leader, write_group_registration,
};

pub(super) struct SupervisedGuardianPreparer<C, W, S, F: FnOnce() -> io::Result<()>> {
    pub(super) command_factory: Option<C>,
    pub(super) registration: Option<W>,
    pub(super) child_spawned: Option<S>,
    pub(super) revoke_registered_resources: Option<F>,
    pub(super) pid_tx: std::sync::mpsc::SyncSender<u32>,
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

pub(super) struct SupervisedGuardianLease<W, S, F> {
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
