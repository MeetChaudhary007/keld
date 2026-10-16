//! Host-owned persistent guardian and exact registered-generation lifecycle.
use super::{
    Arc, BoundRoleGeneration, Child, ChildStdin, ChildStdout, Duration, ExitStatus,
    GUARDIAN_SHUTDOWN_DEADLINE, Instant, JoinHandle, Mutex, Receiver, RecoveryState, RoleEvent,
    RuntimeError, SUPERVISED_ORDERLY_SHUTDOWN, SUPERVISED_QUIT_ACCEPTED, Write, collapse_failures,
    io, lifecycle_error, lock_recovery, mpsc, read_supervised_orderly_ack,
    read_supervised_quit_ack, reject_host_registration, run_generation_host,
    set_liveness_nonblocking, terminate_registered_group, thread,
};

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
    pub(super) child: Child,
    pub(super) liveness_writer: Option<ChildStdin>,
    pub(super) quit_ack_reader: ChildStdout,
    pub(super) current_generation: Arc<Mutex<Option<RegisteredPrimaryGeneration>>>,
    pub(super) recovery_decision: Arc<Mutex<RecoveryState>>,
    pub(super) updates_rx: Receiver<GuardedPrimaryUpdate>,
    pub(super) worker: Option<JoinHandle<Result<(), RuntimeError>>>,
    pub(super) shutdown_attributed: bool,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct RegisteredPrimaryGeneration {
    pub(super) attempt: u32,
    pub(super) group_pid: u32,
}

impl GuardedPrimary {
    pub(super) fn start(
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
        let worker_failed = if let Err(error) = self.join_worker() {
            failures.push(error);
            true
        } else {
            false
        };
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
        if worker_failed {
            // A clean guardian exit does not prove the native group was retired
            // when its host-side generation worker has already failed.
            if let Err(error) = self.fail_safe_current_group() {
                failures.push(error);
            }
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

    pub(super) fn join_worker(&mut self) -> Result<(), RuntimeError> {
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

pub(super) fn lock_generation(
    generation: &Mutex<Option<RegisteredPrimaryGeneration>>,
) -> std::sync::MutexGuard<'_, Option<RegisteredPrimaryGeneration>> {
    match generation.lock() {
        Ok(generation) => generation,
        Err(poisoned) => poisoned.into_inner(),
    }
}

pub(super) fn take_generation(
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
