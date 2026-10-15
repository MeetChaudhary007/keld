const COLLECTION: Duration = Duration::from_secs(7);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeliveryCut {
    Zero,
    Partial,
    FullBeforeLease,
    LeaseBeforeSpawn,
}

enum RelayCommand {
    Full,
    Prefix,
    AwaitClosure,
}

#[derive(Debug, PartialEq, Eq)]
struct ControlFields {
    kind: u8,
    cause: u8,
    attempt: u32,
    pid: u32,
    payload_len: usize,
}

impl ControlFields {
    fn capture(record: &GenerationControlRecord) -> Self {
        Self {
            kind: record.kind,
            cause: record.cause,
            attempt: record.attempt,
            pid: record.pid,
            payload_len: record.payload.len(),
        }
    }
}

enum RelayReceipt {
    ClearedOne,
    PreparedTwo(GenerationControlRecord),
    PrefixSent(Instant),
    NormalRevokeTwo {
        request: ControlFields,
        response: ControlFields,
    },
    NormalClearTwo {
        request: ControlFields,
        response: ControlFields,
    },
    GuardianControlEof,
}

struct PhaseGate {
    entered: Sender<()>,
    release: Receiver<()>,
}

impl PhaseGate {
    fn wait(&self) -> Result<(), RuntimeError> {
        self.entered.send(()).map_err(|_| {
            lifecycle_error(
                "test Runtime phase receipt",
                io::Error::other("custodian ended"),
            )
        })?;
        self.release.recv_timeout(COLLECTION).map_err(|source| {
            lifecycle_error("test Runtime phase release", io::Error::other(source))
        })
    }
}

struct ReturnedLeasePreparer<C> {
    inner: GuardedPrimaryPreparer<C>,
    gate: Option<PhaseGate>,
}

impl<C> ChildPreparer for ReturnedLeasePreparer<C>
where
    C: FnMut(&str) -> Result<Command, RuntimeError> + Send + 'static,
{
    type Lease = GuardedPrimaryLease;

    fn prepare(&mut self, attempt: u32) -> Result<PreparedChild<Self::Lease>, RuntimeError> {
        let prepared = self.inner.prepare(attempt)?;
        // This receipt follows actual GuardedPrimaryLease construction.
        // It does not replace that lease or call another spawn owner.
        if attempt == 2
            && let Some(gate) = &self.gate
        {
            gate.wait()?;
        }
        Ok(prepared)
    }
}

fn timed_pair() -> (UnixStream, UnixStream) {
    let (one, two) = UnixStream::pair().expect("existing private Unix pair");
    for stream in [&one, &two] {
        stream
            .set_read_timeout(Some(GENERATION_CONTROL_POLL))
            .expect("read poll");
        stream
            .set_write_timeout(Some(GENERATION_CONTROL_POLL))
            .expect("write poll");
    }
    (one, two)
}

fn receive_record(stream: &mut UnixStream) -> Result<GenerationControlRecord, RuntimeError> {
    let mut reader = GenerationControlReader::new();
    let deadline = Instant::now() + COLLECTION;
    loop {
        if let Some(record) = reader.poll(stream)? {
            return Ok(record);
        }
        if Instant::now() >= deadline {
            return Err(lifecycle_error(
                "test Runtime record collection",
                io::Error::from(io::ErrorKind::TimedOut),
            ));
        }
    }
}
