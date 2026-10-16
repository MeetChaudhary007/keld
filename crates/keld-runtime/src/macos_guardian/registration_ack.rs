//! One-byte acknowledgment that pins the host's KGR1 group before Bun exec.
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Instant;

use super::GUARDIAN_SHUTDOWN_DEADLINE;

pub(super) const HOST_GROUP_RETAINED_ACK: u8 = b'A';

/// Only used after the Guardian authenticated its private one-use link.
pub(super) struct AwaitHostGroupRetention {
    stream: UnixStream,
}

impl AwaitHostGroupRetention {
    pub(super) const fn new(stream: UnixStream) -> Self {
        Self { stream }
    }
}

impl Write for AwaitHostGroupRetention {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()?;
        // This is the only permit to execute the spawned child: a complete
        // record without a retained, authenticated host group is insufficient.
        self.stream.set_nonblocking(true)?;
        let deadline = Instant::now() + GUARDIAN_SHUTDOWN_DEADLINE;
        let mut ack = [0_u8; 1];
        loop {
            match self.stream.read(&mut ack) {
                Ok(1) if ack[0] == HOST_GROUP_RETAINED_ACK => return Ok(()),
                Ok(1) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "host refused group-retention acknowledgment",
                    ));
                }
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "host closed before retaining the Bun group",
                    ));
                }
                Err(source) if source.kind() == io::ErrorKind::Interrupted => {}
                Err(source) if source.kind() == io::ErrorKind::WouldBlock => {}
                Err(source) => return Err(source),
                Ok(_) => unreachable!("one-byte group retention acknowledgment"),
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "host did not retain the Bun group before exec deadline",
                ));
            }
            std::thread::yield_now();
        }
    }
}
