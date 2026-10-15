//! Private supervised guardian control acknowledgments. No OS authority is minted here.
use std::io::{self, Read};
use std::os::fd::AsFd;
use std::process::ChildStdout;
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, OFlag, fcntl};

use super::{RuntimeError, lifecycle_error, nix_io_error};

pub(super) const SUPERVISED_QUIT_ACCEPTED: u8 = b'Q';
pub(super) const SUPERVISED_QUIT_ACK: [u8; 3] = *b"KQA";
pub(super) const SUPERVISED_ORDERLY_SHUTDOWN: u8 = b'S';
pub(super) const SUPERVISED_ORDERLY_ACK: [u8; 3] = *b"KSA";
pub(super) const SUPERVISED_QUIT_ACK_DEADLINE: Duration = Duration::from_secs(5);

pub(super) fn read_supervised_quit_ack(reader: &mut ChildStdout) -> Result<(), RuntimeError> {
    read_supervised_ack(
        reader,
        SUPERVISED_QUIT_ACK,
        "macOS guardian supervised-Quit acknowledgment",
        "accepted Quit",
    )
}

pub(super) fn read_supervised_orderly_ack(reader: &mut ChildStdout) -> Result<(), RuntimeError> {
    read_supervised_ack(
        reader,
        SUPERVISED_ORDERLY_ACK,
        "macOS guardian orderly-shutdown acknowledgment",
        "orderly shutdown",
    )
}

fn read_supervised_ack(
    reader: &mut ChildStdout,
    expected: [u8; 3],
    phase: &'static str,
    action: &'static str,
) -> Result<(), RuntimeError> {
    let raw_flags = fcntl(reader.as_fd(), FcntlArg::F_GETFL)
        .map_err(|source| lifecycle_error(phase, nix_io_error(source)))?;
    fcntl(
        reader.as_fd(),
        FcntlArg::F_SETFL(OFlag::from_bits_truncate(raw_flags) | OFlag::O_NONBLOCK),
    )
    .map_err(|source| lifecycle_error(phase, nix_io_error(source)))?;
    let deadline = Instant::now() + SUPERVISED_QUIT_ACK_DEADLINE;
    let mut ack = [0_u8; 3];
    let mut filled = 0;
    while filled < ack.len() {
        match reader.read(&mut ack[filled..]) {
            Ok(0) => {
                return Err(lifecycle_error(
                    phase,
                    io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("guardian exited before acknowledging {action}"),
                    ),
                ));
            }
            Ok(read) => filled += read,
            Err(source) if source.kind() == io::ErrorKind::Interrupted => {}
            Err(source) if source.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(lifecycle_error(
                        phase,
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("guardian did not acknowledge {action} before the deadline"),
                        ),
                    ));
                }
                std::thread::yield_now();
            }
            Err(source) => {
                return Err(lifecycle_error(phase, source));
            }
        }
    }
    if ack == expected {
        Ok(())
    } else {
        Err(lifecycle_error(
            phase,
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("guardian returned an invalid {action} acknowledgment"),
            ),
        ))
    }
}
