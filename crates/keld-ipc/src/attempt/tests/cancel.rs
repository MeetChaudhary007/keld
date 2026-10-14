//! The claim wait's early end through the endpoint's claim canceller (KEL-53
//! §4 "Candidate connect-back", *Margin and deadlines*: the wait is bounded
//! by the claim deadline and by the launch handle, whose watcher drives the
//! canceller through this public seam; §7 "8, 20 (profile handover)" h13,
//! the canceller half, in process). Wherever the cancel lands, before the
//! wait, during the connect wait, while a claimant is connected and between
//! two of its record operations, or with the deadline already passed, the
//! owner returns the typed `ClaimCancelled` promptly; after the one-shot, the
//! deadline or the endpoint's drop it is a no-op; and it reaches only its own
//! endpoint.
//!
//! Oracles: the typed outcome, the elapsed time against the landed
//! per-connection deadline and the kill switch (bounds, never
//! synchronization), the owner's reported refusal with its raw Windows code,
//! end of file or the bytes on the dropped claimant's own end, a second
//! endpoint's successful claim, the accepted channel's later exchange, and the
//! closed name, probed independently.

use std::io::{self, Read as _};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_OPERATION_ABORTED};

use super::oracle::probe_exists;
use super::peer::{
    DIGEST, KILL_SWITCH, TestPin, admit_own, claim, connect_back_endpoint, expect_end_of_file,
    fresh_ids, join, kill_switch, pipe_token, raw_claim, raw_client, spawn_admitting_owner,
    spawn_owner, write,
};
use crate::APP_LINK_IO_DEADLINE;
use crate::attempt::WindowsAttemptExchangeError;
use crate::attempt::claim::ClaimRefusal;
use crate::attempt::records::{AttemptRecord, AttemptRecordError};
use crate::windows_named_pipe::WindowsPeerTokenFacts;

/// How long a cancelled wait may take to return: far below the landed
/// per-connection deadline and the kill switch, so a wait that ended only at
/// one of those fails the bound. The in-process latencies measured for S6c2b
/// are recorded in its evidence; this is their bound, not a synchronization.
const PROMPT: Duration = Duration::from_secs(2);

/// Spins, yielding, until `condition` holds or the kill switch passes.
fn await_until(condition: impl Fn() -> bool, what: &str) -> io::Result<()> {
    let deadline = kill_switch();
    while !condition() {
        if Instant::now() >= deadline {
            return Err(io::Error::other(format!("kill switch: {what}")));
        }
        std::thread::yield_now();
    }
    Ok(())
}

fn is_cancelled<T: std::fmt::Debug>(outcome: &Result<T, WindowsAttemptExchangeError>) -> bool {
    matches!(outcome, Err(WindowsAttemptExchangeError::ClaimCancelled))
}

/// Whether `refusal` is one record operation refused or aborted with
/// `ERROR_OPERATION_ABORTED`, the owner's view of a cancel that reached a
/// connected claimant.
fn is_aborted(refusal: &ClaimRefusal) -> bool {
    matches!(
        refusal,
        ClaimRefusal::Record(AttemptRecordError::Io { source })
            if source.raw_os_error() == Some(ERROR_OPERATION_ABORTED.cast_signed())
    )
}

/// Margin row: a cancel delivered before the wait starts is read before the
/// first wait, so the owner returns `ClaimCancelled` at once, with its
/// endpoint closed; the cancel is idempotent before and after.
#[test]
fn a_cancel_before_the_wait_ends_it_at_once_and_closes_the_endpoint() -> io::Result<()> {
    let ids = fresh_ids()?;
    let endpoint = connect_back_endpoint(ids)?;
    let name = endpoint.endpoint().to_owned();
    let canceller = endpoint.claim_canceller();
    for _ in 0..2 {
        canceller.cancel().map_err(io::Error::other)?;
    }
    let pin = TestPin::own()?;
    let (refusals, _refused) = mpsc::channel();
    let started = Instant::now();
    let owner = spawn_owner(
        endpoint,
        kill_switch(),
        APP_LINK_IO_DEADLINE,
        admit_own(&pin),
        pipe_token,
        refusals,
    );
    let (outcome, refusals) = join(owner)?;
    let elapsed = started.elapsed();
    assert!(is_cancelled(&outcome), "{outcome:?}");
    assert!(
        refusals.is_empty(),
        "no connection was admitted: {refusals:?}"
    );
    assert!(
        elapsed < PROMPT,
        "a cancel before the wait is read before the first wait: {elapsed:?}"
    );
    let absent = probe_exists(&name).expect_err("the endpoint is closed by the cancel");
    assert_eq!(
        absent.raw_os_error(),
        Some(ERROR_FILE_NOT_FOUND.cast_signed())
    );
    canceller
        .cancel()
        .map_err(io::Error::other)
        .expect("a cancel after the wait ended is a no-op");
    Ok(())
}

/// Margin row: the cancel is read before the deadline, so a wait whose
/// deadline has already passed when it was also cancelled reports the cancel.
#[test]
fn a_cancel_is_reported_before_a_deadline_that_also_passed() -> io::Result<()> {
    let ids = fresh_ids()?;
    let endpoint = connect_back_endpoint(ids)?;
    endpoint
        .claim_canceller()
        .cancel()
        .map_err(io::Error::other)?;
    let pin = TestPin::own()?;
    let (refusals, _refused) = mpsc::channel();
    let owner = spawn_owner(
        endpoint,
        Instant::now(),
        APP_LINK_IO_DEADLINE,
        admit_own(&pin),
        pipe_token,
        refusals,
    );
    let (outcome, _) = join(owner)?;
    assert!(is_cancelled(&outcome), "{outcome:?}");
    Ok(())
}

/// Margin row: a cancel during the connect wait, with no claimant, wakes the
/// pending accept promptly.
#[test]
fn a_cancel_during_the_connect_wait_ends_it_promptly() -> io::Result<()> {
    let ids = fresh_ids()?;
    let endpoint = connect_back_endpoint(ids)?;
    let server = endpoint.server.clone();
    let canceller = endpoint.claim_canceller();
    let pin = TestPin::own()?;
    let (refusals, _refused) = mpsc::channel();
    let owner = spawn_owner(
        endpoint,
        kill_switch(),
        APP_LINK_IO_DEADLINE,
        admit_own(&pin),
        pipe_token,
        refusals,
    );
    await_until(
        || server.is_accept_pending(),
        "the owner's connect wait is pending",
    )?;
    let cancelled_at = Instant::now();
    canceller.cancel().map_err(io::Error::other)?;
    let (outcome, refusals) = join(owner)?;
    let latency = cancelled_at.elapsed();
    println!(
        "S6C2B_LATENCY connect_wait_cancel_ms={}",
        latency.as_millis()
    );
    assert!(is_cancelled(&outcome), "{outcome:?}");
    assert!(refusals.is_empty(), "{refusals:?}");
    assert!(latency < PROMPT, "woken promptly: {latency:?}");
    Ok(())
}

/// Margin row: a cancel while a claimant is connected but silent reaches the
/// owner's pending record read (or the read it is about to issue), so the
/// owner returns `ClaimCancelled` well before that connection's own
/// per-connection deadline, and the silent claimant observes end of file.
#[test]
fn a_cancel_while_a_silent_claimant_is_connected_ends_the_wait_before_its_per_connection_deadline()
-> io::Result<()> {
    let ids = fresh_ids()?;
    let endpoint = connect_back_endpoint(ids)?;
    let name = endpoint.endpoint().to_owned();
    let server = endpoint.server.clone();
    let canceller = endpoint.claim_canceller();
    let pin = TestPin::own()?;
    let (refusals, _refused) = mpsc::channel();
    let owner = spawn_owner(
        endpoint,
        kill_switch(),
        APP_LINK_IO_DEADLINE,
        admit_own(&pin),
        pipe_token,
        refusals,
    );
    let mut silent = raw_client(&name)?;
    await_until(
        || server.is_connected(),
        "the owner admitted the silent connection",
    )?;
    let cancelled_at = Instant::now();
    canceller.cancel().map_err(io::Error::other)?;
    let (outcome, refusals) = join(owner)?;
    let latency = cancelled_at.elapsed();
    println!(
        "S6C2B_LATENCY silent_claimant_cancel_ms={}",
        latency.as_millis()
    );
    expect_end_of_file(&mut silent)?;
    assert!(is_cancelled(&outcome), "{outcome:?}");
    assert!(
        matches!(refusals.as_slice(), [refusal] if is_aborted(refusal)),
        "the silent connection's read was aborted or refused: {refusals:?}"
    );
    assert!(
        latency < PROMPT && latency < APP_LINK_IO_DEADLINE,
        "ended by the cancel, not by the per-connection deadline: {latency:?}"
    );
    Ok(())
}

/// Margin row: a cancel that lands between two record operations of a
/// connected claimant, here from the owner's own claimant check, after the
/// claim writer's token was read and before `KELD-AC1` is written, is
/// observed at that next operation: the write is refused at once, the
/// claimant reads nothing before end of file, and the owner returns
/// `ClaimCancelled` well before any per-connection deadline. Without the
/// I/O gate the write would succeed and the owner would wait out the
/// `KELD-AA1` read's deadline.
#[test]
fn a_cancel_between_two_record_operations_is_observed_at_the_next_one() -> io::Result<()> {
    let ids = fresh_ids()?;
    let endpoint = connect_back_endpoint(ids)?;
    let name = endpoint.endpoint().to_owned();
    let canceller = endpoint.claim_canceller();
    let pin = TestPin::own()?;
    let (refusals, _refused) = mpsc::channel();
    let (mark, marks) = mpsc::channel();
    let check = {
        let pin = pin.clone();
        let canceller = canceller.clone();
        move |_: u32, _: u32, _: &WindowsPeerTokenFacts| {
            canceller
                .cancel()
                .expect("cancel from the owner's own thread, between two record operations");
            let _ = mark.send(Instant::now());
            Some(pin.clone())
        }
    };
    let owner = spawn_owner(
        endpoint,
        kill_switch(),
        APP_LINK_IO_DEADLINE,
        check,
        pipe_token,
        refusals,
    );
    let mut claimant = raw_client(&name)?;
    write(
        &mut claimant,
        AttemptRecord::Claim(raw_claim(ids.installation, std::process::id())?),
    )?;
    let mut received = Vec::new();
    claimant.read_to_end(&mut received)?;
    let cancelled_at = marks.recv_timeout(KILL_SWITCH).map_err(io::Error::other)?;
    let (outcome, refusals) = join(owner)?;
    let latency = cancelled_at.elapsed();
    println!(
        "S6C2B_LATENCY between_operations_cancel_ms={}",
        latency.as_millis()
    );
    assert!(
        received.is_empty(),
        "no KELD-AC1 reached the claimant after the cancel: {received:x?}"
    );
    assert!(is_cancelled(&outcome), "{outcome:?}");
    assert!(
        matches!(refusals.as_slice(), [refusal] if is_aborted(refusal)),
        "the KELD-AC1 write was refused as aborted: {refusals:?}"
    );
    assert!(
        latency < PROMPT && latency < APP_LINK_IO_DEADLINE,
        "observed at the next record operation, not at its deadline: {latency:?}"
    );
    Ok(())
}

/// Margin row: a cancel after the claimant was accepted is a no-op, even
/// while the accepted channel has a record read pending: that read completes
/// with the candidate's record, and the channel still carries the rest of the
/// health exchange. A cancel that still signalled or aborted after the
/// one-shot would abort that pending read.
#[test]
fn a_cancel_after_the_claimant_was_accepted_is_a_no_op() -> io::Result<()> {
    let ids = fresh_ids()?;
    let endpoint = connect_back_endpoint(ids)?;
    let name = endpoint.endpoint().to_owned();
    let server = endpoint.server.clone();
    let canceller = endpoint.claim_canceller();
    let pin = TestPin::own()?;
    let (owner, _refused) = spawn_admitting_owner(endpoint, &pin);
    let mut candidate = claim(&name, &ids.installation)?.map_err(io::Error::other)?;
    let (owner, refusals) = join(owner)?;
    assert!(refusals.is_empty(), "{refusals:?}");
    let mut owner = owner.map_err(io::Error::other)?;
    // Shares the instance's test-only I/O census with the accepted stream; it
    // performs no I/O itself.
    let census = server.stream()?;
    let reader = std::thread::spawn(move || {
        let read = owner.read_boot(&DIGEST, kill_switch());
        (owner, read)
    });
    await_until(
        || census.has_active_io(),
        "the owner's KELD-AB1 read is pending",
    )?;
    for _ in 0..2 {
        canceller
            .cancel()
            .map_err(io::Error::other)
            .expect("a cancel after acceptance is a no-op");
    }
    candidate.send_boot(&DIGEST).map_err(io::Error::other)?;
    let (mut owner, read) = reader
        .join()
        .map_err(|_| io::Error::other("the reader thread panicked"))?;
    read.map_err(io::Error::other)
        .expect("the pending read completes with the record, untouched by the cancel");
    candidate.send_ready().map_err(io::Error::other)?;
    owner.read_ready(kill_switch()).map_err(io::Error::other)?;
    Ok(())
}

/// Margin row: a cancel after the deadline ended the wait, and one after the
/// endpoint dropped, are no-ops that report success.
#[test]
fn a_cancel_after_the_deadline_or_the_endpoints_drop_is_a_no_op() -> io::Result<()> {
    let ids = fresh_ids()?;
    let endpoint = connect_back_endpoint(ids)?;
    let canceller = endpoint.claim_canceller();
    let pin = TestPin::own()?;
    let (refusals, _refused) = mpsc::channel();
    let owner = spawn_owner(
        endpoint,
        Instant::now() + Duration::from_millis(300),
        APP_LINK_IO_DEADLINE,
        admit_own(&pin),
        pipe_token,
        refusals,
    );
    let (outcome, _) = join(owner)?;
    assert!(
        matches!(outcome, Err(WindowsAttemptExchangeError::ClaimDeadline)),
        "{outcome:?}"
    );
    canceller
        .cancel()
        .map_err(io::Error::other)
        .expect("a cancel after the deadline is a no-op");

    let dropped = connect_back_endpoint(fresh_ids()?)?.claim_canceller();
    dropped
        .cancel()
        .map_err(io::Error::other)
        .expect("a cancel after the endpoint dropped is a no-op");
    Ok(())
}

/// Margin row: a canceller reaches only its own endpoint. With two owners
/// waiting, cancelling the first ends only the first; the second still
/// accepts its claimant afterwards.
#[test]
fn a_cancel_reaches_only_its_own_endpoint() -> io::Result<()> {
    let ids_a = fresh_ids()?;
    let ids_b = fresh_ids()?;
    let endpoint_a = connect_back_endpoint(ids_a)?;
    let endpoint_b = connect_back_endpoint(ids_b)?;
    let name_b = endpoint_b.endpoint().to_owned();
    let canceller_a = endpoint_a.claim_canceller();
    let pin = TestPin::own()?;
    let (owner_a, _refused_a) = spawn_admitting_owner(endpoint_a, &pin);
    let (owner_b, _refused_b) = spawn_admitting_owner(endpoint_b, &pin);
    canceller_a.cancel().map_err(io::Error::other)?;
    let (outcome_a, refusals_a) = join(owner_a)?;
    assert!(is_cancelled(&outcome_a), "{outcome_a:?}");
    assert!(refusals_a.is_empty(), "{refusals_a:?}");
    claim(&name_b, &ids_b.installation)?.map_err(io::Error::other)?;
    let (outcome_b, refusals_b) = join(owner_b)?;
    assert!(
        outcome_b.is_ok(),
        "the other endpoint's wait was untouched: {outcome_b:?}"
    );
    assert!(refusals_b.is_empty(), "{refusals_b:?}");
    Ok(())
}
