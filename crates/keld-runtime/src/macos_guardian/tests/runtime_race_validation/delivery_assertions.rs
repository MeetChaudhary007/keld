fn assert_cleanup_route(cut: DeliveryCut, receipts: &[RelayReceipt]) {
    let revokes: Vec<_> = receipts
        .iter()
        .enumerate()
        .filter_map(|(index, receipt)| match receipt {
            RelayReceipt::NormalRevokeTwo { request, response } => Some((index, request, response)),
            _ => None,
        })
        .collect();
    let clears: Vec<_> = receipts
        .iter()
        .enumerate()
        .filter_map(|(index, receipt)| match receipt {
            RelayReceipt::NormalClearTwo { request, response } => Some((index, request, response)),
            _ => None,
        })
        .collect();
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| matches!(receipt, RelayReceipt::GuardianControlEof))
            .count(),
        1,
        "actual guardian control EOF absent/duplicated"
    );
    if matches!(
        cut,
        DeliveryCut::FullBeforeLease | DeliveryCut::LeaseBeforeSpawn
    ) {
        assert_eq!(
            revokes.len(),
            1,
            "normal lease Revoke2 request/ack missing or duplicated"
        );
        assert_eq!(
            clears.len(),
            1,
            "normal lease Clear2 request/ack missing or duplicated"
        );
        // Literal approved private wire fields are an independent
        // oracle; changing production constants cannot change these.
        let expected = [
            ControlFields {
                kind: 5,
                cause: 2,
                attempt: 2,
                pid: 0,
                payload_len: 0,
            },
            ControlFields {
                kind: 6,
                cause: 0,
                attempt: 2,
                pid: 0,
                payload_len: 0,
            },
            ControlFields {
                kind: 7,
                cause: 0,
                attempt: 2,
                pid: 0,
                payload_len: 0,
            },
            ControlFields {
                kind: 8,
                cause: 0,
                attempt: 2,
                pid: 0,
                payload_len: 0,
            },
        ];
        let actual = [revokes[0].1, revokes[0].2, clears[0].1, clears[0].2];
        assert_eq!(
            actual,
            [&expected[0], &expected[1], &expected[2], &expected[3]]
        );
        assert!(
            revokes[0].0 < clears[0].0,
            "normal Clear2 acknowledgment preceded Revoke2 acknowledgment"
        );
    } else {
        assert!(
            revokes.is_empty(),
            "unclaimed zero/partial cut acquired normal Revoke2 path"
        );
        assert!(
            clears.is_empty(),
            "unclaimed zero/partial cut acquired normal Clear2 path"
        );
        // Together with the separately asserted exact host-owned
        // Revoked2/Shutdown and successful host join, actual EOF plus
        // absent normal exchanges identifies the host EOF cleanup.
    }
}

fn collect_terminal_event(supervisor: &Supervisor) -> (crate::SupervisorEvent, bool) {
    let deadline = Instant::now() + COLLECTION;
    let mut started_two = false;
    let terminal = loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("bounded terminal event collection");
        match supervisor.recv_event(remaining) {
            Some(crate::SupervisorEvent::Started { attempt: 2, .. }) => started_two = true,
            Some(
                event @ (crate::SupervisorEvent::Stopped | crate::SupervisorEvent::Failed { .. }),
            ) => break event,
            Some(_) => {}
            None => panic!("actual Supervisor terminal event absent"),
        }
    };
    (terminal, started_two)
}

fn assert_cut_outcome(
    cut: DeliveryCut,
    terminal: &crate::SupervisorEvent,
    outcome: &SupervisorOutcome,
    began: Option<Instant>,
) {
    if cut == DeliveryCut::Partial {
        assert!(began.expect("actual prefix write clock").elapsed() >= GUARDIAN_SHUTDOWN_DEADLINE);
        assert!(matches!(
            terminal,
            crate::SupervisorEvent::Failed { attempt: 2 }
        ));
        match outcome {
            SupervisorOutcome::Failed(error) => {
                assert_eq!(runtime_io_kind(error), Some(io::ErrorKind::TimedOut));
                assert!(!is_owned_preparation_interruption(error, 2));
                assert!(error.to_string().contains("read deadline"));
            }
            other => panic!("partial Prepared timeout was hidden: {other:?}"),
        }
    } else {
        assert!(matches!(terminal, crate::SupervisorEvent::Stopped));
        assert!(matches!(outcome, SupervisorOutcome::Stopped));
    }
}

impl Drop for CutFixture {
    fn drop(&mut self) {
        lock_recovery(&self.plane.recovery).deny();
        self.plane.consumption_probe.take();
        if let Some(supervisor) = &self.supervisor {
            supervisor.shutdown();
        }
        self.cancelled.store(true, Ordering::Release);
        let _ = self.phase_release.send(());
        let _ = self.plane.commands.send(RelayCommand::AwaitClosure);
        drop(self.supervisor.take());
    }
}

fn run_delivery_cut(cut: DeliveryCut) {
    let mut fixture = CutFixture::start(cut);
    let response = fixture.release_after_clear();
    let mut began = None;
    match cut {
        DeliveryCut::Zero => {
            fixture.accept_actual_q();
            fixture
                .plane
                .commands
                .send(RelayCommand::AwaitClosure)
                .expect("zero-byte closure collection");
        }
        DeliveryCut::Partial => {
            fixture
                .plane
                .commands
                .send(RelayCommand::Prefix)
                .expect("one canonical prefix");
            began = match fixture
                .plane
                .receipts
                .recv_timeout(COLLECTION)
                .expect("actual prefix write receipt")
            {
                RelayReceipt::PrefixSent(time) => Some(time),
                _ => panic!("unexpected prefix receipt"),
            };
            let deadline = Instant::now() + COLLECTION;
            loop {
                if rustix::io::ioctl_fionread(
                    fixture
                        .plane
                        .consumption_probe
                        .as_ref()
                        .expect("observation alias"),
                )
                .expect("existing safe available-byte primitive")
                    == 0
                {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "valid prefix not consumed by sole control reader"
                );
                thread::yield_now();
            }
            drop(fixture.plane.consumption_probe.take());
            fixture.accept_actual_q();
            fixture
                .plane
                .commands
                .send(RelayCommand::AwaitClosure)
                .expect("partial suffix remains withheld until actual failure/EOF");
        }
        DeliveryCut::FullBeforeLease | DeliveryCut::LeaseBeforeSpawn => {
            fixture
                .plane
                .commands
                .send(RelayCommand::Full)
                .expect("full canonical Prepared2 release");
            fixture
                .phase_entered
                .recv_timeout(COLLECTION)
                .expect("exact factory/returned-lease boundary");
            fixture.accept_actual_q();
            fixture
                .phase_release
                .send(())
                .expect("release only after actual Q ACK");
        }
    }
    fixture.collect(cut, &response, began);
}
