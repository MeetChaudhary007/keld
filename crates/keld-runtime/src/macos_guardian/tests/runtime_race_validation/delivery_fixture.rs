struct CutFixture {
    supervisor: Option<Supervisor>,
    plane: ControlPlane,
    phase_entered: Receiver<()>,
    phase_release: Sender<()>,
    cancelled: Arc<AtomicBool>,
    no_effect: tempfile::TempDir,
    initial_pid: u32,
}

impl CutFixture {
    fn start(cut: DeliveryCut) -> Self {
        let mut plane = ControlPlane::start(cut);
        let guardian_control = plane
            .guardian_control
            .take()
            .expect("one guardian private stream");
        let (phase_tx, phase_entered) = mpsc::channel();
        let (phase_release, phase_rx) = mpsc::channel();
        let mut factory_gate = None;
        let mut lease_gate = None;
        match cut {
            DeliveryCut::FullBeforeLease => {
                factory_gate = Some(PhaseGate {
                    entered: phase_tx,
                    release: phase_rx,
                });
            }
            DeliveryCut::LeaseBeforeSpawn => {
                lease_gate = Some(PhaseGate {
                    entered: phase_tx,
                    release: phase_rx,
                });
            }
            DeliveryCut::Zero | DeliveryCut::Partial => {}
        }
        let no_effect = tempfile::tempdir().expect("owned successor no-effect sentinel");
        let successor_effect = no_effect.path().join("unexpected-g2-effect");
        let initial_release = no_effect.path().join("g1-release");
        let initial_release_for_child = initial_release.clone();
        let mut calls = 0;
        let command_factory = move |_app_link: &str| {
            calls += 1;
            let mut command = Command::new("/bin/sh");
            if calls == 1 {
                command.args([
                    "-c",
                    "printf KEL143_RACE_G1; while [ ! -e \"$1\" ]; do :; done; exit 1",
                    "keld-race",
                ]);
                command.arg(&initial_release_for_child);
            } else {
                if let Some(gate) = &factory_gate {
                    gate.wait()?;
                }
                command.args([
                    "-c",
                    "printf KEL143_RACE_BAD_G2; printf bad > \"$1\"; exit 0",
                    "keld-race",
                ]);
                command.arg(&successor_effect);
            }
            Ok(command)
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let supervisor = Supervisor::start_prepared(
            RestartPolicy::default(),
            ReturnedLeasePreparer {
                inner: GuardedPrimaryPreparer {
                    command_factory,
                    control: Arc::new(Mutex::new(GenerationControlPeer {
                        stream: guardian_control,
                        reader: GenerationControlReader::new(),
                    })),
                    host_unavailable: Arc::new(AtomicBool::new(false)),
                    preparation_cancelled: Arc::clone(&cancelled),
                },
                gate: lease_gate,
            },
        )
        .expect("real initial Supervisor child with actual guarded preparation");
        // Startup spawn precedes group enrollment. The production
        // Started receipt follows actual child_spawned/host enrollment.
        let initial_pid = await_initial_registration(&supervisor, &plane.current);
        std::fs::write(initial_release, b"release-g1").expect("release actual registered G1");
        Self {
            supervisor: Some(supervisor),
            plane,
            phase_entered,
            phase_release,
            cancelled,
            no_effect,
            initial_pid,
        }
    }

    fn release_after_clear(&self) -> GenerationControlRecord {
        assert!(matches!(
            self.plane
                .receipts
                .recv_timeout(COLLECTION)
                .expect("actual Clear1"),
            RelayReceipt::ClearedOne
        ));
        assert!(lock_generation(&self.plane.current).is_none());
        lock_recovery(&self.plane.recovery).arm();
        match self
            .plane
            .receipts
            .recv_timeout(COLLECTION)
            .expect("actual host Prepared2 emission")
        {
            RelayReceipt::PreparedTwo(record) => record,
            _ => panic!("unexpected protocol receipt before Prepared2"),
        }
    }

    fn accept_actual_q(&self) {
        lock_recovery(&self.plane.recovery).deny();
        let (mut reader, mut writer) = liveness_pipe();
        validate_liveness_bootstrap(&mut reader).expect("owned validated liveness pipe");
        set_liveness_nonblocking(&reader, true).expect("active liveness poll");
        let (mut ack_writer, mut ack_reader) = timed_pair();
        writer
            .write_all(&[SUPERVISED_QUIT_ACCEPTED])
            .expect("actual Q byte");
        let mut quit = false;
        let mut orderly = false;
        assert!(
            !observe_guarded_liveness(
                &mut reader,
                self.supervisor.as_ref().expect("Supervisor owner"),
                &mut quit,
                &mut orderly,
                &mut ack_writer,
                &self.cancelled
            )
            .expect("existing guardian Q handling")
        );
        let mut bytes = [0; 3];
        ack_reader
            .read_exact(&mut bytes)
            .expect("actual KQA receipt");
        assert_eq!(bytes, *b"KQA");
        assert!(quit && !orderly);
        lock_recovery(&self.plane.recovery).shutdown_acknowledged = true;
    }

    fn collect(
        mut self,
        cut: DeliveryCut,
        response: &GenerationControlRecord,
        began: Option<Instant>,
    ) {
        // All releases/joins precede assertions. The fixture Drop also
        // releases every fence on failed collection or an unwind.
        let supervisor = self.supervisor.as_ref().expect("Supervisor owner");
        let (terminal, started_two) = collect_terminal_event(supervisor);
        let outcome = supervisor.wait_for_outcome();
        let current_pid = supervisor.current_pid();
        let ledger = supervisor.crash_ledger();
        let output = supervisor.output();
        // wait_for_outcome observes completion; dropping this sole
        // Supervisor joins its actual direct child/capture owner.
        drop(self.supervisor.take());
        let relay = self
            .plane
            .relay
            .take()
            .expect("one relay")
            .join()
            .expect("relay thread joins");
        let host = self
            .plane
            .host
            .take()
            .expect("one actual host owner")
            .join()
            .expect("host thread joins");
        let updates: Vec<_> = self.plane.updates.try_iter().collect();
        let cleanup_receipts: Vec<_> = self.plane.receipts.try_iter().collect();
        let (endpoint, _) =
            parse_app_link(std::str::from_utf8(&response.payload).expect("actual app link UTF8"))
                .expect("actual minted locator");
        let endpoint_gone = UnixStream::connect(endpoint).is_err();
        let no_effect = !self.no_effect.path().join("unexpected-g2-effect").exists();
        relay.expect("real control EOF forwarded after guardian-side owner drop");
        host.expect("actual exact host lease cleanup completed before EOF success");
        assert!(!started_two && current_pid.is_none());
        assert!(lock_generation(&self.plane.current).is_none());
        assert_eq!(ledger.self_termination_count, 1);
        assert_eq!(
            ledger.last_self_termination.map(|entry| entry.pid),
            Some(self.initial_pid)
        );
        assert_gone(Some(self.initial_pid));
        assert!(
            ledger
                .last_self_termination
                .is_some_and(|entry| entry.exit_code == Some(1))
        );
        assert!(output.stdout.contains("KEL143_RACE_G1"));
        assert!(!output.stdout.contains("KEL143_RACE_BAD_G2") && no_effect);
        assert!(updates.iter().any(|update| matches!(
            update,
            GuardedPrimaryUpdate::Role(RoleEvent::Provisioned { attempt: 2, .. })
        )));
        assert!(updates.iter().any(|update| matches!(
            update,
            GuardedPrimaryUpdate::Role(RoleEvent::Revoked {
                attempt: 2,
                cause: crate::role::RoleRevocationCause::Shutdown,
                ..
            })
        )));
        assert!(!updates.iter().any(
            |update| matches!(update, GuardedPrimaryUpdate::Bound(bound) if bound.attempt() == 2)
        ));
        assert!(!updates.iter().any(|update| matches!(
            update,
            GuardedPrimaryUpdate::Role(
                RoleEvent::Spawned { attempt: 2, .. } | RoleEvent::LinkBound { attempt: 2, .. }
            )
        )));
        assert!(endpoint_gone, "exact minted successor listener survived");
        assert_cleanup_route(cut, &cleanup_receipts);
        assert_cut_outcome(cut, &terminal, &outcome, began);
        println!(
            "KEL143_PREPARED_CUT cut={cut:?} actual_mint=true q_ack=true exact_revoked=2 listener_absent={endpoint_gone} g2_effect_absent={no_effect} direct_child_reaped=true"
        );
    }
}
