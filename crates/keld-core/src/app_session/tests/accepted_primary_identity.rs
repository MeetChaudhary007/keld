//! KEL-97 authenticated identity proof; no OS-containment or grant claim.
use super::*;
use keld_runtime::primary::{PrimaryRoleConfig, PrimaryRoleSupervisor};
use std::io::{BufRead as _, BufReader};
use std::net::{TcpListener, TcpStream};

const BOUND: Duration = Duration::from_secs(20);

/// Actual role coordinator owns every Bun child/restart/reap, including unwind.
struct AcceptedRole {
    supervisor: PrimaryRoleSupervisor,
    listener: TcpListener,
    finished: bool,
}

impl AcceptedRole {
    fn start(owner: RoleOwner) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("private fixture control");
        listener.set_nonblocking(true).expect("bounded accept poll");
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/app_session/tests/fixtures/accepted_primary_identity_role.ts");
        let config = match owner {
            RoleOwner::Primary => PrimaryRoleConfig::primary("bun"),
            RoleOwner::AppBound => PrimaryRoleConfig::app_bound("bun"),
        };
        let supervisor = PrimaryRoleSupervisor::start_with_bound_generations(
            config
                .arg(script)
                .arg(
                    listener
                        .local_addr()
                        .expect("owned port")
                        .port()
                        .to_string(),
                )
                .env_remove("KELD_KIPC_TEST_HOOKS"),
        )
        .expect("existing authenticated coordinator");
        Self {
            supervisor,
            listener,
            finished: false,
        }
    }

    fn finish(&mut self) -> Option<keld_runtime::SupervisorOutcome> {
        let deadline = Instant::now() + BOUND;
        self.supervisor.shutdown();
        loop {
            if Instant::now() >= deadline {
                return None;
            }
            if let Some(outcome) = self.supervisor.try_wait_for_outcome() {
                self.finished = true;
                return Some(outcome);
            }
            thread::yield_now();
        }
    }

    fn bind(&self) -> (BoundPrimaryGeneration, BufReader<TcpStream>) {
        let deadline = Instant::now() + BOUND;
        let stream = loop {
            assert!(Instant::now() < deadline, "actual child control absent");
            match self.listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::yield_now(),
                Err(error) => panic!("owned control accept: {error}"),
            }
        };
        stream
            .set_nonblocking(false)
            .expect("accepted control stream blocks on Darwin");
        stream
            .set_read_timeout(Some(BOUND))
            .expect("bounded control read");
        stream
            .set_write_timeout(Some(BOUND))
            .expect("bounded control write");
        let bound = self
            .supervisor
            .recv_bound_generation(BOUND)
            .expect("actual HELLO accepted Bound");
        let mut control = BufReader::new(stream);
        assert_eq!(read_control(&mut control), "BOUND");
        (bound, control)
    }
}

impl Drop for AcceptedRole {
    fn drop(&mut self) {
        if !self.finished {
            self.supervisor.shutdown();
        }
    }
}

fn read_control(control: &mut BufReader<TcpStream>) -> String {
    let mut line = String::new();
    assert!(
        control
            .read_line(&mut line)
            .expect("actual controlled role reply")
            > 0
    );
    line.trim_end().to_owned()
}

#[test]
fn accepted_app_bound_identity_is_refused_by_primary_admission() {
    let mut role = AcceptedRole::start(RoleOwner::AppBound);
    let (bound, _control) = role.bind();
    assert_eq!(bound.principal().owner(), RoleOwner::AppBound);
    // This observes typed owner refusal at shipping admission. It does not
    // assert that an app CALL was submitted or independently census handler effects.
    let (owner, _commands) = mpsc::channel();
    let (window, _events) = mpsc::channel();
    let result = PrimaryRouter::start_bound(
        bound,
        window,
        GuardianOwnerHandle { command_tx: owner },
        SessionShutdownState::new(),
        None,
        AuthConfiguration::new(),
    );
    let Err(error) = result else {
        panic!("accepted app-bound role entered primary router");
    };
    assert!(
        error.to_string().contains("KELD-CORE-037"),
        "existing typed admission fault"
    );
    assert!(
        matches!(
            role.finish(),
            Some(keld_runtime::SupervisorOutcome::Stopped)
        ),
        "actual role terminal cleanup"
    );
}
