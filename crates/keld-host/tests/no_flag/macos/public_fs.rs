//! KEL-140 stock producer/public API proof. Native execution belongs to ROOT.
//! No authority boundary change; no pending native-effect or cancellation claim.
use crate::support::EVENT_DEADLINE;
use crate::support::control::wait_child_output;
use crate::support::dev_cycle::ShippingLaunchCleanup;
use crate::support::native_window::{
    NativeWindowObserver, await_same_native_windows, native_windows,
};
use crate::support::process::{
    await_process_gone, kill_pid, parent_process, process_exists, process_group,
};
use serde_json::{Value, json};
use std::fs;
use std::os::unix::net::UnixStream;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::Instant;

#[path = "public_fs/application_link.rs"]
mod application_link;
#[path = "public_fs/component.rs"]
mod component;
#[path = "public_fs/observer.rs"]
mod observer;
#[path = "public_fs/outcomes.rs"]
mod outcomes;
#[path = "public_fs/policy_startup.rs"]
mod policy_startup;
#[path = "public_fs/preclick.rs"]
mod preclick;
#[path = "public_fs/process_image.rs"]
mod process_image;
#[path = "public_fs/project.rs"]
mod project;
use application_link::assert_single_application_link;
use observer::{Observation, RecoveryCommand, RecoveryPhase};
use outcomes::{
    assert_component_outcomes, assert_component_trace, assert_handler_attribution,
    assert_natural_outcomes, assert_page_outcomes,
};
use process_image::process_image_path;
use project::{
    CONTENT, Exercise, Policy, PreparedLaunch, PublicFsProject, RECOVERY_AFTER_CONTENT, SENTINEL,
    TITLE,
};

#[derive(Clone, Copy, Debug)]
struct ProcessFamily {
    bun: u32,
    descendant: u32,
    guardian: u32,
}

#[derive(Default)]
struct LaunchEvidence {
    reports: Vec<Value>,
    click: Option<Output>,
    family: Option<ProcessFamily>,
    window: Vec<u32>,
    retired_family: Option<ProcessFamily>,
    recovery_boot: Option<RecoveryBoot>,
}

struct RecoveryBoot {
    pid: u32,
    app_link: String,
}

#[test]
fn real_pointer_public_fs_uses_stock_project_policy() {
    run(Policy::Narrow, 2);
}

#[test]
fn explicit_empty_policy_denies_public_fs_without_effect() {
    run(Policy::Empty, 1);
}

#[test]
fn absent_project_policy_denies_public_fs_without_effect() {
    run(Policy::Absent, 1);
}

/// Completed-call consumer recovery, not interrupted-effect or full KEL-143 proof.
#[test]
fn renderer_public_fs_recovers_same_document_after_real_bun_loss() {
    let fixture = PublicFsProject::new(Policy::Narrow);
    let recovered = run_recovery_launch(&fixture, 0);
    // A separate ordinary public-main launch independently checks healthy reuse.
    let relaunched = run_launch(&fixture, 1, Exercise::PublicAppComponent);
    let document = |evidence: &LaunchEvidence, key: &str| {
        evidence
            .reports
            .iter()
            .find(|report| report["phase"] == "page-ready")
            .expect("actual initial document")[key]
            .as_str()
            .expect("renderer-created identity")
            .to_owned()
    };
    for key in ["documentNonce", "javascriptToken"] {
        assert_ne!(
            document(&recovered, key),
            document(&relaunched, key),
            "healthy new launch must create a new volatile {key}"
        );
    }
}

fn run_recovery_launch(fixture: &PublicFsProject, launch: usize) -> LaunchEvidence {
    run_launch(fixture, launch, Exercise::RendererRecovery)
}

fn run(policy: Policy, launches: usize) {
    let fixture = PublicFsProject::new(policy);
    for launch in 0..launches {
        run_launch(&fixture, launch, Exercise::RendererPointer);
    }
}

fn run_launch(fixture: &PublicFsProject, launch: usize, exercise: Exercise) -> LaunchEvidence {
    let observer = if exercise == Exercise::RendererRecovery {
        Observation::bind_recovery()
    } else {
        Observation::bind()
    };
    let prepared = match exercise {
        Exercise::RendererPointer => fixture.prepare(launch, observer.port),
        Exercise::RendererRecovery => fixture.prepare_recovery(launch, observer.port),
        Exercise::PublicAppComponent => fixture.prepare_component(launch, observer.port),
        Exercise::PublicAppNaturalCases => fixture.prepare_natural(launch, observer.port),
    };
    let stage = &prepared.stage;
    if exercise != Exercise::RendererPointer {
        assert!(
            matches!(fs::symlink_metadata(&prepared.target), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
            "component target must be absent before host spawn"
        );
    }
    let mut presentation = NativeWindowObserver::arm_for_title(&fixture.census, TITLE);
    let mut cleanup = spawn_shipping_host(stage);
    let host = cleanup.cli.as_mut().expect("host custody");
    let host_pid = host.id();
    let _lease = host.stdin.take().expect("retain dev lease until host exit");
    let mut evidence = LaunchEvidence::default();
    let observation_result = catch_unwind(AssertUnwindSafe(|| {
        observe_launch(
            &observer,
            &mut cleanup,
            &mut presentation,
            &mut evidence,
            fixture,
            &prepared,
            host_pid,
        );
        eprintln!(
            "KELD_KEL140_PUBLIC_WITNESS policy={:?} launch={launch} host={host_pid} window={:?} identities={:?} policy_sha256={} host_sha256={} reports={:?} exercise={exercise:?}",
            fixture.policy,
            evidence.window,
            evidence.family,
            prepared.digest,
            prepared.host_digest,
            evidence.reports,
        );
    }));
    if observation_result.is_err() {
        // Capture pipes even if the host exited first. Fallback is never success.
        let _ = cleanup.cli.as_mut().expect("retained failed host").kill();
    } else {
        observer
            .quit
            .send(())
            .expect("release public app Quit after observations");
    }
    let output = wait_child_output(
        cleanup.cli.take().expect("capture host before unwind"),
        EVENT_DEADLINE,
    );
    eprintln!(
        "KELD_KEL140_PUBLIC_DIAGNOSTICS policy={:?} launch={launch} click={:?} reports={:?} host_output={output:?}",
        fixture.policy, evidence.click, evidence.reports,
    );
    if let Err(failure) = observation_result {
        resume_unwind(failure);
    }
    assert_product_quit(&output, &evidence, stage.root(), host_pid, exercise);
    cleanup.bun_group = None;
    eprintln!(
        "KELD_KEL140_PUBLIC_CLEANUP launch={launch} exact_stage={} family_gone=true window_gone=true fixture_drop_pending=true",
        stage.root().display(),
    );
    evidence
}

fn observe_launch(
    observer: &Observation,
    cleanup: &mut ShippingLaunchCleanup,
    presentation: &mut NativeWindowObserver,
    evidence: &mut LaunchEvidence,
    fixture: &PublicFsProject,
    prepared: &PreparedLaunch,
    host_pid: u32,
) {
    if prepared.exercise == Exercise::RendererRecovery {
        let boot = await_recovery_boot(observer, &mut evidence.reports);
        observer.send_recovery_command(RecoveryCommand::Admit(boot.pid));
        evidence.recovery_boot = Some(boot);
    }
    await_ready(observer, cleanup, evidence, host_pid, prepared);
    let ready = evidence
        .reports
        .iter()
        .find(|report| report["phase"] == "page-ready")
        .expect("page ready");
    assert_eq!(
        ready["initial"],
        json!({"bridge":true,"frozen":true,"nativeHidden":true})
    );
    evidence.window = presentation.expect_initial(host_pid, "kel140-public-fs");
    assert_eq!(evidence.window.len(), 1);
    match prepared.exercise {
        Exercise::RendererPointer => {
            observe_pointer_actions(observer, evidence, fixture, prepared, host_pid);
        }
        Exercise::RendererRecovery => {
            observe_recovery_actions(observer, cleanup, evidence, fixture, prepared, host_pid);
        }
        Exercise::PublicAppComponent | Exercise::PublicAppNaturalCases => {
            observe_component_actions(observer, evidence, fixture, prepared, host_pid);
        }
    }
}

fn await_recovery_boot(observer: &Observation, journal: &mut Vec<Value>) -> RecoveryBoot {
    let mut report = observer
        .reports
        .recv_timeout(EVENT_DEADLINE)
        .expect("real recovery app boot before its public whenReady");
    let app_link = report["appLink"]
        .as_str()
        .expect("fixture-owned bootstrap data")
        .to_owned();
    let endpoint = app_link
        .rsplit_once('#')
        .expect("host-minted app bootstrap")
        .0
        .to_owned();
    let boot = RecoveryBoot {
        pid: pid(&report, "pid"),
        app_link,
    };
    // The possession token is only used in the local hostile connection. Do
    // not copy it into diagnostic reports or retained acceptance artifacts.
    report
        .as_object_mut()
        .expect("boot report object")
        .remove("appLink");
    report["endpoint"] = json!(endpoint);
    assert_eq!(report["phase"], "recovery-app-boot", "{report:?}");
    eprintln!("KELD_KEL140_RECOVERY_BOOT {report}");
    journal.push(report);
    boot
}

fn observe_recovery_actions(
    observer: &Observation,
    cleanup: &mut ShippingLaunchCleanup,
    evidence: &mut LaunchEvidence,
    fixture: &PublicFsProject,
    prepared: &PreparedLaunch,
    host_pid: u32,
) {
    let first_boot = evidence.recovery_boot.take().expect("G1 fixture boot");
    let first = evidence.family.expect("OS-attributed G1 family");
    assert_eq!(first_boot.pid, first.bun);
    let initial_document = evidence
        .reports
        .iter()
        .find(|report| report["phase"] == "page-ready")
        .expect("actual original document")
        .clone();
    let recovery = prepared.recovery.as_ref().expect("owned recovery targets");
    assert!(matches!(fs::symlink_metadata(&recovery.after), Err(error)
        if error.kind() == std::io::ErrorKind::NotFound));
    assert_eq!(fs::read(&recovery.witness).expect("empty witness"), b"");

    observer.send_recovery_command(RecoveryCommand::Invoke(RecoveryPhase::Before));
    let before = await_recovery_page(observer, evidence, RecoveryPhase::Before);
    assert_recovery_phase(
        &before,
        &initial_document,
        RecoveryPhase::Before,
        fixture,
        prepared,
    );
    assert_completed_recovery_files(prepared, RecoveryPhase::Before);
    assert!(evidence.click.is_none(), "recovery has no input action");
    let expected_bun_image = fs::canonicalize(process_image_path(first.bun))
        .expect("independently attributed G1 Bun image");

    // Only this independently attributed admitted Bun PID is killed. The
    // persistent guardian remains the process-family and restart owner.
    kill_pid(first.bun);
    let successor_boot = await_recovery_boot(observer, &mut evidence.reports);
    assert_ne!(first.bun, successor_boot.pid);
    assert_bun_cleanup_custody(
        successor_boot.pid,
        first.guardian,
        host_pid,
        &expected_bun_image,
        prepared.stage.host(),
    );
    // Until every independent census above passes, fallback cleanup retains
    // only the already-attributed G1 group. Ordinary HTTP data grants no custody.
    cleanup.bun_group = Some(successor_boot.pid);
    assert_retired_credentials(&first_boot.app_link, &successor_boot.app_link, prepared);
    observer.send_recovery_command(RecoveryCommand::Admit(successor_boot.pid));
    let ready = observer
        .reports
        .recv_timeout(EVENT_DEADLINE)
        .expect("G2 public whenReady returned after fresh host admission");
    assert_eq!(ready["phase"], "app-ready", "{ready}");
    assert_eq!(pid(&ready, "pid"), successor_boot.pid);
    let successor = ProcessFamily {
        bun: successor_boot.pid,
        descendant: pid(&ready, "descendantPid"),
        guardian: parent_process(successor_boot.pid),
    };
    assert_eq!(first.guardian, successor.guardian, "persistent guardian");
    assert_app_identity(&ready, successor, host_pid, prepared);
    evidence.reports.push(ready);
    evidence.retired_family = Some(first);
    evidence.family = Some(successor);
    await_process_gone(first.bun);
    await_process_gone(first.descendant);
    assert!(process_exists(host_pid) && process_exists(first.guardian));
    assert_eq!(
        await_same_native_windows(host_pid, TITLE, &evidence.window),
        evidence.window,
        "actual Bun loss replaced the original native window"
    );

    observer.send_recovery_command(RecoveryCommand::Invoke(RecoveryPhase::After));
    let after = await_recovery_page(observer, evidence, RecoveryPhase::After);
    assert_recovery_phase(
        &after,
        &initial_document,
        RecoveryPhase::After,
        fixture,
        prepared,
    );
    assert_completed_recovery_files(prepared, RecoveryPhase::After);
    assert_eq!(
        await_same_native_windows(host_pid, TITLE, &evidence.window),
        evidence.window
    );
    assert_eq!(
        evidence
            .reports
            .iter()
            .filter(|report| report["phase"] == "page-ready")
            .count(),
        1,
        "same document; no second initial-page observation"
    );
    observer.send_recovery_command(RecoveryCommand::Quit(successor.bun));
    eprintln!(
        "KELD_KEL140_RECOVERY_CONSUMER host={host_pid} window={:?} first_bun={} second_bun={} input_actions=0 completed_witness=[1,2] interrupted_effect_acceptance=false blocked_syscall_acceptance=false full_kel143_acceptance=false",
        evidence.window, first.bun, successor.bun,
    );
}

fn assert_completed_recovery_files(prepared: &PreparedLaunch, phase: RecoveryPhase) {
    let recovery = prepared.recovery.as_ref().expect("owned recovery targets");
    let target_message = match phase {
        RecoveryPhase::Before => "completed G1 bytes",
        RecoveryPhase::After => "retained G1 bytes",
    };
    assert_eq!(fs::read(&prepared.target).expect(target_message), CONTENT);
    match phase {
        RecoveryPhase::Before => {
            assert_eq!(fs::read(&recovery.witness).expect("G1 witness"), [1]);
            assert!(matches!(fs::symlink_metadata(&recovery.after), Err(error)
                if error.kind() == std::io::ErrorKind::NotFound));
        }
        RecoveryPhase::After => {
            assert_eq!(
                fs::read(&recovery.after).expect("independent G2 bytes"),
                RECOVERY_AFTER_CONTENT
            );
            assert_eq!(fs::read(&recovery.witness).expect("G1/G2 witness"), [1, 2]);
        }
    }
}

fn assert_bun_cleanup_custody(
    candidate: u32,
    guardian: u32,
    host: u32,
    expected_bun_image: &Path,
    expected_host_image: &Path,
) {
    let expected_host_image =
        fs::canonicalize(expected_host_image).expect("owned staged host image");
    for owned in [host, guardian] {
        assert!(
            process_exists(owned),
            "owned host/guardian must remain live"
        );
        assert_eq!(
            fs::canonicalize(process_image_path(owned)).expect("kernel host/guardian image"),
            expected_host_image,
            "owned host/guardian image must remain unchanged"
        );
    }
    assert_eq!(parent_process(guardian), host, "owned guardian parent");
    assert_eq!(
        parent_process(candidate),
        guardian,
        "candidate must be the owned guardian's direct Bun child"
    );
    assert_eq!(process_group(candidate), candidate, "candidate Bun group");
    assert_eq!(
        fs::canonicalize(process_image_path(candidate)).expect("kernel candidate Bun image"),
        expected_bun_image,
        "candidate must run the independently observed Bun image"
    );
}

fn assert_retired_credentials(old_link: &str, successor_link: &str, prepared: &PreparedLaunch) {
    const PROBE: &str = r#"
const { parseAppLink, WriteQueue, DrainSignal, FrameKind, HANDSHAKE_CHANNEL, withIoDeadline } =
  await import(process.env.KELD_RECOVERY_PROBE_TRANSPORT);
const old = parseAppLink(process.env.KELD_RECOVERY_PROBE_OLD);
const fresh = parseAppLink(process.env.KELD_RECOVERY_PROBE_FRESH);
const drain = new DrainSignal();
let resolveEnd, rejectEnd;
const refused = new Promise((resolve, reject) => { resolveEnd = resolve; rejectEnd = reject; });
void refused.catch(() => {});
const socket = await Bun.connect({ unix: fresh.endpoint, socket: {
  data() { rejectEnd(new Error("retired token received server reply bytes")); },
  drain() { drain.fire(); },
  end() { resolveEnd(); },
  close() { resolveEnd(); },
  error(_socket, error) {
    if (error.code === "ECONNRESET" || error.code === "ECONNABORTED") resolveEnd();
    else rejectEnd(error);
  },
} });
try {
  await withIoDeadline(new WriteQueue(socket, drain).writeFrame(FrameKind.Hello, 0, HANDSHAKE_CHANNEL, 0, old.token));
  await withIoDeadline(refused);
  console.log("RETIRED_TOKEN_SERVER_EOF_NO_REPLY");
} finally { socket.end(); }
"#;
    let (old_endpoint, old_token) = old_link.rsplit_once('#').expect("G1 bootstrap");
    let (endpoint, token) = successor_link.rsplit_once('#').expect("G2 bootstrap");
    assert_ne!(old_endpoint, endpoint, "fresh endpoint");
    assert!(old_token != token, "fresh possession token");
    assert!(
        UnixStream::connect(old_endpoint).is_err(),
        "retired endpoint accepts a reconnect"
    );
    // A separate hostile fixture consumes the canonical staged wire helpers.
    // It is not an application adapter or a second link in the public app.
    let probe = Command::new("bun")
        .args(["-e", PROBE])
        .env(
            "KELD_RECOVERY_PROBE_TRANSPORT",
            prepared.stage.root().join("src/kipc-transport.ts"),
        )
        .env("KELD_RECOVERY_PROBE_OLD", old_link)
        .env("KELD_RECOVERY_PROBE_FRESH", successor_link)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("isolated canonical stale-token probe");
    let output = wait_child_output(probe, EVENT_DEADLINE);
    assert!(
        output.status.success(),
        "server-side stale-token refusal failed: {output:?}"
    );
    assert_eq!(output.stdout, b"RETIRED_TOKEN_SERVER_EOF_NO_REPLY\n");
}

fn await_recovery_page(
    observer: &Observation,
    evidence: &mut LaunchEvidence,
    phase: RecoveryPhase,
) -> Value {
    let report = observer
        .reports
        .recv_timeout(EVENT_DEADLINE)
        .expect("actual recovery renderer outcome");
    assert_eq!(
        report["phase"],
        format!("recovery-{}", phase.as_str()),
        "{report}"
    );
    eprintln!("KELD_KEL140_RECOVERY_PAGE {report}");
    evidence.reports.push(report.clone());
    report
}

fn assert_recovery_phase(
    report: &Value,
    initial_document: &Value,
    phase: RecoveryPhase,
    fixture: &PublicFsProject,
    prepared: &PreparedLaunch,
) {
    for key in ["documentNonce", "javascriptToken", "initial"] {
        assert_eq!(initial_document[key], report[key], "same renderer {key}");
    }
    for key in ["documentNonce", "javascriptToken"] {
        let value = report[key].as_str().expect("renderer-created identity");
        assert_eq!(value.len(), 32);
        assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
    assert_eq!(report["automaticRecovery"], true);
    let count = match phase {
        RecoveryPhase::Before => 2,
        RecoveryPhase::After => 4,
    };
    let requests = report["requests"]
        .as_array()
        .expect("actual renderer requests");
    let outcomes = report["outcomes"]
        .as_array()
        .expect("actual renderer outcomes");
    assert_eq!(requests.len(), count);
    assert_eq!(outcomes.len(), count);
    let mut nonces = std::collections::BTreeSet::new();
    for (index, action) in ["recovery-before", "deny", "recovery-after", "deny"]
        .iter()
        .take(count)
        .enumerate()
    {
        assert_eq!(requests[index]["action"], *action);
        assert_eq!(requests[index]["count"], index % 2 + 1);
        let nonce = requests[index]["nonce"]
            .as_str()
            .expect("renderer-created request nonce");
        assert_eq!(nonce.len(), 32);
        assert!(nonce.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(nonces.insert(nonce), "each completed call is distinct");
        assert_eq!(outcomes[index]["action"], *action);
        let expected = if index % 2 == 0 {
            json!({"ok":true,"bytes":if index == 0 { CONTENT } else { RECOVERY_AFTER_CONTENT }})
        } else {
            json!({"ok":false,"code":"KELD-GUARD002","message":format!(
                "KELD-GUARD002: capability `fs.write` denied by scope `{}`. Widen `/app/fs/write` in keld.permissions.jsonc so it includes `{}`.",
                fixture.scope, fixture.outside.display())})
        };
        assert_eq!(outcomes[index]["outcome"], expected);
    }
    assert_eq!(
        fs::read(&fixture.outside).expect("independent outside sentinel"),
        SENTINEL
    );
    assert!(
        prepared.recovery.is_some(),
        "ordinary staged recovery fixture"
    );
}

fn observe_component_actions(
    observer: &Observation,
    evidence: &mut LaunchEvidence,
    fixture: &PublicFsProject,
    prepared: &PreparedLaunch,
    host_pid: u32,
) {
    if !evidence
        .reports
        .iter()
        .any(|report| report["phase"] == "app-result")
    {
        let result = observer
            .reports
            .recv_timeout(EVENT_DEADLINE)
            .expect("actual public-main FS result");
        eprintln!("KELD_KEL140_OBSERVATION {result}");
        evidence.reports.push(result);
    }
    assert!(
        evidence.click.is_none(),
        "component must issue no synthetic input"
    );
    let bun = evidence.family.expect("observed public app family").bun;
    if prepared.exercise == Exercise::PublicAppNaturalCases {
        assert_natural_outcomes(
            &evidence.reports,
            fixture.policy,
            prepared,
            &fixture.outside,
            bun,
        );
    } else {
        assert_component_outcomes(
            &evidence.reports,
            fixture.policy,
            &prepared.target,
            &fixture.outside,
            &fixture.scope,
            bun,
        );
    }
    assert_eq!(
        await_same_native_windows(host_pid, TITLE, &evidence.window),
        evidence.window,
        "public-main filesystem work replaced the actual native window"
    );
}

fn observe_pointer_actions(
    observer: &Observation,
    evidence: &mut LaunchEvidence,
    fixture: &PublicFsProject,
    prepared: &PreparedLaunch,
    host_pid: u32,
) {
    assert!(
        matches!(fs::symlink_metadata(&prepared.target), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
        "target exists before the real pointer action"
    );
    let input_script = preclick::composed_click_script();
    evidence.click = Some(
        Command::new("/usr/bin/xcrun")
            .args(["swift", "-e", &input_script, &host_pid.to_string(), TITLE])
            .output()
            .expect("real CoreGraphics pointer action"),
    );
    assert!(
        evidence
            .click
            .as_ref()
            .expect("retained click result")
            .status
            .success(),
        "{:?}",
        evidence.click
    );
    observer.await_page_result(&mut evidence.reports);
    assert_page_outcomes(
        &evidence.reports,
        fixture.policy,
        &prepared.target,
        &fixture.outside,
        &fixture.scope,
    );
}

fn await_ready(
    observer: &Observation,
    cleanup: &mut ShippingLaunchCleanup,
    evidence: &mut LaunchEvidence,
    host_pid: u32,
    prepared: &PreparedLaunch,
) {
    let exercise = prepared.exercise;
    let deadline = Instant::now() + EVENT_DEADLINE;
    while !evidence
        .reports
        .iter()
        .any(|report| report["phase"] == "app-ready")
        || !evidence
            .reports
            .iter()
            .any(|report| report["phase"] == "page-ready")
    {
        let report = observer
            .reports
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("app Ready and installed page listener observations");
        eprintln!("KELD_KEL140_OBSERVATION {report}");
        // Retain the observation before any identity assertion can unwind.
        evidence.reports.push(report.clone());
        if report["phase"] == "app-ready" {
            let bun = pid(&report, "pid");
            let descendant = pid(&report, "descendantPid");
            let guardian = parent_process(bun);
            let family = ProcessFamily {
                bun,
                descendant,
                guardian,
            };
            assert_app_identity(&report, family, host_pid, prepared);
            // Ordinary app data gains fallback custody only after the
            // independent live host/guardian/group/image/link census passes.
            cleanup.bun_group = Some(bun);
            evidence.family = Some(family);
        }
        assert!(
            report["phase"] == "app-ready"
                || report["phase"] == "page-ready"
                || (exercise != Exercise::RendererPointer && report["phase"] == "app-result"),
            "{report}"
        );
    }
}

fn assert_app_identity(
    report: &Value,
    family: ProcessFamily,
    host_pid: u32,
    prepared: &PreparedLaunch,
) {
    let ProcessFamily {
        bun,
        descendant,
        guardian,
    } = family;
    assert_bun_cleanup_custody(
        bun,
        guardian,
        host_pid,
        &prepared.bun_image,
        prepared.stage.host(),
    );
    assert_eq!(parent_process(guardian), host_pid);
    assert_eq!(parent_process(descendant), bun);
    assert_eq!(process_group(bun), bun);
    assert_eq!(process_group(descendant), bun);
    let executable = Command::new("/bin/ps")
        .args(["-p", &bun.to_string(), "-o", "comm="])
        .output()
        .expect("process display diagnostic");
    eprintln!("KELD_KEL140_PROCESS_DISPLAY pid={bun} ps_output={executable:?}");
    let image = process_image_path(bun);
    eprintln!(
        "KELD_KEL140_PROCESS_IMAGE_MATCH pid={bun} kernel_image={} reported_image={}",
        image.display(),
        report["executable"]
    );
    assert_eq!(
        fs::canonicalize(&image).expect("kernel Bun image"),
        fs::canonicalize(report["executable"].as_str().expect("app executable"))
            .expect("reported Bun image")
    );
    assert_single_application_link(
        host_pid,
        bun,
        report["endpoint"].as_str().expect("endpoint"),
    );
}

fn assert_product_quit(
    output: &Output,
    evidence: &LaunchEvidence,
    stage_root: &Path,
    host_pid: u32,
    exercise: Exercise,
) {
    assert!(output.status.success(), "{output:?}");
    let stderr = std::str::from_utf8(&output.stderr).expect("host diagnostic UTF-8");
    let expected_calls = match exercise {
        Exercise::RendererPointer => 3,
        Exercise::RendererRecovery => 4,
        Exercise::PublicAppComponent | Exercise::PublicAppNaturalCases => 0,
    };
    for marker in [
        "KELD_KEL142_RENDERER_ADMIT webview=",
        "KELD_KEL142_KIPC_CALL webview=",
        "KELD_KEL140_PUBLIC_HANDLER ",
    ] {
        assert_eq!(stderr.matches(marker).count(), expected_calls, "{stderr}");
    }
    assert!(stderr.contains("KELD_KEL142_BIND webview="), "{stderr}");
    let quit_calls = if exercise == Exercise::RendererRecovery {
        2
    } else {
        expected_calls
    };
    assert!(
        stderr.contains(&format!(
            "KELD_KEL140_PUBLIC_QUIT_REQUEST calls={quit_calls}"
        )),
        "{stderr}"
    );
    let ProcessFamily {
        bun,
        descendant,
        guardian,
    } = evidence.family.expect("OS-attributed application family");
    match exercise {
        Exercise::RendererPointer => assert_handler_attribution(
            stderr,
            evidence.reports.last().expect("final page report"),
            bun,
        ),
        Exercise::RendererRecovery => assert_recovery_trace(stderr, evidence),
        Exercise::PublicAppComponent | Exercise::PublicAppNaturalCases => {
            assert_component_trace(stderr, &evidence.reports);
        }
    }
    if let Some(retired) = evidence.retired_family {
        await_process_gone(retired.bun);
        await_process_gone(retired.descendant);
    }
    for process in [host_pid, bun, descendant, guardian] {
        await_process_gone(process);
    }
    assert!(native_windows(host_pid, TITLE).is_empty());
    assert!(
        matches!(fs::symlink_metadata(stage_root), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
        "product Quit retained exact stage before fixture destruction: {}",
        stage_root.display()
    );
}

fn assert_recovery_trace(stderr: &str, evidence: &LaunchEvidence) {
    let first = evidence.retired_family.expect("retired G1 identity");
    let successor = evidence.family.expect("fresh G2 identity");
    let result = evidence
        .reports
        .iter()
        .find(|report| report["phase"] == "recovery-after")
        .expect("same document's completed G2 calls");
    let handlers: Vec<Value> = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("KELD_KEL140_PUBLIC_HANDLER "))
        .map(|line| serde_json::from_str(line).expect("actual recovery handler trace"))
        .collect();
    let outcomes: Vec<Value> = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("KELD_KEL140_PUBLIC_OUTCOME "))
        .map(|line| serde_json::from_str(line).expect("actual recovery public FS trace"))
        .collect();
    assert_eq!(
        handlers.len(),
        4,
        "one invocation per distinct completed call"
    );
    assert_eq!(outcomes.len(), 4, "no replayed completed call");
    for (index, handler) in handlers.iter().enumerate() {
        assert_eq!(
            handler,
            &json!({"call":index % 2 + 1,
            "pid":if index < 2 { first.bun } else { successor.bun },
            "action":result["requests"][index]["action"],
            "nonce":result["requests"][index]["nonce"]})
        );
        assert_eq!(
            outcomes[index],
            json!({"call":index % 2 + 1,
            "nonce":result["requests"][index]["nonce"],
            "outcome":result["outcomes"][index]["outcome"]})
        );
    }
}

fn pid(report: &Value, key: &str) -> u32 {
    u32::try_from(report[key].as_u64().expect("reported PID")).expect("OS PID domain")
}

fn spawn_shipping_host(stage: &keld_cli::boot::DevBootStage) -> ShippingLaunchCleanup {
    let child = Command::new(stage.host())
        .current_dir(stage.root())
        .env("KELD_DEV_LEASE", "stdin-v1")
        .env("KELD_KEL142_ACCEPTANCE_REPORT", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch staged shipping no-flag host");
    ShippingLaunchCleanup::new(child)
}
