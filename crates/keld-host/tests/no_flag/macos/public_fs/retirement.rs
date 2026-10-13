//! Public-main local admission after Quit; native handler-entry absence is unobserved.
use super::project::{CONTENT, Exercise, Policy, PublicFsProject};
use super::{LaunchEvidence, run_launch};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::process::Output;

#[test]
fn public_app_fs_after_quit_is_locally_refused_without_effect_and_relaunches() {
    let fixture = PublicFsProject::new(Policy::Narrow);
    let retired = run_launch(&fixture, 0, Exercise::PublicAppRetirement);
    // The existing ordinary public-main roundtrip proves the next launch is healthy.
    let relaunched = run_launch(&fixture, 1, Exercise::PublicAppComponent);
    for key in ["documentNonce", "javascriptToken"] {
        let document_identity = |evidence: &LaunchEvidence| {
            evidence
                .reports
                .iter()
                .find(|report| report["phase"] == "page-ready")
                .expect("actual launch document")[key]
                .as_str()
                .expect("renderer-created identity")
                .to_owned()
        };
        assert_ne!(
            document_identity(&retired),
            document_identity(&relaunched),
            "healthy relaunch reused old volatile {key}"
        );
    }
    assert_ne!(
        retired.family.expect("retired process family").bun,
        relaunched.family.expect("healthy process family").bun,
        "healthy relaunch reused retired Bun identity"
    );
    eprintln!(
        "KELD_KEL140_PUBLIC_RETIREMENT_ACCEPTANCE launches=2 input_actions=0 local_closed=true unchanged_allowed_bytes=true native_entry_absence=unknown renderer_action_acceptance=false"
    );
}

pub(super) fn assert_after_quit(output: &Output, evidence: &LaunchEvidence, target: &Path) {
    // This runs after product cleanup and before fixture Drop/fallback cleanup.
    // File effects are an independent OS oracle, not inferred from app output.
    assert_eq!(
        fs::read(target).expect("allowed target after public Quit"),
        CONTENT,
        "post-Quit write changed independently observed allowed bytes"
    );
    let stderr = std::str::from_utf8(&output.stderr).expect("retirement output UTF-8");
    let actual: Vec<Value> = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("KELD_KEL140_PUBLIC_FS_RETIRED "))
        .map(|line| {
            assert!(line.len() <= 4096, "bounded public retirement output");
            serde_json::from_str(line).expect("actual public retirement JSON")
        })
        .collect();
    assert_eq!(
        actual.len(),
        1,
        "one actual post-Quit public outcome record"
    );
    assert_eq!(
        actual[0],
        json!({
            "phase":"app-retirement",
            "pid":evidence.family.expect("OS-attributed Bun family").bun,
            "componentOnly":true,
            "outcomes":[
                {"action":"write","status":"rejected","errorName":"Error",
                    "message":"KELD-IPC-001: session is closed",
                    "codePresent":false,"callError":false},
                {"action":"read","status":"rejected","errorName":"Error",
                    "message":"KELD-IPC-001: session is closed",
                    "codePresent":false,"callError":false}
            ]
        }),
        "post-Quit methods must report the exact ordinary local closed Error"
    );
}
