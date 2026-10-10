//! Owns ordinary project inputs and stock CLI preparation, never live authority.
use crate::renderer_bridge::bundle_public_api_entry;
use crate::support::native_window::compile_native_window_census;
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(super) const TITLE: &str = "KEL140 Public FS Acceptance";
pub(super) const CONTENT: &[u8] = &[0, 255, 65, 226, 130, 185];
pub(super) const SENTINEL: &[u8] = b"KEL140-outside-sentinel-unchanged";
pub(super) const READ_SENTINEL: &[u8] = b"KEL140-read-sentinel-must-not-be-returned";
pub(super) const INTERNAL_INITIAL: &[u8] = b"KEL140-internal-link-original";
pub(super) const WRITE_SENTINEL: &[u8] = b"KEL140-oversize-write-target-unchanged";

#[derive(Clone, Copy, Debug)]
pub(super) enum Policy {
    Narrow,
    Empty,
    Absent,
}

pub(super) struct PublicFsProject {
    _owned: tempfile::TempDir,
    project: PathBuf,
    repo: PathBuf,
    allowed: PathBuf,
    policy_bytes: Vec<u8>,
    pub(super) policy: Policy,
    pub(super) outside: PathBuf,
    pub(super) scope: String,
    pub(super) census: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Exercise {
    RendererPointer,
    PublicAppComponent,
    PublicAppNaturalCases,
}

pub(super) struct NaturalInputs {
    pub(super) read_sentinel: PathBuf,
    pub(super) internal_target: PathBuf,
    pub(super) internal_alias: PathBuf,
    pub(super) external_alias: PathBuf,
    pub(super) oversized_write: PathBuf,
    pub(super) oversized_read: PathBuf,
    pub(super) fresh: PathBuf,
    pub(super) maximum_content: usize,
    pub(super) oversized_read_digest: String,
}

pub(super) struct PreparedLaunch {
    pub(super) exercise: Exercise,
    pub(super) stage: keld_cli::boot::DevBootStage,
    pub(super) target: PathBuf,
    pub(super) digest: String,
    pub(super) host_digest: String,
    pub(super) natural: Option<NaturalInputs>,
}

impl PublicFsProject {
    pub(super) fn new(policy: Policy) -> Self {
        let owned = tempfile::tempdir().expect("owned public FS project");
        let root = fs::canonicalize(owned.path()).expect("canonical project parent");
        let project = root.join("public-fs");
        fs::create_dir_all(project.join("src")).expect("ordinary project source directory");
        let allowed = root.join("allowed");
        fs::create_dir(&allowed).expect("existing granted scope root");
        let scope = format!("{}/**", allowed.to_str().expect("UTF-8 scope"));
        let outside = root.join("outside.txt");
        fs::write(&outside, SENTINEL).expect("independent outside sentinel");
        let policy_bytes = match policy {
            Policy::Narrow => json!({"app":{"fs":{"read":[scope],"write":[scope]}}})
                .to_string()
                .into_bytes(),
            Policy::Empty => b"{}".to_vec(),
            Policy::Absent => b"{}\n".to_vec(),
        };
        if !matches!(policy, Policy::Absent) {
            fs::write(project.join("keld.permissions.jsonc"), &policy_bytes)
                .expect("explicit project policy");
        }
        fs::write(project.join("keld.config.ts"), format!(
            "export default {{\n  name: {TITLE:?},\n  entry: \"src/main.ts\",\n  renderer: \"index.html\",\n}} as const;\n"
        )).expect("ordinary configured project");
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("repository root")
            .to_path_buf();
        let census = compile_native_window_census(&root);
        Self {
            _owned: owned,
            project,
            repo,
            allowed,
            policy_bytes,
            policy,
            outside,
            scope,
            census,
        }
    }

    pub(super) fn with_project_policy_source(bytes: &[u8]) -> Self {
        let mut fixture = Self::new(Policy::Narrow);
        fixture.policy_bytes = bytes.to_vec();
        fs::write(
            fixture.project.join("keld.permissions.jsonc"),
            &fixture.policy_bytes,
        )
        .expect("literal project policy input before stock staging");
        fixture
    }

    pub(super) fn owned_root(&self) -> &Path {
        self.project
            .parent()
            .expect("canonical owned project parent")
    }

    pub(super) fn prepare(&self, launch: usize, port: u16) -> PreparedLaunch {
        self.prepare_for(launch, port, Exercise::RendererPointer)
    }

    pub(super) fn prepare_component(&self, launch: usize, port: u16) -> PreparedLaunch {
        self.prepare_for(launch, port, Exercise::PublicAppComponent)
    }

    pub(super) fn prepare_natural(&self, launch: usize, port: u16) -> PreparedLaunch {
        self.prepare_for(launch, port, Exercise::PublicAppNaturalCases)
    }

    fn natural_inputs(&self, launch: usize) -> NaturalInputs {
        let read_sentinel = self.allowed.join(format!("read-sentinel-{launch}.bin"));
        fs::write(&read_sentinel, READ_SENTINEL).expect("independent read-only sentinel");
        let internal_target = self.allowed.join(format!("internal-target-{launch}.bin"));
        let internal_alias = self.allowed.join(format!("internal-alias-{launch}"));
        let external_alias = self.allowed.join(format!("external-alias-{launch}"));
        let oversized_write = self.allowed.join(format!("oversized-write-{launch}.bin"));
        let oversized_read = self.allowed.join(format!("oversized-read-{launch}.bin"));
        let fresh = self.allowed.join(format!("fresh-control-{launch}.bin"));
        let maximum_content = native_content_ceiling();
        let mut oversized_read_digest = String::new();
        if matches!(self.policy, Policy::Narrow) {
            fs::write(&internal_target, INTERNAL_INITIAL).expect("inside link target");
            symlink(
                internal_target.file_name().expect("inside relative leaf"),
                &internal_alias,
            )
            .expect("internal relative alias");
            // The alias spelling is in scope; its relative target escapes the
            // retained root, independently of the guard's literal path match.
            symlink("../outside.txt", &external_alias).expect("external relative alias");
            fs::write(&oversized_write, WRITE_SENTINEL).expect("oversized write sentinel");
            fs::write(&oversized_read, vec![0x79; maximum_content + 1])
                .expect("parent-owned oversized read fixture");
            oversized_read_digest = file_digest(&oversized_read);
        }
        NaturalInputs {
            read_sentinel,
            internal_target,
            internal_alias,
            external_alias,
            oversized_write,
            oversized_read,
            fresh,
            maximum_content,
            oversized_read_digest,
        }
    }

    fn prepare_for(&self, launch: usize, port: u16, exercise: Exercise) -> PreparedLaunch {
        let target = self.allowed.join(format!("result-{launch}.bin"));
        let natural =
            (exercise == Exercise::PublicAppNaturalCases).then(|| self.natural_inputs(launch));
        self.prepare_application_inputs(&target, port, exercise, natural.as_ref());
        let (stage, digest, host_digest) = self.stage_and_verify_inputs();
        PreparedLaunch {
            exercise,
            stage,
            target,
            digest,
            host_digest,
            natural,
        }
    }

    fn prepare_application_inputs(
        &self,
        target: &Path,
        port: u16,
        exercise: Exercise,
        natural: Option<&NaturalInputs>,
    ) {
        let natural_case = if natural.is_some() {
            if matches!(self.policy, Policy::Narrow) {
                json!("links-limits")
            } else {
                json!("deny-read")
            }
        } else {
            Value::Null
        };
        let natural_config = natural.map_or(Value::Null, |input| {
            json!({
                "readSentinel":input.read_sentinel,
                "internalAlias":input.internal_alias,
                "externalAlias":input.external_alias,
                "oversizedWrite":input.oversized_write,
                "oversizedRead":input.oversized_read,
                "fresh":input.fresh,
                "maximumContent":input.maximum_content,
            })
        });
        let api = serde_json::to_string(
            &self
                .repo
                .join("packages/@keld/api/src/index.ts")
                .to_string_lossy(),
        )
        .expect("public index path JSON");
        let body = include_str!("../../../fixtures/public_fs_app.ts")
            .replace("__NATURAL_CASE__", &natural_case.to_string())
            .replace("__NATURAL_INPUTS__", &natural_config.to_string())
            .replace(
                "__AUTOMATIC_COMPONENT__",
                if exercise == Exercise::PublicAppComponent {
                    "true"
                } else {
                    "false"
                },
            )
            .replace("__PORT__", &port.to_string())
            .replace(
                "__TARGET__",
                &serde_json::to_string(&target.to_string_lossy()).expect("target JSON"),
            )
            .replace(
                "__OUTSIDE__",
                &serde_json::to_string(&self.outside.to_string_lossy()).expect("outside JSON"),
            )
            .replace(
                "__CONTENT__",
                &serde_json::to_string(CONTENT).expect("content JSON"),
            );
        assert!(!body.contains("WorkerLink") && !body.contains("invokeFs"));
        bundle_public_api_entry(
            &self.project,
            &self.repo,
            "kel140-public-fs",
            &format!(
                "import {{ app, channels, echoChannel, fs, isCallError }} from {api};\n{body}"
            ),
        );
        fs::write(
            self.project.join("index.html"),
            include_str!("../../../fixtures/public_fs_page.html")
                .replace("__PORT__", &port.to_string()),
        )
        .expect("public FS renderer");
    }

    fn stage_and_verify_inputs(&self) -> (keld_cli::boot::DevBootStage, String, String) {
        let stage = keld_cli::boot::stage_dev_boot(
            &self.project,
            Path::new(env!("CARGO_BIN_EXE_keld-host")),
        )
        .expect("stock CLI stages explicit project inputs");
        assert_eq!(
            fs::read(stage.root().join("keld.permissions.jsonc")).expect("staged bytes"),
            self.policy_bytes
        );
        let boot: Value = serde_json::from_slice(
            &fs::read(stage.root().join("keld.boot.json")).expect("boot bytes"),
        )
        .expect("boot descriptor");
        eprintln!("KELD_KEL140_STAGED_BOOT {boot}");
        assert_eq!(
            boot["name"], TITLE,
            "stock producer selected the configured window name"
        );
        assert_eq!(
            boot["entry"], "src/main.ts",
            "stock producer selected the public app entry"
        );
        assert_eq!(
            boot["renderer"], "index.html",
            "stock producer selected the fixture document"
        );
        let digest = file_digest(&stage.root().join("keld.permissions.jsonc"));
        assert_eq!(
            boot["permissions"]["content_sha256"],
            format!("sha256:{digest}")
        );
        let host_digest = file_digest(stage.host());
        assert_eq!(
            host_digest,
            file_digest(Path::new(env!("CARGO_BIN_EXE_keld-host")))
        );
        (stage, digest, host_digest)
    }
}

pub(super) fn file_digest(path: &Path) -> String {
    let digest = Command::new("/usr/bin/shasum")
        .args(["-a", "256"])
        .arg(path)
        .output()
        .expect("independent staged byte digest");
    assert!(digest.status.success(), "{digest:?}");
    String::from_utf8(digest.stdout)
        .expect("hash UTF-8")
        .split_whitespace()
        .next()
        .expect("SHA256 field")
        .to_owned()
}

fn native_content_ceiling() -> usize {
    // Fixture input comes from the exact native owner, not a mirrored limit.
    // Admit only its current numeric-product form and fail on any schema edit.
    let source = include_str!("../../../../../keld-native/src/fs.rs");
    let declaration = source
        .lines()
        .find_map(|line| line.strip_prefix("pub const MAX_FS_CONTENT_BYTES: usize = "))
        .expect("owning native content ceiling declaration")
        .strip_suffix(';')
        .expect("owning native content ceiling terminator");
    declaration.split(" * ").fold(1_usize, |product, factor| {
        product
            .checked_mul(factor.parse::<usize>().expect("literal native size factor"))
            .expect("native fixture ceiling fits usize")
    })
}
