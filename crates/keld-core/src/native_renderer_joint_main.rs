//! Opt-in process-main acceptance executable; production owns every actual facility.
#[cfg(all(keld_core_native_renderer_main, target_os = "macos", debug_assertions))]
pub mod app_session;

#[cfg(all(keld_core_native_renderer_main, target_os = "macos", debug_assertions))]
mod macos_profile_identity;

// The owning source's Linux-only documentation points to this existing public primitive.
#[cfg(all(keld_core_native_renderer_main, target_os = "macos", debug_assertions))]
pub use keld_core::prepare_webview_process;

const NATIVE_RENDERER_CASE: &str = "actual_renderer_native_held_same_document_recovers_g2";

fn main() -> std::process::ExitCode {
    #[cfg(all(keld_core_native_renderer_main, target_os = "macos", debug_assertions))]
    {
        app_session::native_renderer_main_thread_entry();
        std::process::ExitCode::SUCCESS
    }
    #[cfg(not(all(keld_core_native_renderer_main, target_os = "macos", debug_assertions)))]
    {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.is_empty() {
            println!(
                "{NATIVE_RENDERER_CASE} ... ignored, explicit physical joint lane\ntest result: ok. 0 passed; 0 failed; 1 ignored;"
            );
            return std::process::ExitCode::SUCCESS;
        }
        if args == ["--list"] {
            println!("{NATIVE_RENDERER_CASE}: test\n\n1 test, 0 benchmarks");
            return std::process::ExitCode::SUCCESS;
        }
        eprintln!(
            "KELD-TEST-MAIN: missing checked macOS debug acceptance-target identity. Build the exact opt-in test with --cfg keld_core_native_renderer_main and its registered check-cfg; ordinary Cargo/libtest is not the main-thread runner."
        );
        std::process::ExitCode::FAILURE
    }
}
