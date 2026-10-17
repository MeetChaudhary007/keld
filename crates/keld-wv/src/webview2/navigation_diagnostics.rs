//! Bounded, monotonic observations of first `WebView2` navigation (GH-814).
//! No URLs, profile paths, origins, or renderer content enter diagnostics.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use windows::core::Result as ComResult;

pub(super) struct FirstNavigationDiagnostic {
    created: Instant,
    issued: Option<Instant>,
    loop_entered: Option<Instant>,
    phase: &'static str,
    phase_at: Instant,
    detail: Option<String>,
}

impl FirstNavigationDiagnostic {
    pub(super) fn new() -> Self {
        let now = Instant::now();
        Self {
            created: now,
            issued: None,
            loop_entered: None,
            phase: "window-creation",
            phase_at: now,
            detail: None,
        }
    }

    pub(super) fn issued(&mut self) {
        self.issued = Some(Instant::now());
        self.record("navigation-issued");
    }

    pub(super) fn entered_loop(&mut self) {
        self.loop_entered = Some(Instant::now());
        self.record("message-loop-entered");
    }

    pub(super) fn deadline_elapsed(&mut self) {
        self.record("navigation-deadline-elapsed");
    }

    fn record(&mut self, phase: &'static str) {
        self.phase = phase;
        self.phase_at = Instant::now();
    }

    /// Returns true only for the first successful navigation notification.
    /// Any COM failure is a typed startup failure, never an absent callback.
    pub(super) fn completed(
        &mut self,
        result: ComResult<bool>,
        web_error: Option<String>,
        ready: &AtomicBool,
        failed: &AtomicBool,
    ) -> bool {
        match result {
            Ok(true) => {
                self.record("navigation-completed");
                !ready.swap(true, Ordering::AcqRel)
            }
            Ok(false) => {
                self.record("navigation-failed");
                self.detail = web_error.map(|status| format!("web_error={status}"));
                if !ready.load(Ordering::Acquire) {
                    failed.store(true, Ordering::Release);
                }
                false
            }
            Err(error) => {
                self.record("navigation-completed-com-error");
                self.detail = Some(format!("is_success_hresult={:#010x}", error.code().0));
                if !ready.load(Ordering::Acquire) {
                    failed.store(true, Ordering::Release);
                }
                false
            }
        }
    }

    pub(super) fn snapshot(&self) -> String {
        let now = Instant::now();
        let since_created = now.saturating_duration_since(self.created).as_millis();
        let issued_ms = self
            .issued
            .map(|at| at.saturating_duration_since(self.created).as_millis());
        let loop_ms = self
            .loop_entered
            .map(|at| at.saturating_duration_since(self.created).as_millis());
        let phase_ms = self
            .phase_at
            .saturating_duration_since(self.created)
            .as_millis();
        let detail = self.detail.as_deref().unwrap_or("none");
        format!(
            "first-navigation phase={} phase_at_ms={} total_ms={} issued_at_ms={:?} loop_at_ms={:?} detail={}",
            self.phase, phase_ms, since_created, issued_ms, loop_ms, detail
        )
    }
}

#[cfg(test)]
mod tests {
    use super::FirstNavigationDiagnostic;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn failed_is_success_com_hresult_is_immediately_fatal_and_recorded() {
        let mut diag = FirstNavigationDiagnostic::new();
        diag.issued();
        let ready = AtomicBool::new(false);
        let failed = AtomicBool::new(false);
        let com_error = windows::core::Error::from(windows::Win32::Foundation::E_POINTER);
        assert!(!diag.completed(Err(com_error), None, &ready, &failed));
        assert!(failed.load(Ordering::Acquire));
        assert!(!ready.load(Ordering::Acquire));
        let evidence = diag.snapshot();
        assert!(evidence.contains("navigation-completed-com-error"));
        assert!(
            evidence.contains("is_success_hresult=0x80004003"),
            "{evidence}"
        );
        assert!(!evidence.contains("http://"));
    }

    #[test]
    fn navigation_failure_retains_web_error_and_success_only_signals_once() {
        let ready = AtomicBool::new(false);
        let failed = AtomicBool::new(false);
        let mut diag = FirstNavigationDiagnostic::new();
        assert!(!diag.completed(
            Ok(false),
            Some("CONNECTION_ABORTED".to_owned()),
            &ready,
            &failed
        ));
        assert!(failed.load(Ordering::Acquire));
        assert!(diag.snapshot().contains("web_error=CONNECTION_ABORTED"));

        let ready = AtomicBool::new(false);
        let failed = AtomicBool::new(false);
        let mut diag = FirstNavigationDiagnostic::new();
        assert!(diag.completed(Ok(true), None, &ready, &failed));
        assert!(!diag.completed(Ok(true), None, &ready, &failed));
        assert!(ready.load(Ordering::Acquire));
        assert!(!failed.load(Ordering::Acquire));
        let com_error = windows::core::Error::from(windows::Win32::Foundation::E_POINTER);
        assert!(!diag.completed(Err(com_error), None, &ready, &failed));
        assert!(
            !failed.load(Ordering::Acquire),
            "late navigation cannot fail startup"
        );
    }
}
