# keld-native invariants

Owner/load: native/always. Trigger: crates/keld-native. Extends root AGENTS.md.

- KEL-89 production unsafe is limited to `src/auth/macos_http.rs`: typed
  `AuthHttpDelegate` NSObject class/ABI and NSObjectProtocol/
  NSURLSession{,Task,Data}Delegate conformances; NSObject super-init;
  `sessionWithConfiguration_delegate_delegateQueue`. No manual Send/Sync,
  unchecked pointer adoption/casts, trust overrides or other production unsafe.
- Test-only unsafe: `tests/support/windows_handle_census.rs` MAY call
  GetCurrentProcess/GetProcessHandleCount with the current-process pseudo
  handle and local count; never close that handle.
- `src/fs.rs` cfg(test) MAY call WaitForSingleObject only on a retained Child.
  Keep the bounded wait. Retire these allowances if the probes move.
