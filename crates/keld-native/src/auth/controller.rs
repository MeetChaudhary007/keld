//! Guarded, owner-thread macOS Native auth controller for approved KEL-89/T3.
//! Core owns callers/generations/correlations/leases; this owns real native jobs.
use super::browser::{BrowserDeadlines, BrowserLaunch, BrowserProgress};
use super::errors::AuthError;
use super::loopback::{LoopbackFlow, LoopbackProgress};
use super::macos_http::{HttpDeadlines, HttpError, HttpOperation, HttpProgress, HttpResponse};
use super::primitives::{
    CorrelatedAuthorization, PendingAuthorization, PrimitiveError, RedirectPlan,
    refresh_token_form, validate_login_hint,
};
use super::registry::{
    Completion, ExchangeFailure, FlightId, SessionRegistry, SharedOutcome, StartState, StateFault,
    TokenPlan,
};
use super::token_reply::{ExchangeMode, decode_token_reply};
use super::{
    AuthConfiguration, AuthRequest, AuthResponse, BEGIN_HOST_TIMEOUT, BROWSER_LAUNCH_TIMEOUT,
    OWNER_CLEANUP_TIMEOUT, ProviderProfile, TOKEN_REQUEST_TIMEOUT, TokenDenial, provider_profile,
};
use keld_guard::verified_manifest::VerifiedManifest;
use keld_guard::{PermissionsManifest, Principal, capability};
use keld_ipc::{CallError, guard_dispatch::dispatch_privileged};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

const UNRESOLVED_RESOURCE: &str = "\0unresolved";

/// Opaque identity for one guard-admitted native physical operation.
/// No public constructor, serialization, principal or generation is provided.
/// Clones name the same operation; ids from another broker never match.
#[derive(Clone)]
pub struct OperationId {
    owner: Arc<()>,
    serial: u64,
}
impl PartialEq for OperationId {
    fn eq(&self, other: &Self) -> bool {
        self.serial == other.serial && Arc::ptr_eq(&self.owner, &other.owner)
    }
}
impl Eq for OperationId {}
impl Hash for OperationId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::ptr::hash(Arc::as_ptr(&self.owner), state);
        self.serial.hash(state);
    }
}
impl fmt::Debug for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperationId").finish_non_exhaustive()
    }
}

#[derive(Clone)]
enum ReadyKind {
    Begin(AuthResponse),
    Token(SharedOutcome),
    Error(Arc<CallError>),
}
/// Owned logical result. Core checks final caller liveness before consuming it.
/// Token conversion rechecks monotonic freshness at that final boundary.
#[derive(Clone)]
pub struct ReadyResponse {
    inner: ReadyKind,
}
impl ReadyResponse {
    /// Constructs the final DTO immediately after Core's final caller check.
    ///
    /// # Errors
    /// Returns the canonical typed error, or redacted local AUTH016 if a token
    /// expired during publication/scheduling. No account eviction/retry occurs.
    pub fn into_response(self) -> Result<AuthResponse, Arc<CallError>> {
        match self.inner {
            ReadyKind::Begin(response) => Ok(response),
            ReadyKind::Error(error) => Err(error),
            ReadyKind::Token(result) => match result.as_ref() {
                Ok(token) => token.response().map_err(|e| AuthError::State(e).wire()),
                Err(error) => Err(Arc::clone(error)),
            },
        }
    }
    fn error(error: &AuthError) -> Self {
        Self {
            inner: ReadyKind::Error(error.wire()),
        }
    }
    fn wire_error(error: Arc<CallError>) -> Self {
        Self {
            inner: ReadyKind::Error(error),
        }
    }
    fn token(result: SharedOutcome) -> Self {
        Self {
            inner: ReadyKind::Token(result),
        }
    }
}
impl fmt::Debug for ReadyResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadyResponse").finish_non_exhaustive()
    }
}

/// Resource-free host invariant/physical-cleanup signal, never a wire auth code.
/// Core closes admission and uses its existing typed fatal host-error owner.
#[derive(Clone, PartialEq, Eq)]
pub enum HostFault {
    /// Presented verified snapshot differs from the prepared immutable one.
    SnapshotMismatch,
    /// Supplied opaque operation belongs to another broker; no drain receipt.
    OwnerMismatch,
    /// An absolute owner clock cannot represent the fixed approved duration.
    ClockOverflow,
    /// A v0 token decision returned a code outside the two approved constants.
    UnexpectedTokenDenial,
    /// Guard Allowed the reserved unresolved resource; emit synthetic002 too.
    UnresolvedAfterAllow,
    /// Single-flight metadata has no corresponding actual admitted native job.
    MissingTokenOwner,
    /// Actual browser-helper reaping is not proved; retain and poll its owner.
    BrowserCleanupUnproven(Arc<CallError>),
    /// Actual HTTP callback/delegate quiescence is not proved; retain its owner.
    HttpCleanupUnproven(Arc<CallError>),
}
impl fmt::Debug for HostFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::SnapshotMismatch => "SnapshotMismatch",
            Self::OwnerMismatch => "OwnerMismatch",
            Self::ClockOverflow => "ClockOverflow",
            Self::UnexpectedTokenDenial => "UnexpectedTokenDenial",
            Self::UnresolvedAfterAllow => "UnresolvedAfterAllow",
            Self::MissingTokenOwner => "MissingTokenOwner",
            Self::BrowserCleanupUnproven(_) => "BrowserCleanupUnproven",
            Self::HttpCleanupUnproven(_) => "HttpCleanupUnproven",
        };
        f.debug_struct(name).finish_non_exhaustive()
    }
}
/// One request's logical admission/result; capacity belongs to the caller.
pub enum HandleState<A> {
    /// No physical operation remains; publish after Core's final caller check.
    Ready(ReadyResponse),
    /// Existing admitted operation; only a new leader returns Some(lease).
    Pending {
        /// Opaque native operation associated with existing Core correlations.
        operation: OperationId,
        /// Existing Core/executor lease; retain until `Progress::Drained`.
        admission: Option<A>,
    },
    /// Existing nonblocking capacity reservation returned no lease.
    AtCapacity,
    /// No reply is fabricated for an internal invariant; Core fails closed.
    HostFault(HostFault),
    /// Required synthetic denial plus a separate host-only invariant report.
    DeniedInvariant {
        /// Same constant002 response as actual granted-level denial.
        response: ReadyResponse,
        /// Resource-free diagnostic; never encoded into the peer response.
        fault: HostFault,
    },
}
impl<A> fmt::Debug for HandleState<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Ready(_) => "Ready",
            Self::Pending { .. } => "Pending",
            Self::AtCapacity => "AtCapacity",
            Self::HostFault(_) => "HostFault",
            Self::DeniedInvariant { .. } => "DeniedInvariant",
        };
        f.debug_struct(name).finish_non_exhaustive()
    }
}
/// Logical response event; Core owns fan-out and one terminal reply per caller.
pub struct ResponseEvent {
    /// Operation whose existing Core followers receive this immutable result.
    pub operation: OperationId,
    /// Final DTO/error constructor; token freshness is checked when consumed.
    pub response: ReadyResponse,
}
impl fmt::Debug for ResponseEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseEvent").finish_non_exhaustive()
    }
}
/// Physical progress is separate from logical response readiness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Progress {
    /// Keep the existing operation and real admission lease; service other work.
    Pending,
    /// Actual owner is complete/quiescent; Core may now release its lease.
    Drained,
    /// Cleanup/invariant is unproved; retain the job/lease through fatal cleanup.
    HostFault(HostFault),
}

struct Prompt {
    flow: LoopbackFlow,
    browser: BrowserLaunch,
    callback: Option<Result<CorrelatedAuthorization, Arc<CallError>>>,
    browser_done: bool,
}
enum BeginPhase {
    Prompt(Box<Prompt>),
    Http(HttpOperation),
}
struct BeginJob {
    profile: &'static ProviderProfile,
    client_id: String,
    scopes: Option<Vec<String>>,
    end: Instant,
    cancelled: Arc<AtomicBool>,
    phase: BeginPhase,
    forced: Option<Arc<CallError>>,
    logical_done: bool,
}
struct TokenJob {
    flight: FlightId,
    client_id: String,
    end: Instant,
    cancelled: Arc<AtomicBool>,
    http: Option<HttpOperation>,
    forced: Option<Arc<CallError>>,
    logical_done: bool,
}
enum Job {
    Begin(BeginJob),
    Token(TokenJob),
}

/// One host-session broker, constructed and used inside Core's native worker.
///
/// Uses the existing guard dispatcher and bounded Core admission callback.
/// Owns no thread/queue/correlation/generation/lease or arbitrary provider.
/// Preserve this same broker across Bun generations and filesystem retirement.
/// Real SDK handles remain on this owner; do not move an active broker between
/// threads or drop it in place of the qualified stop/poll/drain protocol.
pub struct AuthBroker {
    prepared_digest: [u8; 32],
    configuration: AuthConfiguration,
    registry: SessionRegistry,
    owner: Arc<()>,
    next_operation: u64,
    // Active ownership table, not FIFO/cleanup queue; one slot per Core lease.
    jobs: Vec<(u64, Option<Job>)>,
    #[cfg(test)]
    test_token_endpoint: Option<String>,
}
impl fmt::Debug for AuthBroker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthBroker").finish_non_exhaustive()
    }
}
impl AuthBroker {
    /// Prepares resource-free mutable state from verified boot inputs.
    /// Unknown configuration keys must already have been filtered/warned once
    /// by Native's existing boot-load owner. No browser/socket/HTTP/RNG starts.
    #[must_use]
    pub fn prepare(verified: &VerifiedManifest, configuration: AuthConfiguration) -> Self {
        Self {
            prepared_digest: verified.verified_sha256(),
            configuration,
            registry: SessionRegistry::new(),
            owner: Arc::new(()),
            next_operation: 0,
            jobs: Vec::new(),
            #[cfg(test)]
            test_token_endpoint: None,
        }
    }
    /// Handles one Core-admitted decoded auth request with exactly one guard
    /// decision. Only unknown Begin provider002 refuses before that decision.
    /// `admit` is the existing nonblocking real physical-operation lease owner;
    /// it must not perform I/O/reenter this worker or duplicate a capacity rule.
    pub fn handle_request<A>(
        &mut self,
        verified: &VerifiedManifest,
        principal: Principal,
        request: AuthRequest,
        admit: impl FnOnce() -> Option<A>,
    ) -> HandleState<A> {
        if self.prepared_digest != verified.verified_sha256() {
            return HandleState::HostFault(HostFault::SnapshotMismatch);
        }
        self.handle_manifest_request(verified.manifest(), principal, request, admit)
    }
    fn handle_manifest_request<A>(
        &mut self,
        manifest: &PermissionsManifest,
        principal: Principal,
        request: AuthRequest,
        admit: impl FnOnce() -> Option<A>,
    ) -> HandleState<A> {
        match request {
            AuthRequest::Begin {
                provider,
                scopes,
                login_hint,
            } => {
                let Some(profile) = provider_profile(&provider) else {
                    return HandleState::Ready(ReadyResponse::error(&AuthError::unknown_provider(
                        &provider,
                    )));
                };
                match dispatch_privileged(
                    manifest,
                    principal,
                    capability::AUTH_BEGIN,
                    profile.issuer,
                    |_| {
                        self.begin_allowed(
                            profile,
                            scopes,
                            login_hint.as_deref(),
                            Instant::now(),
                            admit,
                        )
                    },
                ) {
                    Ok(result) => result,
                    Err(reason) => HandleState::Ready(ReadyResponse::wire_error(Arc::new(
                        CallError::from(&reason),
                    ))),
                }
            }
            AuthRequest::Token { account_id, scopes } => {
                let issuer = self.registry.issuer_for(&account_id);
                let resource = issuer.unwrap_or(UNRESOLVED_RESOURCE);
                match dispatch_privileged(
                    manifest,
                    principal,
                    capability::AUTH_TOKEN,
                    resource,
                    |_| {
                        if issuer.is_none() {
                            return unresolved_after_allow();
                        }
                        self.token_allowed(&account_id, scopes, Instant::now(), admit)
                    },
                ) {
                    Ok(result) => result,
                    Err(reason) => match TokenDenial::from_guard(&reason) {
                        Some(denial) => HandleState::Ready(ReadyResponse::wire_error(Arc::new(
                            CallError::from(denial),
                        ))),
                        None => HandleState::HostFault(HostFault::UnexpectedTokenDenial),
                    },
                }
            }
        }
    }
    fn client_id(&self, profile: &'static ProviderProfile) -> Result<String, AuthError> {
        self.configuration
            .get(profile.key)
            .and_then(|value| value.client_id.as_ref())
            .filter(|value| !value.is_empty())
            .cloned()
            .ok_or(AuthError::MissingClient(profile))
    }
    fn next_id(&mut self) -> Result<OperationId, StateFault> {
        self.next_operation = self
            .next_operation
            .checked_add(1)
            .ok_or(StateFault::CounterExhausted)?;
        Ok(OperationId {
            owner: Arc::clone(&self.owner),
            serial: self.next_operation,
        })
    }
    fn begin_allowed<A>(
        &mut self,
        profile: &'static ProviderProfile,
        scopes: Option<Vec<String>>,
        hint: Option<&str>,
        admitted_at: Instant,
        admit: impl FnOnce() -> Option<A>,
    ) -> HandleState<A> {
        if !self.registry.admission_open() {
            return HandleState::Ready(ReadyResponse::error(&AuthError::State(
                StateFault::Stopping,
            )));
        }
        let client_id = match self.client_id(profile) {
            Ok(value) => value,
            Err(e) => return HandleState::Ready(ReadyResponse::error(&e)),
        };
        if let Err(e) = validate_login_hint(hint) {
            return HandleState::Ready(ReadyResponse::error(&AuthError::Primitive(e)));
        }
        let fixed = self
            .configuration
            .get(profile.key)
            .and_then(|value| value.fixed_redirect.as_deref());
        let plan = match RedirectPlan::new(profile, fixed) {
            Ok(value) => value,
            Err(e) => return HandleState::Ready(ReadyResponse::error(&AuthError::Primitive(e))),
        };
        let Some(end) = admitted_at.checked_add(BEGIN_HOST_TIMEOUT) else {
            return HandleState::HostFault(HostFault::ClockOverflow);
        };
        let Some(admission) = admit() else {
            return HandleState::AtCapacity;
        };
        let id = match self.next_id() {
            Ok(id) => id,
            Err(e) => return HandleState::Ready(ReadyResponse::error(&AuthError::State(e))),
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let pending = match PendingAuthorization::generate() {
            Ok(value) => value,
            Err(e) => return HandleState::Ready(ReadyResponse::error(&AuthError::Primitive(e))),
        };
        let flow = match LoopbackFlow::bind(plan, pending, end, Arc::clone(&cancelled)) {
            Ok(value) => value,
            Err(e) => return HandleState::Ready(ReadyResponse::error(&AuthError::Loopback(e))),
        };
        let url = match flow.authorization_url(profile, &client_id, scopes.as_deref(), hint) {
            Ok(value) => value,
            Err(e) => return HandleState::Ready(ReadyResponse::error(&AuthError::Loopback(e))),
        };
        let Some(launch) = Instant::now()
            .checked_add(BROWSER_LAUNCH_TIMEOUT)
            .map(|bound| bound.min(end))
        else {
            return HandleState::HostFault(HostFault::ClockOverflow);
        };
        let Some(cleanup) = launch.checked_add(OWNER_CLEANUP_TIMEOUT) else {
            return HandleState::HostFault(HostFault::ClockOverflow);
        };
        let browser = match BrowserLaunch::start(
            &url,
            BrowserDeadlines { launch, cleanup },
            Arc::clone(&cancelled),
        ) {
            Ok(value) => value,
            Err(e) => return HandleState::Ready(ReadyResponse::error(&AuthError::Browser(e))),
        };
        self.jobs.push((
            id.serial,
            Some(Job::Begin(BeginJob {
                profile,
                client_id,
                scopes,
                end,
                cancelled,
                phase: BeginPhase::Prompt(Box::new(Prompt {
                    flow,
                    browser,
                    callback: None,
                    browser_done: false,
                })),
                forced: None,
                logical_done: false,
            })),
        ));
        HandleState::Pending {
            operation: id,
            admission: Some(admission),
        }
    }
    fn token_allowed<A>(
        &mut self,
        account_id: &str,
        scopes: Option<Vec<String>>,
        admitted_at: Instant,
        admit: impl FnOnce() -> Option<A>,
    ) -> HandleState<A> {
        let plan = match self.registry.token_request(account_id, scopes, admit) {
            Ok(plan) => plan,
            Err(e) => return HandleState::Ready(ReadyResponse::error(&AuthError::State(e))),
        };
        match plan {
            TokenPlan::Unresolved => unresolved_after_allow(),
            TokenPlan::AtCapacity => HandleState::AtCapacity,
            TokenPlan::Ready(result) => HandleState::Ready(ReadyResponse::token(result)),
            TokenPlan::InFlight(flight) => {
                match self.jobs.iter().find_map(|(serial, job)| {
                    matches!(job, Some(Job::Token(token)) if token.flight == flight)
                        .then_some(*serial)
                }) {
                    Some(serial) => HandleState::Pending {
                        operation: OperationId {
                            owner: Arc::clone(&self.owner),
                            serial,
                        },
                        admission: None,
                    },
                    None => HandleState::HostFault(HostFault::MissingTokenOwner),
                }
            }
            TokenPlan::Leader { flight, admission } => {
                let id = match self.next_id() {
                    Ok(id) => id,
                    Err(e) => {
                        self.registry
                            .abandon(&flight, (*AuthError::State(e).wire()).clone());
                        return HandleState::Ready(ReadyResponse::error(&AuthError::State(e)));
                    }
                };
                let Some(end) = admitted_at.checked_add(TOKEN_REQUEST_TIMEOUT) else {
                    self.registry.abandon(
                        &flight,
                        (*AuthError::State(StateFault::ExpiryOverflow).wire()).clone(),
                    );
                    return HandleState::HostFault(HostFault::ClockOverflow);
                };
                // Same closed profile was bound at Begin; no returned iss rebind.
                let Some(profile) = self.registry.profile_for(account_id) else {
                    self.registry.abandon(
                        &flight,
                        (*AuthError::State(StateFault::UnknownProfile).wire()).clone(),
                    );
                    return HandleState::HostFault(HostFault::MissingTokenOwner);
                };
                let client_id = match self.client_id(profile) {
                    Ok(id) => id,
                    Err(e) => {
                        self.registry.abandon(&flight, (*e.wire()).clone());
                        return HandleState::Ready(ReadyResponse::error(&e));
                    }
                };
                self.jobs.push((
                    id.serial,
                    Some(Job::Token(TokenJob {
                        flight,
                        client_id,
                        end,
                        cancelled: Arc::new(AtomicBool::new(false)),
                        http: None,
                        forced: None,
                        logical_done: false,
                    })),
                ));
                HandleState::Pending {
                    operation: id,
                    admission: Some(admission),
                }
            }
        }
    }
    /// Cancels the PHYSICAL producer using the existing Core-owned terminal
    /// error. A local follower timeout merely detaches in Core, never calls this.
    /// Keep the operation/lease until poll reports Drained; no dialog007 inferred.
    pub fn cancel(&mut self, id: &OperationId, terminal: CallError) -> bool {
        if !Arc::ptr_eq(&self.owner, &id.owner) {
            return false;
        }
        let Some((_, Some(job))) = self
            .jobs
            .iter_mut()
            .find(|(serial, _)| *serial == id.serial)
        else {
            return false;
        };
        let error = Arc::new(terminal);
        match job {
            Job::Begin(job) => {
                if job.forced.is_none() {
                    job.forced = Some(error);
                }
                job.cancelled.store(true, Ordering::Release);
                match &mut job.phase {
                    BeginPhase::Prompt(prompt) => {
                        prompt.flow.cancel();
                        prompt.browser.cancel();
                    }
                    BeginPhase::Http(http) => http.cancel(),
                }
            }
            Job::Token(job) => {
                if job.forced.is_none() {
                    job.forced = Some(error);
                }
                job.cancelled.store(true, Ordering::Release);
                if let Some(http) = &mut job.http {
                    http.cancel();
                }
            }
        }
        true
    }
    /// Advances one admitted real operation without blocking waits. emit must
    /// perform existing nonblocking Core result bookkeeping, never wire I/O.
    /// `HostFault` retains this job; only `Drained` authorizes releasing its lease.
    pub fn poll(&mut self, id: &OperationId, mut emit: impl FnMut(ResponseEvent)) -> Progress {
        if !Arc::ptr_eq(&self.owner, &id.owner) {
            return Progress::HostFault(HostFault::OwnerMismatch);
        }
        let Some(index) = self
            .jobs
            .iter()
            .position(|(serial, _)| *serial == id.serial)
        else {
            return Progress::Drained;
        };
        let Some(mut job) = self.jobs[index].1.take() else {
            return Progress::HostFault(HostFault::MissingTokenOwner);
        };
        let progress = match &mut job {
            Job::Begin(job) => self.poll_begin(id, job, &mut emit),
            Job::Token(job) => self.poll_token(id, job, &mut emit),
        };
        if progress == Progress::Drained {
            self.jobs.swap_remove(index);
        } else {
            self.jobs[index].1 = Some(job);
            // Native admission closes on any unproved owner invariant, before
            // returning to Core. Core still owns fatal lifecycle and must call
            // stop_for_host_tail then retain/poll owners through actual drain.
            if matches!(progress, Progress::HostFault(_)) {
                self.registry.close_admission();
            }
        }
        progress
    }
    fn poll_begin(
        &mut self,
        id: &OperationId,
        job: &mut BeginJob,
        emit: &mut impl FnMut(ResponseEvent),
    ) -> Progress {
        match &mut job.phase {
            BeginPhase::Prompt(prompt) => {
                match Self::poll_prompt(prompt) {
                    Ok(true) => {}
                    Ok(false) => return Progress::Pending,
                    Err(fault) => return Progress::HostFault(fault),
                }
                if let Some(error) = job.forced.as_ref() {
                    if !job.logical_done {
                        emit(ResponseEvent {
                            operation: id.clone(),
                            response: ReadyResponse::wire_error(Arc::clone(error)),
                        });
                        job.logical_done = true;
                    }
                    return Progress::Drained;
                }
                let Some(callback) = prompt.callback.take() else {
                    return Progress::Pending;
                };
                let correlated = match callback {
                    Ok(value) => value,
                    Err(error) => {
                        emit(ResponseEvent {
                            operation: id.clone(),
                            response: ReadyResponse::wire_error(error),
                        });
                        job.logical_done = true;
                        return Progress::Drained;
                    }
                };
                let body = match correlated.token_form(&job.client_id, prompt.flow.redirect()) {
                    Ok(form) => form.as_str().as_bytes().to_vec(),
                    Err(error) => {
                        emit(ResponseEvent {
                            operation: id.clone(),
                            response: ReadyResponse::error(&AuthError::Primitive(error)),
                        });
                        job.logical_done = true;
                        return Progress::Drained;
                    }
                };
                let deadlines = match http_deadlines(job.end) {
                    Ok(value) => value,
                    Err(fault) => return Progress::HostFault(fault),
                };
                match HttpOperation::start(
                    job.profile.key,
                    body,
                    deadlines,
                    Arc::clone(&job.cancelled),
                ) {
                    Ok(http) => {
                        job.phase = BeginPhase::Http(http);
                        Progress::Pending
                    }
                    Err(error) => {
                        emit(ResponseEvent {
                            operation: id.clone(),
                            response: ReadyResponse::error(&AuthError::Http(error)),
                        });
                        job.logical_done = true;
                        Progress::Drained
                    }
                }
            }
            BeginPhase::Http(http) => match http.poll() {
                HttpProgress::Pending => Progress::Pending,
                HttpProgress::CleanupUnproven(error) => Progress::HostFault(
                    HostFault::HttpCleanupUnproven(AuthError::Http(error).wire()),
                ),
                HttpProgress::Complete(result) => self.finish_begin_http(id, job, result, emit),
            },
        }
    }
    fn poll_prompt(prompt: &mut Prompt) -> Result<bool, HostFault> {
        if prompt.callback.is_none() {
            match prompt.flow.poll() {
                LoopbackProgress::Pending => {}
                LoopbackProgress::Complete(result) => {
                    prompt.callback = Some(result.map_err(|e| AuthError::Loopback(e).wire()));
                    if prompt.callback.as_ref().is_some_and(Result::is_err) {
                        prompt.browser.cancel();
                    }
                }
            }
        }
        if !prompt.browser_done {
            match prompt.browser.poll() {
                BrowserProgress::Pending => {}
                BrowserProgress::CleanupUnproven(error) => {
                    return Err(HostFault::BrowserCleanupUnproven(
                        AuthError::Browser(error).wire(),
                    ));
                }
                BrowserProgress::Complete(result) => {
                    prompt.browser_done = true;
                    if let Err(error) = result {
                        // Preserve a correlated callback error as primary.
                        if !prompt.callback.as_ref().is_some_and(Result::is_err) {
                            prompt.callback = Some(Err(AuthError::Browser(error).wire()));
                        }
                        prompt.flow.cancel();
                    }
                }
            }
        }
        Ok(prompt.browser_done)
    }
    fn finish_begin_http(
        &mut self,
        id: &OperationId,
        job: &mut BeginJob,
        result: Result<HttpResponse, HttpError>,
        emit: &mut impl FnMut(ResponseEvent),
    ) -> Progress {
        if job.logical_done {
            return Progress::Drained;
        }
        let response = if let Some(error) = job.forced.as_ref() {
            ReadyResponse::wire_error(Arc::clone(error))
        } else {
            match result {
                Err(error) => ReadyResponse::error(&AuthError::Http(error)),
                Ok(receipt) => match decode_token_reply(
                    receipt.status(),
                    receipt.body(),
                    receipt.received_at(),
                    receipt.receipt_mono(),
                    job.scopes.as_deref(),
                    ExchangeMode::AuthorizationCode,
                ) {
                    Err(error) => ReadyResponse::error(&AuthError::TokenReply(error)),
                    Ok(token) => {
                        let mut entropy = [0_u8; 32];
                        match getrandom::fill(&mut entropy) {
                            Err(_) => {
                                ReadyResponse::error(&AuthError::Primitive(PrimitiveError::Entropy))
                            }
                            Ok(()) => match self.registry.register_completed_begin(
                                job.profile.key,
                                entropy,
                                token.refresh,
                                job.scopes.as_deref(),
                                Some(token.access),
                                token.granted_scopes,
                            ) {
                                Ok(response) => ReadyResponse {
                                    inner: ReadyKind::Begin(response),
                                },
                                Err(error) => ReadyResponse::error(&AuthError::State(error)),
                            },
                        }
                    }
                },
            }
        };
        emit(ResponseEvent {
            operation: id.clone(),
            response,
        });
        job.logical_done = true;
        Progress::Drained
    }
    fn poll_token(
        &mut self,
        id: &OperationId,
        job: &mut TokenJob,
        emit: &mut impl FnMut(ResponseEvent),
    ) -> Progress {
        if job.http.is_none() {
            return self.start_token(id, job, emit);
        }
        let Some(http) = &mut job.http else {
            return Progress::HostFault(HostFault::MissingTokenOwner);
        };
        match http.poll() {
            HttpProgress::Pending => Progress::Pending,
            HttpProgress::CleanupUnproven(error) => Progress::HostFault(
                HostFault::HttpCleanupUnproven(AuthError::Http(error).wire()),
            ),
            HttpProgress::Complete(result) => self.finish_token_http(id, job, result, emit),
        }
    }
    fn start_token(
        &mut self,
        id: &OperationId,
        job: &mut TokenJob,
        emit: &mut impl FnMut(ResponseEvent),
    ) -> Progress {
        if let Some(error) = job.forced.as_ref() {
            if let Some(completion) = self.registry.abandon(&job.flight, (**error).clone()) {
                self.emit_token(completion, Some((id, &mut *job)), emit);
            }
            return Progress::Drained;
        }
        if Instant::now() >= job.end {
            let error = AuthError::Deadline.wire();
            if let Some(completion) = self.registry.abandon(&job.flight, (*error).clone()) {
                self.emit_token(completion, Some((id, &mut *job)), emit);
            }
            return Progress::Drained;
        }
        let input = match self.registry.try_start(&job.flight) {
            StartState::WaitingForRefresh => return Progress::Pending,
            StartState::Retired => return Progress::Drained,
            StartState::Completed(completion) => {
                self.emit_token(completion, Some((id, &mut *job)), emit);
                return Progress::Drained;
            }
            StartState::AlreadyStarted => {
                return Progress::HostFault(HostFault::MissingTokenOwner);
            }
            StartState::Started(input) => input,
        };
        let body = match refresh_token_form(
            &job.client_id,
            input.refresh_token(),
            input.requested_scopes(),
        ) {
            Ok(form) => form.as_str().as_bytes().to_vec(),
            Err(error) => {
                if let Some(completion) = self
                    .registry
                    .abandon(&job.flight, (*AuthError::Primitive(error).wire()).clone())
                {
                    self.emit_token(completion, Some((id, &mut *job)), emit);
                }
                return Progress::Drained;
            }
        };
        let deadlines = match http_deadlines(job.end) {
            Ok(value) => value,
            Err(fault) => return Progress::HostFault(fault),
        };
        #[cfg(test)]
        let started = if let Some(endpoint) = self.test_token_endpoint.as_deref() {
            let mut body = body;
            let started = HttpOperation::start_test_url(
                endpoint,
                &body,
                deadlines,
                Arc::clone(&job.cancelled),
            );
            body.fill(0);
            started
        } else {
            HttpOperation::start(
                input.profile().key,
                body,
                deadlines,
                Arc::clone(&job.cancelled),
            )
        };
        #[cfg(not(test))]
        let started = HttpOperation::start(
            input.profile().key,
            body,
            deadlines,
            Arc::clone(&job.cancelled),
        );
        match started {
            Ok(http) => {
                job.http = Some(http);
                Progress::Pending
            }
            Err(error) => {
                if let Some(completion) = self
                    .registry
                    .abandon(&job.flight, (*AuthError::Http(error).wire()).clone())
                {
                    self.emit_token(completion, Some((id, &mut *job)), emit);
                }
                Progress::Drained
            }
        }
    }
    fn finish_token_http(
        &mut self,
        id: &OperationId,
        job: &mut TokenJob,
        result: Result<HttpResponse, HttpError>,
        emit: &mut impl FnMut(ResponseEvent),
    ) -> Progress {
        if job.logical_done {
            return Progress::Drained;
        }
        if let Some(error) = job.forced.as_ref() {
            if let Some(completion) = self.registry.abandon(&job.flight, (**error).clone()) {
                self.emit_token(completion, Some((id, &mut *job)), emit);
            }
            return Progress::Drained;
        }
        match result {
            Err(error) => {
                let mut completions = Vec::new();
                self.registry.finish_failure(
                    &job.flight,
                    ExchangeFailure::Failed((*AuthError::Http(error).wire()).clone()),
                    |c| completions.push(c),
                );
                for c in completions {
                    self.emit_token(c, Some((id, &mut *job)), emit);
                }
            }
            Ok(receipt) => {
                // Requested vector is retained from the actual active job
                // only for Begin grant fallback; Token has no grant echo.
                match decode_token_reply(
                    receipt.status(),
                    receipt.body(),
                    receipt.received_at(),
                    receipt.receipt_mono(),
                    None,
                    ExchangeMode::Refresh,
                ) {
                    Ok(token) => {
                        if let Some(c) =
                            self.registry
                                .finish_success(&job.flight, token.access, token.refresh)
                        {
                            self.emit_token(c, Some((id, &mut *job)), emit);
                        }
                    }
                    Err(error) => {
                        let terminal = error.terminal_invalid_grant();
                        let wire = AuthError::TokenReply(error).wire();
                        let failure = if terminal {
                            ExchangeFailure::InvalidGrant((*wire).clone())
                        } else {
                            ExchangeFailure::Failed((*wire).clone())
                        };
                        let mut completions = Vec::new();
                        self.registry
                            .finish_failure(&job.flight, failure, |c| completions.push(c));
                        for c in completions {
                            self.emit_token(c, Some((id, &mut *job)), emit);
                        }
                    }
                }
            }
        }
        job.logical_done = true;
        Progress::Drained
    }
    fn emit_token(
        &mut self,
        completion: Completion,
        current: Option<(&OperationId, &mut TokenJob)>,
        emit: &mut impl FnMut(ResponseEvent),
    ) {
        if let Some((id, token)) = current
            && token.flight == completion.flight
        {
            if !token.logical_done {
                token.logical_done = true;
                emit(ResponseEvent {
                    operation: id.clone(),
                    response: ReadyResponse::token(completion.result),
                });
            }
            return;
        }
        for (serial, slot) in &mut self.jobs {
            if let Some(Job::Token(token)) = slot
                && token.flight == completion.flight
            {
                if !token.logical_done {
                    token.logical_done = true;
                    emit(ResponseEvent {
                        operation: OperationId {
                            owner: Arc::clone(&self.owner),
                            serial: *serial,
                        },
                        response: ReadyResponse::token(completion.result),
                    });
                }
                return;
            }
        }
    }
    /// Accepted host tail: emit stopped logical outcomes, close admission,
    /// cancel actual owners, then keep polling every id until Drained. This does
    /// not release any Core lease or prove HTTP/browser cleanup by itself.
    pub fn stop_for_host_tail(&mut self, mut emit: impl FnMut(ResponseEvent)) {
        let mut completions = Vec::new();
        self.registry.stop_for_host_tail(|c| completions.push(c));
        for completion in completions {
            self.emit_token(completion, None, &mut emit);
        }
        let stopped = AuthError::State(StateFault::Stopping).wire();
        for (serial, slot) in &mut self.jobs {
            let Some(job) = slot else {
                continue;
            };
            match job {
                Job::Begin(job) => {
                    if !job.logical_done {
                        emit(ResponseEvent {
                            operation: OperationId {
                                owner: Arc::clone(&self.owner),
                                serial: *serial,
                            },
                            response: ReadyResponse::wire_error(Arc::clone(&stopped)),
                        });
                        job.logical_done = true;
                    }
                    if job.forced.is_none() {
                        job.forced = Some(Arc::clone(&stopped));
                    }
                    job.cancelled.store(true, Ordering::Release);
                    match &mut job.phase {
                        BeginPhase::Prompt(p) => {
                            p.flow.cancel();
                            p.browser.cancel();
                        }
                        BeginPhase::Http(http) => http.cancel(),
                    }
                }
                Job::Token(job) => {
                    if job.forced.is_none() {
                        job.forced = Some(Arc::clone(&stopped));
                    }
                    job.cancelled.store(true, Ordering::Release);
                    if let Some(http) = &mut job.http {
                        http.cancel();
                    }
                }
            }
        }
    }
}
fn http_deadlines(end: Instant) -> Result<HttpDeadlines, HostFault> {
    let request = Instant::now()
        .checked_add(TOKEN_REQUEST_TIMEOUT)
        .ok_or(HostFault::ClockOverflow)?
        .min(end);
    let cleanup = request
        .checked_add(OWNER_CLEANUP_TIMEOUT)
        .ok_or(HostFault::ClockOverflow)?;
    Ok(HttpDeadlines { request, cleanup })
}
fn unresolved_after_allow<A>() -> HandleState<A> {
    HandleState::DeniedInvariant {
        response: ReadyResponse::wire_error(Arc::new(CallError::from(TokenDenial::OutOfScope))),
        fault: HostFault::UnresolvedAfterAllow,
    }
}
#[cfg(test)]
#[path = "controller_tests.rs"]
mod tests;
