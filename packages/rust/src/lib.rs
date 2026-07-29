//! NEBULA — Opaque Rotating Refresh Tokens
//!
//! Rust implementation of `SPECIFICATION.md` (spec version 1), an implementation
//! profile of the refresh-token recommendations in RFC 9700: opaque tokens,
//! rotation on every use, replay detection with family revocation, bounded
//! lifetimes and optional sender binding.
//!
//! Requirement identifiers in comments (`[N-*]`) refer to `SPECIFICATION.md`.
//!
//! # Two failure channels ([N-20])
//!
//! Every engine method returns `Result<_, S::Error>`. The **outer** `Result` is
//! the infrastructure channel: a store that is unreachable, times out, or
//! violates a constraint surfaces there and is never downgraded into a protocol
//! outcome, so a caller that uses `?` always fails closed. The **inner** value
//! carries the protocol outcome of §7 as data ([N-29]).
//!
//! ```no_run
//! use nebula_token::{Config, ErrorCode, MemoryRefreshTokenStore, NebulaEngine};
//! use std::collections::HashMap;
//! use std::sync::Arc;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let peppers = HashMap::from([("k1".to_string(), std::env::var("NEBULA_PEPPER_K1")?)]);
//! // `&self` everywhere, so the engine can be shared across request handlers.
//! let engine = Arc::new(NebulaEngine::new(Config::new(
//!     peppers,
//!     "k1",
//!     MemoryRefreshTokenStore::new(),
//! ))?);
//!
//! let issued = engine.issue("usr_1", Some("device-1"))?;
//! match engine.refresh(&issued.token, Some("device-1"))? {
//!     Ok(next) => { /* persist next.token client-side; the presented one is dead */ }
//!     Err(failure) => match failure.code {
//!         ErrorCode::Conflict => { /* transient: retry once ([N-35]) */ }
//!         _ => { /* require a new login */ }
//!     },
//! }
//! # Ok(())
//! # }
//! ```

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

// ─── Spec constants (§1, [N-4]) ──────────────────────────────────────────────

/// Version of `SPECIFICATION.md` this crate implements ([N-52]).
pub const SPEC_VERSION: u32 = 1;
/// Reserved wire prefix ([N-51]). Case-sensitive.
pub const PREFIX: &str = "nbl";
pub const SELECTOR_BYTES: usize = 16;
pub const VERIFIER_BYTES: usize = 32;
/// base64url of [`SELECTOR_BYTES`], unpadded.
pub const SELECTOR_CHARS: usize = 22;
/// base64url of [`VERIFIER_BYTES`], unpadded.
pub const VERIFIER_CHARS: usize = 43;
/// Maximum `kid` length, in bytes ([N-1]).
pub const MAX_KID_LENGTH: usize = 64;
/// Maximum accepted token length, in bytes ([N-1]).
pub const MAX_TOKEN_LENGTH: usize = 512;
/// Minimum pepper length, in **bytes** of its UTF-8 encoding ([N-1], [N-23]).
pub const MIN_PEPPER_LENGTH: usize = 32;
pub const DEFAULT_ABSOLUTE_TTL: i64 = 60 * 60 * 24 * 30;
pub const DEFAULT_IDLE_TTL: i64 = 60 * 60 * 24 * 7;
/// Strict by default; read [N-30] before raising it.
pub const DEFAULT_REUSE_GRACE: i64 = 0;

/// HMAC-SHA-256 output, in lowercase hex characters.
const HASH_HEX_CHARS: usize = 64;

// ─── Types ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenStatus {
    Active,
    Rotated,
    Revoked,
}

impl TokenStatus {
    /// Canonical spec name (§3), suitable for a `status` column.
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenStatus::Active => "active",
            TokenStatus::Rotated => "rotated",
            TokenStatus::Revoked => "revoked",
        }
    }
}

impl fmt::Display for TokenStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Protocol outcomes ([N-38]).
///
/// `#[non_exhaustive]` per [N-40]: a future minor version may add a code, so a
/// downstream `match` MUST carry a wildcard arm and MUST treat an unrecognised
/// code as a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// The presented string is not a NEBULA token (§2).
    Malformed,
    /// No pepper is configured for the required key identifier.
    UnknownKid,
    /// No record exists for the selector.
    NotFound,
    /// The proof of possession failed.
    VerifierMismatch,
    /// A rotated token was replayed. The family has been revoked.
    ReuseDetected,
    /// The record was revoked.
    Revoked,
    /// The family passed its fixed deadline. The family has been revoked.
    ExpiredAbsolute,
    /// The sliding deadline passed. The family has been revoked.
    ExpiredIdle,
    /// Sender binding failed. The family has been revoked.
    DeviceMismatch,
    /// A concurrent refresh won the compare-and-set. Nothing was rotated.
    /// Retryable ([N-35]).
    Conflict,
}

impl ErrorCode {
    /// Canonical spec name (§7). Stable; the `Display` text is not ([N-41]).
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::Malformed => "MALFORMED",
            ErrorCode::UnknownKid => "UNKNOWN_KID",
            ErrorCode::NotFound => "NOT_FOUND",
            ErrorCode::VerifierMismatch => "VERIFIER_MISMATCH",
            ErrorCode::ReuseDetected => "REUSE_DETECTED",
            ErrorCode::Revoked => "REVOKED",
            ErrorCode::ExpiredAbsolute => "EXPIRED_ABSOLUTE",
            ErrorCode::ExpiredIdle => "EXPIRED_IDLE",
            ErrorCode::DeviceMismatch => "DEVICE_MISMATCH",
            ErrorCode::Conflict => "CONFLICT",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Server-side record — one row per issued token ([N-10]).
///
/// The `Debug` rendering is safe to log: the struct holds only hashes and
/// public identifiers, never the verifier or the raw device id ([N-14]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRecord {
    /// Primary key. The only token-derived value that may be indexed ([N-45]).
    pub selector: String,
    /// Lowercase hex `HMAC-SHA-256(pepper[kid], verifier_bytes)`.
    pub verifier_hash: String,
    pub kid: String,
    pub family_id: String,
    pub generation: u32,
    pub user_id: String,
    /// Lowercase hex `HMAC-SHA-256(pepper[kid], "device:" ‖ device_id)`, or
    /// `None` when the family is unbound.
    pub device_id_hash: Option<String>,
    pub created_at: i64,
    /// Absolute deadline, fixed at login. Never extended.
    pub family_expires_at: i64,
    /// Sliding deadline: `min(now + idle_ttl, family_expires_at)`.
    pub idle_expires_at: i64,
    pub status: TokenStatus,
    /// Set on first rotation. A grace retry MUST keep the original value ([N-30]).
    pub rotated_at: Option<i64>,
    pub replaced_by_selector: Option<String>,
}

/// Storage contract ([N-16]) — six methods, implement over Postgres / Redis / …
///
/// Every method takes `&self`: an engine is shared, so the implementation owns
/// its synchronisation (a connection pool, or a `Mutex` as in
/// [`MemoryRefreshTokenStore`]).
///
/// Two failure channels ([N-20]): protocol outcomes are the returned values
/// below; infrastructure failures are `Err(Self::Error)` and MUST NOT be
/// converted into a protocol outcome or swallowed.
///
/// A record MUST be retained with its `status` and `replaced_by_selector`
/// intact until at least its `family_expires_at` ([N-15]) — deleting rotated
/// rows early silently disables reuse detection.
pub trait RefreshTokenStore {
    /// Infrastructure failure type. Use [`std::convert::Infallible`] for a
    /// store that genuinely cannot fail.
    type Error;

    fn find_by_selector(&self, selector: &str) -> Result<Option<TokenRecord>, Self::Error>;

    fn insert(&self, record: TokenRecord) -> Result<(), Self::Error>;

    /// Compare-and-set ([N-17]). Apply the rotation write **if and only if** the
    /// stored status still equals `from`, and report whether it was applied.
    ///
    /// SQL: `UPDATE … SET status='rotated', rotated_at=$3, replaced_by_selector=$4
    /// WHERE selector=$1 AND status=$2` → `rows_affected == 1`.
    ///
    /// Returning `true` unconditionally is non-conforming: it re-opens the race
    /// in which two concurrent refreshes both mint a successor and fork the
    /// family into two independently valid lineages.
    fn mark_rotated(
        &self,
        selector: &str,
        from: TokenStatus,
        rotated_at: i64,
        replaced_by: &str,
    ) -> Result<bool, Self::Error>;

    /// Compare-and-set ([N-18]): revoke only if still `Active`; report whether
    /// it did.
    fn revoke_if_active(&self, selector: &str) -> Result<bool, Self::Error>;

    /// Revoke every record of the family. Returns how many changed ([N-19]).
    /// Idempotent: a second call over the same family returns 0.
    fn revoke_family(&self, family_id: &str) -> Result<u64, Self::Error>;

    /// Revoke every record of the user. Returns how many changed ([N-19]).
    fn revoke_user(&self, user_id: &str) -> Result<u64, Self::Error>;
}

/// Shared stores are stores. Lets one backing store serve several engines —
/// for instance while rotating peppers, where the old and new configurations
/// must observe the same rows.
impl<S: RefreshTokenStore + ?Sized> RefreshTokenStore for Arc<S> {
    type Error = S::Error;

    fn find_by_selector(&self, selector: &str) -> Result<Option<TokenRecord>, Self::Error> {
        (**self).find_by_selector(selector)
    }
    fn insert(&self, record: TokenRecord) -> Result<(), Self::Error> {
        (**self).insert(record)
    }
    fn mark_rotated(
        &self,
        selector: &str,
        from: TokenStatus,
        rotated_at: i64,
        replaced_by: &str,
    ) -> Result<bool, Self::Error> {
        (**self).mark_rotated(selector, from, rotated_at, replaced_by)
    }
    fn revoke_if_active(&self, selector: &str) -> Result<bool, Self::Error> {
        (**self).revoke_if_active(selector)
    }
    fn revoke_family(&self, family_id: &str) -> Result<u64, Self::Error> {
        (**self).revoke_family(family_id)
    }
    fn revoke_user(&self, user_id: &str) -> Result<u64, Self::Error> {
        (**self).revoke_user(user_id)
    }
}

/// Injectable "now", in unix seconds ([N-2], [N-3]).
///
/// `Send + Sync` is part of the type: without it the whole engine would be
/// neither, and could not be parked in an `Arc` inside an axum or actix
/// application state.
pub type Clock = Box<dyn Fn() -> i64 + Send + Sync>;

/// Engine configuration (§5). Validated by [`NebulaEngine::new`].
pub struct Config<S: RefreshTokenStore> {
    /// Map kid → pepper secret. Each secret ≥ [`MIN_PEPPER_LENGTH`] **bytes**;
    /// see [N-23] for the entropy requirement. Keep it in env/KMS, never in
    /// source or the database.
    pub peppers: HashMap<String, String>,
    /// kid used for newly minted tokens. MUST be present in `peppers`.
    pub active_kid: String,
    pub store: S,
    pub absolute_ttl_seconds: i64,
    pub idle_ttl_seconds: i64,
    /// See [N-30] for the reliability-versus-detectability trade-off before
    /// raising this above 0.
    pub reuse_grace_seconds: i64,
    /// `None` = system time.
    pub clock: Option<Clock>,
}

impl<S: RefreshTokenStore> Config<S> {
    /// Configuration with the specification's defaults (§1).
    pub fn new(peppers: HashMap<String, String>, active_kid: &str, store: S) -> Self {
        Config {
            peppers,
            active_kid: active_kid.to_string(),
            store,
            absolute_ttl_seconds: DEFAULT_ABSOLUTE_TTL,
            idle_ttl_seconds: DEFAULT_IDLE_TTL,
            reuse_grace_seconds: DEFAULT_REUSE_GRACE,
            clock: None,
        }
    }
}

/// Rejected configuration (§5) — a caller mistake, not a protocol outcome.
///
/// Never carries a pepper: only the offending `kid` and the rule it broke
/// ([N-14], [N-46]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[NEBULA] {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

#[derive(Clone, PartialEq, Eq)]
pub struct IssueResult {
    /// The wire token. It embeds the verifier, so it is a live credential:
    /// hand it to the client and never log it ([N-14], [N-46]).
    pub token: String,
    pub user_id: String,
    pub family_id: String,
    pub generation: u32,
    /// Unix seconds ([N-2]) — the family's fixed absolute deadline.
    pub expires_at: i64,
    /// Unix seconds ([N-2]) — this token's sliding idle deadline.
    pub idle_expires_at: i64,
}

/// [N-14]: a derived `Debug` would print the live token into every
/// `tracing::debug!(?issued)`, every `dbg!`, and every panic message that
/// captures this value. The token stays reachable through the field; only the
/// debug rendering is redacted.
impl fmt::Debug for IssueResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssueResult")
            .field("token", &"<redacted>")
            .field("user_id", &self.user_id)
            .field("family_id", &self.family_id)
            .field("generation", &self.generation)
            .field("expires_at", &self.expires_at)
            .field("idle_expires_at", &self.idle_expires_at)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RefreshOk {
    /// The successor's wire token — a live credential, exactly like
    /// [`IssueResult::token`] ([N-14], [N-46]).
    pub token: String,
    pub user_id: String,
    pub family_id: String,
    pub generation: u32,
    pub expires_at: i64,
    pub idle_expires_at: i64,
}

/// Redacted for the same reason as [`IssueResult`] ([N-14]).
impl fmt::Debug for RefreshOk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshOk")
            .field("token", &"<redacted>")
            .field("user_id", &self.user_id)
            .field("family_id", &self.family_id)
            .field("generation", &self.generation)
            .field("expires_at", &self.expires_at)
            .field("idle_expires_at", &self.idle_expires_at)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeOk {
    pub user_id: String,
    pub family_id: String,
    /// Number of records whose status this call changed.
    pub revoked: u64,
}

/// A refused operation ([N-38]).
///
/// `user_id` and `family_id` are populated whenever the engine resolved a
/// record — every code except `Malformed`, `UnknownKid` and `NotFound` — so a
/// `ReuseDetected` or `DeviceMismatch` event can be attributed to a session
/// without a second lookup of a token you were told never to log ([N-39]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub code: ErrorCode,
    pub user_id: Option<String>,
    pub family_id: Option<String>,
}

impl Failure {
    fn bare(code: ErrorCode) -> Self {
        Failure {
            code,
            user_id: None,
            family_id: None,
        }
    }

    fn attributed(code: ErrorCode, record: &TokenRecord) -> Self {
        Failure {
            code,
            user_id: Some(record.user_id.clone()),
            family_id: Some(record.family_id.clone()),
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code.as_str())
    }
}

impl std::error::Error for Failure {}

/// Protocol outcome of [`NebulaEngine::refresh`] ([N-29]).
pub type RefreshResult = Result<RefreshOk, Failure>;

/// Protocol outcome of [`NebulaEngine::revoke_token`] ([N-29]).
pub type RevokeResult = Result<RevokeOk, Failure>;

#[derive(Clone)]
pub struct ParsedToken {
    pub kid: String,
    pub selector: String,
    /// The raw 32 secret bytes. Never persist or log these ([N-14]).
    pub verifier: Vec<u8>,
}

/// [N-14]: a derived `Debug` would print the 32 secret bytes as a plain integer
/// array, so a single `dbg!(parse_token(t))` or `?parsed` tracing field would
/// put the credential in the log. The `kid` and the `selector` stay visible —
/// the selector is the designated correlation identifier ([N-46]).
impl fmt::Debug for ParsedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedToken")
            .field("kid", &self.kid)
            .field("selector", &self.selector)
            .field("verifier", &"<redacted>")
            .finish()
    }
}

// ─── Spec primitives (§2, §6.4) ──────────────────────────────────────────────

/// True iff every byte is in the `b64url` production of §2.
///
/// A byte predicate rather than a regex, deliberately: `^…$` accepts a trailing
/// newline in several regex dialects, which would let `"…{verifier}\n"` through
/// as well-formed (vector `p-24`). There is no anchor to get wrong here.
fn is_b64url(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Parse a wire token (§2, [N-5]..[N-9]).
///
/// Total: returns `None` for every rejection and never panics ([N-8]). Rust's
/// `&str` is UTF-8 by construction, so the "invalid UTF-8 input" and "null
/// reference" cases of [N-8] are unrepresentable rather than handled.
pub fn parse_token(token: &str) -> Option<ParsedToken> {
    // [N-6.1] byte length, before any other parsing work. `str::len()` is
    // already a byte count ([N-1]).
    if token.len() > MAX_TOKEN_LENGTH {
        return None;
    }

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 4 {
        return None; // [N-6.2]
    }
    let (prefix, kid, selector, verifier_b64) = (parts[0], parts[1], parts[2], parts[3]);

    if prefix != PREFIX {
        return None; // [N-6.3] case-sensitive, and no locale is consulted ([N-9])
    }
    // [N-6.5]/[N-6.6] exact lengths, in bytes; the alphabet check below makes
    // byte length and character length coincide.
    if kid.is_empty() || kid.len() > MAX_KID_LENGTH {
        return None;
    }
    if selector.len() != SELECTOR_CHARS || verifier_b64.len() != VERIFIER_CHARS {
        return None;
    }
    // [N-6.4] rejects padding, whitespace, '+', '/' and anything non-ASCII.
    if !is_b64url(kid) || !is_b64url(selector) || !is_b64url(verifier_b64) {
        return None;
    }

    let verifier = URL_SAFE_NO_PAD.decode(verifier_b64).ok()?;
    if verifier.len() != VERIFIER_BYTES {
        return None; // [N-6.7]
    }
    // [N-7] canonical encoding: a 32-byte value has four 43-character
    // spellings, because the last character carries only four significant
    // bits. Only the minimal one is a token.
    if URL_SAFE_NO_PAD.encode(&verifier) != verifier_b64 {
        return None; // [N-6.8]
    }

    Some(ParsedToken {
        kid: kid.to_string(),
        selector: selector.to_string(),
        verifier,
    })
}

/// `verifier_hash` = lowercase hex `HMAC-SHA-256(pepper, verifier)` ([N-11], [N-13]).
///
/// The HMAC key is the pepper's UTF-8 encoding; no normalisation, trimming or
/// case transformation is applied to it.
pub fn hash_verifier(pepper: &str, verifier: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(pepper.as_bytes()).expect("HMAC accepts a key of any length");
    mac.update(verifier);
    hex::encode(mac.finalize().into_bytes())
}

/// `device_id_hash` = lowercase hex `HMAC-SHA-256(pepper, "device:" ‖ device_id)`
/// ([N-11], [N-13]).
///
/// Infallible here: [N-12] concerns runtimes whose string type can hold an
/// unpaired surrogate, and `&str` cannot. The two `update` calls hash exactly
/// the same message as concatenating first, without copying the identifier.
pub fn hash_device_id(pepper: &str, device_id: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(pepper.as_bytes()).expect("HMAC accepts a key of any length");
    mac.update(b"device:");
    mac.update(device_id.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// True iff `s` is exactly 64 lowercase hex characters.
fn is_lower_hex_64(s: &str) -> bool {
    s.len() == HASH_HEX_CHARS && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Constant-time comparison of two hex digests ([N-31]). Never panics.
///
/// Operands that are not exactly 64 lowercase hex characters compare unequal.
/// The guard is deliberate: a lenient hex decode stops at the first invalid
/// character and silently compares decoded prefixes, so a stored hash that was
/// truncated by a narrow column, space-padded by `CHAR(64)`, or upper-cased by
/// an ETL job would keep verifying instead of failing closed.
pub fn constant_time_equal_hex(a_hex: &str, b_hex: &str) -> bool {
    if !is_lower_hex_64(a_hex) || !is_lower_hex_64(b_hex) {
        return false;
    }
    // Both operands are known to be 64 ASCII bytes, so comparing the hex text
    // is as constant-time as comparing the decoded bytes and cannot fail.
    a_hex.as_bytes().ct_eq(b_hex.as_bytes()).into()
}

// ─── Engine ──────────────────────────────────────────────────────────────────

/// The NEBULA engine (§6).
///
/// Every method takes `&self`, so the engine is normally built once at startup
/// and shared (`Arc<NebulaEngine<_>>`) across request handlers. It is `Send +
/// Sync` whenever its store is.
pub struct NebulaEngine<S: RefreshTokenStore> {
    peppers: HashMap<String, String>,
    active_kid: String,
    store: S,
    absolute_ttl: i64,
    idle_ttl: i64,
    reuse_grace: i64,
    clock: Clock,
}

/// Renders the engine's shape without its secrets: the pepper *values* never
/// appear in a debug rendering, a log line or a panic message ([N-14], [N-46]).
impl<S: RefreshTokenStore> fmt::Debug for NebulaEngine<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NebulaEngine")
            .field("kids", &self.peppers.keys().collect::<Vec<_>>())
            .field("active_kid", &self.active_kid)
            .field("absolute_ttl", &self.absolute_ttl)
            .field("idle_ttl", &self.idle_ttl)
            .field("reuse_grace", &self.reuse_grace)
            .finish_non_exhaustive()
    }
}

/// A refusal with nothing to attribute it to ([N-39]).
fn refuse<T, E>(code: ErrorCode) -> Result<Result<T, Failure>, E> {
    Ok(Err(Failure::bare(code)))
}

/// A refusal carrying the resolved record's `user_id` and `family_id` ([N-39]).
fn refuse_with<T, E>(code: ErrorCode, record: &TokenRecord) -> Result<Result<T, Failure>, E> {
    Ok(Err(Failure::attributed(code, record)))
}

impl<S: RefreshTokenStore> NebulaEngine<S> {
    /// Validate the configuration (§5) and build an engine.
    ///
    /// The configuration is moved in, so a caller that keeps a copy of its
    /// pepper map cannot weaken the engine afterwards ([N-24]).
    pub fn new(config: Config<S>) -> Result<Self, ConfigError> {
        for (kid, secret) in &config.peppers {
            if kid.is_empty() || kid.len() > MAX_KID_LENGTH || !is_b64url(kid) {
                return Err(ConfigError(format!(
                    "kid {kid:?} must be 1-{MAX_KID_LENGTH} bytes from [A-Za-z0-9_-]"
                )));
            }
            // [N-11] holds vacuously here: `String` is UTF-8 by construction,
            // so a pepper with no UTF-8 encoding cannot be built in Rust and
            // there is nothing to reject. The languages whose strings are
            // UTF-16 or byte sequences must fail construction explicitly.
            //
            // [N-1]/[N-23]: bytes of the UTF-8 encoding, not characters — a
            // 31-character passphrase of astral emoji is not a 256-bit key,
            // and a 16-character CJK string is longer than it looks.
            if secret.len() < MIN_PEPPER_LENGTH {
                return Err(ConfigError(format!(
                    "pepper {kid:?} must be at least {MIN_PEPPER_LENGTH} bytes"
                )));
            }
        }
        if !config.peppers.contains_key(&config.active_kid) {
            return Err(ConfigError(format!(
                "active_kid {:?} not present in peppers",
                config.active_kid
            )));
        }
        if config.absolute_ttl_seconds <= 0 {
            return Err(ConfigError(
                "absolute_ttl_seconds must be positive".to_string(),
            ));
        }
        if config.idle_ttl_seconds <= 0 {
            return Err(ConfigError("idle_ttl_seconds must be positive".to_string()));
        }
        if config.reuse_grace_seconds < 0 {
            return Err(ConfigError(
                "reuse_grace_seconds must not be negative".to_string(),
            ));
        }

        Ok(NebulaEngine {
            peppers: config.peppers,
            active_kid: config.active_kid,
            store: config.store,
            absolute_ttl: config.absolute_ttl_seconds,
            idle_ttl: config.idle_ttl_seconds,
            reuse_grace: config.reuse_grace_seconds,
            clock: config.clock.unwrap_or_else(|| Box::new(system_clock)),
        })
    }

    /// Issue the first token of a new family ([N-25]). Call at login.
    ///
    /// `device_id` binds the family to a sender ([N-32]); `Some("")` is a real
    /// binding, distinct from `None`.
    ///
    /// Returns `Err` if the record could not be persisted — a token is never
    /// handed back for state that was not written ([N-20]).
    pub fn issue(&self, user_id: &str, device_id: Option<&str>) -> Result<IssueResult, S::Error> {
        let now = (self.clock)();
        let family_id = random_hex(16);
        let family_expires_at = now + self.absolute_ttl;
        let device_id_hash = device_id.map(|d| hash_device_id(self.active_pepper(), d));
        let (token, record) = self.mint(
            user_id,
            &family_id,
            0,
            device_id_hash,
            family_expires_at,
            now,
        );
        let idle_expires_at = record.idle_expires_at;
        self.store.insert(record)?;
        Ok(IssueResult {
            token,
            user_id: user_id.to_string(),
            family_id,
            generation: 0,
            expires_at: family_expires_at,
            idle_expires_at,
        })
    }

    /// Exchange a refresh token for its successor ([N-26]).
    ///
    /// The check order is normative and observable ([N-28]).
    pub fn refresh(&self, token: &str, device_id: Option<&str>) -> Result<RefreshResult, S::Error> {
        // 1. Parse (§2)
        let Some(parsed) = parse_token(token) else {
            return refuse(ErrorCode::Malformed);
        };

        // 2. Pepper for the token's kid
        if !self.peppers.contains_key(&parsed.kid) {
            return refuse(ErrorCode::UnknownKid);
        }

        // 3. Record lookup — keyed on the selector only ([N-45])
        let Some(record) = self.store.find_by_selector(&parsed.selector)? else {
            return refuse(ErrorCode::NotFound);
        };

        // 4. Verifier proof under the RECORD's pepper ([N-27]), constant time
        let Some(record_pepper) = self.peppers.get(&record.kid) else {
            return refuse(ErrorCode::UnknownKid);
        };
        if !constant_time_equal_hex(
            &hash_verifier(record_pepper, &parsed.verifier),
            &record.verifier_hash,
        ) {
            // [N-28] no family revocation here: knowledge of a selector alone
            // must never be enough to destroy a session.
            return refuse_with(ErrorCode::VerifierMismatch, &record);
        }

        let now = (self.clock)();

        match record.status {
            // 5. Reuse
            TokenStatus::Rotated => self.handle_reuse(&record, record_pepper, device_id, now),
            // 6. Revoked
            TokenStatus::Revoked => refuse_with(ErrorCode::Revoked, &record),
            TokenStatus::Active => {
                // 7-8. Expiry
                if now >= record.family_expires_at {
                    self.store.revoke_family(&record.family_id)?;
                    return refuse_with(ErrorCode::ExpiredAbsolute, &record);
                }
                if now >= record.idle_expires_at {
                    self.store.revoke_family(&record.family_id)?;
                    return refuse_with(ErrorCode::ExpiredIdle, &record);
                }
                // 9. Sender binding, under the RECORD's pepper ([N-32])
                if record.device_id_hash.is_some()
                    && !device_matches(&record, record_pepper, device_id)
                {
                    self.store.revoke_family(&record.family_id)?;
                    return refuse_with(ErrorCode::DeviceMismatch, &record);
                }
                // 10. Rotate
                self.rotate(&record, device_id, now, TokenStatus::Active, now)
            }
        }
    }

    /// Revoke the family a token belongs to ([N-36]).
    ///
    /// Authenticated: the verifier is proved exactly as in [`Self::refresh`],
    /// because the selector is a public lookup key and must not by itself be a
    /// capability to terminate someone's session. Succeeds whatever the
    /// record's status, so a client can still log out with a token that was
    /// already rotated or revoked.
    ///
    /// Takes no device identifier and performs no sender-binding check
    /// ([N-36]): sender binding is deliberately not required to log out.
    pub fn revoke_token(&self, token: &str) -> Result<RevokeResult, S::Error> {
        let Some(parsed) = parse_token(token) else {
            return refuse(ErrorCode::Malformed);
        };
        if !self.peppers.contains_key(&parsed.kid) {
            return refuse(ErrorCode::UnknownKid);
        }
        let Some(record) = self.store.find_by_selector(&parsed.selector)? else {
            return refuse(ErrorCode::NotFound);
        };
        let Some(record_pepper) = self.peppers.get(&record.kid) else {
            return refuse(ErrorCode::UnknownKid);
        };
        if !constant_time_equal_hex(
            &hash_verifier(record_pepper, &parsed.verifier),
            &record.verifier_hash,
        ) {
            return refuse_with(ErrorCode::VerifierMismatch, &record);
        }

        let revoked = self.store.revoke_family(&record.family_id)?;
        Ok(Ok(RevokeOk {
            user_id: record.user_id,
            family_id: record.family_id,
            revoked,
        }))
    }

    /// Revoke a whole family by its server-side identifier ([N-37]).
    ///
    /// Requires no token; the caller is responsible for authorising it.
    /// Idempotent, and returns the number of records it changed.
    pub fn revoke_family(&self, family_id: &str) -> Result<u64, S::Error> {
        self.store.revoke_family(family_id)
    }

    /// Revoke every session of a user ([N-37]) — password change, "log out all
    /// devices", incident response. Returns the number of records it changed.
    pub fn revoke_all_for_user(&self, user_id: &str) -> Result<u64, S::Error> {
        self.store.revoke_user(user_id)
    }

    /// Borrow the store, e.g. to run its maintenance helpers.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Consume the engine and return its store.
    pub fn into_store(self) -> S {
        self.store
    }

    // ── Private ────────────────────────────────────────────────────────────

    fn handle_reuse(
        &self,
        record: &TokenRecord,
        record_pepper: &str,
        device_id: Option<&str>,
        now: i64,
    ) -> Result<RefreshResult, S::Error> {
        if let Some(successor) = self.grace_successor(record, now)? {
            // Sender binding first ([N-30] step 1): a thief who also fails the
            // binding check must burn the family, not merely lose a race.
            if record.device_id_hash.is_some() && !device_matches(record, record_pepper, device_id)
            {
                self.store.revoke_family(&record.family_id)?;
                return refuse_with(ErrorCode::DeviceMismatch, record);
            }
            // Compare-and-set: exactly one concurrent retry may consume the
            // unused successor. The loser mints nothing ([N-30] step 2).
            if !self.store.revoke_if_active(&successor.selector)? {
                return refuse_with(ErrorCode::Conflict, record);
            }
            // Preserve the original rotated_at: the window is anchored to the
            // first rotation and cannot be walked forward ([N-30] step 3).
            let rotated_at = record.rotated_at.unwrap_or(now);
            return self.rotate(record, device_id, now, TokenStatus::Rotated, rotated_at);
        }

        // Not a retry: a theft signal.
        self.store.revoke_family(&record.family_id)?;
        refuse_with(ErrorCode::ReuseDetected, record)
    }

    /// The successor a grace retry may consume, if all six preconditions of
    /// [N-30] hold. `Ok(None)` means "this presentation is a replay".
    fn grace_successor(
        &self,
        record: &TokenRecord,
        now: i64,
    ) -> Result<Option<TokenRecord>, S::Error> {
        if self.reuse_grace <= 0 {
            return Ok(None); // 1
        }
        let Some(rotated_at) = record.rotated_at else {
            return Ok(None); // 2
        };
        if now.saturating_sub(rotated_at) > self.reuse_grace {
            return Ok(None); // 3
        }
        let Some(replaced_by) = record.replaced_by_selector.as_deref() else {
            return Ok(None); // 4
        };
        // 6 — a grace retry must never mint a token past the family's
        // absolute deadline.
        if now >= record.family_expires_at {
            return Ok(None);
        }
        // 5 — the successor exists and is still unused.
        Ok(self
            .store
            .find_by_selector(replaced_by)?
            .filter(|s| s.status == TokenStatus::Active))
    }

    /// Rotation of `record` ([N-34]). `rotated_at` is `now` for a fresh
    /// rotation and the record's original value for a grace retry.
    fn rotate(
        &self,
        record: &TokenRecord,
        device_id: Option<&str>,
        now: i64,
        from: TokenStatus,
        rotated_at: i64,
    ) -> Result<RefreshResult, S::Error> {
        // Re-hash the binding with the ACTIVE pepper, migrating it forward
        // across a pepper rotation ([N-33] step 4).
        let device_id_hash = match (&record.device_id_hash, device_id) {
            (Some(_), Some(d)) => Some(hash_device_id(self.active_pepper(), d)),
            _ => record.device_id_hash.clone(),
        };
        let (token, next) = self.mint(
            &record.user_id,
            &record.family_id,
            record.generation + 1,
            device_id_hash,
            record.family_expires_at,
            now,
        );
        let next_selector = next.selector.clone();
        let generation = next.generation;
        let expires_at = next.family_expires_at;
        let idle_expires_at = next.idle_expires_at;

        self.store.insert(next)?;

        if !self
            .store
            .mark_rotated(&record.selector, from, rotated_at, &next_selector)?
        {
            // [N-34] step 5: a concurrent refresh won. Clean up the successor
            // we just inserted and report a retryable conflict — never a token.
            self.store.revoke_if_active(&next_selector)?;
            return refuse_with(ErrorCode::Conflict, record);
        }

        Ok(Ok(RefreshOk {
            token,
            user_id: record.user_id.clone(),
            family_id: record.family_id.clone(),
            generation,
            expires_at,
            idle_expires_at,
        }))
    }

    /// Mint a fresh selector/verifier pair and its record ([N-33]).
    fn mint(
        &self,
        user_id: &str,
        family_id: &str,
        generation: u32,
        device_id_hash: Option<String>,
        family_expires_at: i64,
        now: i64,
    ) -> (String, TokenRecord) {
        let mut selector_raw = [0u8; SELECTOR_BYTES];
        let mut verifier = [0u8; VERIFIER_BYTES];
        // [N-43]: the platform CSPRNG, and nothing weaker. `thread_rng` is a
        // ChaCha12 stream seeded from the OS entropy source and periodically
        // reseeded from it — a CSPRNG, not the OS source read directly. What
        // the requirement needs is that a failure to obtain entropy is never
        // silently replaced by something weaker, and that holds: seeding is
        // infallible-or-panic (`getrandom` failure aborts the thread rather
        // than yielding low-entropy bytes), and `fill_bytes` cannot fail.
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut selector_raw);
        rng.fill_bytes(&mut verifier);

        let selector = URL_SAFE_NO_PAD.encode(selector_raw);
        let record = TokenRecord {
            selector: selector.clone(),
            verifier_hash: hash_verifier(self.active_pepper(), &verifier),
            kid: self.active_kid.clone(),
            family_id: family_id.to_string(),
            generation,
            user_id: user_id.to_string(),
            device_id_hash,
            created_at: now,
            family_expires_at,
            idle_expires_at: (now + self.idle_ttl).min(family_expires_at),
            status: TokenStatus::Active,
            rotated_at: None,
            replaced_by_selector: None,
        };
        let token = format!(
            "{PREFIX}.{}.{selector}.{}",
            self.active_kid,
            URL_SAFE_NO_PAD.encode(verifier)
        );
        (token, record)
    }

    fn active_pepper(&self) -> &str {
        // Unreachable: `new` rejects a configuration whose active_kid is absent
        // and the map is immutable afterwards. Panicking beats defaulting to an
        // empty key, which would mint plausible-looking but unkeyed hashes.
        self.peppers
            .get(&self.active_kid)
            .expect("active_kid is present in peppers, checked at construction")
    }
}

/// Sender binding check ([N-32]). A missing device id against a bound record
/// fails, and nothing here can panic.
fn device_matches(record: &TokenRecord, record_pepper: &str, device_id: Option<&str>) -> bool {
    match (device_id, &record.device_id_hash) {
        (Some(d), Some(h)) => constant_time_equal_hex(&hash_device_id(record_pepper, d), h),
        _ => false,
    }
}

fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Unix seconds ([N-2]). Signed, and total: a pre-epoch system clock yields a
/// negative value instead of panicking.
fn system_clock() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

// ─── In-memory store — development and tests ONLY ───────────────────────────

/// The only failure [`MemoryRefreshTokenStore`] can report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateSelector {
    pub selector: String,
}

impl fmt::Display for DuplicateSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[NEBULA] duplicate selector {}", self.selector)
    }
}

impl std::error::Error for DuplicateSelector {}

/// Reference store ([N-21]).
///
/// Safe to share across threads: each operation takes the `Mutex` for its whole
/// read-modify-write, which is what makes [`RefreshTokenStore::mark_rotated`]
/// and [`RefreshTokenStore::revoke_if_active`] genuine compare-and-sets.
///
/// **NOT FOR PRODUCTION**: state is per-process and lost on restart, so reuse
/// detection does not survive a deploy and does not work behind more than one
/// instance. Implement [`RefreshTokenStore`] over your database instead — see
/// `docs/STORE.md` and `examples/sql_store.rs`.
#[derive(Debug, Default)]
pub struct MemoryRefreshTokenStore {
    rows: Mutex<HashMap<String, TokenRecord>>,
}

impl MemoryRefreshTokenStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Test helper: every record currently stored. Not part of the contract.
    pub fn all(&self) -> Vec<TokenRecord> {
        self.rows().values().cloned().collect()
    }

    /// Test helper: drop records whose family deadline has passed ([N-15]).
    /// Records before that deadline are what makes replay detectable.
    pub fn delete_expired(&self, now: i64) -> u64 {
        let mut rows = self.rows();
        let before = rows.len();
        rows.retain(|_, r| now < r.family_expires_at);
        (before - rows.len()) as u64
    }

    /// The critical sections below cannot panic, so a poisoned lock can only
    /// come from a panic elsewhere in the process and the map is still
    /// consistent; recovering keeps a dev store from becoming permanently
    /// unusable after an unrelated test failure.
    fn rows(&self) -> std::sync::MutexGuard<'_, HashMap<String, TokenRecord>> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl RefreshTokenStore for MemoryRefreshTokenStore {
    type Error = DuplicateSelector;

    fn find_by_selector(&self, selector: &str) -> Result<Option<TokenRecord>, Self::Error> {
        Ok(self.rows().get(selector).cloned())
    }

    fn insert(&self, record: TokenRecord) -> Result<(), Self::Error> {
        let mut rows = self.rows();
        if rows.contains_key(&record.selector) {
            // Refuse rather than overwrite: silently replacing a row would
            // destroy the predecessor's status and its reuse evidence.
            return Err(DuplicateSelector {
                selector: record.selector,
            });
        }
        rows.insert(record.selector.clone(), record);
        Ok(())
    }

    fn mark_rotated(
        &self,
        selector: &str,
        from: TokenStatus,
        rotated_at: i64,
        replaced_by: &str,
    ) -> Result<bool, Self::Error> {
        let mut rows = self.rows();
        let Some(r) = rows.get_mut(selector) else {
            return Ok(false);
        };
        if r.status != from {
            return Ok(false); // [N-17]
        }
        r.status = TokenStatus::Rotated;
        r.rotated_at = Some(rotated_at);
        r.replaced_by_selector = Some(replaced_by.to_string());
        Ok(true)
    }

    fn revoke_if_active(&self, selector: &str) -> Result<bool, Self::Error> {
        let mut rows = self.rows();
        let Some(r) = rows.get_mut(selector) else {
            return Ok(false);
        };
        if r.status != TokenStatus::Active {
            return Ok(false); // [N-18]
        }
        r.status = TokenStatus::Revoked;
        Ok(true)
    }

    fn revoke_family(&self, family_id: &str) -> Result<u64, Self::Error> {
        Ok(self.revoke_matching(|r| r.family_id == family_id))
    }

    fn revoke_user(&self, user_id: &str) -> Result<u64, Self::Error> {
        Ok(self.revoke_matching(|r| r.user_id == user_id))
    }
}

impl MemoryRefreshTokenStore {
    /// Counts only the records it changed, so a repeated call returns 0 ([N-19]).
    fn revoke_matching(&self, predicate: impl Fn(&TokenRecord) -> bool) -> u64 {
        let mut n = 0;
        for r in self.rows().values_mut() {
            if r.status != TokenStatus::Revoked && predicate(r) {
                r.status = TokenStatus::Revoked;
                n += 1;
            }
        }
        n
    }
}
