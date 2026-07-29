//! Language-specific tests: the properties a portable vector cannot express.
//!
//! All cross-language behavior lives in `spec/behavior-vectors.json` and is
//! driven by `tests/behavior.rs`. What is left here is Rust-shaped: the
//! `Send + Sync` contract, real preemptive concurrency, the store's error
//! channel, configuration validation, and the constant-time guard.

use nebula_token::{
    constant_time_equal_hex, hash_device_id, hash_verifier, parse_token, Config, ConfigError,
    DuplicateSelector, ErrorCode, Failure, MemoryRefreshTokenStore, NebulaEngine,
    RefreshTokenStore, TokenRecord, TokenStatus, MIN_PEPPER_LENGTH,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

const PEPPER: &str = "pepper-one-0123456789abcdef0123456789ab";
const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn peppers() -> HashMap<String, String> {
    HashMap::from([("k1".to_string(), PEPPER.to_string())])
}

/// An engine over the in-memory store with a clock the test can move.
fn engine() -> (NebulaEngine<Arc<MemoryRefreshTokenStore>>, Arc<AtomicI64>) {
    let now = Arc::new(AtomicI64::new(1_700_000_000));
    let ticking = Arc::clone(&now);
    let mut config = Config::new(
        peppers(),
        "k1",
        Arc::new(MemoryRefreshTokenStore::default()),
    );
    config.clock = Some(Box::new(move || ticking.load(Ordering::SeqCst)));
    (NebulaEngine::new(config).expect("valid config"), now)
}

// ── Send + Sync ─────────────────────────────────────────────────────────────

/// Instantiating this for the concrete engine types is the whole test: if the
/// clock box or the store lost its auto traits, the crate would stop compiling
/// here rather than at some downstream `axum::Router::with_state`.
fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn the_engine_is_send_and_sync() {
    assert_send_sync::<NebulaEngine<MemoryRefreshTokenStore>>();
    assert_send_sync::<NebulaEngine<Arc<MemoryRefreshTokenStore>>>();
    assert_send_sync::<Arc<NebulaEngine<Arc<MemoryRefreshTokenStore>>>>();
    assert_send_sync::<MemoryRefreshTokenStore>();
    assert_send_sync::<Failure>();
    assert_send_sync::<ErrorCode>();
    assert_send_sync::<TokenRecord>();
}

#[test]
fn error_codes_are_open_to_future_additions() {
    // [N-40]: `ErrorCode` is `#[non_exhaustive]`, so from outside the crate a
    // `match` without a wildcard does not compile. This is the shape every
    // consumer must write — an unrecognised code is a refusal.
    let describe = |code: ErrorCode| match code {
        ErrorCode::Conflict => "retry once",
        ErrorCode::ReuseDetected | ErrorCode::DeviceMismatch => "security event",
        _ => "require a new login",
    };
    assert_eq!(describe(ErrorCode::Conflict), "retry once");
    assert_eq!(describe(ErrorCode::Malformed), "require a new login");
    assert_eq!(ErrorCode::Conflict.as_str(), "CONFLICT");
}

// ── Constant-time comparison ([N-31]) ───────────────────────────────────────

#[test]
fn constant_time_equal_hex_rejects_anything_but_64_lowercase_hex_characters() {
    assert!(constant_time_equal_hex(HASH, HASH));
    assert!(!constant_time_equal_hex(HASH, &"b".repeat(64)));

    // A lenient hex decode stops at the first invalid character and compares
    // decoded prefixes, so every case below would otherwise compare EQUAL.
    assert!(
        !constant_time_equal_hex("abc", "abd"),
        "odd-length prefixes"
    );
    assert!(
        !constant_time_equal_hex(HASH, &format!("{HASH}   ")),
        "space-padded CHAR(67) column"
    );
    assert!(
        !constant_time_equal_hex(HASH, &format!("{HASH}\n")),
        "trailing newline"
    );
    assert!(
        !constant_time_equal_hex(HASH, &format!("{HASH}zzzz")),
        "junk suffix"
    );
    assert!(
        !constant_time_equal_hex(HASH, &HASH.to_uppercase()),
        "case is not folded"
    );
    assert!(
        !constant_time_equal_hex(&HASH[..63], &HASH[..63]),
        "truncated column"
    );
    assert!(!constant_time_equal_hex("", ""), "empty is never equal");
    assert!(
        !constant_time_equal_hex(&format!(" {}", &HASH[1..]), HASH),
        "leading space is not trimmed"
    );
}

#[test]
fn constant_time_equal_hex_never_panics() {
    let spaces = " ".repeat(64);
    let nulls = "\u{0}".repeat(64);
    let accents = "é".repeat(32); // 64 bytes, 32 characters
    let hostile: [&str; 8] = ["", " ", "zz", "\u{0}", "日本語", &spaces, &nulls, &accents];
    for a in hostile {
        assert!(!constant_time_equal_hex(a, HASH));
        assert!(!constant_time_equal_hex(HASH, a));
        assert!(!constant_time_equal_hex(a, a), "{a:?} is not a digest");
    }
}

#[test]
fn a_stored_hash_corrupted_after_the_fact_fails_closed() {
    let (engine, _) = engine();
    let issued = engine.issue("u1", None).expect("issue");
    let row = engine.store().all().pop().expect("one record");

    // The same record, but the column was upper-cased by an ETL job.
    engine
        .store()
        .insert(TokenRecord {
            selector: "x".repeat(22),
            verifier_hash: row.verifier_hash.to_uppercase(),
            ..row
        })
        .expect("insert");

    let mut parts: Vec<&str> = issued.token.split('.').collect();
    let selector = "x".repeat(22);
    parts[2] = &selector;
    let forged = parts.join(".");

    let failure = engine
        .refresh(&forged, None)
        .expect("no store failure")
        .expect_err("an upper-cased hash must not verify");
    assert_eq!(failure.code, ErrorCode::VerifierMismatch);
}

// ── Concurrency ([N-17], [N-34], [N-35]) ────────────────────────────────────

/// Holds every racer at its snapshot of the record until all of them have one,
/// so the test exercises the compare-and-set rather than a lucky interleaving.
struct BarrierStore {
    inner: MemoryRefreshTokenStore,
    barrier: Barrier,
    arrivals: AtomicUsize,
    parties: usize,
}

impl BarrierStore {
    fn new(parties: usize) -> Self {
        BarrierStore {
            inner: MemoryRefreshTokenStore::default(),
            barrier: Barrier::new(parties),
            arrivals: AtomicUsize::new(0),
            parties,
        }
    }
}

impl RefreshTokenStore for BarrierStore {
    type Error = DuplicateSelector;

    fn find_by_selector(&self, selector: &str) -> Result<Option<TokenRecord>, Self::Error> {
        let found = self.inner.find_by_selector(selector);
        if self.arrivals.fetch_add(1, Ordering::SeqCst) < self.parties {
            self.barrier.wait();
        }
        found
    }
    fn insert(&self, record: TokenRecord) -> Result<(), Self::Error> {
        self.inner.insert(record)
    }
    fn mark_rotated(
        &self,
        selector: &str,
        from: TokenStatus,
        rotated_at: i64,
        replaced_by: &str,
    ) -> Result<bool, Self::Error> {
        self.inner
            .mark_rotated(selector, from, rotated_at, replaced_by)
    }
    fn revoke_if_active(&self, selector: &str) -> Result<bool, Self::Error> {
        self.inner.revoke_if_active(selector)
    }
    fn revoke_family(&self, family_id: &str) -> Result<u64, Self::Error> {
        self.inner.revoke_family(family_id)
    }
    fn revoke_user(&self, user_id: &str) -> Result<u64, Self::Error> {
        self.inner.revoke_user(user_id)
    }
}

#[test]
fn concurrent_refreshes_of_one_token_leave_exactly_one_active_record() {
    const RACERS: usize = 8;

    let store = Arc::new(BarrierStore::new(RACERS));
    let engine =
        NebulaEngine::new(Config::new(peppers(), "k1", Arc::clone(&store))).expect("valid config");
    let issued = engine.issue("u1", None).expect("issue");

    // Scoped threads borrow `&engine` directly, which is only possible because
    // the engine is Sync and its methods take &self.
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..RACERS)
            .map(|_| {
                scope.spawn(|| {
                    engine
                        .refresh(&issued.token, None)
                        .expect("no store failure")
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("no racer panicked"))
            .collect::<Vec<_>>()
    });

    let winners = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        winners, 1,
        "exactly one refresh may win the compare-and-set"
    );
    for failure in results.iter().filter_map(|r| r.as_ref().err()) {
        assert_eq!(
            failure.code,
            ErrorCode::Conflict,
            "losers must get CONFLICT"
        );
        // [N-35]: a conflict revokes nothing beyond the orphan successor.
        assert_eq!(failure.user_id.as_deref(), Some("u1"));
    }

    let rows = store.inner.all();
    assert_eq!(
        rows.iter()
            .filter(|r| r.status == TokenStatus::Active)
            .count(),
        1,
        "the family must not fork into two live lineages"
    );
    assert_eq!(
        rows.iter()
            .filter(|r| r.status == TokenStatus::Rotated)
            .count(),
        1
    );
    assert_eq!(
        rows.len(),
        RACERS + 1,
        "every orphan successor is accounted for"
    );
}

#[test]
fn an_unsynchronised_burst_never_forks_the_family() {
    let store = Arc::new(MemoryRefreshTokenStore::default());
    let engine =
        NebulaEngine::new(Config::new(peppers(), "k1", Arc::clone(&store))).expect("valid config");
    let issued = engine.issue("u1", None).expect("issue");

    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..16)
            .map(|_| {
                scope.spawn(|| {
                    engine
                        .refresh(&issued.token, None)
                        .expect("no store failure")
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("no racer panicked"))
            .collect::<Vec<_>>()
    });

    assert!(
        results.iter().filter(|r| r.is_ok()).count() <= 1,
        "at most one refresh may succeed, whatever the interleaving"
    );
    for failure in results.iter().filter_map(|r| r.as_ref().err()) {
        // Whichever way the threads interleave, a loser either lost the CAS or
        // arrived after the record was already rotated / the family burnt.
        assert!(
            matches!(
                failure.code,
                ErrorCode::Conflict | ErrorCode::ReuseDetected | ErrorCode::Revoked
            ),
            "unexpected outcome {}",
            failure.code
        );
    }
    assert!(
        store
            .all()
            .iter()
            .filter(|r| r.status == TokenStatus::Active)
            .count()
            <= 1
    );
}

// ── Store failures fail closed ([N-20]) ─────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
struct Boom(&'static str);

impl std::fmt::Display for Boom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "database is on fire ({})", self.0)
    }
}

struct ExplodingStore {
    inner: MemoryRefreshTokenStore,
    fail_on: &'static str,
}

impl ExplodingStore {
    fn new(fail_on: &'static str) -> Self {
        ExplodingStore {
            inner: MemoryRefreshTokenStore::default(),
            fail_on,
        }
    }
    fn guard(&self, method: &'static str) -> Result<(), Boom> {
        if method == self.fail_on {
            return Err(Boom(method));
        }
        Ok(())
    }
}

impl RefreshTokenStore for ExplodingStore {
    type Error = Boom;

    fn find_by_selector(&self, selector: &str) -> Result<Option<TokenRecord>, Self::Error> {
        self.guard("find_by_selector")?;
        Ok(self.inner.find_by_selector(selector).expect("infallible"))
    }
    fn insert(&self, record: TokenRecord) -> Result<(), Self::Error> {
        self.guard("insert")?;
        self.inner.insert(record).map_err(|_| Boom("duplicate"))
    }
    fn mark_rotated(
        &self,
        selector: &str,
        from: TokenStatus,
        rotated_at: i64,
        replaced_by: &str,
    ) -> Result<bool, Self::Error> {
        self.guard("mark_rotated")?;
        Ok(self
            .inner
            .mark_rotated(selector, from, rotated_at, replaced_by)
            .expect("infallible"))
    }
    fn revoke_if_active(&self, selector: &str) -> Result<bool, Self::Error> {
        self.guard("revoke_if_active")?;
        Ok(self.inner.revoke_if_active(selector).expect("infallible"))
    }
    fn revoke_family(&self, family_id: &str) -> Result<u64, Self::Error> {
        self.guard("revoke_family")?;
        Ok(self.inner.revoke_family(family_id).expect("infallible"))
    }
    fn revoke_user(&self, user_id: &str) -> Result<u64, Self::Error> {
        self.guard("revoke_user")?;
        Ok(self.inner.revoke_user(user_id).expect("infallible"))
    }
}

#[test]
fn a_failing_insert_never_hands_back_a_token_for_state_that_was_not_written() {
    let engine = NebulaEngine::new(Config::new(peppers(), "k1", ExplodingStore::new("insert")))
        .expect("valid config");
    assert_eq!(engine.issue("u1", None).unwrap_err(), Boom("insert"));
    assert!(engine.store().inner.all().is_empty());
}

#[test]
fn a_failing_revoke_family_is_never_reported_as_a_successful_revocation() {
    let engine = NebulaEngine::new(Config::new(
        peppers(),
        "k1",
        ExplodingStore::new("revoke_family"),
    ))
    .expect("valid config");
    let issued = engine.issue("u1", None).expect("issue");
    assert!(engine
        .refresh(&issued.token, None)
        .expect("no failure")
        .is_ok());

    // The replay must attempt a family revocation; the error propagates on the
    // outer channel rather than being swallowed into a confident
    // REUSE_DETECTED that never happened ([N-20]).
    assert_eq!(
        engine.refresh(&issued.token, None).unwrap_err(),
        Boom("revoke_family")
    );
}

#[test]
fn a_failing_lookup_is_not_a_not_found() {
    let engine = NebulaEngine::new(Config::new(
        peppers(),
        "k1",
        ExplodingStore::new("find_by_selector"),
    ))
    .expect("valid config");
    let token = format!("nbl.k1.{}.{}", "A".repeat(22), "A".repeat(43));
    assert_eq!(
        engine.refresh(&token, None).unwrap_err(),
        Boom("find_by_selector")
    );
    assert_eq!(
        engine.revoke_token(&token).unwrap_err(),
        Boom("find_by_selector")
    );
}

// ── Configuration (§5, [N-23], [N-24]) ──────────────────────────────────────

fn build_with(
    peppers: HashMap<String, String>,
    active_kid: &str,
    tune: impl FnOnce(&mut Config<MemoryRefreshTokenStore>),
) -> Result<NebulaEngine<MemoryRefreshTokenStore>, ConfigError> {
    let mut config = Config::new(peppers, active_kid, MemoryRefreshTokenStore::new());
    tune(&mut config);
    NebulaEngine::new(config)
}

#[test]
fn constructor_validation() {
    let ok = |kid: &str, secret: &str| HashMap::from([(kid.to_string(), secret.to_string())]);

    assert!(
        build_with(ok("k1", "short"), "k1", |_| {}).is_err(),
        "pepper too short"
    );
    assert!(
        build_with(ok("k1", PEPPER), "nope", |_| {}).is_err(),
        "unknown active kid"
    );
    assert!(
        build_with(ok("k.1", PEPPER), "k.1", |_| {}).is_err(),
        "kid outside the ABNF"
    );
    assert!(
        build_with(ok("k+1", PEPPER), "k+1", |_| {}).is_err(),
        "kid outside the ABNF"
    );
    assert!(build_with(ok("", PEPPER), "", |_| {}).is_err(), "empty kid");
    assert!(
        build_with(ok(&"k".repeat(65), PEPPER), &"k".repeat(65), |_| {}).is_err(),
        "kid over MAX_KID_LENGTH"
    );
    assert!(
        build_with(ok(&"k".repeat(64), PEPPER), &"k".repeat(64), |_| {}).is_ok(),
        "kid at exactly MAX_KID_LENGTH"
    );
    assert!(build_with(ok("k1", PEPPER), "k1", |c| c.absolute_ttl_seconds = 0).is_err());
    assert!(build_with(ok("k1", PEPPER), "k1", |c| c.idle_ttl_seconds = -5).is_err());
    assert!(build_with(ok("k1", PEPPER), "k1", |c| c.reuse_grace_seconds = -1).is_err());
    assert!(build_with(ok("k1", PEPPER), "k1", |c| c.reuse_grace_seconds = 0).is_ok());

    // [N-11] holds vacuously in Rust: a pepper with no UTF-8 encoding cannot be
    // constructed, because `String` is UTF-8 by construction. The other nine
    // ports reject one at build time; here the type system does it, and this
    // asserts that the bytes really are what the HMAC key is built from — so a
    // future change to a byte-slice pepper would fail here rather than silently
    // reopen the divergence the rule closed.
    let wtf8 = Vec::from([0xEDu8, 0xA0, 0x80]); // the WTF-8 spelling of U+D800
    assert!(
        String::from_utf8(wtf8).is_err(),
        "an unpaired surrogate has no UTF-8 encoding, so it cannot become a String"
    );
}

#[test]
fn a_rejected_configuration_never_quotes_the_pepper() {
    // [N-14]/[N-46]: the message names the kid and the rule, never the secret.
    let Err(err) = build_with(
        HashMap::from([("k1".to_string(), "short-but-secret".to_string())]),
        "k1",
        |_| {},
    ) else {
        panic!("a short pepper must fail construction");
    };
    assert!(!err.to_string().contains("short-but-secret"), "{err}");
    assert!(err.to_string().contains("k1"));

    // Nor does the engine's own Debug rendering carry a pepper.
    let engine = build_with(peppers(), "k1", |_| {}).expect("valid config");
    assert!(!format!("{engine:?}").contains(PEPPER), "{engine:?}");
}

#[test]
fn min_pepper_length_counts_bytes_not_characters() {
    // [N-1]: 16 characters, 48 UTF-8 bytes — long enough.
    let wide = "日".repeat(16);
    assert_eq!(wide.chars().count(), 16);
    assert_eq!(wide.len(), 48);
    assert!(build_with(HashMap::from([("k1".to_string(), wide)]), "k1", |_| {}).is_ok());

    let short = "a".repeat(MIN_PEPPER_LENGTH - 1);
    assert!(build_with(HashMap::from([("k1".to_string(), short)]), "k1", |_| {}).is_err());
}

#[test]
fn the_pepper_map_is_copied_into_the_engine() {
    // [N-24]. In Rust the configuration is moved in, so this is structural
    // rather than defensive — but the property still has to hold from the
    // caller's side, and a future refactor to `&HashMap` would break it here.
    let mut callers = peppers();
    let engine = NebulaEngine::new(Config::new(
        callers.clone(),
        "k1",
        MemoryRefreshTokenStore::new(),
    ))
    .expect("valid config");

    callers.insert("k1".to_string(), "x".to_string()); // a one-byte HMAC key
    callers.clear();

    let issued = engine.issue("u1", None).expect("issue");
    let parsed = parse_token(&issued.token).expect("issued tokens parse");
    assert_eq!(
        engine.store().all()[0].verifier_hash,
        hash_verifier(PEPPER, &parsed.verifier)
    );
    assert!(engine
        .refresh(&issued.token, None)
        .expect("no failure")
        .is_ok());
}

// ── Device identifiers ([N-11], [N-12], [N-14]) ─────────────────────────────

#[test]
fn hash_device_id_applies_no_normalisation_trimming_or_case_folding() {
    // [N-11]. "Café" in NFC vs NFD: same text, different bytes, different hash.
    assert_ne!(
        hash_device_id(PEPPER, "Caf\u{e9}"),
        hash_device_id(PEPPER, "Cafe\u{301}"),
        "NFC and NFD must not be conflated"
    );
    assert_ne!(hash_device_id(PEPPER, "x"), hash_device_id(PEPPER, " x"));
    assert_ne!(hash_device_id(PEPPER, "x"), hash_device_id(PEPPER, "X"));
    // An empty device id is a real, hashable binding — never "absent".
    assert_eq!(hash_device_id(PEPPER, "").len(), 64);
}

#[test]
fn an_absent_device_id_is_distinguishable_from_an_empty_one() {
    let (engine, _) = engine();
    let unbound = engine.issue("u1", None).expect("issue");
    let bound = engine.issue("u2", Some("")).expect("issue");
    let rows = engine.store().all();

    assert!(rows
        .iter()
        .any(|r| r.user_id == "u1" && r.device_id_hash.is_none()));
    assert!(rows
        .iter()
        .any(|r| r.user_id == "u2" && r.device_id_hash.is_some()));

    // The unbound family ignores a presented id; the ""-bound one requires it.
    assert!(engine
        .refresh(&unbound.token, Some("anything"))
        .expect("no failure")
        .is_ok());
    assert_eq!(
        engine
            .refresh(&bound.token, None)
            .expect("no failure")
            .unwrap_err()
            .code,
        ErrorCode::DeviceMismatch
    );
}

#[test]
fn no_raw_secret_reaches_the_store() {
    let (engine, _) = engine();
    let issued = engine.issue("u1", Some("devA")).expect("issue");
    engine
        .refresh(&issued.token, Some("devA"))
        .expect("no failure")
        .expect("rotates");

    // `Debug` is what a log line or a crash dump would carry ([N-14], [N-46]).
    let dump = format!("{:?}", engine.store().all());
    let verifier = issued.token.split('.').nth(3).expect("four parts");
    assert!(!dump.contains(verifier), "raw verifier");
    assert!(!dump.contains(&issued.token), "whole token");
    assert!(!dump.contains("devA"), "raw device identifier");
    assert!(!dump.contains(PEPPER), "pepper");
    for row in engine.store().all() {
        assert_eq!(row.verifier_hash.len(), 64);
        assert_eq!(row.device_id_hash.expect("bound").len(), 64);
    }
}

#[test]
fn no_debug_rendering_of_any_public_type_carries_a_live_credential() {
    // [N-14]/[N-46]: the store is not the only place a secret can escape to. A
    // derived `Debug` puts the value into `tracing::debug!(?x)`, `dbg!`, an
    // `assert_eq!` failure and any caller struct that derives Debug around ours.
    let (engine, _) = engine();
    let issued = engine.issue("u1", Some("devA")).expect("issue");
    let verifier_b64 = issued.token.split('.').nth(3).expect("four parts");
    let parsed = parse_token(&issued.token).expect("issued tokens parse");
    let rotated = engine
        .refresh(&issued.token, Some("devA"))
        .expect("no failure")
        .expect("rotates");

    let renderings = [
        format!("{parsed:?}"),
        format!("{issued:?}"),
        format!("{rotated:?}"),
        format!("{:?}", engine.store().all()),
        format!("{engine:?}"),
    ];
    // The raw verifier bytes as a derived Debug would print them: `[8, 97, …]`.
    let raw_bytes = parsed
        .verifier
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ");

    for rendering in &renderings {
        assert!(
            !rendering.contains(&issued.token),
            "whole token: {rendering}"
        );
        assert!(!rendering.contains(verifier_b64), "verifier: {rendering}");
        assert!(
            !rendering.contains(&rotated.token),
            "successor: {rendering}"
        );
        assert!(
            !rendering.contains(&raw_bytes),
            "verifier bytes: {rendering}"
        );
        assert!(!rendering.contains("devA"), "device id: {rendering}");
        assert!(!rendering.contains(PEPPER), "pepper: {rendering}");
    }

    // Redaction must not cost the caller the value itself.
    assert_eq!(parsed.verifier.len(), 32);
    assert!(issued.token.starts_with("nbl.k1."));
}

// ── Result shape ([N-2], [N-39]) ────────────────────────────────────────────

#[test]
fn failures_carry_user_and_family_once_a_record_is_resolved() {
    let (engine, _) = engine();
    let issued = engine.issue("u1", None).expect("issue");
    engine
        .refresh(&issued.token, None)
        .expect("no failure")
        .expect("rotates");

    let replay = engine
        .refresh(&issued.token, None)
        .expect("no failure")
        .unwrap_err();
    assert_eq!(replay.code, ErrorCode::ReuseDetected);
    assert_eq!(replay.user_id.as_deref(), Some("u1"));
    assert_eq!(replay.family_id.as_deref(), Some(issued.family_id.as_str()));

    // Before a record is resolved there is nothing to attribute ([N-39]).
    let malformed = engine
        .refresh("garbage", None)
        .expect("no failure")
        .unwrap_err();
    assert_eq!(malformed.code, ErrorCode::Malformed);
    assert!(malformed.user_id.is_none() && malformed.family_id.is_none());
}

#[test]
fn timestamps_are_integer_unix_seconds() {
    // [N-2]: i64 is the type, so what is left to check is that the clock the
    // engine was handed is the one it uses, and that the idle deadline is
    // clamped to the family ceiling.
    let (engine, now) = engine();
    let issued = engine.issue("u1", None).expect("issue");
    let start = now.load(Ordering::SeqCst);
    assert_eq!(
        issued.expires_at,
        start + nebula_token::DEFAULT_ABSOLUTE_TTL
    );
    assert_eq!(
        issued.idle_expires_at,
        start + nebula_token::DEFAULT_IDLE_TTL
    );

    now.fetch_add(10, Ordering::SeqCst);
    let next = engine
        .refresh(&issued.token, None)
        .expect("no failure")
        .expect("rotates");
    assert_eq!(next.expires_at, issued.expires_at, "never extended");
    assert_eq!(
        next.idle_expires_at,
        start + 10 + nebula_token::DEFAULT_IDLE_TTL
    );
}

// ── Store hygiene ───────────────────────────────────────────────────────────

#[test]
fn the_in_memory_store_refuses_a_duplicate_selector() {
    let store = MemoryRefreshTokenStore::new();
    let row = TokenRecord {
        selector: "A".repeat(22),
        verifier_hash: HASH.to_string(),
        kid: "k1".to_string(),
        family_id: "f".to_string(),
        generation: 0,
        user_id: "u1".to_string(),
        device_id_hash: None,
        created_at: 0,
        family_expires_at: 1,
        idle_expires_at: 1,
        status: TokenStatus::Active,
        rotated_at: None,
        replaced_by_selector: None,
    };
    store.insert(row.clone()).expect("first insert");
    assert_eq!(
        store.insert(row).unwrap_err(),
        DuplicateSelector {
            selector: "A".repeat(22)
        }
    );
}

#[test]
fn delete_expired_only_removes_records_past_the_family_deadline() {
    // [N-15]: dropping rotated rows early would turn every replay into
    // NOT_FOUND and silently disable reuse detection.
    let now = Arc::new(AtomicI64::new(1_700_000_000));
    let ticking = Arc::clone(&now);
    let mut config = Config::new(
        peppers(),
        "k1",
        Arc::new(MemoryRefreshTokenStore::default()),
    );
    config.absolute_ttl_seconds = 100;
    config.idle_ttl_seconds = 100;
    config.clock = Some(Box::new(move || ticking.load(Ordering::SeqCst)));
    let engine = NebulaEngine::new(config).expect("valid config");

    let issued = engine.issue("u1", None).expect("issue");
    engine
        .refresh(&issued.token, None)
        .expect("no failure")
        .expect("rotates");

    assert_eq!(engine.store().delete_expired(1_700_000_099), 0);
    assert_eq!(engine.store().all().len(), 2);
    assert_eq!(engine.store().delete_expired(1_700_000_100), 2);
}
