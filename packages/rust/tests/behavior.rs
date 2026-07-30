//! Runner for the normative behavioral suite — `spec/behavior-vectors.json`
//! ([N-47], [N-49]).
//!
//! The scenarios are data. Only this driver is language-specific, which is what
//! stops the ten ports from drifting apart the way ten hand-written suites did.
//! Properties the vectors cannot express — concurrency, store failures,
//! configuration validation — live in `tests/engine.rs`.

use nebula_token::{
    Config, DuplicateSelector, ErrorCode, Failure, MemoryRefreshTokenStore, NebulaEngine,
    RefreshTokenStore, TokenRecord, TokenStatus,
};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;

/// Locate `spec/` by walking up from this package rather than hardcoding a
/// path, and never copy the vectors into the package.
fn spec_dir() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        if dir.join("spec").join("behavior-vectors.json").is_file() {
            return dir.join("spec");
        }
        assert!(
            dir.pop(),
            "could not find spec/behavior-vectors.json above {}",
            env!("CARGO_MANIFEST_DIR")
        );
    }
}

fn load_behavior_vectors() -> Value {
    let path = spec_dir().join("behavior-vectors.json");
    let raw = std::fs::read_to_string(&path).expect("spec/behavior-vectors.json is readable");
    serde_json::from_str(&raw).expect("spec/behavior-vectors.json is valid JSON")
}

/// Conditions this runtime satisfies.
///
/// `runtime-admits-invalid-unicode-strings` is deliberately absent: `str` is
/// UTF-8 by construction, so a Rust program cannot hold the unpaired surrogate
/// that scenario presents. The scenario is reported as skipped, not silently
/// passed ([N-48]).
const SATISFIED_CONDITIONS: &[&str] = &[];

/// 32 zero bytes, canonically encoded: well-formed, and never the real secret.
const FORGED_VERIFIER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const FORGED_SELECTOR: &str = "AAAAAAAAAAAAAAAAAAAAAA";

// ─── A store one scenario can make lose a compare-and-set ───────────────────

#[derive(Default)]
struct ControllableStore {
    inner: MemoryRefreshTokenStore,
    fail_mark_rotated: AtomicBool,
    fail_revoke_if_active: AtomicBool,
}

impl ControllableStore {
    fn fail_next_cas(&self, method: &str) {
        match method {
            "markRotated" => self.fail_mark_rotated.store(true, Ordering::SeqCst),
            "revokeIfActive" => self.fail_revoke_if_active.store(true, Ordering::SeqCst),
            other => panic!("unknown CAS method {other:?}"),
        }
    }

    fn all(&self) -> Vec<TokenRecord> {
        self.inner.all()
    }
}

impl RefreshTokenStore for ControllableStore {
    type Error = DuplicateSelector;

    fn find_by_selector(&self, selector: &str) -> Result<Option<TokenRecord>, Self::Error> {
        self.inner.find_by_selector(selector)
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
        if self.fail_mark_rotated.swap(false, Ordering::SeqCst) {
            return Ok(false); // a concurrent refresh won the race
        }
        self.inner
            .mark_rotated(selector, from, rotated_at, replaced_by)
    }

    fn revoke_if_active(&self, selector: &str) -> Result<bool, Self::Error> {
        if self.fail_revoke_if_active.swap(false, Ordering::SeqCst) {
            return Ok(false);
        }
        self.inner.revoke_if_active(selector)
    }

    fn revoke_family(&self, family_id: &str) -> Result<u64, Self::Error> {
        self.inner.revoke_family(family_id)
    }

    fn revoke_user(&self, user_id: &str) -> Result<u64, Self::Error> {
        self.inner.revoke_user(user_id)
    }
}

// ─── Runner ─────────────────────────────────────────────────────────────────

type Engine = NebulaEngine<Arc<ControllableStore>>;

#[derive(Clone)]
struct Binding {
    token: String,
    family_id: String,
    expires_at: i64,
}

/// What a successful `issue` or `refresh` produced, in the shape the `expect`
/// block talks about.
struct Minted {
    token: String,
    generation: u32,
    family_id: String,
    expires_at: i64,
    idle_expires_at: i64,
}

#[derive(Default)]
struct RunOutcome {
    executed: Vec<String>,
    skipped: Vec<(String, String)>,
}

fn str_at<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn i64_at(v: &Value, key: &str) -> Option<i64> {
    v.get(key).and_then(Value::as_i64)
}

fn run_behavior_vectors(vectors: &Value) -> RunOutcome {
    let mut outcome = RunOutcome::default();
    for scenario in vectors["scenarios"]
        .as_array()
        .expect("scenarios is an array")
    {
        let id = str_at(scenario, "id")
            .expect("scenario has an id")
            .to_string();
        match str_at(scenario, "condition") {
            Some(c) if !SATISFIED_CONDITIONS.contains(&c) => {
                outcome.skipped.push((id, c.to_string()));
            }
            _ => {
                run_scenario(vectors, scenario, &id);
                outcome.executed.push(id);
            }
        }
    }
    outcome
}

#[allow(clippy::too_many_lines)]
fn run_scenario(vectors: &Value, scenario: &Value, id: &str) {
    // `Value` owns heap data, so a `&Value::Null` temporary cannot be promoted
    // to 'static; one binding serves as the "absent object" for the scenario.
    let null = Value::Null;
    let defaults = &vectors["defaults"];
    let cfg = scenario.get("config").unwrap_or(&null);
    let cfg_i64 = |key: &str| {
        i64_at(cfg, key)
            .or_else(|| i64_at(defaults, key))
            .unwrap_or_else(|| panic!("[{id}] no value for {key}"))
    };
    let cfg_kids = |key: &str| -> Vec<String> {
        cfg.get(key)
            .or_else(|| defaults.get(key))
            .and_then(Value::as_array)
            .expect("peppers is an array")
            .iter()
            .map(|k| k.as_str().expect("kid is a string").to_string())
            .collect()
    };

    let store = Arc::new(ControllableStore::default());
    let now = Arc::new(AtomicI64::new(cfg_i64("now")));
    let (absolute_ttl, idle_ttl, grace) = (
        cfg_i64("absoluteTtlSeconds"),
        cfg_i64("idleTtlSeconds"),
        cfg_i64("reuseGraceSeconds"),
    );

    let build = |kids: &[String], active_kid: &str| -> Engine {
        let peppers = kids
            .iter()
            .map(|kid| {
                let secret = vectors["peppers"][kid]
                    .as_str()
                    .unwrap_or_else(|| panic!("[{id}] no pepper published for {kid}"));
                (kid.clone(), secret.to_string())
            })
            .collect::<HashMap<_, _>>();
        let mut config = Config::new(peppers, active_kid, Arc::clone(&store));
        config.absolute_ttl_seconds = absolute_ttl;
        config.idle_ttl_seconds = idle_ttl;
        config.reuse_grace_seconds = grace;
        let ticking = Arc::clone(&now);
        config.clock = Some(Box::new(move || ticking.load(Ordering::SeqCst)));
        NebulaEngine::new(config).unwrap_or_else(|e| panic!("[{id}] engine construction: {e}"))
    };

    let mut engine = build(
        &cfg_kids("peppers"),
        str_at(cfg, "activeKid")
            .or_else(|| str_at(defaults, "activeKid"))
            .expect("activeKid"),
    );

    let mut bindings: HashMap<String, Binding> = HashMap::new();
    let mut issued_secrets: Vec<String> = Vec::new();
    let mut device_ids: HashSet<String> = HashSet::new();

    for (i, step) in scenario["steps"]
        .as_array()
        .expect("steps is an array")
        .iter()
        .enumerate()
    {
        let at = format!("[{id}] step {i} ({})", str_at(step, "op").unwrap_or("?"));
        let expect = step.get("expect").unwrap_or(&null);
        let expect_ok = expect.get("ok").and_then(Value::as_bool);
        let expect_error = str_at(expect, "error");

        let resolve_token = |bindings: &HashMap<String, Binding>| -> String {
            let token = &step["token"];
            if let Some(literal) = str_at(token, "literal") {
                return literal.to_string();
            }
            let name = str_at(token, "ref").unwrap_or_else(|| panic!("{at}: no token reference"));
            let bound = bindings
                .get(name)
                .unwrap_or_else(|| panic!("{at}: unknown binding {name:?}"));
            let Some(forge) = str_at(token, "forge") else {
                return bound.token.clone();
            };
            let mut parts: Vec<&str> = bound.token.split('.').collect();
            match forge {
                "verifier" => parts[3] = FORGED_VERIFIER,
                "unknownKid" => parts[1] = "zz",
                "unknownSelector" => parts[2] = FORGED_SELECTOR,
                other => panic!("{at}: unknown forge {other:?}"),
            }
            parts.join(".")
        };

        // A device id named only by `deviceIdKind` is a lone surrogate, which
        // `&str` cannot hold; such scenarios carry a `condition` and are
        // skipped before they reach this point.
        assert!(
            step.get("deviceIdKind").is_none(),
            "{at}: deviceIdKind is not representable in Rust and the scenario carries no condition"
        );
        let device_id = str_at(step, "deviceId");

        let check_success = |res: &Minted, bindings: &HashMap<String, Binding>| {
            if let Some(want) = expect.get("generation").and_then(Value::as_u64) {
                assert_eq!(u64::from(res.generation), want, "{at}: generation");
            }
            if let Some(want) = str_at(expect, "kid") {
                let kid = res.token.split('.').nth(1).unwrap_or_default();
                assert_eq!(kid, want, "{at}: kid of the minted token");
            }
            if let Some(other) = str_at(expect, "sameFamilyAs") {
                let want = &bindings[other].family_id;
                assert_eq!(
                    &res.family_id, want,
                    "{at}: familyId changed across rotation"
                );
            }
            if let Some(other) = str_at(expect, "sameExpiresAtAs") {
                let want = bindings[other].expires_at;
                assert_eq!(res.expires_at, want, "{at}: absolute deadline moved");
            }
            if expect.get("idleEqualsExpires").and_then(Value::as_bool) == Some(true) {
                assert_eq!(
                    res.idle_expires_at, res.expires_at,
                    "{at}: idleExpiresAt is not clamped to the family ceiling"
                );
            }
        };

        // [N-39] attribution, tri-state: `true` demands the field, `false`
        // demands its absence — the exclusion list (MALFORMED, UNKNOWN_KID,
        // NOT_FOUND) is a requirement too, and a truthy-only check could never
        // observe it. Absent means the scenario does not assert it.
        let check_attribution = |failure: &Failure| {
            if let Some(want) = expect.get("hasUserId").and_then(Value::as_bool) {
                assert_eq!(
                    failure.user_id.is_some(),
                    want,
                    "{at}: expected userId {} ([N-39])",
                    if want { "present" } else { "absent" }
                );
            }
            if let Some(want) = expect.get("hasFamilyId").and_then(Value::as_bool) {
                assert_eq!(
                    failure.family_id.is_some(),
                    want,
                    "{at}: expected familyId {} ([N-39])",
                    if want { "present" } else { "absent" }
                );
            }
        };

        match str_at(step, "op").expect("step has an op") {
            "issue" => {
                let user_id = str_at(step, "userId").expect("issue has a userId");
                let res = engine
                    .issue(user_id, device_id)
                    .unwrap_or_else(|e| panic!("{at}: store failure {e}"));
                assert_ne!(expect_ok, Some(false), "{at}: expected issue to fail");
                let minted = Minted {
                    token: res.token.clone(),
                    generation: res.generation,
                    family_id: res.family_id.clone(),
                    expires_at: res.expires_at,
                    idle_expires_at: res.idle_expires_at,
                };
                check_success(&minted, &bindings);
                if let Some(name) = str_at(step, "bind") {
                    bindings.insert(
                        name.to_string(),
                        Binding {
                            token: res.token.clone(),
                            family_id: res.family_id,
                            expires_at: res.expires_at,
                        },
                    );
                }
                issued_secrets.push(verifier_part(&res.token));
                if let Some(d) = device_id.filter(|d| !d.is_empty()) {
                    device_ids.insert(d.to_string());
                }
            }

            "refresh" => {
                let token = resolve_token(&bindings);
                let res = engine
                    .refresh(&token, device_id)
                    .unwrap_or_else(|e| panic!("{at}: store failure {e}"));
                if expect_ok == Some(true) || (expect_ok.is_none() && expect_error.is_none()) {
                    let ok =
                        res.unwrap_or_else(|f| panic!("{at}: expected success, got {}", f.code));
                    let minted = Minted {
                        token: ok.token.clone(),
                        generation: ok.generation,
                        family_id: ok.family_id.clone(),
                        expires_at: ok.expires_at,
                        idle_expires_at: ok.idle_expires_at,
                    };
                    check_success(&minted, &bindings);
                    if let Some(name) = str_at(step, "bind") {
                        bindings.insert(
                            name.to_string(),
                            Binding {
                                token: ok.token.clone(),
                                family_id: ok.family_id,
                                expires_at: ok.expires_at,
                            },
                        );
                    }
                    issued_secrets.push(verifier_part(&ok.token));
                } else {
                    let failure = match res {
                        Ok(ok) => panic!(
                            "{at}: expected {}, got success (generation {})",
                            expect_error.unwrap_or("failure"),
                            ok.generation
                        ),
                        Err(f) => f,
                    };
                    assert_eq!(failure.code.as_str(), expect_error.unwrap_or(""), "{at}");
                    check_attribution(&failure);
                }
            }

            "revokeToken" => {
                let token = resolve_token(&bindings);
                let res = engine
                    .revoke_token(&token)
                    .unwrap_or_else(|e| panic!("{at}: store failure {e}"));
                if expect_ok == Some(false) {
                    let failure = match res {
                        Ok(_) => {
                            panic!("{at}: expected {}, got success", expect_error.unwrap_or(""))
                        }
                        Err(f) => f,
                    };
                    assert_eq!(failure.code.as_str(), expect_error.unwrap_or(""), "{at}");
                    // [N-39] governs every failure result, not `refresh` alone.
                    check_attribution(&failure);
                } else {
                    let ok =
                        res.unwrap_or_else(|f| panic!("{at}: expected success, got {}", f.code));
                    if let Some(want) = i64_at(expect, "revoked") {
                        assert_eq!(ok.revoked as i64, want, "{at}: revoked count");
                    }
                }
            }

            "revokeFamilyOf" => {
                let of = str_at(step, "of").expect("revokeFamilyOf has `of`");
                let family_id = bindings[of].family_id.clone();
                let n = engine
                    .revoke_family(&family_id)
                    .unwrap_or_else(|e| panic!("{at}: store failure {e}"));
                if let Some(want) = i64_at(expect, "revoked") {
                    assert_eq!(n as i64, want, "{at}: revoked count");
                }
            }

            "revokeUser" => {
                let user_id = str_at(step, "userId").expect("revokeUser has a userId");
                let n = engine
                    .revoke_all_for_user(user_id)
                    .unwrap_or_else(|e| panic!("{at}: store failure {e}"));
                if let Some(want) = i64_at(expect, "revoked") {
                    assert_eq!(n as i64, want, "{at}: revoked count");
                }
            }

            "advance" => {
                let seconds = i64_at(step, "seconds").expect("advance has seconds");
                now.fetch_add(seconds, Ordering::SeqCst);
            }

            "reconfigure" => {
                // A new engine over the SAME store: exactly what a pepper
                // rotation deploy looks like.
                engine = build(
                    &cfg_kids_of(step, "peppers"),
                    str_at(step, "activeKid").expect("reconfigure has activeKid"),
                );
            }

            "failNextCas" => {
                store.fail_next_cas(str_at(step, "method").expect("failNextCas has a method"));
            }

            "expectStatusCounts" => {
                let mut actual: HashMap<&str, i64> =
                    HashMap::from([("active", 0), ("rotated", 0), ("revoked", 0)]);
                for r in store.all() {
                    *actual.get_mut(r.status.as_str()).expect("known status") += 1;
                }
                for (status, want) in step["counts"].as_object().expect("counts is an object") {
                    assert_eq!(
                        actual.get(status.as_str()).copied().unwrap_or(-1),
                        want.as_i64().expect("count is an integer"),
                        "{at}: {status} records (actual {actual:?})"
                    );
                }
            }

            "expectNoRawSecrets" => {
                // The `Debug` rendering is what a log line or a crash dump
                // would contain ([N-14]).
                let dump = format!("{:?}", store.all());
                for secret in &issued_secrets {
                    assert!(
                        !dump.contains(secret),
                        "{at}: a raw verifier reached the store ([N-14])"
                    );
                }
                for device_id in &device_ids {
                    assert!(
                        !dump.contains(device_id),
                        "{at}: a raw device identifier reached the store ([N-14])"
                    );
                }
            }

            other => panic!("{at}: unknown op {other:?}"),
        }
    }
}

fn cfg_kids_of(step: &Value, key: &str) -> Vec<String> {
    step[key]
        .as_array()
        .expect("peppers is an array")
        .iter()
        .map(|k| k.as_str().expect("kid is a string").to_string())
        .collect()
}

fn verifier_part(token: &str) -> String {
    token
        .split('.')
        .nth(3)
        .expect("an issued token has four parts")
        .to_string()
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[test]
fn every_applicable_scenario_passes() {
    let vectors = load_behavior_vectors();
    let outcome = run_behavior_vectors(&vectors);

    let published = vectors["counts"]["scenarios"]
        .as_u64()
        .expect("counts.scenarios") as usize;
    let unconditional = vectors["counts"]["unconditional"]
        .as_u64()
        .expect("counts.unconditional") as usize;

    for id in &outcome.executed {
        println!("executed: {id}");
    }
    // [N-48]: conditional scenarios that were not run are reported by id, never
    // quietly dropped.
    for (id, condition) in &outcome.skipped {
        println!("skipped:  {id} (condition not satisfied: {condition})");
    }

    assert_eq!(
        outcome.executed.len() + outcome.skipped.len(),
        published,
        "every published scenario must be executed or explicitly skipped ([N-48])"
    );
    assert!(
        outcome.executed.len() >= unconditional,
        "every unconditional scenario must be executed ([N-48])"
    );
    // Rust strings are UTF-8, so exactly the invalid-Unicode scenario is
    // inapplicable here.
    assert_eq!(
        outcome.skipped.len(),
        published - unconditional,
        "only conditional scenarios may be skipped"
    );
    assert_eq!(
        outcome
            .skipped
            .iter()
            .map(|(id, _)| id.as_str())
            .collect::<Vec<_>>(),
        vec!["device-05-invalid-unicode-is-a-mismatch-not-a-crash"]
    );
}

#[test]
fn spec_version_matches_the_published_scenarios() {
    assert_eq!(
        u64::from(nebula_token::SPEC_VERSION),
        load_behavior_vectors()["spec_version"]
            .as_u64()
            .expect("spec_version")
    );
}

#[test]
fn error_codes_cover_the_published_names() {
    // Every code named by any scenario must be a code this port can produce,
    // so a vector cannot expect an outcome the engine has no way to report.
    let vectors = load_behavior_vectors();
    let all = [
        ErrorCode::Malformed,
        ErrorCode::UnknownKid,
        ErrorCode::NotFound,
        ErrorCode::VerifierMismatch,
        ErrorCode::ReuseDetected,
        ErrorCode::Revoked,
        ErrorCode::ExpiredAbsolute,
        ErrorCode::ExpiredIdle,
        ErrorCode::DeviceMismatch,
        ErrorCode::Conflict,
    ];
    let known: HashSet<&str> = all.iter().map(|c| c.as_str()).collect();
    let mut seen = HashSet::new();
    for scenario in vectors["scenarios"].as_array().expect("scenarios") {
        for step in scenario["steps"].as_array().expect("steps") {
            if let Some(code) = step.get("expect").and_then(|e| str_at(e, "error")) {
                assert!(known.contains(code), "vectors expect unknown code {code:?}");
                seen.insert(code.to_string());
            }
        }
    }
    assert!(!seen.is_empty(), "no scenario expects any error code");
}
