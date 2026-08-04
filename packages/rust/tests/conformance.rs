//! Shared conformance vectors — `spec/test-vectors.json` ([N-47], [N-48]).
//!
//! The vectors are published data: this file only drives them. Every section is
//! required to execute exactly as many cases as the file's `counts` block
//! declares, so a runner that silently iterated nothing cannot report a pass.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use nebula_token::*;
use serde_json::Value;
use std::path::PathBuf;

/// Locate `spec/` by walking up from this package, so the suite keeps working
/// wherever the checkout lives and whatever the working directory is. The
/// vectors are never copied into the package — one file, ten implementations.
fn spec_dir() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        if dir.join("spec").join("test-vectors.json").is_file() {
            return dir.join("spec");
        }
        assert!(
            dir.pop(),
            "could not find spec/test-vectors.json above {}",
            env!("CARGO_MANIFEST_DIR")
        );
    }
}

fn vectors() -> Value {
    let path = spec_dir().join("test-vectors.json");
    let raw = std::fs::read_to_string(&path).expect("spec/test-vectors.json is readable");
    serde_json::from_str(&raw).expect("spec/test-vectors.json is valid JSON")
}

fn section<'a>(v: &'a Value, name: &str) -> &'a Vec<Value> {
    let cases = v[name]
        .as_array()
        .unwrap_or_else(|| panic!("section {name:?} is absent"));
    // [N-48]: an absent or empty section is a conformance failure.
    assert!(!cases.is_empty(), "section {name:?} is empty");
    cases
}

fn published_count(v: &Value, name: &str) -> usize {
    v["counts"][name]
        .as_u64()
        .unwrap_or_else(|| panic!("counts.{name} is absent")) as usize
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("field {key:?} is absent or not a string"))
}

#[test]
fn spec_version_matches_the_published_vectors() {
    assert_eq!(
        u64::from(SPEC_VERSION),
        vectors()["spec_version"].as_u64().unwrap()
    );
}

#[test]
fn constants_match_the_specification() {
    let v = vectors();
    let c = &v["constants"];
    assert_eq!(PREFIX, str_of(c, "prefix"));
    assert_eq!(SELECTOR_BYTES as u64, c["selector_bytes"].as_u64().unwrap());
    assert_eq!(VERIFIER_BYTES as u64, c["verifier_bytes"].as_u64().unwrap());
    assert_eq!(SELECTOR_CHARS as u64, c["selector_chars"].as_u64().unwrap());
    assert_eq!(VERIFIER_CHARS as u64, c["verifier_chars"].as_u64().unwrap());
    assert_eq!(MAX_KID_LENGTH as u64, c["max_kid_length"].as_u64().unwrap());
    assert_eq!(
        MAX_TOKEN_LENGTH as u64,
        c["max_token_length"].as_u64().unwrap()
    );
    assert_eq!(
        MIN_PEPPER_LENGTH as u64,
        c["min_pepper_length"].as_u64().unwrap()
    );
    assert_eq!(
        DEFAULT_ABSOLUTE_TTL,
        c["default_absolute_ttl_seconds"].as_i64().unwrap()
    );
    assert_eq!(
        DEFAULT_IDLE_TTL,
        c["default_idle_ttl_seconds"].as_i64().unwrap()
    );
    assert_eq!(
        DEFAULT_REUSE_GRACE,
        c["default_reuse_grace_seconds"].as_i64().unwrap()
    );

    // [N-48]: every constant the vectors publish is compared above, not only
    // the ones this file happened to remember.
    assert_eq!(
        c.as_object().expect("constants is an object").len(),
        11,
        "a constant was published but never asserted"
    );
}

#[test]
fn verifier_hashing_vectors() {
    let v = vectors();
    let mut executed = 0;
    for case in section(&v, "verifier_hashing") {
        let verifier = URL_SAFE_NO_PAD
            .decode(str_of(case, "verifier_b64url"))
            .expect("vector verifier is base64url");
        assert_eq!(
            hash_verifier(str_of(case, "pepper"), &verifier),
            str_of(case, "expected_hmac_sha256_hex"),
            "{}: {}",
            str_of(case, "id"),
            str_of(case, "note")
        );
        executed += 1;
    }
    assert_eq!(
        executed,
        published_count(&v, "verifier_hashing"),
        "executed count must equal the published count ([N-48])"
    );
}

#[test]
fn device_hashing_vectors() {
    let v = vectors();
    let mut executed = 0;
    for case in section(&v, "device_hashing") {
        assert_eq!(
            hash_device_id(str_of(case, "pepper"), str_of(case, "device_id")),
            str_of(case, "expected_hmac_sha256_hex"),
            "{}: {}",
            str_of(case, "id"),
            str_of(case, "note")
        );
        // [N-11] keys the HMAC on the UTF-8 encoding of the identifier, not on
        // however the runtime happens to hold it. A Rust `&str` *is* that
        // encoding, so the faithful conversion is `String::from_utf8`, and its
        // success is part of the assertion; a runner whose strings carry a
        // separate encoding tag has more to do. Either way the case's one
        // expected hash must come out, which is the portable statement of the
        // rule — and the assertion that a runtime cannot decide a device
        // identifier on anything but its bytes.
        if let Some(hex_bytes) = case["device_id_bytes"].as_str() {
            let id = str_of(case, "id");
            let bytes = hex::decode(hex_bytes).expect("vector device_id_bytes is hex");
            let from_bytes = String::from_utf8(bytes).expect("vector device_id_bytes is UTF-8");
            assert_eq!(
                from_bytes,
                str_of(case, "device_id"),
                "{id}: device_id_bytes must be the UTF-8 encoding of device_id"
            );
            assert_eq!(
                hash_device_id(str_of(case, "pepper"), &from_bytes),
                str_of(case, "expected_hmac_sha256_hex"),
                "{id} from bytes"
            );
        }
        executed += 1;
    }
    assert_eq!(
        executed,
        published_count(&v, "device_hashing"),
        "executed count must equal the published count ([N-48])"
    );
}

#[test]
fn parsing_vectors() {
    let v = vectors();
    let mut executed = 0;
    for case in section(&v, "parsing") {
        let (id, note) = (str_of(case, "id"), str_of(case, "note"));
        let parsed = parse_token(str_of(case, "token"));
        if case["valid"].as_bool().expect("vector declares validity") {
            let p = parsed.unwrap_or_else(|| panic!("{id} should parse: {note}"));
            assert_eq!(p.kid, str_of(case, "kid"), "{id}");
            assert_eq!(p.selector, str_of(case, "selector"), "{id}");
            assert_eq!(p.verifier.len(), VERIFIER_BYTES, "{id}");
        } else {
            assert!(
                parsed.is_none(),
                "{id} should be MALFORMED ({}): {note}",
                str_of(case, "rule")
            );
        }
        executed += 1;
    }
    assert_eq!(
        executed,
        published_count(&v, "parsing"),
        "executed count must equal the published count ([N-48])"
    );
}

#[test]
fn parsing_is_total_nothing_panics() {
    // [N-8]. The null-reference and invalid-UTF-8 cases of that requirement are
    // unrepresentable in `&str`, so what is left to prove is that no length,
    // alphabet or base64 edge case reaches a panicking path.
    let long_kid = format!("nbl.{}", "k".repeat(10_000));
    let spaces = format!("nbl.k1.{}.{}", " ".repeat(22), "A".repeat(43));
    let dots = ".".repeat(1000);
    let replacements = "\u{FFFD}".repeat(200);
    let hostile: [&str; 10] = [
        "",
        " ",
        ".",
        "...",
        &dots,
        &long_kid,
        &spaces,
        "nbl.k1.\u{1F600}\u{1F600}\u{1F600}\u{1F600}\u{1F600}.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        "nbl.\u{0}\u{0}.AAECAwQFBgcICQoLDA0ODw.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        &replacements,
    ];
    for input in hostile {
        assert!(
            parse_token(input).is_none(),
            "{input:?} must be refused as a value"
        );
    }
}
