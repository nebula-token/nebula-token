package nebulatoken

// Shared conformance vectors — spec/test-vectors.json (SPECIFICATION.md [N-47]).
//
// The vectors are data published once for all ten implementations; nothing in
// this file re-derives a case by hand. Every section asserts that the number of
// cases it executed equals the published count, so a runner that silently
// iterated zero cases fails instead of passing ([N-48]).

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type testVectors struct {
	SpecVersion int `json:"spec_version"`
	Counts      struct {
		VerifierHashing int `json:"verifier_hashing"`
		DeviceHashing   int `json:"device_hashing"`
		Parsing         int `json:"parsing"`
	} `json:"counts"`
	Constants       json.RawMessage `json:"constants"`
	VerifierHashing []struct {
		ID       string `json:"id"`
		Pepper   string `json:"pepper"`
		Verifier string `json:"verifier_b64url"`
		Note     string `json:"note"`
		Expected string `json:"expected_hmac_sha256_hex"`
	} `json:"verifier_hashing"`
	DeviceHashing []struct {
		ID       string `json:"id"`
		Pepper   string `json:"pepper"`
		DeviceID string `json:"device_id"`
		Note     string `json:"note"`
		Expected string `json:"expected_hmac_sha256_hex"`
	} `json:"device_hashing"`
	Parsing []struct {
		ID       string `json:"id"`
		Token    string `json:"token"`
		Valid    bool   `json:"valid"`
		Kid      string `json:"kid"`
		Selector string `json:"selector"`
		Note     string `json:"note"`
		Rule     string `json:"rule"`
	} `json:"parsing"`
}

// specDir walks up from this source file to the repository root and returns its
// spec/ directory. Walking beats a hardcoded path: the tests run from the
// package directory locally and from a bind mount in CI, and the vectors are
// never copied into the package — one published copy, ten implementations.
func specDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate this source file")
	}
	dir := filepath.Dir(thisFile)
	for {
		candidate := filepath.Join(dir, "spec")
		if _, err := os.Stat(filepath.Join(candidate, "test-vectors.json")); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no spec/test-vectors.json found walking up from %s", filepath.Dir(thisFile))
		}
		dir = parent
	}
}

func loadTestVectors(t *testing.T) testVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(specDir(t), "test-vectors.json"))
	if err != nil {
		t.Fatalf("cannot read vectors: %v", err)
	}
	var v testVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("cannot parse vectors: %v", err)
	}
	return v
}

func TestSpecVersionMatchesVectors(t *testing.T) {
	if got := loadTestVectors(t).SpecVersion; got != SpecVersion {
		t.Fatalf("package implements spec version %d, vectors publish %d", SpecVersion, got)
	}
}

// TestConstants compares every constant the specification publishes against the
// exported value, in both directions: a constant published but not compared is
// a conformance gap, and a comparison of something that is not published is a
// stale test ([N-4], [N-48]).
func TestConstants(t *testing.T) {
	published := map[string]json.RawMessage{}
	if err := json.Unmarshal(loadTestVectors(t).Constants, &published); err != nil {
		t.Fatalf("cannot parse constants section: %v", err)
	}
	if len(published) == 0 {
		t.Fatal("constants section is absent or empty ([N-48])")
	}

	ours := map[string]any{
		"prefix":                       Prefix,
		"selector_bytes":               SelectorBytes,
		"verifier_bytes":               VerifierBytes,
		"selector_chars":               SelectorChars,
		"verifier_chars":               VerifierChars,
		"max_kid_length":               MaxKidLength,
		"max_token_length":             MaxTokenLength,
		"min_pepper_length":            MinPepperLength,
		"default_absolute_ttl_seconds": DefaultAbsoluteTTL,
		"default_idle_ttl_seconds":     DefaultIdleTTL,
		"default_reuse_grace_seconds":  DefaultReuseGrace,
	}

	for name, want := range published {
		got, ok := ours[name]
		if !ok {
			t.Errorf("constant %q is published but never compared ([N-4])", name)
			continue
		}
		encoded, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(encoded) != string(want) {
			t.Errorf("constant %q: package has %s, specification publishes %s", name, encoded, want)
		}
	}
	for name := range ours {
		if _, ok := published[name]; !ok {
			t.Errorf("compared %q, which the specification does not publish", name)
		}
	}
}

func TestVerifierHashingVectors(t *testing.T) {
	v := loadTestVectors(t)
	n := 0
	for _, c := range v.VerifierHashing {
		verifier, err := base64.RawURLEncoding.DecodeString(c.Verifier)
		if err != nil {
			t.Fatalf("%s: unusable vector: %v", c.ID, err)
		}
		if got := HashVerifier(c.Pepper, verifier); got != c.Expected {
			t.Errorf("%s (%s): got %s want %s", c.ID, c.Note, got, c.Expected)
		}
		n++
	}
	if n != v.Counts.VerifierHashing {
		t.Fatalf("executed %d verifier_hashing cases, published count is %d ([N-48])", n, v.Counts.VerifierHashing)
	}
}

func TestDeviceHashingVectors(t *testing.T) {
	v := loadTestVectors(t)
	n := 0
	for _, c := range v.DeviceHashing {
		got, err := HashDeviceID(c.Pepper, c.DeviceID)
		if err != nil {
			t.Fatalf("%s (%s): unexpected error %v", c.ID, c.Note, err)
		}
		if got != c.Expected {
			t.Errorf("%s (%s): got %s want %s", c.ID, c.Note, got, c.Expected)
		}
		n++
	}
	if n != v.Counts.DeviceHashing {
		t.Fatalf("executed %d device_hashing cases, published count is %d ([N-48])", n, v.Counts.DeviceHashing)
	}
}

func TestParsingVectors(t *testing.T) {
	v := loadTestVectors(t)
	n := 0
	for _, c := range v.Parsing {
		parsed := ParseToken(c.Token)
		switch {
		case c.Valid && parsed == nil:
			t.Errorf("%s: expected a valid token (%s)", c.ID, c.Note)
		case c.Valid:
			if parsed.Kid != c.Kid {
				t.Errorf("%s: kid %q, want %q", c.ID, parsed.Kid, c.Kid)
			}
			if parsed.Selector != c.Selector {
				t.Errorf("%s: selector %q, want %q", c.ID, parsed.Selector, c.Selector)
			}
			if len(parsed.Verifier) != VerifierBytes {
				t.Errorf("%s: verifier decoded to %d bytes, want %d", c.ID, len(parsed.Verifier), VerifierBytes)
			}
		case parsed != nil:
			t.Errorf("%s: expected MALFORMED per %s (%s)", c.ID, c.Rule, c.Note)
		}
		n++
	}
	if n != v.Counts.Parsing {
		t.Fatalf("executed %d parsing cases, published count is %d ([N-48])", n, v.Counts.Parsing)
	}
}

// TestParsingIsTotal covers [N-8] for inputs no JSON vector can carry: Go
// strings are arbitrary byte sequences, so they reach the parser holding
// invalid UTF-8, NUL bytes and lone surrogates in WTF-8 form.
func TestParsingIsTotal(t *testing.T) {
	hostile := []string{
		"",
		" ",
		".",
		strings.Repeat(".", 1000),
		"nbl." + strings.Repeat("k", 10000),
		"nbl.k1." + strings.Repeat(" ", 22) + "." + strings.Repeat("A", 43),
		"nbl.k1.\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00." + strings.Repeat("A", 43),
		"\xff\xfe",
		"nbl.\xed\xa0\x80." + strings.Repeat("A", 22) + "." + strings.Repeat("A", 43),
		strings.Repeat("\xff", MaxTokenLength+1),
	}
	for _, in := range hostile {
		// A panic here fails the test by itself; the assertion pins the value.
		if got := ParseToken(in); got != nil {
			t.Errorf("ParseToken(%q) = %+v, want nil", in, got)
		}
	}
}
