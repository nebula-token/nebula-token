package nebulatoken

// Runner for the normative behavioral suite — spec/behavior-vectors.json
// (SPECIFICATION.md [N-47], [N-49]).
//
// The scenarios are data. This file is the only part that is language-specific,
// which is what stops the ten ports from drifting apart the way ten
// hand-written suites did. Nothing here may be edited to make a scenario pass:
// if a vector looks wrong, report it.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// satisfiedConditions lists the runner conditions this runtime meets.
//
// A Go string is an arbitrary byte sequence, not a sequence of scalar values:
// it can hold the WTF-8 encoding of an unpaired surrogate (and any other
// invalid UTF-8) exactly as JavaScript, Java, C#, Dart and Python can hold one.
// So this runtime DOES admit invalid-Unicode strings and executes that
// scenario rather than skipping it ([N-12]).
var satisfiedConditions = map[string]bool{
	"runtime-admits-invalid-unicode-strings": true,
}

const (
	// 32 zero bytes, canonically encoded: well-formed, and never the real secret.
	forgedVerifier = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	forgedSelector = "AAAAAAAAAAAAAAAAAAAAAA"
	// U+D800 in WTF-8. Go source cannot spell "\uD800" — the compiler rejects a
	// surrogate escape — so the byte sequence that carries one is written out.
	loneSurrogate = "\xed\xa0\x80"
)

// ─── Vector shapes ───────────────────────────────────────────────────────────

type behaviorVectors struct {
	SpecVersion int `json:"spec_version"`
	Counts      struct {
		Scenarios     int `json:"scenarios"`
		Unconditional int `json:"unconditional"`
	} `json:"counts"`
	Peppers   map[string]string `json:"peppers"`
	Defaults  runConfig         `json:"defaults"`
	Scenarios []scenario        `json:"scenarios"`
}

type runConfig struct {
	Now                int64    `json:"now"`
	AbsoluteTTLSeconds int64    `json:"absoluteTtlSeconds"`
	IdleTTLSeconds     int64    `json:"idleTtlSeconds"`
	ReuseGraceSeconds  int64    `json:"reuseGraceSeconds"`
	ActiveKid          string   `json:"activeKid"`
	Peppers            []string `json:"peppers"`
}

// configOverride mirrors runConfig with every field optional, so that a
// scenario overriding reuseGraceSeconds to 0 is distinguishable from one that
// does not mention it.
type configOverride struct {
	Now                *int64   `json:"now"`
	AbsoluteTTLSeconds *int64   `json:"absoluteTtlSeconds"`
	IdleTTLSeconds     *int64   `json:"idleTtlSeconds"`
	ReuseGraceSeconds  *int64   `json:"reuseGraceSeconds"`
	ActiveKid          *string  `json:"activeKid"`
	Peppers            []string `json:"peppers"`
}

type scenario struct {
	ID           string          `json:"id"`
	Title        string          `json:"title"`
	Requirements []string        `json:"requirements"`
	Condition    string          `json:"condition"`
	Config       *configOverride `json:"config"`
	Steps        []step          `json:"steps"`
}

type step struct {
	Op string `json:"op"`
	// DeviceID is a pointer: an absent device identifier and an empty-string
	// one are different bindings ([N-25]).
	DeviceID     *string        `json:"deviceId"`
	DeviceIDKind string         `json:"deviceIdKind"`
	UserID       string         `json:"userId"`
	Token        *tokenRef      `json:"token"`
	Bind         string         `json:"bind"`
	Of           string         `json:"of"`
	Seconds      int64          `json:"seconds"`
	Method       string         `json:"method"`
	Peppers      []string       `json:"peppers"`
	ActiveKid    string         `json:"activeKid"`
	Counts       map[string]int `json:"counts"`
	Expect       *expectation   `json:"expect"`
}

type tokenRef struct {
	Ref string `json:"ref"`
	// Literal is a pointer because "" is one of the published MALFORMED cases.
	Literal *string `json:"literal"`
	Forge   string  `json:"forge"`
}

type expectation struct {
	OK                *bool  `json:"ok"`
	Error             string `json:"error"`
	Generation        *int   `json:"generation"`
	Kid               string `json:"kid"`
	SameFamilyAs      string `json:"sameFamilyAs"`
	SameExpiresAtAs   string `json:"sameExpiresAtAs"`
	IdleEqualsExpires bool   `json:"idleEqualsExpires"`
	// HasUserID and HasFamilyID are tri-state ([N-39]), so they are pointers:
	// true demands the field, false demands its absence, and a nil pointer —
	// the key absent from the vector — asserts nothing.
	HasUserID   *bool `json:"hasUserId"`
	HasFamilyID *bool `json:"hasFamilyId"`
	Revoked     *int  `json:"revoked"`
}

// presence spells a tri-state [N-39] expectation for a failure message.
func presence(want bool) string {
	if want {
		return "present"
	}
	return "absent"
}

func (c runConfig) with(o *configOverride) runConfig {
	if o == nil {
		return c
	}
	if o.Now != nil {
		c.Now = *o.Now
	}
	if o.AbsoluteTTLSeconds != nil {
		c.AbsoluteTTLSeconds = *o.AbsoluteTTLSeconds
	}
	if o.IdleTTLSeconds != nil {
		c.IdleTTLSeconds = *o.IdleTTLSeconds
	}
	if o.ReuseGraceSeconds != nil {
		c.ReuseGraceSeconds = *o.ReuseGraceSeconds
	}
	if o.ActiveKid != nil {
		c.ActiveKid = *o.ActiveKid
	}
	if o.Peppers != nil {
		c.Peppers = o.Peppers
	}
	return c
}

func loadBehaviorVectors(t *testing.T) behaviorVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(specDir(t), "behavior-vectors.json"))
	if err != nil {
		t.Fatalf("cannot read behavior vectors: %v", err)
	}
	var v behaviorVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("cannot parse behavior vectors: %v", err)
	}
	return v
}

// ─── Store wrapper ───────────────────────────────────────────────────────────

// controllableStore wraps the reference store so a scenario can force one
// compare-and-set to lose, which is how the CONFLICT paths are reachable
// deterministically.
type controllableStore struct {
	inner    *MemoryRefreshTokenStore
	mu       sync.Mutex
	failNext map[string]bool
}

func newControllableStore() *controllableStore {
	return &controllableStore{inner: NewMemoryRefreshTokenStore(), failNext: map[string]bool{}}
}

func (s *controllableStore) failNextCas(method string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failNext[method] = true
}

func (s *controllableStore) consume(method string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failNext[method] {
		s.failNext[method] = false
		return true
	}
	return false
}

func (s *controllableStore) FindBySelector(ctx context.Context, selector string) (*TokenRecord, error) {
	return s.inner.FindBySelector(ctx, selector)
}

func (s *controllableStore) Insert(ctx context.Context, record *TokenRecord) error {
	return s.inner.Insert(ctx, record)
}

func (s *controllableStore) MarkRotated(ctx context.Context, selector string, fromStatus TokenStatus, rotatedAt int64, replacedBySelector string) (bool, error) {
	if s.consume("markRotated") {
		return false, nil
	}
	return s.inner.MarkRotated(ctx, selector, fromStatus, rotatedAt, replacedBySelector)
}

func (s *controllableStore) RevokeIfActive(ctx context.Context, selector string) (bool, error) {
	if s.consume("revokeIfActive") {
		return false, nil
	}
	return s.inner.RevokeIfActive(ctx, selector)
}

func (s *controllableStore) RevokeFamily(ctx context.Context, familyID string) (int, error) {
	return s.inner.RevokeFamily(ctx, familyID)
}

func (s *controllableStore) RevokeUser(ctx context.Context, userID string) (int, error) {
	return s.inner.RevokeUser(ctx, userID)
}

// ─── Runner ──────────────────────────────────────────────────────────────────

type binding struct {
	token     string
	familyID  string
	expiresAt int64
}

// successView normalises IssueResult and a successful RefreshResult so the
// expectation checks are written once.
type successView struct {
	token         string
	familyID      string
	generation    int
	expiresAt     int64
	idleExpiresAt int64
}

func TestBehaviorVectors(t *testing.T) {
	v := loadBehaviorVectors(t)
	if v.SpecVersion != SpecVersion {
		t.Fatalf("package implements spec version %d, vectors publish %d", SpecVersion, v.SpecVersion)
	}
	if len(v.Scenarios) == 0 {
		t.Fatal("behavioral suite is absent or empty ([N-48])")
	}

	var executed, skipped []string
	for _, sc := range v.Scenarios {
		sc := sc
		if sc.Condition != "" && !satisfiedConditions[sc.Condition] {
			skipped = append(skipped, fmt.Sprintf("%s (%s)", sc.ID, sc.Condition))
			t.Run(sc.ID, func(t *testing.T) { t.Skipf("runtime does not satisfy %q", sc.Condition) })
			continue
		}
		executed = append(executed, sc.ID)
		// Each scenario is a named subtest over its own store and clock, so a
		// failure names the vector and no scenario can leak state into another.
		t.Run(sc.ID, func(t *testing.T) { runScenario(t, v, sc) })
	}

	// [N-48]: a runner that silently iterated nothing must not report success.
	if got := len(executed) + len(skipped); got != v.Counts.Scenarios {
		t.Errorf("saw %d scenarios, published count is %d", got, v.Counts.Scenarios)
	}
	if len(executed) < v.Counts.Unconditional {
		t.Errorf("executed %d scenarios, %d are unconditional", len(executed), v.Counts.Unconditional)
	}
	// Report every skipped scenario by id, as the runner contract requires.
	if len(skipped) > 0 {
		t.Logf("skipped %d conditional scenario(s): %s", len(skipped), strings.Join(skipped, ", "))
	} else {
		t.Logf("executed all %d published scenarios, none skipped", len(executed))
	}
}

// runScenario executes one scenario's steps against a fresh engine and store.
//
// go:S3776 measures cognitive complexity 150 against a threshold of 15 — the
// highest number in the repository, and an accurate one. It is suppressed rather
// than refactored, for the reason the file exists:
//
// The switch below is an interpreter for the step vocabulary published in
// spec/behavior-vectors.json under `runner.ops`. Each case is one entry of that
// table, in the same order, so that a reviewer checking this runtime against the
// vectors reads the two side by side. That one-to-one correspondence is what
// makes a conformance runner auditable at all, and a dispatch over a published
// op vocabulary is branchy by construction: the branching belongs to the
// specification, not to this function.
//
// Go inflates the count further than the other ports for two reasons that are
// conventions rather than choices: every store and engine call is followed by an
// `if err != nil` guard, and every assertion is an explicit `if ... { t.Fatalf }`
// rather than an assertion library call. Neither is removable without making the
// runner less like ordinary Go.
//
// Per-op functions were considered and rejected: the ops share one mutable
// scenario state (engine, store, bindings, issuedSecrets, presentedDeviceIDs,
// now), "reconfigure" reassigns engine and "advance" reassigns now, so each
// extracted function would need a pointer to a context struct, and the dispatch
// table would stop resembling the vector format. Sonar has no inline suppression
// form for Go; the entry is in sonar-project.properties.
func runScenario(t *testing.T, v behaviorVectors, sc scenario) {
	t.Helper()
	ctx := context.Background()
	cfg := v.Defaults.with(sc.Config)
	store := newControllableStore()
	bindings := map[string]binding{}
	var issuedSecrets, presentedDeviceIDs []string
	now := cfg.Now

	failf := func(i int, format string, args ...any) {
		t.Helper()
		t.Fatalf("[%s] step %d (%s): %s", sc.ID, i, strings.Join(sc.Requirements, ", "), fmt.Sprintf(format, args...))
	}

	build := func(kids []string, activeKid string) *Engine {
		peppers := make(map[string]string, len(kids))
		for _, kid := range kids {
			secret, ok := v.Peppers[kid]
			if !ok {
				t.Fatalf("[%s] vectors do not publish a pepper for kid %q", sc.ID, kid)
			}
			peppers[kid] = secret
		}
		engine, err := NewEngine(Config{
			Peppers:            peppers,
			ActiveKid:          activeKid,
			Store:              store,
			AbsoluteTTLSeconds: cfg.AbsoluteTTLSeconds,
			IdleTTLSeconds:     cfg.IdleTTLSeconds,
			ReuseGraceSeconds:  cfg.ReuseGraceSeconds,
			Clock:              func() int64 { return now },
		})
		if err != nil {
			t.Fatalf("[%s] cannot build engine: %v", sc.ID, err)
		}
		return engine
	}
	engine := build(cfg.Peppers, cfg.ActiveKid)

	resolveToken := func(i int, ref *tokenRef) string {
		if ref == nil {
			failf(i, "step has no token reference")
			return ""
		}
		if ref.Literal != nil {
			return *ref.Literal
		}
		bound, ok := bindings[ref.Ref]
		if !ok {
			failf(i, "unknown binding %q", ref.Ref)
			return ""
		}
		if ref.Forge == "" {
			return bound.token
		}
		parts := strings.Split(bound.token, ".")
		switch ref.Forge {
		case "verifier":
			parts[3] = forgedVerifier
		case "unknownKid":
			parts[1] = "zz"
		case "unknownSelector":
			parts[2] = forgedSelector
		default:
			failf(i, "unknown forge %q", ref.Forge)
		}
		return strings.Join(parts, ".")
	}

	deviceOf := func(st step) *string {
		if st.DeviceIDKind == "lone-surrogate" {
			s := loneSurrogate
			return &s
		}
		return st.DeviceID
	}

	remember := func(st step, sv successView) {
		if st.Bind != "" {
			bindings[st.Bind] = binding{token: sv.token, familyID: sv.familyID, expiresAt: sv.expiresAt}
		}
		if parts := strings.Split(sv.token, "."); len(parts) == 4 {
			issuedSecrets = append(issuedSecrets, parts[3])
		}
		if d := deviceOf(st); d != nil && *d != "" {
			presentedDeviceIDs = append(presentedDeviceIDs, *d)
		}
	}

	// checkAttribution asserts the tri-state [N-39] expectation on a failure
	// result. true demands the field, false demands its absence — the exclusion
	// list (MALFORMED, UNKNOWN_KID, NOT_FOUND) is a requirement too, and the
	// truthy-only check this replaced could never observe it. Absent asserts
	// nothing. Go's failure results always carry the fields, so "absent" reads
	// as the empty string, which is how the engine signals "no record was
	// resolved" on both the Refresh and the RevokeToken path.
	checkAttribution := func(i int, userID, familyID string, exp *expectation) {
		if exp == nil {
			return
		}
		if exp.HasUserID != nil && (userID != "") != *exp.HasUserID {
			failf(i, "expected userId %s ([N-39])", presence(*exp.HasUserID))
		}
		if exp.HasFamilyID != nil && (familyID != "") != *exp.HasFamilyID {
			failf(i, "expected familyId %s ([N-39])", presence(*exp.HasFamilyID))
		}
	}

	checkSuccess := func(i int, sv successView, exp *expectation) {
		if exp == nil {
			return
		}
		if exp.Generation != nil && sv.generation != *exp.Generation {
			failf(i, "expected generation %d, got %d", *exp.Generation, sv.generation)
		}
		if exp.Kid != "" {
			if kid := strings.Split(sv.token, ".")[1]; kid != exp.Kid {
				failf(i, "expected kid %q, got %q", exp.Kid, kid)
			}
		}
		if exp.SameFamilyAs != "" && sv.familyID != bindings[exp.SameFamilyAs].familyID {
			failf(i, "familyId changed across rotation")
		}
		if exp.SameExpiresAtAs != "" {
			if want := bindings[exp.SameExpiresAtAs].expiresAt; sv.expiresAt != want {
				failf(i, "absolute deadline moved: %d -> %d", want, sv.expiresAt)
			}
		}
		if exp.IdleEqualsExpires && sv.idleExpiresAt != sv.expiresAt {
			failf(i, "idleExpiresAt %d should be clamped to %d", sv.idleExpiresAt, sv.expiresAt)
		}
	}

	for i, st := range sc.Steps {
		exp := st.Expect

		switch st.Op {
		case "issue":
			res, err := engine.Issue(ctx, st.UserID, deviceOf(st))
			if err != nil {
				failf(i, "issue returned an infrastructure error: %v", err)
			}
			if exp != nil && exp.OK != nil && !*exp.OK {
				failf(i, "expected issue to fail")
			}
			sv := successView{res.Token, res.FamilyID, res.Generation, res.ExpiresAt, res.IdleExpiresAt}
			checkSuccess(i, sv, exp)
			remember(st, sv)

		case "refresh":
			res, err := engine.Refresh(ctx, resolveToken(i, st.Token), deviceOf(st))
			if err != nil {
				failf(i, "refresh returned an infrastructure error: %v", err)
			}
			wantOK := exp == nil || (exp.OK != nil && *exp.OK) || (exp.OK == nil && exp.Error == "")
			if wantOK {
				if !res.OK {
					failf(i, "expected success, got %s", res.Error)
				}
				sv := successView{res.Token, res.FamilyID, res.Generation, res.ExpiresAt, res.IdleExpiresAt}
				checkSuccess(i, sv, exp)
				remember(st, sv)
				break
			}
			if res.OK {
				failf(i, "expected %s, got success", exp.Error)
			}
			if string(res.Error) != exp.Error {
				failf(i, "expected %s, got %s", exp.Error, res.Error)
			}
			checkAttribution(i, res.UserID, res.FamilyID, exp)

		case "revokeToken":
			res, err := engine.RevokeToken(ctx, resolveToken(i, st.Token))
			if err != nil {
				failf(i, "revokeToken returned an infrastructure error: %v", err)
			}
			if exp != nil && exp.OK != nil && !*exp.OK {
				if res.OK {
					failf(i, "expected %s, got success", exp.Error)
				}
				if string(res.Error) != exp.Error {
					failf(i, "expected %s, got %s", exp.Error, res.Error)
				}
				// [N-39] governs every failure result, RevokeToken's included.
				checkAttribution(i, res.UserID, res.FamilyID, exp)
				break
			}
			if !res.OK {
				failf(i, "expected success, got %s", res.Error)
			}
			if exp != nil && exp.Revoked != nil && res.Revoked != *exp.Revoked {
				failf(i, "expected %d revoked, got %d", *exp.Revoked, res.Revoked)
			}

		case "revokeFamilyOf":
			bound, ok := bindings[st.Of]
			if !ok {
				failf(i, "unknown binding %q", st.Of)
			}
			n, err := engine.RevokeFamily(ctx, bound.familyID)
			if err != nil {
				failf(i, "revokeFamily returned an infrastructure error: %v", err)
			}
			if exp != nil && exp.Revoked != nil && n != *exp.Revoked {
				failf(i, "expected %d revoked, got %d", *exp.Revoked, n)
			}

		case "revokeUser":
			n, err := engine.RevokeAllForUser(ctx, st.UserID)
			if err != nil {
				failf(i, "revokeAllForUser returned an infrastructure error: %v", err)
			}
			if exp != nil && exp.Revoked != nil && n != *exp.Revoked {
				failf(i, "expected %d revoked, got %d", *exp.Revoked, n)
			}

		case "advance":
			now += st.Seconds

		case "reconfigure":
			engine = build(st.Peppers, st.ActiveKid)

		case "failNextCas":
			store.failNextCas(st.Method)

		case "expectStatusCounts":
			actual := map[string]int{"active": 0, "rotated": 0, "revoked": 0}
			for _, r := range store.inner.All() {
				actual[string(r.Status)]++
			}
			for status, want := range st.Counts {
				if actual[status] != want {
					failf(i, "expected %d %s, got %d (%v)", want, status, actual[status], actual)
				}
			}

		case "expectNoRawSecrets":
			dump, err := json.Marshal(store.inner.All())
			if err != nil {
				failf(i, "cannot serialise the store: %v", err)
			}
			for _, secret := range issuedSecrets {
				if strings.Contains(string(dump), secret) {
					failf(i, "a raw verifier reached the store ([N-14])")
				}
			}
			for _, device := range presentedDeviceIDs {
				if strings.Contains(string(dump), device) {
					failf(i, "a raw device identifier reached the store ([N-14])")
				}
			}

		default:
			failf(i, "unknown op %q", st.Op)
		}
	}
}
