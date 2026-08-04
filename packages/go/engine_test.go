package nebulatoken

// Language-specific tests: properties that cannot be expressed as portable
// behavior vectors. Every cross-language behaviour lives in
// spec/behavior-vectors.json and is exercised by behavior_test.go.
//
// Run with -race: the concurrency tests below are only meaningful when the
// detector is watching.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

const (
	testPepper = "pepper-one-0123456789abcdef0123456789ab"
	testHash   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 64 lowercase hex
)

func makeEngine(t *testing.T, mutate func(*Config)) (*Engine, *MemoryRefreshTokenStore, func(int64)) {
	t.Helper()
	store := NewMemoryRefreshTokenStore()
	now := int64(1_700_000_000)
	cfg := Config{
		Peppers:   map[string]string{"k1": testPepper},
		ActiveKid: "k1",
		Store:     store,
		Clock:     func() int64 { return now },
	}
	if mutate != nil {
		mutate(&cfg)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine, store, func(s int64) { now += s }
}

func mustIssue(t *testing.T, e *Engine, userID string, deviceID *string) *IssueResult {
	t.Helper()
	res, err := e.Issue(context.Background(), userID, deviceID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return res
}

func mustRefresh(t *testing.T, e *Engine, token string, deviceID *string) *RefreshResult {
	t.Helper()
	res, err := e.Refresh(context.Background(), token, deviceID)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	return res
}

func countStatus(records []*TokenRecord, status TokenStatus) int {
	n := 0
	for _, r := range records {
		if r.Status == status {
			n++
		}
	}
	return n
}

// ─── Constant-time comparison ([N-31]) ──────────────────────────────────────

func TestConstantTimeEqualHexRejectsAnythingButLowercaseHex64(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{"identical", testHash, testHash, true},
		{"different", testHash, strings.Repeat("b", 64), false},
		// A lenient hex decode stops at the first invalid character and compares
		// the decoded prefixes, so every case below would otherwise be EQUAL.
		{"odd-length prefixes", "abc", "abd", false},
		{"space-padded CHAR column", testHash, testHash + "   ", false},
		{"trailing newline", testHash, testHash + "\n", false},
		{"junk suffix", testHash, testHash + "zzzz", false},
		{"upper-cased by an ETL job", testHash, strings.ToUpper(testHash), false},
		{"both upper-cased", strings.ToUpper(testHash), strings.ToUpper(testHash), false},
		{"truncated column", testHash[:63], testHash[:63], false},
		{"empty", "", "", false},
		{"not hex at all", strings.Repeat("z", 64), strings.Repeat("z", 64), false},
		{"invalid utf-8", "\xff\xfe", testHash, false},
		{"64 spaces", strings.Repeat(" ", 64), testHash, false},
	}
	for _, c := range cases {
		if got := ConstantTimeEqualHex(c.a, c.b); got != c.want {
			t.Errorf("%s: ConstantTimeEqualHex = %v, want %v", c.name, got, c.want)
		}
		if got := ConstantTimeEqualHex(c.b, c.a); got != c.want {
			t.Errorf("%s (swapped): ConstantTimeEqualHex = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCorruptedStoredHashFailsClosed(t *testing.T) {
	ctx := context.Background()
	engine, store, _ := makeEngine(t, nil)
	issued := mustIssue(t, engine, "u1", nil)

	// The same record, but its hash column was upper-cased in transit.
	row := store.All()[0]
	row.Selector = strings.Repeat("x", 22)
	row.VerifierHash = strings.ToUpper(row.VerifierHash)
	if err := store.Insert(ctx, row); err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(issued.Token, ".")
	parts[2] = row.Selector
	if res := mustRefresh(t, engine, strings.Join(parts, "."), nil); res.OK || res.Error != CodeVerifierMismatch {
		t.Fatalf("an upper-cased stored hash must fail closed, got %+v", res)
	}
}

// ─── Concurrency ([N-17], [N-21], [N-34]) ───────────────────────────────────

// barrierStore holds every reader at the point where it has seen the record but
// not yet written, which is exactly the two-browser-tabs race of [N-34]. Without
// it the interleaving is up to the scheduler and the test would be flaky about
// which loser sees CONFLICT and which sees the ordinary reuse path.
type barrierStore struct {
	*MemoryRefreshTokenStore
	n    int
	mu   sync.Mutex
	seen int
	gate chan struct{}
}

func newBarrierStore(n int) *barrierStore {
	return &barrierStore{MemoryRefreshTokenStore: NewMemoryRefreshTokenStore(), n: n, gate: make(chan struct{})}
}

func (s *barrierStore) FindBySelector(ctx context.Context, selector string) (*TokenRecord, error) {
	record, err := s.MemoryRefreshTokenStore.FindBySelector(ctx, selector)
	s.mu.Lock()
	s.seen++
	if s.seen == s.n {
		close(s.gate)
	}
	s.mu.Unlock()
	<-s.gate
	return record, err
}

func TestConcurrentRefreshesLeaveExactlyOneActiveRecord(t *testing.T) {
	const goroutines = 8
	ctx := context.Background()
	store := newBarrierStore(goroutines)
	now := int64(1_700_000_000)
	engine, err := NewEngine(Config{
		Peppers:   map[string]string{"k1": testPepper},
		ActiveKid: "k1",
		Store:     store,
		Clock:     func() int64 { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := engine.Issue(ctx, "u1", nil)
	if err != nil {
		t.Fatal(err)
	}

	results := make([]*RefreshResult, goroutines)
	errs := make([]error, goroutines)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = engine.Refresh(ctx, issued.Token, nil)
		}(i)
	}
	wg.Wait()

	winners, conflicts := 0, 0
	for i, res := range results {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		switch {
		case res.OK:
			winners++
		case res.Error == CodeConflict:
			conflicts++
		default:
			t.Errorf("goroutine %d: expected CONFLICT, got %s", i, res.Error)
		}
	}
	if winners != 1 {
		t.Errorf("exactly one refresh may win the compare-and-set, %d did", winners)
	}
	if conflicts != goroutines-1 {
		t.Errorf("expected %d CONFLICT losers, got %d", goroutines-1, conflicts)
	}
	if active := countStatus(store.All(), StatusActive); active != 1 {
		t.Errorf("the family forked: %d active records, want 1", active)
	}
}

// TestConcurrentRefreshesUnderTheRealScheduler is the same race without the
// barrier: whichever way the scheduler interleaves, the family must never end
// up with two live lineages, and the in-memory store must not crash with
// "concurrent map writes" ([N-21]).
func TestConcurrentRefreshesUnderTheRealScheduler(t *testing.T) {
	ctx := context.Background()
	engine, store, _ := makeEngine(t, nil)
	issued := mustIssue(t, engine, "u1", nil)

	const goroutines = 32
	results := make([]*RefreshResult, goroutines)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := engine.Refresh(ctx, issued.Token, nil)
			if err != nil {
				t.Errorf("goroutine %d: %v", i, err)
				return
			}
			results[i] = res
		}(i)
	}
	wg.Wait()

	winners := 0
	for _, res := range results {
		if res != nil && res.OK {
			winners++
		}
	}
	if winners > 1 {
		t.Errorf("%d refreshes succeeded; at most one may", winners)
	}
	if active := countStatus(store.All(), StatusActive); active > 1 {
		t.Errorf("%d active records; the family forked", active)
	}
}

// TestMemoryStoreIsSafeForConcurrentUse pins [N-21]: net/http serves every
// request on its own goroutine, and an unsynchronised map here would abort the
// process with "fatal error: concurrent map writes", which no recover() can
// intercept.
func TestMemoryStoreIsSafeForConcurrentUse(t *testing.T) {
	ctx := context.Background()
	engine, store, _ := makeEngine(t, nil)

	const goroutines = 32
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			issued, err := engine.Issue(ctx, "u1", nil)
			if err != nil {
				t.Errorf("Issue: %v", err)
				return
			}
			if _, err := engine.Refresh(ctx, issued.Token, nil); err != nil {
				t.Errorf("Refresh: %v", err)
			}
			if _, err := engine.RevokeFamily(ctx, issued.FamilyID); err != nil {
				t.Errorf("RevokeFamily: %v", err)
			}
			store.All()
		}()
	}
	wg.Wait()

	if got := len(store.All()); got != goroutines*2 {
		t.Errorf("expected %d records, got %d", goroutines*2, got)
	}
}

// ─── Store failures fail closed ([N-20]) ────────────────────────────────────

var errOnFire = errors.New("database is on fire")

// explodingStore fails one method, optionally after letting the first `after`
// calls through, so a failure can be aimed at the rotation rather than the
// initial insert.
type explodingStore struct {
	inner  *MemoryRefreshTokenStore
	failOn string
	after  int
	mu     sync.Mutex
	calls  map[string]int
}

func newExplodingStore(failOn string, after int) *explodingStore {
	return &explodingStore{inner: NewMemoryRefreshTokenStore(), failOn: failOn, after: after, calls: map[string]int{}}
}

func (s *explodingStore) boom(method string) bool {
	if method != s.failOn {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls[method]++
	return s.calls[method] > s.after
}

func (s *explodingStore) FindBySelector(ctx context.Context, selector string) (*TokenRecord, error) {
	if s.boom("FindBySelector") {
		return nil, errOnFire
	}
	return s.inner.FindBySelector(ctx, selector)
}

func (s *explodingStore) Insert(ctx context.Context, record *TokenRecord) error {
	if s.boom("Insert") {
		return errOnFire
	}
	return s.inner.Insert(ctx, record)
}

func (s *explodingStore) MarkRotated(ctx context.Context, selector string, fromStatus TokenStatus, rotatedAt int64, replacedBySelector string) (bool, error) {
	if s.boom("MarkRotated") {
		return false, errOnFire
	}
	return s.inner.MarkRotated(ctx, selector, fromStatus, rotatedAt, replacedBySelector)
}

func (s *explodingStore) RevokeIfActive(ctx context.Context, selector string) (bool, error) {
	if s.boom("RevokeIfActive") {
		return false, errOnFire
	}
	return s.inner.RevokeIfActive(ctx, selector)
}

func (s *explodingStore) RevokeFamily(ctx context.Context, familyID string) (int, error) {
	if s.boom("RevokeFamily") {
		return 0, errOnFire
	}
	return s.inner.RevokeFamily(ctx, familyID)
}

func (s *explodingStore) RevokeUser(ctx context.Context, userID string) (int, error) {
	if s.boom("RevokeUser") {
		return 0, errOnFire
	}
	return s.inner.RevokeUser(ctx, userID)
}

func engineOver(t *testing.T, store RefreshTokenStore) *Engine {
	t.Helper()
	engine, err := NewEngine(Config{Peppers: map[string]string{"k1": testPepper}, ActiveKid: "k1", Store: store})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

// TestStoreFailuresFailClosed asserts [N-20]: an infrastructure failure
// propagates and is never converted into a protocol answer.
//
// go:S3776 measures cognitive complexity 31 here. The number is the sum of six
// independent t.Run subtests, each of which is five lines of flat, guard-only
// code; Sonar attributes a closure's complexity to the function that lexically
// contains it, so the idiomatic Go grouping construct reads as one large
// function. Promoting the six to top-level Test funcs would satisfy the rule and
// lose the grouping that says what they collectively assert. Suppressed in
// sonar-project.properties.
func TestStoreFailuresFailClosed(t *testing.T) {
	ctx := context.Background()

	t.Run("issue does not hand back a token for state that was never written", func(t *testing.T) {
		engine := engineOver(t, newExplodingStore("Insert", 0))
		res, err := engine.Issue(ctx, "u1", nil)
		if !errors.Is(err, errOnFire) {
			t.Fatalf("expected the store error to propagate, got %v", err)
		}
		if res != nil {
			t.Fatal("a token was returned for a row that does not exist")
		}
	})

	t.Run("a failing rotation insert is not reported as a rotation", func(t *testing.T) {
		store := newExplodingStore("Insert", 1) // the issue insert succeeds
		engine := engineOver(t, store)
		issued, err := engine.Issue(ctx, "u1", nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := engine.Refresh(ctx, issued.Token, nil)
		if !errors.Is(err, errOnFire) || res != nil {
			t.Fatalf("expected the store error to propagate, got (%+v, %v)", res, err)
		}
	})

	t.Run("a failing markRotated is not a silent success", func(t *testing.T) {
		store := newExplodingStore("MarkRotated", 0)
		engine := engineOver(t, store)
		issued, err := engine.Issue(ctx, "u1", nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := engine.Refresh(ctx, issued.Token, nil)
		if !errors.Is(err, errOnFire) || res != nil {
			t.Fatalf("expected the store error to propagate, got (%+v, %v)", res, err)
		}
	})

	t.Run("a failing lookup is not NOT_FOUND", func(t *testing.T) {
		store := newExplodingStore("FindBySelector", 0)
		engine := engineOver(t, store)
		// Mint a syntactically valid token without touching the failing store.
		other, _, _ := makeEngine(t, nil)
		issued := mustIssue(t, other, "u1", nil)
		res, err := engine.Refresh(ctx, issued.Token, nil)
		if !errors.Is(err, errOnFire) || res != nil {
			t.Fatalf("an unreachable store must not look like NOT_FOUND, got (%+v, %v)", res, err)
		}
	})

	t.Run("a failing revokeFamily is not a confident REUSE_DETECTED", func(t *testing.T) {
		store := newExplodingStore("RevokeFamily", 0)
		engine := engineOver(t, store)
		issued, err := engine.Issue(ctx, "u1", nil)
		if err != nil {
			t.Fatal(err)
		}
		if res, err := engine.Refresh(ctx, issued.Token, nil); err != nil || !res.OK {
			t.Fatalf("first rotation should succeed: (%+v, %v)", res, err)
		}
		res, err := engine.Refresh(ctx, issued.Token, nil)
		if !errors.Is(err, errOnFire) || res != nil {
			t.Fatalf("a revocation that did not happen must not be reported, got (%+v, %v)", res, err)
		}
	})

	t.Run("a failing revokeUser is not a revocation count", func(t *testing.T) {
		engine := engineOver(t, newExplodingStore("RevokeUser", 0))
		n, err := engine.RevokeAllForUser(ctx, "u1")
		if !errors.Is(err, errOnFire) || n != 0 {
			t.Fatalf("expected (0, error), got (%d, %v)", n, err)
		}
	})

	t.Run("a failing revokeFamily is not a revocation count", func(t *testing.T) {
		engine := engineOver(t, newExplodingStore("RevokeFamily", 0))
		n, err := engine.RevokeFamily(ctx, "f1")
		if !errors.Is(err, errOnFire) || n != 0 {
			t.Fatalf("expected (0, error), got (%d, %v)", n, err)
		}
	})
}

// ─── Configuration (§5, [N-23], [N-24]) ─────────────────────────────────────

func TestConfigValidation(t *testing.T) {
	store := NewMemoryRefreshTokenStore()
	cases := []struct {
		name string
		cfg  Config
	}{
		{"pepper below the byte floor", Config{Peppers: map[string]string{"k1": "short"}, ActiveKid: "k1", Store: store}},
		// [N-11] a Go string is arbitrary bytes, so a pepper can arrive without a
		// UTF-8 encoding; it is then not a usable HMAC key in any of the ten.
		{"pepper with no UTF-8 encoding", Config{Peppers: map[string]string{"k1": testPepper + loneSurrogate}, ActiveKid: "k1", Store: store}},
		{"pepper one byte short", Config{Peppers: map[string]string{"k1": strings.Repeat("a", 31)}, ActiveKid: "k1", Store: store}},
		{"activeKid absent", Config{Peppers: map[string]string{"k1": testPepper}, ActiveKid: "nope", Store: store}},
		{"no peppers at all", Config{Peppers: map[string]string{}, ActiveKid: "k1", Store: store}},
		{"kid outside the ABNF", Config{Peppers: map[string]string{"k.1": testPepper}, ActiveKid: "k.1", Store: store}},
		{"kid with a plus", Config{Peppers: map[string]string{"k+1": testPepper}, ActiveKid: "k+1", Store: store}},
		{"empty kid", Config{Peppers: map[string]string{"": testPepper}, ActiveKid: "", Store: store}},
		{"kid over MaxKidLength", Config{Peppers: map[string]string{strings.Repeat("k", 65): testPepper}, ActiveKid: strings.Repeat("k", 65), Store: store}},
		{"nil store", Config{Peppers: map[string]string{"k1": testPepper}, ActiveKid: "k1"}},
		{"negative absolute ttl", Config{Peppers: map[string]string{"k1": testPepper}, ActiveKid: "k1", Store: store, AbsoluteTTLSeconds: -1}},
		{"negative idle ttl", Config{Peppers: map[string]string{"k1": testPepper}, ActiveKid: "k1", Store: store, IdleTTLSeconds: -5}},
		{"negative grace", Config{Peppers: map[string]string{"k1": testPepper}, ActiveKid: "k1", Store: store, ReuseGraceSeconds: -1}},
	}
	for _, c := range cases {
		engine, err := NewEngine(c.cfg)
		if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: expected ErrInvalidConfig, got %v", c.name, err)
		}
		if engine != nil {
			t.Errorf("%s: an engine was returned for an invalid configuration", c.name)
		}
	}

	// A kid at exactly MaxKidLength is legal.
	kid := strings.Repeat("k", MaxKidLength)
	if _, err := NewEngine(Config{Peppers: map[string]string{kid: testPepper}, ActiveKid: kid, Store: store}); err != nil {
		t.Errorf("a %d-byte kid must be accepted: %v", MaxKidLength, err)
	}
}

func TestMinPepperLengthCountsBytesNotCharacters(t *testing.T) {
	store := NewMemoryRefreshTokenStore()

	wide := strings.Repeat("日", 16) // 16 characters, 48 UTF-8 bytes
	if utf8.RuneCountInString(wide) != 16 || len(wide) != 48 {
		t.Fatalf("test fixture is wrong: %d runes, %d bytes", utf8.RuneCountInString(wide), len(wide))
	}
	if _, err := NewEngine(Config{Peppers: map[string]string{"k1": wide}, ActiveKid: "k1", Store: store}); err != nil {
		t.Errorf("a 48-byte pepper must be accepted ([N-1]): %v", err)
	}
	if _, err := NewEngine(Config{Peppers: map[string]string{"k1": strings.Repeat("a", 31)}, ActiveKid: "k1", Store: store}); err == nil {
		t.Error("a 31-byte pepper must be rejected")
	}
}

func TestPepperMapIsCopied(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryRefreshTokenStore()
	peppers := map[string]string{"k1": testPepper}
	engine, err := NewEngine(Config{Peppers: peppers, ActiveKid: "k1", Store: store})
	if err != nil {
		t.Fatal(err)
	}

	// [N-24]: neither of these may reach the engine. Substituting a one-byte
	// secret would key the HMAC with something validation rejected; deleting
	// the active kid would, with a map lookup per call, key it with "".
	peppers["k1"] = "x"
	delete(peppers, "k1")

	issued, err := engine.Issue(ctx, "u1", nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed := ParseToken(issued.Token)
	if parsed == nil {
		t.Fatal("issued token must parse")
	}
	if got, want := store.All()[0].VerifierHash, HashVerifier(testPepper, parsed.Verifier); got != want {
		t.Errorf("the engine used a mutated pepper: %s != %s", got, want)
	}
	if res := mustRefresh(t, engine, issued.Token, nil); !res.OK {
		t.Errorf("the engine stopped working after the caller mutated its map: %s", res.Error)
	}
}

// ─── Device identifiers ([N-11], [N-12], [N-25], [N-32]) ────────────────────

func TestIssueRejectsInvalidUnicodeDeviceID(t *testing.T) {
	ctx := context.Background()
	engine, store, _ := makeEngine(t, nil)

	res, err := engine.Issue(ctx, "u1", Device(loneSurrogate))
	if !errors.Is(err, ErrInvalidDeviceID) {
		t.Fatalf("expected ErrInvalidDeviceID at the call site ([N-12]), got %v", err)
	}
	if res != nil {
		t.Fatal("a token was minted with a binding nothing can satisfy")
	}
	if err != nil && strings.Contains(err.Error(), loneSurrogate) {
		t.Error("the error message echoes the raw device identifier ([N-14])")
	}
	if len(store.All()) != 0 {
		t.Error("a record was written for a rejected issue")
	}
}

func TestRefreshTreatsInvalidUnicodeDeviceIDAsABindingFailure(t *testing.T) {
	engine, store, _ := makeEngine(t, nil)
	issued := mustIssue(t, engine, "u1", Device("devA"))

	// [N-12] attacker-controlled: a binding failure, never an error.
	res := mustRefresh(t, engine, issued.Token, Device(loneSurrogate))
	if res.OK || res.Error != CodeDeviceMismatch {
		t.Fatalf("expected DEVICE_MISMATCH, got %+v", res)
	}
	if revoked := countStatus(store.All(), StatusRevoked); revoked != 1 {
		t.Errorf("the family must be revoked, %d records revoked", revoked)
	}
}

func TestAbsentDeviceIDIsDistinctFromEmptyOne(t *testing.T) {
	unbound, store, _ := makeEngine(t, nil)
	issued := mustIssue(t, unbound, "u1", nil)
	if store.All()[0].DeviceIDHash != nil {
		t.Error("a nil deviceID must leave the record unbound")
	}
	if res := mustRefresh(t, unbound, issued.Token, Device("anything")); !res.OK {
		t.Errorf("an unbound family must ignore a presented device: %s", res.Error)
	}

	bound, boundStore, _ := makeEngine(t, nil)
	empty := mustIssue(t, bound, "u1", Device(""))
	hash := boundStore.All()[0].DeviceIDHash
	if hash == nil {
		t.Fatal(`Device("") must be a real binding, not "unbound" ([N-25])`)
	}
	want, err := HashDeviceID(testPepper, "")
	if err != nil {
		t.Fatal(err)
	}
	if *hash != want {
		t.Errorf("empty-string binding hashed as %s, want %s", *hash, want)
	}
	if res := mustRefresh(t, bound, empty.Token, Device("")); !res.OK {
		t.Fatalf("the empty identifier must satisfy its own binding: %s", res.Error)
	}
}

func TestBoundFamilyRefreshedWithoutADeviceIDFailsClosed(t *testing.T) {
	engine, _, _ := makeEngine(t, nil)
	issued := mustIssue(t, engine, "u1", Device(""))
	if res := mustRefresh(t, engine, issued.Token, nil); res.OK || res.Error != CodeDeviceMismatch {
		t.Fatalf("a missing identifier against a bound family must fail, got %+v", res)
	}
}

func TestHashDeviceIDAppliesNoNormalisation(t *testing.T) {
	must := func(deviceID string) string {
		t.Helper()
		h, err := HashDeviceID(testPepper, deviceID)
		if err != nil {
			t.Fatalf("HashDeviceID(%q): %v", deviceID, err)
		}
		return h
	}
	// [N-11]: NFC and NFD are different byte sequences and must stay different —
	// normalising here would make the same identifier hash differently from the
	// ports that do not normalise. The two spellings of "Cafe" are built from
	// code points rather than written literally, so that no editor can quietly
	// re-normalise this file and hide the regression.
	nfc := string([]rune{0x43, 0x61, 0x66, 0x00e9})
	nfd := string([]rune{0x43, 0x61, 0x66, 0x65, 0x0301})
	if must(nfc) == must(nfd) {
		t.Error("NFC and NFD must not be conflated")
	}
	if must("x") == must(" x") {
		t.Error("device identifiers must not be trimmed")
	}
	if must("x") == must("X") {
		t.Error("device identifiers must not be case-folded")
	}
	if _, err := HashDeviceID(testPepper, loneSurrogate); !errors.Is(err, ErrInvalidDeviceID) {
		t.Errorf("invalid UTF-8 has no defined hash ([N-12]), got %v", err)
	}
}

// ─── Privacy ([N-14]) ───────────────────────────────────────────────────────

func TestNoRawSecretReachesTheStore(t *testing.T) {
	engine, store, _ := makeEngine(t, nil)
	issued := mustIssue(t, engine, "u1", Device("devA"))
	if res := mustRefresh(t, engine, issued.Token, Device("devA")); !res.OK {
		t.Fatalf("rotation failed: %s", res.Error)
	}

	// JSON rather than %+v: the nullable columns are pointers, and %+v would
	// print their addresses instead of the values under test.
	dump, err := json.Marshal(store.All())
	if err != nil {
		t.Fatal(err)
	}
	text := string(dump)
	for _, secret := range []string{strings.Split(issued.Token, ".")[3], issued.Token, "devA", testPepper} {
		if strings.Contains(text, secret) {
			t.Errorf("the store holds a raw secret (%.12s…)", secret)
		}
	}
	for _, r := range store.All() {
		if len(r.VerifierHash) != 64 || r.DeviceIDHash == nil || len(*r.DeviceIDHash) != 64 {
			t.Errorf("hashes must be 64 lowercase hex characters: %+v", r)
		}
	}
}

// TestDebugRenderingsRedactSecrets pins the String methods of the three types
// that carry a live credential ([N-14], [N-46]).
//
// fmt's default struct rendering would print the token into every "%v" and
// "%+v" — a log line, an error message, a panic dump of a refresh handler's
// locals — and the verifier as a plain byte slice. Only the rendering is
// redacted: the fields themselves are untouched, so the caller still reads
// .Token and encoding/json still serialises it.
// TestEngineAndConfigRenderingsRedactPeppers covers the type that holds the KEY
// material rather than the credential ([N-46]). fmt reaches unexported fields
// by reflection, so before the String methods existed a single "%+v" on any
// struct embedding an engine printed every configured pepper — and an engine is
// long-lived application state, so the realistic trigger is a startup log or a
// panic dump, whose audience is far wider than the database's.
func TestEngineAndConfigRenderingsRedactPeppers(t *testing.T) {
	engine, store, _ := makeEngine(t, nil)
	cfg := Config{Peppers: map[string]string{"k1": testPepper}, ActiveKid: "k1", Store: store}

	check := func(name, rendered string) {
		t.Helper()
		if strings.Contains(rendered, testPepper) {
			t.Errorf("%s leaks the pepper: %s", name, rendered)
		}
		if !strings.Contains(rendered, "<redacted>") {
			t.Errorf("%s is not redacted: %s", name, rendered)
		}
		// The kid NAMES must survive: they are on the wire in every token and
		// are what makes a pepper-rotation problem legible.
		if !strings.Contains(rendered, "k1") {
			t.Errorf("%s lost the kid names: %s", name, rendered)
		}
	}

	check("Engine %v", fmt.Sprintf("%v", engine))
	check("Engine %+v", fmt.Sprintf("%+v", engine))
	check("Engine %#v", fmt.Sprintf("%#v", engine))
	check("Engine deref %+v", fmt.Sprintf("%+v", *engine))
	check("Config %v", fmt.Sprintf("%v", cfg))
	check("Config %+v", fmt.Sprintf("%+v", cfg))
	check("Config %#v", fmt.Sprintf("%#v", cfg))
}

func TestDebugRenderingsRedactSecrets(t *testing.T) {
	engine, _, _ := makeEngine(t, nil)
	issued := mustIssue(t, engine, "u1", nil)
	verifier := strings.Split(issued.Token, ".")[3]

	for _, rendered := range []string{fmt.Sprintf("%v", issued), fmt.Sprintf("%+v", issued), issued.String()} {
		if strings.Contains(rendered, issued.Token) || strings.Contains(rendered, verifier) {
			t.Errorf("IssueResult rendering leaks the token: %s", rendered)
		}
		if !strings.Contains(rendered, "<redacted>") {
			t.Errorf("IssueResult rendering is not redacted: %s", rendered)
		}
		// The redaction must not cost the fields anyone actually debugs with.
		if !strings.Contains(rendered, "u1") || !strings.Contains(rendered, issued.FamilyID) {
			t.Errorf("IssueResult rendering lost its family metadata: %s", rendered)
		}
	}
	// …and the caller still gets the value itself.
	if !strings.HasPrefix(issued.Token, "nbl.") {
		t.Error("the Token field must be untouched")
	}

	parsed := ParseToken(issued.Token)
	if parsed == nil {
		t.Fatal("ParseToken rejected a freshly minted token")
	}
	for _, rendered := range []string{fmt.Sprintf("%v", parsed), fmt.Sprintf("%+v", *parsed)} {
		if strings.Contains(rendered, fmt.Sprintf("%d", parsed.Verifier[0])) && strings.Contains(rendered, "[") {
			t.Errorf("ParsedToken rendering leaks the verifier bytes: %s", rendered)
		}
		if !strings.Contains(rendered, "<redacted>") {
			t.Errorf("ParsedToken rendering is not redacted: %s", rendered)
		}
		// The selector is the one loggable correlation id ([N-46]).
		if !strings.Contains(rendered, parsed.Selector) {
			t.Errorf("ParsedToken rendering dropped the selector: %s", rendered)
		}
	}

	res := mustRefresh(t, engine, issued.Token, nil)
	if !res.OK {
		t.Fatalf("rotation failed: %s", res.Error)
	}
	for _, rendered := range []string{fmt.Sprintf("%v", res), fmt.Sprintf("%+v", *res)} {
		if strings.Contains(rendered, res.Token) || strings.Contains(rendered, strings.Split(res.Token, ".")[3]) {
			t.Errorf("RefreshResult rendering leaks the successor token: %s", rendered)
		}
		if !strings.Contains(rendered, "<redacted>") || !strings.Contains(rendered, res.FamilyID) {
			t.Errorf("RefreshResult rendering is wrong: %s", rendered)
		}
	}
	// A failure carries no token; its rendering shows the error and the
	// attribution instead ([N-39]).
	failed, err := engine.Refresh(context.Background(), "not-a-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rendered := fmt.Sprintf("%v", failed); !strings.Contains(rendered, "MALFORMED") {
		t.Errorf("a failure rendering must name its code: %s", rendered)
	}
}

// ─── Result shape ([N-2], [N-39]) ───────────────────────────────────────────

func TestResultTimestampsAreUnixSeconds(t *testing.T) {
	engine, _, _ := makeEngine(t, func(c *Config) { c.AbsoluteTTLSeconds = 3600; c.IdleTTLSeconds = 600 })
	issued := mustIssue(t, engine, "u1", nil)
	if issued.ExpiresAt != 1_700_000_000+3600 {
		t.Errorf("ExpiresAt = %d", issued.ExpiresAt)
	}
	if issued.IdleExpiresAt != 1_700_000_000+600 {
		t.Errorf("IdleExpiresAt = %d", issued.IdleExpiresAt)
	}
	if issued.UserID != "u1" || issued.Generation != 0 || issued.FamilyID == "" {
		t.Errorf("IssueResult is missing family metadata: %+v", issued)
	}
	res := mustRefresh(t, engine, issued.Token, nil)
	if res.ExpiresAt != issued.ExpiresAt || res.IdleExpiresAt != issued.IdleExpiresAt {
		t.Errorf("refresh timestamps: %+v", res)
	}
}

func TestFailuresCarryAttributionOnceARecordIsResolved(t *testing.T) {
	engine, _, _ := makeEngine(t, nil)
	issued := mustIssue(t, engine, "u1", nil)
	mustRefresh(t, engine, issued.Token, nil)

	replay := mustRefresh(t, engine, issued.Token, nil)
	if replay.UserID != "u1" || replay.FamilyID != issued.FamilyID {
		t.Errorf("REUSE_DETECTED must carry userId and familyId ([N-39]): %+v", replay)
	}
	// Before a record is resolved there is nothing to attribute.
	for _, token := range []string{"garbage", strings.Replace(issued.Token, ".k1.", ".zz.", 1)} {
		res := mustRefresh(t, engine, token, nil)
		if res.UserID != "" || res.FamilyID != "" {
			t.Errorf("%s must not carry attribution: %+v", res.Error, res)
		}
	}
}

// ─── Store hygiene ──────────────────────────────────────────────────────────

func TestMemoryStoreRefusesADuplicateSelector(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryRefreshTokenStore()
	row := &TokenRecord{
		Selector: strings.Repeat("A", 22), VerifierHash: testHash, Kid: "k1", FamilyID: "f",
		UserID: "u1", CreatedAt: 0, FamilyExpiresAt: 1, IdleExpiresAt: 1, Status: StatusActive,
	}
	if err := store.Insert(ctx, row); err != nil {
		t.Fatal(err)
	}
	if err := store.Insert(ctx, row); err == nil {
		t.Fatal("a duplicate selector must not silently overwrite a live record")
	}
}

func TestDeleteExpiredKeepsRecordsUntilTheFamilyDeadline(t *testing.T) {
	engine, store, _ := makeEngine(t, func(c *Config) { c.AbsoluteTTLSeconds = 100; c.IdleTTLSeconds = 100 })
	issued := mustIssue(t, engine, "u1", nil)
	mustRefresh(t, engine, issued.Token, nil)

	// [N-15]: dropping a rotated record early turns every replay into
	// NOT_FOUND and disables reuse detection.
	if n := store.DeleteExpired(1_700_000_099); n != 0 {
		t.Errorf("deleted %d records before the family deadline", n)
	}
	if got := len(store.All()); got != 2 {
		t.Errorf("expected 2 records, got %d", got)
	}
	if n := store.DeleteExpired(1_700_000_100); n != 2 {
		t.Errorf("expected 2 records collected at the deadline, got %d", n)
	}
}

// ─── Store contract ─────────────────────────────────────────────────────────

// The reference store must satisfy the interface it documents; the sqlstore
// example under examples/ is compiled by the same `go build ./...`.
var _ RefreshTokenStore = (*MemoryRefreshTokenStore)(nil)
