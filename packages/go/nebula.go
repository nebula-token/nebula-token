// Package nebulatoken implements NEBULA — opaque rotating refresh tokens.
//
// Go implementation of SPECIFICATION.md (spec version 1). Standard library
// only, Go >= 1.25. Requirement identifiers in comments ([N-*]) refer to that
// document, which is normative for every behaviour in this file.
//
// The import path is github.com/nebula-token/nebula-token/packages/go — the
// module is a submodule of the NEBULA monorepo, so it is versioned by tags
// prefixed with that directory (packages/go/v1.0.0), never by a bare vX.Y.Z.
//
// The package name is nebulatoken rather than nebula, and rather than the last
// element of the path: the short name collides head-on with
// github.com/slackhq/nebula, an unrelated — and also security-critical —
// overlay network, and a mistaken import in an auth path is expensive. Import
// it with the explicit qualifier:
//
//	import nebulatoken "github.com/nebula-token/nebula-token/packages/go"
//
// Store and engine methods take a context.Context first and return
// (value, error): protocol outcomes are the value, infrastructure failures are
// the error ([N-20]).
package nebulatoken

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// ─── Spec constants (§1) ─────────────────────────────────────────────────────

// Every constant of §1 is exported as a named value ([N-4]).
const (
	// SpecVersion is the version of SPECIFICATION.md this package implements ([N-52]).
	SpecVersion = 1

	Prefix          = "nbl"
	SelectorBytes   = 16
	VerifierBytes   = 32
	SelectorChars   = 22
	VerifierChars   = 43
	MaxKidLength    = 64
	MaxTokenLength  = 512
	MinPepperLength = 32
)

// Timestamps and durations are integer Unix seconds in a signed 64-bit type
// ([N-2]), so these are typed int64 rather than untyped constants.
const (
	DefaultAbsoluteTTL int64 = 60 * 60 * 24 * 30 // 30 days
	DefaultIdleTTL     int64 = 60 * 60 * 24 * 7  // 7 days
	DefaultReuseGrace  int64 = 0                 // strict
)

// hashHexChars is the width of an HMAC-SHA-256 digest in lowercase hex ([N-13]).
const hashHexChars = 64

// ─── Errors on the native channel ([N-20]) ───────────────────────────────────

// ErrInvalidConfig is returned by NewEngine for a configuration that violates
// §5. Test for it with errors.Is.
var ErrInvalidConfig = errors.New("nebulatoken: invalid configuration")

// ErrInvalidDeviceID is returned by Issue and HashDeviceID when the device
// identifier is not valid UTF-8, so [N-11] cannot define a hash for it. On the
// attacker-reachable path (Refresh) the same input is a binding failure
// instead, never an error ([N-12]).
//
// The identifier itself is never included in the message ([N-14]).
var ErrInvalidDeviceID = errors.New("nebulatoken: device identifier is not valid UTF-8")

// ─── Types ───────────────────────────────────────────────────────────────────

// TokenStatus is the lifecycle state of a record (§3).
type TokenStatus string

const (
	StatusActive  TokenStatus = "active"
	StatusRotated TokenStatus = "rotated"
	StatusRevoked TokenStatus = "revoked"
)

// ErrorCode is a protocol outcome ([N-38]). It is deliberately a string type
// rather than an enumerated int so that an unrecognised code stays readable.
//
// Treat the set as OPEN ([N-40]): Go has no exhaustive switch, so the policy is
// documented instead — a future minor version may add a code, and a switch over
// ErrorCode MUST have a default branch that treats the unknown value as a
// refusal. Never assume the constants below are the complete set.
type ErrorCode string

const (
	CodeMalformed        ErrorCode = "MALFORMED"
	CodeUnknownKid       ErrorCode = "UNKNOWN_KID"
	CodeNotFound         ErrorCode = "NOT_FOUND"
	CodeVerifierMismatch ErrorCode = "VERIFIER_MISMATCH"
	CodeReuseDetected    ErrorCode = "REUSE_DETECTED"
	CodeRevoked          ErrorCode = "REVOKED"
	CodeExpiredAbsolute  ErrorCode = "EXPIRED_ABSOLUTE"
	CodeExpiredIdle      ErrorCode = "EXPIRED_IDLE"
	CodeDeviceMismatch   ErrorCode = "DEVICE_MISMATCH"
	CodeConflict         ErrorCode = "CONFLICT"
)

// TokenRecord is the server-side record — one row per issued token ([N-10]).
//
// The nullable columns are pointers, not zero values: a nil DeviceIDHash means
// "unbound", which must stay distinguishable from a binding to the empty device
// identifier ([N-25]), and a nil RotatedAt means "never rotated", which must
// stay distinguishable from a rotation at Unix time 0.
type TokenRecord struct {
	Selector           string
	VerifierHash       string
	Kid                string
	FamilyID           string
	Generation         int
	UserID             string
	DeviceIDHash       *string
	CreatedAt          int64
	FamilyExpiresAt    int64
	IdleExpiresAt      int64
	Status             TokenStatus
	RotatedAt          *int64
	ReplacedBySelector *string
}

// Clone returns a deep copy. A store MUST hand out copies rather than pointers
// into its own state, or a caller could mutate a row it merely read.
func (r *TokenRecord) Clone() *TokenRecord {
	if r == nil {
		return nil
	}
	cp := *r
	cp.DeviceIDHash = copyString(r.DeviceIDHash)
	cp.ReplacedBySelector = copyString(r.ReplacedBySelector)
	cp.RotatedAt = copyInt64(r.RotatedAt)
	return &cp
}

// RefreshTokenStore is the storage contract ([N-16]) — exactly six capabilities.
//
// Two failure channels ([N-20]): protocol outcomes are the returned values;
// infrastructure failures (store unreachable, timeout, constraint violation)
// are returned as a non-nil error. The engine never converts an error into a
// protocol outcome, so a caller always fails closed.
type RefreshTokenStore interface {
	// FindBySelector returns (nil, nil) when no record exists — a missing row is
	// not an error. Lookups key only on the selector ([N-45]).
	FindBySelector(ctx context.Context, selector string) (*TokenRecord, error)

	Insert(ctx context.Context, record *TokenRecord) error

	// MarkRotated is a compare-and-set ([N-17]). It applies the rotation write
	// if and only if the stored status is still fromStatus, and reports whether
	// it applied.
	//
	// SQL: UPDATE … SET status='rotated', rotated_at=$2, replaced_by_selector=$3
	//      WHERE selector=$1 AND status=$4  → RowsAffected() == 1
	//
	// Returning true unconditionally is non-conforming: it re-opens the race in
	// which two concurrent refreshes both mint a successor and fork the family.
	MarkRotated(ctx context.Context, selector string, fromStatus TokenStatus, rotatedAt int64, replacedBySelector string) (bool, error)

	// RevokeIfActive is a compare-and-set ([N-18]): revoke only if the current
	// status is active, and report whether it did.
	RevokeIfActive(ctx context.Context, selector string) (bool, error)

	// RevokeFamily revokes every record of the family and returns how many
	// records it changed. Idempotent ([N-19]).
	RevokeFamily(ctx context.Context, familyID string) (int, error)

	// RevokeUser revokes every record of the user and returns how many records
	// it changed. Idempotent ([N-19]).
	RevokeUser(ctx context.Context, userID string) (int, error)
}

// Config configures the engine (§5). It is copied by NewEngine ([N-24]).
type Config struct {
	// Peppers maps kid → secret. Each kid MUST match the kid production of §2,
	// each secret MUST be at least MinPepperLength BYTES ([N-1]); see [N-23] for
	// why the floor is not a sufficient condition.
	Peppers map[string]string

	// ActiveKid names the pepper new tokens are minted under. MUST be present
	// in Peppers.
	ActiveKid string

	Store RefreshTokenStore

	// AbsoluteTTLSeconds, IdleTTLSeconds and ReuseGraceSeconds follow the Go
	// convention that the zero value means "unset, use the default"; a negative
	// value is a configuration error. The effective values are always > 0, > 0
	// and >= 0 respectively, as §5 requires.
	AbsoluteTTLSeconds int64
	IdleTTLSeconds     int64

	// ReuseGraceSeconds: read the security trade-off in [N-30] before raising
	// this above 0.
	ReuseGraceSeconds int64

	// Clock is the injectable "now" in Unix seconds ([N-3]). Defaults to
	// time.Now().Unix().
	Clock func() int64
}

// IssueResult is returned by Issue. Timestamps are integer Unix seconds ([N-2]).
type IssueResult struct {
	Token         string
	UserID        string
	FamilyID      string
	Generation    int
	ExpiresAt     int64
	IdleExpiresAt int64
}

// String redacts the token ([N-14], [N-46]).
//
// Without it, fmt's default struct rendering prints the live credential into
// every log.Printf("%v", res), every %+v in an error message and every panic
// dump that captures this value. The Token field is untouched, so the caller
// still hands the token to the client and encoding/json still serialises it;
// only the debug rendering is redacted, exactly as Rust's Debug, Python's
// __repr__ and Ruby's inspect do.
//
// The value receiver puts String in the method set of both IssueResult and
// *IssueResult, so the redaction holds for the pointer the engine returns.
func (r IssueResult) String() string {
	return fmt.Sprintf("IssueResult{Token:<redacted> UserID:%s FamilyID:%s Generation:%d ExpiresAt:%d IdleExpiresAt:%d}",
		r.UserID, r.FamilyID, r.Generation, r.ExpiresAt, r.IdleExpiresAt)
}

// RefreshResult is the outcome of Refresh. OK discriminates the two shapes:
// when OK is true the token and expiry fields are set, otherwise Error carries
// the protocol outcome.
//
// UserID and FamilyID are populated on failure whenever the engine resolved a
// record — every code except MALFORMED, UNKNOWN_KID and NOT_FOUND — so that a
// REUSE_DETECTED or DEVICE_MISMATCH event can be attributed to a session
// without a second lookup of a token you were told never to log ([N-39]).
type RefreshResult struct {
	OK            bool
	Token         string
	UserID        string
	FamilyID      string
	Generation    int
	ExpiresAt     int64
	IdleExpiresAt int64
	Error         ErrorCode
}

// String redacts the successor token ([N-14], [N-46]), for the same reason as
// IssueResult.String. A failure carries no token, so it renders the attribution
// fields instead — the two shapes correspond to the separate success and
// failure types the other ports declare.
func (r RefreshResult) String() string {
	if !r.OK {
		return fmt.Sprintf("RefreshResult{OK:false Error:%s UserID:%s FamilyID:%s}", r.Error, r.UserID, r.FamilyID)
	}
	return fmt.Sprintf("RefreshResult{OK:true Token:<redacted> UserID:%s FamilyID:%s Generation:%d ExpiresAt:%d IdleExpiresAt:%d}",
		r.UserID, r.FamilyID, r.Generation, r.ExpiresAt, r.IdleExpiresAt)
}

// RevokeResult is the outcome of RevokeToken. Revoked counts the records the
// store changed.
type RevokeResult struct {
	OK       bool
	UserID   string
	FamilyID string
	Revoked  int
	Error    ErrorCode
}

// ParsedToken is the decomposed wire token (§2).
type ParsedToken struct {
	Kid      string
	Selector string
	// Verifier holds the raw 32 secret bytes. Never persist or log it ([N-14]).
	Verifier []byte
}

// String redacts the verifier ([N-14], [N-46]): fmt would otherwise print the
// 32 secret bytes as a plain integer slice, so one %v on a parse result puts
// the credential in the log. The Kid and the Selector stay visible — the
// selector is the designated correlation identifier ([N-46]).
func (p ParsedToken) String() string {
	return fmt.Sprintf("ParsedToken{Kid:%s Selector:%s Verifier:<redacted>}", p.Kid, p.Selector)
}

// Device returns a pointer to id, for the optional deviceID parameters of
// Issue and Refresh. A nil argument means "no device identifier";
// Device("") means "bound to the empty identifier". The two are different
// bindings and MUST NOT be conflated ([N-25], [N-32]).
func Device(id string) *string { return &id }

// ─── Spec primitives (§2, §6.4) ──────────────────────────────────────────────

var b64 = base64.RawURLEncoding

// ParseToken parses a wire token (§2, [N-5]..[N-9]).
//
// Total by construction: it returns nil for every rejection and never panics,
// whatever bytes it is handed ([N-8]). Nothing here consults locale or case
// folding ([N-9]).
func ParseToken(token string) *ParsedToken {
	// [N-6.1] length in BYTES, before any other parsing work. len() on a Go
	// string counts bytes, which is exactly what the spec measures ([N-1]).
	if len(token) > MaxTokenLength {
		return nil
	}

	parts := strings.Split(token, ".")
	if len(parts) != 4 { // [N-6.2]; the empty string yields one part
		return nil
	}
	prefix, kid, selector, verifierB64 := parts[0], parts[1], parts[2], parts[3]

	if prefix != Prefix { // [N-6.3] byte-exact, case-sensitive
		return nil
	}
	if len(kid) == 0 || len(kid) > MaxKidLength { // [N-6.2], [N-6.5]
		return nil
	}
	if len(selector) != SelectorChars || len(verifierB64) != VerifierChars { // [N-6.2], [N-6.6]
		return nil
	}

	// [N-6.4] alphabet: rejects padding '=', whitespace, '+', '/' and every
	// non-ASCII byte. An explicit scan rather than a regexp — no anchor
	// subtleties (in several dialects '$' also matches before a trailing
	// newline, which would accept "…{verifier}\n"), no locale, no allocation.
	if !isB64URL(kid) || !isB64URL(selector) || !isB64URL(verifierB64) {
		return nil
	}

	verifier, err := b64.DecodeString(verifierB64)
	if err != nil || len(verifier) != VerifierBytes { // [N-6.7]
		return nil
	}

	// [N-7] canonical encoding. A 32-byte value has four 43-character
	// spellings; Go's non-strict decoder accepts all four, so the re-encode is
	// what pins the credential to a single wire form.
	if b64.EncodeToString(verifier) != verifierB64 {
		return nil
	}

	return &ParsedToken{Kid: kid, Selector: selector, Verifier: verifier}
}

// isB64URL reports whether s is non-empty and drawn only from the b64url set.
func isB64URL(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// HashVerifier returns lowercase hex HMAC-SHA-256(pepper, verifier) ([N-11]).
// The key is the pepper's UTF-8 bytes; the message is the raw verifier bytes.
func HashVerifier(pepper string, verifier []byte) string {
	m := hmac.New(sha256.New, []byte(pepper))
	m.Write(verifier)
	return hex.EncodeToString(m.Sum(nil))
}

// HashDeviceID returns lowercase hex HMAC-SHA-256(pepper, "device:"+deviceID)
// ([N-11]). No normalisation form, case transformation or trimming is applied
// to either operand: doing so would make the same identifier hash differently
// across implementations.
//
// A Go string is an arbitrary byte sequence, so it can hold input that is not
// valid UTF-8 (an unpaired surrogate arrives as its WTF-8 encoding through many
// JSON and JNI boundaries). Such a value has no UTF-8 encoding and therefore no
// defined hash: it is rejected with ErrInvalidDeviceID ([N-12]).
func HashDeviceID(pepper, deviceID string) (string, error) {
	if !utf8.ValidString(deviceID) {
		return "", ErrInvalidDeviceID
	}
	m := hmac.New(sha256.New, []byte(pepper))
	m.Write([]byte("device:" + deviceID))
	return hex.EncodeToString(m.Sum(nil)), nil
}

// ConstantTimeEqualHex compares two hex digests in constant time ([N-31]).
//
// Operands that are not exactly 64 lowercase hex characters compare unequal.
// The guard is deliberate rather than defensive: hex.DecodeString stops at the
// first invalid character, so without it a stored hash that an ETL job
// upper-cased, a CHAR column space-padded, or a truncating migration cut short
// would keep verifying against a decoded prefix instead of failing closed.
//
// The length/alphabet guard is not secret-dependent — it inspects the shape of
// the operands, never their equality — so short-circuiting there leaks nothing.
// Never panics, whatever it is handed.
func ConstantTimeEqualHex(aHex, bHex string) bool {
	if !isLowerHex64(aHex) || !isLowerHex64(bHex) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(aHex), []byte(bHex)) == 1
}

func isLowerHex64(s string) bool {
	if len(s) != hashHexChars {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ─── Engine ──────────────────────────────────────────────────────────────────

// Engine implements the operations of §6. It is safe for concurrent use by
// multiple goroutines as long as the store is.
type Engine struct {
	peppers map[string]string
	// activePepper is resolved once at construction. Looking it up per call
	// would make a missing kid representable — and a map miss on a Go map
	// yields "" silently, which would key the HMAC with the empty secret
	// ([N-24]).
	activePepper string
	activeKid    string
	store        RefreshTokenStore
	absoluteTTL  int64
	idleTTL      int64
	reuseGrace   int64
	clock        func() int64
}

// NewEngine validates the configuration (§5) and returns an engine.
//
// The pepper map is COPIED ([N-24]): mutating the caller's map afterwards
// cannot bypass validation, swap a secret, or delete the active kid.
func NewEngine(cfg Config) (*Engine, error) {
	peppers := make(map[string]string, len(cfg.Peppers))
	for kid, secret := range cfg.Peppers {
		if !isB64URL(kid) || len(kid) > MaxKidLength {
			return nil, fmt.Errorf("%w: kid %q must be 1-%d bytes from [A-Za-z0-9_-]", ErrInvalidConfig, kid, MaxKidLength)
		}
		// [N-11] the HMAC key is the pepper's UTF-8 encoding, and a Go string is
		// an arbitrary byte sequence, so a secret that is not valid UTF-8 — the
		// WTF-8 encoding of an unpaired surrogate arrives trivially from a JSON
		// secrets file or a lenient UTF-16 decode — has no such encoding and is
		// not a usable key. Go would key the HMAC with the raw bytes, Node
		// substitutes U+FFFD and Python refuses: three different keys for the
		// same configured value. §5 resolves it by failing construction
		// everywhere. The message never quotes the secret ([N-14]).
		if !utf8.ValidString(secret) {
			return nil, fmt.Errorf("%w: pepper %q must have a UTF-8 encoding (no unpaired surrogate)", ErrInvalidConfig, kid)
		}
		// [N-1] the floor is in bytes of that encoding, not characters: a
		// 16-character CJK passphrase is 48 bytes and passes, "a"*31 is 31 bytes
		// and does not.
		if len(secret) < MinPepperLength {
			return nil, fmt.Errorf("%w: pepper %q must be at least %d bytes", ErrInvalidConfig, kid, MinPepperLength)
		}
		peppers[kid] = secret
	}
	activePepper, ok := peppers[cfg.ActiveKid]
	if !ok {
		return nil, fmt.Errorf("%w: activeKid %q not present in peppers", ErrInvalidConfig, cfg.ActiveKid)
	}
	if cfg.Store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalidConfig)
	}
	if cfg.AbsoluteTTLSeconds < 0 || cfg.IdleTTLSeconds < 0 || cfg.ReuseGraceSeconds < 0 {
		return nil, fmt.Errorf("%w: TTLs must be positive and reuseGraceSeconds must be non-negative", ErrInvalidConfig)
	}

	e := &Engine{
		peppers:      peppers,
		activePepper: activePepper,
		activeKid:    cfg.ActiveKid,
		store:        cfg.Store,
		absoluteTTL:  cfg.AbsoluteTTLSeconds,
		idleTTL:      cfg.IdleTTLSeconds,
		reuseGrace:   cfg.ReuseGraceSeconds,
		clock:        cfg.Clock,
	}
	if e.absoluteTTL == 0 {
		e.absoluteTTL = DefaultAbsoluteTTL
	}
	if e.idleTTL == 0 {
		e.idleTTL = DefaultIdleTTL
	}
	if e.clock == nil {
		e.clock = func() int64 { return time.Now().Unix() }
	}
	return e, nil
}

// Issue creates the first token of a new family ([N-25]). Call it at login.
//
// deviceID is optional: nil binds nothing, Device("") binds the empty
// identifier. A device identifier that is not valid UTF-8 is a caller mistake
// and is reported as ErrInvalidDeviceID, so the defect surfaces at the call
// site rather than minting a binding nothing can ever satisfy ([N-12]).
func (e *Engine) Issue(ctx context.Context, userID string, deviceID *string) (*IssueResult, error) {
	var deviceHash *string
	if deviceID != nil {
		h, err := HashDeviceID(e.activePepper, *deviceID)
		if err != nil {
			return nil, err
		}
		deviceHash = &h
	}

	now := e.clock()
	familyID, err := randomHex(16)
	if err != nil {
		return nil, err // [N-43] never silently fall back to a weaker source
	}
	familyExpiresAt := now + e.absoluteTTL

	token, record, err := e.mint(userID, familyID, 0, deviceHash, familyExpiresAt, now)
	if err != nil {
		return nil, err
	}
	// [N-20] fail closed: no token is returned for state that was not written.
	if err := e.store.Insert(ctx, record); err != nil {
		return nil, err
	}
	return &IssueResult{
		Token:         token,
		UserID:        userID,
		FamilyID:      familyID,
		Generation:    0,
		ExpiresAt:     familyExpiresAt,
		IdleExpiresAt: record.IdleExpiresAt,
	}, nil
}

// Refresh exchanges a refresh token for its successor ([N-26]).
//
// The ten checks run in the order of [N-26], which is normative and observable:
// it fixes which code is returned when several conditions hold at once.
//
// go:S3776 measures cognitive complexity 18 against a threshold of 15. The two
// parts worth extracting already are — handleReuse for step 5 and rotate for
// step 10 — which is the same split the TypeScript reference makes, so the
// structure here is the reference structure and not an accident. What remains is
// the [N-26] table itself: ten checks that must run in this order, each
// returning the first failure, with the step numbers in the trailing comments
// serving as the reader's cross-check against the specification. Folding any
// step into a helper would move it out of the numbered list.
//
// Of the 18 counted constructs, five are `if err != nil` guards that the
// TypeScript and Java ports do not have at all, because they signal
// infrastructure failure by throwing. That is Go's (value, error) convention
// costing three points over Java's 16 for the identical algorithm — a language
// tax, not a design defect. Suppressed in sonar-project.properties; Sonar has no
// inline suppression form for Go, which is why this note is here.
func (e *Engine) Refresh(ctx context.Context, token string, deviceID *string) (*RefreshResult, error) {
	// 1. Parse
	parsed := ParseToken(token)
	if parsed == nil {
		return fail(CodeMalformed), nil
	}

	// 2. Pepper lookup by the TOKEN's kid
	if _, ok := e.peppers[parsed.Kid]; !ok {
		return fail(CodeUnknownKid), nil
	}

	// 3. Record lookup
	record, err := e.store.FindBySelector(ctx, parsed.Selector)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return fail(CodeNotFound), nil
	}

	// 4. Verifier proof under the RECORD's pepper, constant time
	recordPepper, ok := e.peppers[record.Kid]
	if !ok {
		return fail(CodeUnknownKid), nil // [N-27] the record's pepper was retired
	}
	if !ConstantTimeEqualHex(HashVerifier(recordPepper, parsed.Verifier), record.VerifierHash) {
		// [N-28] no family revocation here: knowledge of a selector alone must
		// never be sufficient to destroy a session.
		return failWith(CodeVerifierMismatch, record), nil
	}

	now := e.clock()

	// 5. Reuse
	if record.Status == StatusRotated {
		return e.handleReuse(ctx, record, recordPepper, deviceID, now)
	}

	// 6. Revoked
	if record.Status == StatusRevoked {
		return failWith(CodeRevoked, record), nil
	}

	// 7-8. Expiry
	if now >= record.FamilyExpiresAt {
		if _, err := e.store.RevokeFamily(ctx, record.FamilyID); err != nil {
			return nil, err
		}
		return failWith(CodeExpiredAbsolute, record), nil
	}
	if now >= record.IdleExpiresAt {
		if _, err := e.store.RevokeFamily(ctx, record.FamilyID); err != nil {
			return nil, err
		}
		return failWith(CodeExpiredIdle, record), nil
	}

	// 9. Sender binding, under the RECORD's pepper ([N-32])
	if record.DeviceIDHash != nil && !deviceMatches(record, recordPepper, deviceID) {
		if _, err := e.store.RevokeFamily(ctx, record.FamilyID); err != nil {
			return nil, err
		}
		return failWith(CodeDeviceMismatch, record), nil
	}

	// 10. Rotate
	return e.rotate(ctx, record, deviceID, now, StatusActive, now)
}

// RevokeToken revokes the family a token belongs to ([N-36]).
//
// Authenticated: the verifier is proved exactly as in Refresh, because the
// selector is a public lookup key (§3) and must not by itself be a capability
// to terminate a session. It succeeds whatever the record's status, so a client
// can still log out with a token that was already rotated or revoked.
//
// It takes no device identifier and performs no sender-binding check ([N-36]):
// sender binding is not required to log out.
func (e *Engine) RevokeToken(ctx context.Context, token string) (*RevokeResult, error) {
	parsed := ParseToken(token)
	if parsed == nil {
		return &RevokeResult{Error: CodeMalformed}, nil
	}
	if _, ok := e.peppers[parsed.Kid]; !ok {
		return &RevokeResult{Error: CodeUnknownKid}, nil
	}

	record, err := e.store.FindBySelector(ctx, parsed.Selector)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return &RevokeResult{Error: CodeNotFound}, nil
	}

	recordPepper, ok := e.peppers[record.Kid]
	if !ok {
		return &RevokeResult{Error: CodeUnknownKid}, nil // [N-27]
	}
	if !ConstantTimeEqualHex(HashVerifier(recordPepper, parsed.Verifier), record.VerifierHash) {
		// [N-39] a record was resolved, so the failure can be attributed.
		return &RevokeResult{Error: CodeVerifierMismatch, UserID: record.UserID, FamilyID: record.FamilyID}, nil
	}

	revoked, err := e.store.RevokeFamily(ctx, record.FamilyID)
	if err != nil {
		return nil, err // [N-20] never report a revocation that did not happen
	}
	return &RevokeResult{OK: true, UserID: record.UserID, FamilyID: record.FamilyID, Revoked: revoked}, nil
}

// RevokeFamily revokes a whole family by its server-side identifier ([N-37]).
// It requires no token; the caller is responsible for authorising it. Returns
// the number of records revoked. Idempotent.
func (e *Engine) RevokeFamily(ctx context.Context, familyID string) (int, error) {
	return e.store.RevokeFamily(ctx, familyID)
}

// RevokeAllForUser revokes every session of a user ([N-37]) — password change,
// "log out all devices", incident response. Returns the number of records
// revoked. Idempotent.
func (e *Engine) RevokeAllForUser(ctx context.Context, userID string) (int, error) {
	return e.store.RevokeUser(ctx, userID)
}

// ─── Private ─────────────────────────────────────────────────────────────────

// handleReuse is step 5 of [N-26]: a rotated record was presented ([N-30]).
//
// go:S3776 measures cognitive complexity 22. This function *is* the extraction
// the rule would otherwise ask for — it and rotate are exactly the split the
// TypeScript reference makes — so the remedy has already been applied and the
// residue is the [N-30] decision itself: six preconditions, then a live-successor
// round-trip, then the theft path. Eleven of the twenty-two points come from
// `if err != nil` guards around four store calls; the equivalent reference
// method has none, because it throws.
//
// Splitting the grace-retry branch out again was considered and rejected: it
// would put [N-30] steps 1 and 3 in a different function from the precondition
// list they qualify, and it would make the Go port the only one of the ten whose
// reuse handling is shaped differently from the reference — the ports are meant
// to be readable against each other. Suppressed in sonar-project.properties.
func (e *Engine) handleReuse(ctx context.Context, record *TokenRecord, recordPepper string, deviceID *string, now int64) (*RefreshResult, error) {
	// [N-30] preconditions 1, 2, 3, 4 and 6. Condition 6 (now <
	// familyExpiresAt) is what stops a grace retry from minting a token past
	// the family's absolute deadline; condition 5 (the successor exists and is
	// active) is checked below, because it needs a store round-trip.
	withinGrace := e.reuseGrace > 0 &&
		record.RotatedAt != nil &&
		now-*record.RotatedAt <= e.reuseGrace &&
		record.ReplacedBySelector != nil &&
		now < record.FamilyExpiresAt

	if withinGrace {
		successor, err := e.store.FindBySelector(ctx, *record.ReplacedBySelector)
		if err != nil {
			return nil, err
		}
		if successor != nil && successor.Status == StatusActive {
			// Sender binding first: a wrong device on the grace path is a theft
			// signal, not a retry ([N-30] step 1).
			if record.DeviceIDHash != nil && !deviceMatches(record, recordPepper, deviceID) {
				if _, err := e.store.RevokeFamily(ctx, record.FamilyID); err != nil {
					return nil, err
				}
				return failWith(CodeDeviceMismatch, record), nil
			}
			// Compare-and-set: exactly one concurrent retry may consume the
			// unused successor. The loser mints nothing and reports CONFLICT.
			applied, err := e.store.RevokeIfActive(ctx, successor.Selector)
			if err != nil {
				return nil, err
			}
			if !applied {
				return failWith(CodeConflict, record), nil
			}
			// Preserve the original RotatedAt: the window is anchored to the
			// first rotation and cannot be walked forward ([N-30] step 3).
			return e.rotate(ctx, record, deviceID, now, StatusRotated, *record.RotatedAt)
		}
	}

	// Otherwise the presentation is a theft signal.
	if _, err := e.store.RevokeFamily(ctx, record.FamilyID); err != nil {
		return nil, err
	}
	return failWith(CodeReuseDetected, record), nil
}

// rotate mints a successor and flips the predecessor with a compare-and-set
// ([N-34]). rotatedAt is now for a fresh rotation and the record's original
// RotatedAt for a grace retry.
func (e *Engine) rotate(ctx context.Context, record *TokenRecord, deviceID *string, now int64, fromStatus TokenStatus, rotatedAt int64) (*RefreshResult, error) {
	deviceHash := copyString(record.DeviceIDHash)
	if record.DeviceIDHash != nil && deviceID != nil {
		// Re-hash with the ACTIVE pepper: this is what migrates a binding
		// forward across a pepper rotation ([N-33] step 4). The identifier was
		// already proved valid by the binding check that got us here.
		h, err := HashDeviceID(e.activePepper, *deviceID)
		if err != nil {
			return nil, err
		}
		deviceHash = &h
	}

	token, next, err := e.mint(record.UserID, record.FamilyID, record.Generation+1, deviceHash, record.FamilyExpiresAt, now)
	if err != nil {
		return nil, err
	}
	if err := e.store.Insert(ctx, next); err != nil {
		return nil, err
	}

	applied, err := e.store.MarkRotated(ctx, record.Selector, fromStatus, rotatedAt, next.Selector)
	if err != nil {
		return nil, err
	}
	if !applied {
		// [N-34] step 5: a concurrent refresh won the compare-and-set. Clean up
		// the successor we just inserted and report a retryable conflict —
		// never a token, or the family would fork into two live lineages.
		// [N-35] nothing beyond that successor is revoked.
		if _, err := e.store.RevokeIfActive(ctx, next.Selector); err != nil {
			return nil, err
		}
		return failWith(CodeConflict, record), nil
	}

	return &RefreshResult{
		OK:            true,
		Token:         token,
		UserID:        record.UserID,
		FamilyID:      record.FamilyID,
		Generation:    next.Generation,
		ExpiresAt:     next.FamilyExpiresAt,
		IdleExpiresAt: next.IdleExpiresAt,
	}, nil
}

// mint produces a fresh selector/verifier pair and its record ([N-33]).
func (e *Engine) mint(userID, familyID string, generation int, deviceIDHash *string, familyExpiresAt, now int64) (string, *TokenRecord, error) {
	selectorRaw := make([]byte, SelectorBytes)
	verifier := make([]byte, VerifierBytes)
	if _, err := rand.Read(selectorRaw); err != nil {
		return "", nil, err // [N-43]
	}
	if _, err := rand.Read(verifier); err != nil {
		return "", nil, err
	}
	selector := b64.EncodeToString(selectorRaw)

	idle := now + e.idleTTL
	if idle > familyExpiresAt { // min(now+idleTtl, familyExpiresAt) ([N-33] step 3)
		idle = familyExpiresAt
	}

	record := &TokenRecord{
		Selector:        selector,
		VerifierHash:    HashVerifier(e.activePepper, verifier),
		Kid:             e.activeKid,
		FamilyID:        familyID,
		Generation:      generation,
		UserID:          userID,
		DeviceIDHash:    deviceIDHash,
		CreatedAt:       now,
		FamilyExpiresAt: familyExpiresAt,
		IdleExpiresAt:   idle,
		Status:          StatusActive,
	}
	token := Prefix + "." + e.activeKid + "." + selector + "." + b64.EncodeToString(verifier)
	return token, record, nil
}

// deviceMatches implements the sender-binding comparison ([N-32]).
func deviceMatches(record *TokenRecord, recordPepper string, deviceID *string) bool {
	if record.DeviceIDHash == nil || deviceID == nil {
		// A missing device identifier where the record is bound MUST fail.
		return false
	}
	// [N-12] on the attacker-reachable path an identifier that is not valid
	// UTF-8 is a binding failure, never an error.
	presented, err := HashDeviceID(recordPepper, *deviceID)
	if err != nil {
		return false
	}
	return ConstantTimeEqualHex(presented, *record.DeviceIDHash)
}

func fail(code ErrorCode) *RefreshResult {
	return &RefreshResult{Error: code}
}

// failWith attributes the failure to the resolved record ([N-39]).
func failWith(code ErrorCode, record *TokenRecord) *RefreshResult {
	return &RefreshResult{Error: code, UserID: record.UserID, FamilyID: record.FamilyID}
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func copyString(s *string) *string {
	if s == nil {
		return nil
	}
	v := *s
	return &v
}

func copyInt64(n *int64) *int64 {
	if n == nil {
		return nil
	}
	v := *n
	return &v
}

// ─── In-memory store — development and tests ONLY ───────────────────────────

// MemoryRefreshTokenStore is the reference store required by [N-21].
//
// It is safe for concurrent use: net/http serves every request on its own
// goroutine, so an unsynchronised map here would produce "fatal error:
// concurrent map writes" — a runtime crash that no recover() can intercept —
// under ordinary traffic. The mutex also makes each compare-and-set atomic,
// which is the property [N-17] and [N-18] actually require.
//
// NOT FOR PRODUCTION: state is per-process and lost on restart, so reuse
// detection does not survive a deploy and does not work behind more than one
// instance. Implement RefreshTokenStore over your database instead — see
// examples/sqlstore and docs/STORE.md.
type MemoryRefreshTokenStore struct {
	mu   sync.RWMutex
	rows map[string]*TokenRecord
}

func NewMemoryRefreshTokenStore() *MemoryRefreshTokenStore {
	return &MemoryRefreshTokenStore{rows: make(map[string]*TokenRecord)}
}

func (s *MemoryRefreshTokenStore) FindBySelector(_ context.Context, selector string) (*TokenRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.rows[selector]
	if !ok {
		return nil, nil
	}
	return r.Clone(), nil
}

func (s *MemoryRefreshTokenStore) Insert(_ context.Context, record *TokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.rows[record.Selector]; exists {
		// A real store has a primary key; surfacing the collision beats
		// silently overwriting a live record.
		return fmt.Errorf("nebulatoken: duplicate selector %q", record.Selector)
	}
	s.rows[record.Selector] = record.Clone()
	return nil
}

func (s *MemoryRefreshTokenStore) MarkRotated(_ context.Context, selector string, fromStatus TokenStatus, rotatedAt int64, replacedBySelector string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[selector]
	if !ok || r.Status != fromStatus { // [N-17] compare-and-set
		return false, nil
	}
	r.Status = StatusRotated
	r.RotatedAt = &rotatedAt
	r.ReplacedBySelector = &replacedBySelector
	return true, nil
}

func (s *MemoryRefreshTokenStore) RevokeIfActive(_ context.Context, selector string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[selector]
	if !ok || r.Status != StatusActive { // [N-18] compare-and-set
		return false, nil
	}
	r.Status = StatusRevoked
	return true, nil
}

func (s *MemoryRefreshTokenStore) RevokeFamily(_ context.Context, familyID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.rows {
		if r.FamilyID == familyID && r.Status != StatusRevoked {
			r.Status = StatusRevoked
			n++
		}
	}
	return n, nil
}

func (s *MemoryRefreshTokenStore) RevokeUser(_ context.Context, userID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.rows {
		if r.UserID == userID && r.Status != StatusRevoked {
			r.Status = StatusRevoked
			n++
		}
	}
	return n, nil
}

// All returns every record currently stored. Test helper, not part of the
// store contract.
func (s *MemoryRefreshTokenStore) All() []*TokenRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*TokenRecord, 0, len(s.rows))
	for _, r := range s.rows {
		out = append(out, r.Clone())
	}
	return out
}

// DeleteExpired drops records whose family deadline has passed and returns how
// many it removed. Records MUST NOT be dropped any earlier than this: reuse
// detection is the act of finding a rotated record ([N-15]).
func (s *MemoryRefreshTokenStore) DeleteExpired(now int64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for selector, r := range s.rows {
		if now >= r.FamilyExpiresAt {
			delete(s.rows, selector)
			n++
		}
	}
	return n
}
