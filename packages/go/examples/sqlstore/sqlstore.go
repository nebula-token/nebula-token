// Package sqlstore is a production-style SQL store for NEBULA built on the
// standard library's database/sql — driver-agnostic (works with pgx/stdlib,
// lib/pq, go-sqlite3, and MySQL with placeholder tweaks).
//
// What it demonstrates: parameterised queries only; lookups keyed on the
// non-secret selector ([N-45]); the two compare-and-set writes expressed as
// conditional UPDATEs whose RowsAffected is the return value ([N-17], [N-18]);
// rotated and revoked rows kept until the family's absolute deadline, because
// deleting them silently disables reuse detection ([N-15]); DeleteExpired for
// GC after that deadline.
//
// Wrap one refresh request in a single *sql.Tx at the call site so that the
// insert of the successor and the mark-rotated of the predecessor commit
// atomically ([N-22]); the engine's compensation in [N-34] step 5 covers the
// deployments that cannot.
//
// Schema: docs/STORE.md. This package lives under examples/ and is not part of
// the published module surface.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	nebulatoken "github.com/nebula-token/nebula-token/packages/go"
)

const cols = `selector, verifier_hash, kid, family_id, generation, user_id, device_id_hash,
	created_at, family_expires_at, idle_expires_at, status, rotated_at, replaced_by_selector`

// Queryer is satisfied by *sql.DB and *sql.Tx alike.
type Queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// Store implements nebulatoken.RefreshTokenStore over database/sql.
type Store struct{ DB Queryer }

func New(db Queryer) *Store { return &Store{DB: db} }

// Compile-time proof that the six methods still match the contract.
var _ nebulatoken.RefreshTokenStore = (*Store)(nil)

func (s *Store) FindBySelector(ctx context.Context, selector string) (*nebulatoken.TokenRecord, error) {
	var r nebulatoken.TokenRecord
	var deviceIDHash, replacedBy sql.NullString
	var rotatedAt sql.NullInt64
	var status string

	err := s.DB.QueryRowContext(ctx,
		`SELECT `+cols+` FROM refresh_tokens WHERE selector = $1`, selector,
	).Scan(&r.Selector, &r.VerifierHash, &r.Kid, &r.FamilyID, &r.Generation, &r.UserID,
		&deviceIDHash, &r.CreatedAt, &r.FamilyExpiresAt, &r.IdleExpiresAt,
		&status, &rotatedAt, &replacedBy)
	if errors.Is(err, sql.ErrNoRows) {
		// A missing row is a protocol outcome (NOT_FOUND), not an
		// infrastructure failure ([N-20]).
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// NULL stays NULL: an unbound family and a family bound to the empty device
	// identifier are different things ([N-25]), and a record rotated at Unix
	// time 0 is not an unrotated one.
	if deviceIDHash.Valid {
		r.DeviceIDHash = &deviceIDHash.String
	}
	if replacedBy.Valid {
		r.ReplacedBySelector = &replacedBy.String
	}
	if rotatedAt.Valid {
		r.RotatedAt = &rotatedAt.Int64
	}
	r.Status = nebulatoken.TokenStatus(status)
	return &r, nil
}

func (s *Store) Insert(ctx context.Context, r *nebulatoken.TokenRecord) error {
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO refresh_tokens (`+cols+`)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		r.Selector, r.VerifierHash, r.Kid, r.FamilyID, r.Generation, r.UserID,
		nullString(r.DeviceIDHash), r.CreatedAt, r.FamilyExpiresAt, r.IdleExpiresAt,
		string(r.Status), nullInt64(r.RotatedAt), nullString(r.ReplacedBySelector))
	return err
}

// MarkRotated is the compare-and-set of [N-17]: the status predicate is part of
// the WHERE clause and the affected-row count is the answer. An unconditional
// UPDATE that discarded sql.Result would report success to both of two
// concurrent refreshes and fork the family into two live lineages.
func (s *Store) MarkRotated(ctx context.Context, selector string, fromStatus nebulatoken.TokenStatus, rotatedAt int64, replacedBySelector string) (bool, error) {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE refresh_tokens SET status='rotated', rotated_at=$2, replaced_by_selector=$3
		 WHERE selector=$1 AND status=$4`,
		selector, rotatedAt, replacedBySelector, string(fromStatus))
	if err != nil {
		return false, err
	}
	return changed(res)
}

// RevokeIfActive is the compare-and-set of [N-18].
func (s *Store) RevokeIfActive(ctx context.Context, selector string) (bool, error) {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE refresh_tokens SET status='revoked' WHERE selector=$1 AND status='active'`, selector)
	if err != nil {
		return false, err
	}
	return changed(res)
}

// RevokeFamily returns the number of records it changed ([N-19]). The
// `status <> 'revoked'` predicate is what makes the count idempotent: revoking
// an already-revoked family reports 0, not its size.
func (s *Store) RevokeFamily(ctx context.Context, familyID string) (int, error) {
	return s.revokeWhere(ctx, `family_id=$1`, familyID)
}

// RevokeUser returns the number of records it changed ([N-19]).
func (s *Store) RevokeUser(ctx context.Context, userID string) (int, error) {
	return s.revokeWhere(ctx, `user_id=$1`, userID)
}

func (s *Store) revokeWhere(ctx context.Context, predicate string, arg any) (int, error) {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE refresh_tokens SET status='revoked' WHERE `+predicate+` AND status <> 'revoked'`, arg)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		// A driver that cannot count rows cannot support this contract:
		// reporting 0 would understate a revocation, reporting a guess would
		// overstate one. Fail closed instead ([N-20]).
		return 0, err
	}
	return int(n), nil
}

// DeleteExpired is an operational helper: collect families past their absolute
// deadline. Nothing may be deleted before it ([N-15]).
func (s *Store) DeleteExpired(ctx context.Context, now int64) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE family_expires_at <= $1`, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func changed(res sql.Result) (bool, error) {
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func nullString(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

func nullInt64(n *int64) any {
	if n == nil {
		return nil
	}
	return *n
}
