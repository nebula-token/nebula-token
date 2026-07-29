#![allow(dead_code)]

//! Production-style SQL store for NEBULA — driver-agnostic template.
//!
//! The store is generic over a tiny [`SqlExecutor`] trait: implement it with the
//! driver of your choice (`postgres`, `rusqlite`, blocking `sqlx`) and you have
//! a spec-compliant store. That keeps this example dependency-free while
//! showing the exact SQL and semantics (schema: `docs/STORE.md`).
//!
//! What this file is really demonstrating:
//!
//! * [`RefreshTokenStore`] takes `&self`, so the store owns its synchronisation.
//!   Most Rust drivers want `&mut` for a query, so the connection lives behind a
//!   `Mutex` here; a pooled driver would check a connection out per call
//!   instead and drop the mutex entirely.
//! * `mark_rotated` and `revoke_if_active` are genuine compare-and-sets
//!   ([N-17], [N-18]): the status is part of the `WHERE` clause and the
//!   affected-row count is the return value. An `UPDATE` without it re-opens
//!   the race that forks a token family.
//! * Every failure is reported on the error channel ([N-20]) — nothing is
//!   swallowed into a protocol outcome, and an unrecognised `status` column
//!   fails closed rather than being read as `active`.
//! * Parameterised queries only; lookups keyed on the non-secret selector
//!   ([N-45]); rotated and revoked rows kept until the family's absolute
//!   deadline ([N-15]) — they are what makes replay detectable.

use nebula_token::{RefreshTokenStore, TokenRecord, TokenStatus};
use std::fmt;
use std::sync::Mutex;

/// A parameter value for a SQL statement.
pub enum SqlParam {
    Text(String),
    Int(i64),
    Null,
}

/// One row of `refresh_tokens`, in the canonical column order used below.
pub struct SqlRow {
    pub selector: String,
    pub verifier_hash: String,
    pub kid: String,
    pub family_id: String,
    pub generation: u32,
    pub user_id: String,
    pub device_id_hash: Option<String>,
    pub created_at: i64,
    pub family_expires_at: i64,
    pub idle_expires_at: i64,
    pub status: String,
    pub rotated_at: Option<i64>,
    pub replaced_by_selector: Option<String>,
}

/// Minimal driver abstraction. `execute` returns the affected-row count, which
/// is what makes the compare-and-sets below observable.
pub trait SqlExecutor {
    type Error;

    fn execute(&mut self, sql: &str, params: &[SqlParam]) -> Result<u64, Self::Error>;
    fn query_row(&mut self, sql: &str, params: &[SqlParam]) -> Result<Option<SqlRow>, Self::Error>;
}

/// Everything that can go wrong on the infrastructure channel ([N-20]).
#[derive(Debug)]
#[non_exhaustive]
pub enum SqlStoreError<E> {
    Driver(E),
    /// A previous caller panicked while holding the connection. Refusing is the
    /// fail-closed answer: we cannot know what the half-finished statement did.
    Poisoned,
    /// The `status` column holds something this version does not understand.
    /// Guessing `active` here would resurrect a revoked session.
    UnknownStatus(String),
}

impl<E: fmt::Display> fmt::Display for SqlStoreError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SqlStoreError::Driver(e) => write!(f, "refresh-token store: {e}"),
            SqlStoreError::Poisoned => f.write_str("refresh-token store: connection poisoned"),
            SqlStoreError::UnknownStatus(s) => {
                write!(f, "refresh-token store: unknown status {s:?}")
            }
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for SqlStoreError<E> {}

const COLS: &str = "selector, verifier_hash, kid, family_id, generation, user_id, device_id_hash, \
                    created_at, family_expires_at, idle_expires_at, status, rotated_at, replaced_by_selector";

pub struct SqlStore<E: SqlExecutor> {
    db: Mutex<E>,
}

impl<E: SqlExecutor> SqlStore<E> {
    pub fn new(db: E) -> Self {
        SqlStore { db: Mutex::new(db) }
    }

    fn with_db<T>(
        &self,
        f: impl FnOnce(&mut E) -> Result<T, E::Error>,
    ) -> Result<T, SqlStoreError<E::Error>> {
        let mut db = self.db.lock().map_err(|_| SqlStoreError::Poisoned)?;
        f(&mut db).map_err(SqlStoreError::Driver)
    }

    /// Operational helper: GC families past their absolute deadline. Never run
    /// anything narrower than this — deleting `rotated` rows early disables
    /// reuse detection ([N-15]).
    pub fn delete_expired(&self, now: i64) -> Result<u64, SqlStoreError<E::Error>> {
        self.with_db(|db| {
            db.execute(
                "DELETE FROM refresh_tokens WHERE family_expires_at <= $1",
                &[SqlParam::Int(now)],
            )
        })
    }
}

impl<E: SqlExecutor> RefreshTokenStore for SqlStore<E> {
    type Error = SqlStoreError<E::Error>;

    fn find_by_selector(&self, selector: &str) -> Result<Option<TokenRecord>, Self::Error> {
        let sql = format!("SELECT {COLS} FROM refresh_tokens WHERE selector = $1");
        let row = self.with_db(|db| db.query_row(&sql, &[SqlParam::Text(selector.to_string())]))?;
        row.map(row_to_record).transpose()
    }

    fn insert(&self, r: TokenRecord) -> Result<(), Self::Error> {
        let sql = format!(
            "INSERT INTO refresh_tokens ({COLS}) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)"
        );
        self.with_db(|db| {
            db.execute(
                &sql,
                &[
                    SqlParam::Text(r.selector),
                    SqlParam::Text(r.verifier_hash),
                    SqlParam::Text(r.kid),
                    SqlParam::Text(r.family_id),
                    SqlParam::Int(i64::from(r.generation)),
                    SqlParam::Text(r.user_id),
                    r.device_id_hash.map_or(SqlParam::Null, SqlParam::Text),
                    SqlParam::Int(r.created_at),
                    SqlParam::Int(r.family_expires_at),
                    SqlParam::Int(r.idle_expires_at),
                    SqlParam::Text(r.status.as_str().to_string()),
                    r.rotated_at.map_or(SqlParam::Null, SqlParam::Int),
                    r.replaced_by_selector
                        .map_or(SqlParam::Null, SqlParam::Text),
                ],
            )
        })?;
        Ok(())
    }

    /// Compare-and-set ([N-17]): `status = $2` in the `WHERE` clause is the
    /// whole point, and `rows == 1` is the answer the engine acts on.
    fn mark_rotated(
        &self,
        selector: &str,
        from: TokenStatus,
        rotated_at: i64,
        replaced_by: &str,
    ) -> Result<bool, Self::Error> {
        let rows = self.with_db(|db| {
            db.execute(
                "UPDATE refresh_tokens SET status='rotated', rotated_at=$3, replaced_by_selector=$4 \
                 WHERE selector=$1 AND status=$2",
                &[
                    SqlParam::Text(selector.to_string()),
                    SqlParam::Text(from.as_str().to_string()),
                    SqlParam::Int(rotated_at),
                    SqlParam::Text(replaced_by.to_string()),
                ],
            )
        })?;
        Ok(rows == 1)
    }

    /// Compare-and-set ([N-18]).
    fn revoke_if_active(&self, selector: &str) -> Result<bool, Self::Error> {
        let rows = self.with_db(|db| {
            db.execute(
                "UPDATE refresh_tokens SET status='revoked' WHERE selector=$1 AND status='active'",
                &[SqlParam::Text(selector.to_string())],
            )
        })?;
        Ok(rows == 1)
    }

    /// `status <> 'revoked'` keeps the count honest, which is what makes the
    /// operation idempotent ([N-19]).
    fn revoke_family(&self, family_id: &str) -> Result<u64, Self::Error> {
        self.with_db(|db| {
            db.execute(
                "UPDATE refresh_tokens SET status='revoked' WHERE family_id=$1 AND status<>'revoked'",
                &[SqlParam::Text(family_id.to_string())],
            )
        })
    }

    fn revoke_user(&self, user_id: &str) -> Result<u64, Self::Error> {
        self.with_db(|db| {
            db.execute(
                "UPDATE refresh_tokens SET status='revoked' WHERE user_id=$1 AND status<>'revoked'",
                &[SqlParam::Text(user_id.to_string())],
            )
        })
    }
}

fn row_to_record<E>(r: SqlRow) -> Result<TokenRecord, SqlStoreError<E>> {
    let status = match r.status.as_str() {
        "active" => TokenStatus::Active,
        "rotated" => TokenStatus::Rotated,
        "revoked" => TokenStatus::Revoked,
        other => return Err(SqlStoreError::UnknownStatus(other.to_string())),
    };
    Ok(TokenRecord {
        selector: r.selector,
        verifier_hash: r.verifier_hash,
        kid: r.kid,
        family_id: r.family_id,
        generation: r.generation,
        user_id: r.user_id,
        device_id_hash: r.device_id_hash,
        created_at: r.created_at,
        family_expires_at: r.family_expires_at,
        idle_expires_at: r.idle_expires_at,
        status,
        rotated_at: r.rotated_at,
        replaced_by_selector: r.replaced_by_selector,
    })
}

fn main() {
    println!("This example is a template: implement SqlExecutor with your DB driver,");
    println!("then `NebulaEngine::new(Config::new(peppers, \"k1\", SqlStore::new(conn)))`.");
    println!("Wrap one refresh request in one transaction so the successor INSERT and");
    println!("the predecessor's compare-and-set UPDATE commit together ([N-22]).");
    println!("Schema and operational guidance: docs/STORE.md");
}
