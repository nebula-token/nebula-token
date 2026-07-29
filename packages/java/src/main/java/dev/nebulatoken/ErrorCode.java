package dev.nebulatoken;

/**
 * Protocol outcomes (&sect;7, [N-38]). Exactly these names, exactly these
 * semantics.
 *
 * <p><b>Extensibility policy ([N-40]).</b> Java enums cannot be marked open the
 * way a Rust {@code #[non_exhaustive]} enum can, so the policy is documented
 * here and is part of the compatibility promise: <em>a future minor version MAY
 * add a constant to this enum.</em> Consumers MUST therefore treat an
 * unrecognised code as a refusal -- always give {@code switch} a
 * {@code default} arm that denies, never one that grants. A {@code switch} over
 * this enum with no {@code default} will still compile after a code is added
 * and will then fall through at runtime, which is the failure mode this note
 * exists to prevent.
 *
 * <p>Human-readable messages built from a code are non-normative and may change
 * in any release; only the codes are stable ([N-41]). At the transport boundary
 * a deployment SHOULD collapse every code to one generic refusal and log the
 * specific code server-side ([N-42]) -- returning it verbatim to an
 * unauthenticated caller reveals whether a selector exists.
 */
public enum ErrorCode {

    /** The presented string is not a NEBULA token (&sect;2). */
    MALFORMED,

    /** No pepper is configured for the required key identifier. */
    UNKNOWN_KID,

    /** No record exists for the selector. */
    NOT_FOUND,

    /** The proof of possession failed. */
    VERIFIER_MISMATCH,

    /** A rotated token was replayed. The family has been revoked. */
    REUSE_DETECTED,

    /** The record was revoked. */
    REVOKED,

    /** The family passed its fixed deadline. The family has been revoked. */
    EXPIRED_ABSOLUTE,

    /** The sliding deadline passed. The family has been revoked. */
    EXPIRED_IDLE,

    /** Sender binding failed. The family has been revoked. */
    DEVICE_MISMATCH,

    /**
     * A concurrent refresh won the compare-and-set. Nothing was rotated, and
     * nothing beyond the engine's own orphan successor was revoked.
     *
     * <p>Transient: clients SHOULD retry the refresh once, which then meets the
     * ordinary reuse path ([N-35]).
     */
    CONFLICT
}
