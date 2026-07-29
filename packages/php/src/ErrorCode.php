<?php

declare(strict_types=1);

namespace NebulaToken;

/**
 * Protocol outcomes ([N-38]). Exactly these names, exactly these semantics.
 *
 * **Treat this enum as open** ([N-40]). PHP enums cannot be marked extensible,
 * so the policy is documented instead: a future minor version MAY add a case,
 * and consumers MUST treat an unrecognised code as a refusal. Concretely,
 * always give `match ($result->error)` a `default` arm — a match without one
 * raises \UnhandledMatchError the day a case is added.
 *
 * The human-readable meaning of each code is non-normative and may change;
 * only the names are stable ([N-41]). Do not return them to unauthenticated
 * callers — collapse every failure to one generic response ([N-42]).
 */
enum ErrorCode: string
{
    /** The presented string is not a NEBULA token (§2). */
    case Malformed = 'MALFORMED';
    /** No pepper is configured for the required key identifier. */
    case UnknownKid = 'UNKNOWN_KID';
    /** No record exists for the selector. */
    case NotFound = 'NOT_FOUND';
    /** The proof of possession failed. */
    case VerifierMismatch = 'VERIFIER_MISMATCH';
    /** A rotated token was replayed. The family has been revoked. */
    case ReuseDetected = 'REUSE_DETECTED';
    /** The record was revoked. */
    case Revoked = 'REVOKED';
    /** The family passed its fixed deadline. The family has been revoked. */
    case ExpiredAbsolute = 'EXPIRED_ABSOLUTE';
    /** The sliding deadline passed. The family has been revoked. */
    case ExpiredIdle = 'EXPIRED_IDLE';
    /** Sender binding failed. The family has been revoked. */
    case DeviceMismatch = 'DEVICE_MISMATCH';
    /** A concurrent refresh won the compare-and-set. Nothing was rotated. Retryable ([N-35]). */
    case Conflict = 'CONFLICT';
}
