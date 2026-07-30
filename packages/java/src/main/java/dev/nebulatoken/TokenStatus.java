package dev.nebulatoken;

/**
 * Record lifecycle (&sect;3).
 *
 * <p>A record MUST keep its status until at least its {@code familyExpiresAt}
 * ([N-15]): reuse detection <em>is</em> the act of finding a {@link #ROTATED}
 * row, so a store that expires rotated rows early silently turns every replay
 * into {@link ErrorCode#NOT_FOUND}.
 */
public enum TokenStatus {
    /** Usable exactly once. */
    ACTIVE,
    /** Already exchanged for a successor. Presenting it again is a theft signal. */
    ROTATED,
    /** Terminated, by logout, replay, expiry, binding failure or admin action. */
    REVOKED
}
