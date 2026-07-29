/**
 * NEBULA -- opaque rotating refresh tokens, an implementation profile of the
 * refresh-token recommendations in RFC 9700.
 *
 * <p>This package implements SPECIFICATION.md spec version 1
 * ({@link dev.nebulatoken.Nebula#SPEC_VERSION}). Requirement identifiers in the
 * Javadoc ([N-*]) refer to that document, which is normative; this Javadoc is
 * not.
 *
 * <h2>The two failure channels ([N-20])</h2>
 *
 * Every operation in this package separates two kinds of "it did not work",
 * and they never cross over.
 *
 * <ol>
 *   <li><b>Protocol outcomes are return values.</b> A token that is malformed,
 *       unknown, replayed, expired, bound to another device, or lost a
 *       compare-and-set is an ordinary, expected answer:
 *       {@link dev.nebulatoken.RefreshResult.Failure} carrying an
 *       {@link dev.nebulatoken.ErrorCode}. These are never thrown ([N-29]), so
 *       control flow does not depend on exceptions and no {@code catch} block
 *       can accidentally widen a refusal into an acceptance.</li>
 *
 *   <li><b>Infrastructure failures use Java's native error channel.</b> The
 *       store being unreachable, a statement timing out, a constraint
 *       violation: a {@link dev.nebulatoken.RefreshTokenStore} reports these by
 *       throwing an unchecked exception, which propagates out of the engine
 *       unchanged. It is never converted into an {@code ErrorCode} and never
 *       swallowed.</li>
 * </ol>
 *
 * The consequence is the fail-closed property: an engine operation whose store
 * call throws does not return a success result, and does not report a
 * revocation that did not take place. A caller that treats a thrown exception
 * as "refresh failed, require login" is correct; a caller that treats it as
 * "probably fine" is not.
 *
 * <p>{@link dev.nebulatoken.NebulaConfigException} is a third, narrower case:
 * a caller mistake (invalid configuration, or a device identifier that is not
 * valid Unicode passed to {@code issue}) surfaced at the call site rather than
 * encoded as a protocol outcome ([N-12]).
 *
 * <h2>Concurrency</h2>
 *
 * {@link dev.nebulatoken.NebulaEngine} is immutable after construction and safe
 * to share across threads; it is as thread-safe as the store behind it. The API
 * is synchronous, which on JDK 21 virtual threads is the right shape: a
 * blocking store call parks the carrier thread rather than occupying it.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9700">RFC 9700</a>
 */
package dev.nebulatoken;
