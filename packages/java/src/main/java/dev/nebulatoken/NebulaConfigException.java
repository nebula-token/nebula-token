package dev.nebulatoken;

/**
 * A caller mistake: an invalid engine configuration (&sect;5), or an argument
 * that has no valid encoding ([N-12]).
 *
 * <p>This is deliberately not an {@link ErrorCode}. Protocol outcomes describe
 * what a <em>presented token</em> turned out to be; this describes a defect in
 * the calling application, and belongs at the call site where it can be fixed
 * ([N-20]). It extends {@link IllegalArgumentException} so that generic
 * bad-argument handling already in place keeps working.
 *
 * <p>Messages never contain a pepper, a verifier or a raw device identifier
 * ([N-14], [N-46]).
 */
public class NebulaConfigException extends IllegalArgumentException {

    private static final long serialVersionUID = 1L;

    public NebulaConfigException(String message) {
        super("[NEBULA] " + message);
    }
}
