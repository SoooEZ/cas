package org.apereo.cas.protocol;

import module java.base;

/**
 * Fail-closed final-response lease or commit rejection.
 *
 * <p>The exception contains only a stable code and retry classification.
 * Bundle identifiers, lease credentials, subjects, relying parties, manifests,
 * and capability references are never included in its message.</p>
 *
 * @author SoooEZ
 * @since 8.0.0
 */
public class ProtocolFinalResponseCommitException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = -7846709962499637969L;

    private final Code code;

    /**
     * Create a typed fail-closed rejection.
     *
     * @param code stable rejection code
     */
    public ProtocolFinalResponseCommitException(final Code code) {
        super("Protocol final response commit rejected [code=%s, retryable=%s]"
            .formatted(
                Objects.requireNonNull(code, "code"),
                code.isRetryable()));
        this.code = code;
    }

    /**
     * Get the stable rejection code.
     *
     * @return rejection code
     */
    public Code getCode() {
        return code;
    }

    /**
     * Whether state reconciliation may make a new acquire attempt safe.
     *
     * @return true when a new attempt may be retried
     */
    public boolean isRetryable() {
        return code.isRetryable();
    }

    /** Closed set of final-response commit failures. */
    public enum Code {
        /** The supplied request violated the API contract. */
        INVALID_REQUEST(false),
        /** The durable bundle does not exist. */
        BUNDLE_NOT_FOUND(false),
        /** Bundle identity or exact manifest did not match durable state. */
        MANIFEST_MISMATCH(false),
        /** Another owner currently holds the short response lease. */
        LEASE_CONFLICT(true),
        /** The supplied lease has expired. */
        LEASE_EXPIRED(true),
        /** The supplied owner token or fencing epoch no longer owns the lease. */
        LEASE_LOST(true),
        /** The subject generation was security-closed before final commit. */
        GENERATION_CLOSED(false),
        /** Current subject authority no longer equals the bundle generation. */
        GENERATION_CHANGED(false),
        /** One or more source intents or artifacts are not releasable. */
        SOURCE_NOT_RELEASABLE(false),
        /** Commit conflicts with an exact bundle that was already aborted. */
        ALREADY_ABORTED(false),
        /** Abort conflicts with an exact bundle that was already committed. */
        ALREADY_COMMITTED(false),
        /**
         * Durable recovery evidence cannot prove whether disclosure occurred.
         * Automated callers must not retry issuance or rewrite this state as an abort.
         */
        OUTCOME_UNCERTAIN(false),
        /** The commit authority could not be reached or establish a decision. */
        AUTHORITY_UNAVAILABLE(true),
        /** The implementation failed before establishing a typed durable result. */
        COMMIT_FAILURE(true);

        private final boolean retryable;

        Code(final boolean retryable) {
            this.retryable = retryable;
        }

        /**
         * Whether this failure may be retried by acquiring a fresh lease.
         *
         * @return retry classification
         */
        public boolean isRetryable() {
            return retryable;
        }
    }
}
