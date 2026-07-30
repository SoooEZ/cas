package org.apereo.cas.protocol;

import module java.base;

/**
 * Durable, fenced commit authority for exact final protocol responses.
 *
 * <p>This is intentionally not a permissive or no-op policy. Implementations
 * must fail closed with {@link ProtocolFinalResponseCommitException} whenever
 * they cannot establish a typed result. Returning {@code null} is a contract
 * violation and callers must treat it as {@code COMMIT_FAILURE}.</p>
 *
 * <p>A response lease must never hold a database transaction, distributed lock,
 * or other authority that delays security closure. Account disablement, deletion,
 * logout, password change, and equivalent generation closure always take
 * precedence and may invalidate an unexpired response lease.</p>
 *
 * @author SoooEZ
 * @since 8.0.0
 */
public interface ProtocolFinalResponseCommitPolicy extends Serializable {

    /** Default Spring bean name for the durable response commit policy. */
    String BEAN_NAME = "protocolFinalResponseCommitPolicy";

    /**
     * Acquire short-lived fenced ownership of one exact response bundle.
     *
     * <p>The implementation must atomically validate the immutable manifest,
     * current open subject generation, relying-party binding, and releasability
     * of every source artifact. The protocol manifest digest is not a database
     * inventory digest or keyed lifecycle-evidence HMAC; durable state must bind
     * those evidence domains explicitly. The implementation must bound the
     * requested duration, return a lease whose expiration is still in the
     * future, and must not use the lease to block or postpone security closure.</p>
     *
     * @param bundle exact immutable response manifest
     * @param ownerToken unguessable caller-generated owner token
     * @param requestedLeaseDuration requested short lease duration
     * @return non-null acquired or idempotently replayed lease
     * @throws ProtocolFinalResponseCommitException when ownership cannot be established
     */
    ProtocolFinalResponseLease acquire(
        ProtocolFinalResponseBundle bundle,
        String ownerToken,
        Duration requestedLeaseDuration);

    /**
     * Renew the caller's current lease under the same exact manifest.
     *
     * <p>Renewal must check the lease identifier, owner token, fencing epoch,
     * bundle identifier, and manifest digest. It must also revalidate current
     * generation authority. Renewal does not reserve the generation and may
     * lose a race to security closure. A successful result must have a future
     * expiration at the time it is returned.</p>
     *
     * @param bundle exact immutable response manifest
     * @param lease current fenced lease
     * @param requestedLeaseDuration requested short lease duration
     * @return non-null renewed lease with a current expiration and fencing epoch
     * @throws ProtocolFinalResponseCommitException when renewal is not safe
     */
    ProtocolFinalResponseLease renew(
        ProtocolFinalResponseBundle bundle,
        ProtocolFinalResponseLease lease,
        Duration requestedLeaseDuration);

    /**
     * Commit disclosure of every item in the exact bundle.
     *
     * <p>The implementation must atomically revalidate, at the commit point,
     * that the subject generation is still open and exactly equals
     * {@link ProtocolFinalResponseBundle#generation()}; the lease remains owned
     * and unexpired; every source is releasable; and the durable manifest equals
     * the bundle and lease digests. A concurrent security closure must win and
     * cause {@code GENERATION_CLOSED} or {@code GENERATION_CHANGED}; an
     * unexpired lease is never sufficient authority to commit.</p>
     *
     * @param bundle exact immutable response manifest
     * @param lease current fenced lease
     * @return non-null applied or exact idempotent replay result
     * @throws ProtocolFinalResponseCommitException when exact disclosure is not safe
     */
    ProtocolFinalResponseCommitResult commit(
        ProtocolFinalResponseBundle bundle,
        ProtocolFinalResponseLease lease);

    /**
     * Abort disclosure of every item in the exact bundle.
     *
     * <p>Abort is permitted only when the caller or recovery authority can
     * establish that disclosure did not occur. An uncertain external outcome
     * must enter a separate durable uncertain/recovery path and must never be
     * represented as aborted. Abort must validate exact manifest and lease
     * ownership and record one durable terminal outcome including the reason.
     * Only an abort with the same exact manifest and reason may return replay;
     * a changed reason is a manifest conflict. Abort after commit must fail with
     * {@code ALREADY_COMMITTED}, while commit after abort must fail with
     * {@code ALREADY_ABORTED}. Abort releases response ownership only; it must
     * not reopen a closed generation or reverse a security closure.</p>
     *
     * @param bundle exact immutable response manifest
     * @param lease current fenced lease
     * @param reason typed durable abort reason
     * @return non-null applied or exact idempotent replay result
     * @throws ProtocolFinalResponseCommitException when the request conflicts
     * with durable state
     */
    ProtocolFinalResponseCommitResult abort(
        ProtocolFinalResponseBundle bundle,
        ProtocolFinalResponseLease lease,
        AbortReason reason);

    /** Durable reason for abandoning a final response without disclosure. */
    enum AbortReason {
        /** The protocol caller abandoned the response before any disclosure. */
        CALLER_ABANDONED_BEFORE_DISCLOSURE,
        /** Response construction failed before disclosure. */
        RESPONSE_BUILD_FAILED_BEFORE_DISCLOSURE,
        /** A security closure preempted response ownership. */
        SECURITY_CLOSURE_BEFORE_DISCLOSURE,
        /** Recovery established that a previously incomplete response was not disclosed. */
        RECOVERY_CONFIRMED_UNDISCLOSED
    }
}
