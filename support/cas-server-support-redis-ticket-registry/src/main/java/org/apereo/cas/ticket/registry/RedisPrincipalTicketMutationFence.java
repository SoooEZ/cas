package org.apereo.cas.ticket.registry;

import module java.base;

/**
 * Coordinates a principal-scoped Redis ticket mutation fence.
 *
 * <p>All principal arguments are raw account identifiers. Implementations
 * must apply the Redis ticket authority's exact-identity identifier codec internally. A fence is
 * checked by every default Redis ticket write, independent of issuance mode,
 * but does not prevent authoritative ticket deletion for that principal.</p>
 *
 * @author SoooEZ
 * @since 8.0.1
 */
public interface RedisPrincipalTicketMutationFence {

    /** Default Spring bean name. */
    String BEAN_NAME = "redisPrincipalTicketMutationFence";

    /**
     * Acquire or renew a temporary fence. Replaying the same token is
     * idempotent and renews the lease; a different token or fence mode fails.
     *
     * @param principalId raw principal identifier
     * @param token opaque owner token
     * @param leaseDuration positive lease duration
     * @return fence handle
     */
    Handle acquire(String principalId, String token, Duration leaseDuration);

    /**
     * Acquire a permanent terminal fence. Replaying the same terminal token
     * is idempotent. A temporary fence owned by the same token is atomically
     * promoted; any different token fails.
     *
     * @param principalId raw principal identifier
     * @param token opaque owner token
     * @return terminal fence handle
     */
    Handle acquireTerminal(String principalId, String token);

    /**
     * Inspect the authoritative fence state on the Redis primary.
     *
     * @param principalId raw principal identifier
     * @return current state, or empty when unfenced
     */
    Optional<State> inspect(String principalId);

    /**
     * Release a temporary fence only when its owner token matches. Terminal
     * fences are permanent and this operation never removes one.
     *
     * @param principalId raw principal identifier
     * @param token opaque owner token
     * @return true when a matching temporary fence was removed
     */
    boolean release(String principalId, String token);

    /**
     * Map a raw principal id to the exact Redis key supplied to ticket-write
     * executors. This is intended for composing a custom atomic write script.
     *
     * @param principalId raw principal identifier
     * @return exact Redis fence key
     */
    String keyForPrincipal(String principalId);

    /** Fence mode. */
    enum Mode {
        /** A leased, token-releasable fence. */
        TEMPORARY,
        /** A permanent terminal account fence. */
        TERMINAL
    }

    /**
     * An acquired fence handle.
     *
     * @param redisKey exact Redis fence key
     * @param token opaque owner token
     * @param mode fence mode
     */
    record Handle(String redisKey, String token, Mode mode) {
    }

    /**
     * Authoritative fence state. Tokens are intentionally not exposed by
     * inspection.
     *
     * @param redisKey exact Redis fence key
     * @param mode fence mode
     * @param remainingLease remaining temporary lease, empty for terminal
     */
    record State(String redisKey, Mode mode, Optional<Duration> remainingLease) {
    }
}
