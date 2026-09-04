package org.apereo.cas.redis.core;

import module java.base;

/**
 * Public account-deletion contract implemented by Redis-backed security stores.
 *
 * <p>Overlay deletion coordinators use this contract rather than reaching into
 * repository-private Redis templates. Implementations must acquire and verify
 * the terminal fence in the exact Redis datastore used by their writers.</p>
 *
 * @author Apereo CAS
 * @since 8.0.1
 */
public interface RedisAccountSecurityStore {
    /**
     * Stable store identifier.
     *
     * @return store identifier
     */
    String getAccountSecurityStoreId();

    /**
     * Acquire the permanent terminal deletion fence.
     *
     * @param rawPrincipal account principal
     * @param closureId durable account-deletion closure identifier
     * @return acquisition result
     */
    RedisAccountSecurityDeletionFence.TerminalFenceResult acquireTerminal(
        String rawPrincipal, UUID closureId);

    /**
     * Check exact ownership of the permanent terminal fence.
     *
     * @param rawPrincipal account principal
     * @param closureId durable closure identifier
     * @return true only for the same terminal token
     */
    boolean isTerminal(String rawPrincipal, UUID closureId);

    /**
     * Delete all security data for the principal and prove exact absence while
     * the same terminal fence remains installed.
     *
     * @param rawPrincipal account principal
     * @param closureId durable closure identifier
     * @return true when the data is absent under the exact fence
     */
    boolean eraseAndVerify(String rawPrincipal, UUID closureId);

    /**
     * Prove that this store contains no security data for the principal.
     *
     * @param rawPrincipal account principal
     * @return true when absent
     */
    boolean isAccountSecurityDataAbsent(String rawPrincipal);
}
