package org.apereo.cas.redis.core;

import module java.base;

import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.dao.DataAccessException;

/**
 * Startup proof that all account-security fence beans address one Redis
 * endpoint and logical database.
 *
 * @author Apereo CAS
 * @since 8.0.1
 */
@RequiredArgsConstructor
public final class RedisAccountSecurityDeletionFenceStoreVerifier
    implements SmartInitializingSingleton {

    private final ListableBeanFactory beanFactory;

    @Override
    public void afterSingletonsInstantiated() {
        val stores = beanFactory.getBeansOfType(
            RedisAccountSecurityDeletionFence.class, false, false);
        if (stores.size() < 2) {
            return;
        }
        val probeKey = "CAS_ACCOUNT_SECURITY_STORE_PROBE:{shared}:" + UUID.randomUUID();
        val probeToken = UUID.randomUUID().toString().getBytes(StandardCharsets.US_ASCII);
        val fences = new ArrayList<>(stores.values());
        val authority = fences.getFirst();
        try {
            if (!authority.writeStoreProbe(probeKey, probeToken)
                || fences.stream().skip(1).anyMatch(
                    fence -> !fence.readsStoreProbe(probeKey, probeToken))) {
                throw new IllegalStateException(
                    "ACCOUNT_SECURITY_REDIS_STARTUP_REJECTED:DATASTORE_DIVERGENCE");
            }
        } finally {
            fences.forEach(fence -> {
                try {
                    fence.deleteStoreProbe(probeKey);
                } catch (final DataAccessException | IllegalStateException ignored) {
                    /*
                     * The probe has a hard 30-second TTL. Preserve the primary
                     * verification outcome if cleanup encounters a transient.
                     */
                }
            });
        }
    }
}
