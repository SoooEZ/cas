package org.apereo.cas.ticket.registry.key;

import module java.base;
import org.apereo.cas.util.DigestUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.integration.support.locks.LockRegistry;

/**
 * Prevents ticket identifiers from appearing in Redis lock keys.
 *
 * <p>The digest is deterministic so every CAS node still resolves the same
 * distributed lock. The domain and output prefix version the key format and
 * keep it separate from unrelated uses of the same ticket identifier.</p>
 *
 * @author SoooEZ
 * @since 8.0.0
 */
@RequiredArgsConstructor
public final class DigestingRedisLockRegistry implements LockRegistry<Lock> {
    private static final String DIGEST_DOMAIN =
        "cas:ticket-registry:redis-lock:v1\u0000";

    private static final String LOCK_KEY_PREFIX =
        "cas-ticket-lock:v1:";

    private final LockRegistry<? extends Lock> delegate;

    @Override
    public Lock obtain(final Object lockKey) {
        Objects.requireNonNull(lockKey, "lockKey");
        if (!(lockKey instanceof final String canonicalKey)) {
            throw new IllegalArgumentException(
                "Redis ticket lock keys must be strings");
        }
        return delegate.obtain(LOCK_KEY_PREFIX
            + DigestUtils.sha256(DIGEST_DOMAIN + canonicalKey));
    }
}
