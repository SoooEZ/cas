package org.apereo.cas.ticket.registry.key;

import module java.base;
import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.integration.support.locks.LockRegistry;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link DigestingRedisLockRegistry}.
 *
 * @author SoooEZ
 * @since 8.0.0
 */
@Tag("Redis")
class DigestingRedisLockRegistryTests {
    @Test
    void verifyRawTicketIdentifierNeverReachesRedisDelegate() {
        val observedKeys = new ArrayList<Object>();
        val lock = mock(Lock.class);
        val delegate = (LockRegistry<Lock>) key -> {
            observedKeys.add(key);
            return lock;
        };
        val registry = new DigestingRedisLockRegistry(delegate);
        val ticketId = "TGT-super-secret-capability";

        assertSame(lock, registry.obtain(ticketId));
        assertSame(lock, registry.obtain(ticketId));
        assertSame(lock, registry.obtain("ST-another-secret"));

        assertEquals(observedKeys.getFirst(), observedKeys.get(1));
        assertNotEquals(observedKeys.getFirst(), observedKeys.getLast());
        observedKeys.forEach(key -> {
            val value = key.toString();
            assertTrue(value.matches("cas-ticket-lock:v1:[0-9a-f]{64}"));
            assertFalse(value.contains("TGT-"));
            assertFalse(value.contains("ST-"));
            assertFalse(value.contains("secret"));
        });
        assertThrows(NullPointerException.class, () -> registry.obtain(null));
        assertThrows(IllegalArgumentException.class,
            () -> registry.obtain(UUID.randomUUID()));
    }
}
