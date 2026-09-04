package org.apereo.cas.redis.core;

import module java.base;

import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ListableBeanFactory;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link RedisAccountSecurityDeletionFenceStoreVerifier}.
 *
 * @author Apereo CAS
 * @since 8.0.1
 */
@Tag("Redis")
class RedisAccountSecurityDeletionFenceStoreVerifierTests {

    @Test
    void provesAllFenceBeansReadTheSameAuthority() {
        val first = mock(RedisAccountSecurityDeletionFence.class);
        val second = mock(RedisAccountSecurityDeletionFence.class);
        val beanFactory = beanFactory(first, second);
        when(first.writeStoreProbe(anyString(), any(byte[].class))).thenReturn(true);
        when(second.readsStoreProbe(anyString(), any(byte[].class))).thenReturn(true);

        assertDoesNotThrow(() -> new RedisAccountSecurityDeletionFenceStoreVerifier(
            beanFactory).afterSingletonsInstantiated());

        verify(first).deleteStoreProbe(anyString());
        verify(second).deleteStoreProbe(anyString());
    }

    @Test
    void failsClosedAndCleansUpWhenStoresDiverge() {
        val first = mock(RedisAccountSecurityDeletionFence.class);
        val second = mock(RedisAccountSecurityDeletionFence.class);
        val beanFactory = beanFactory(first, second);
        when(first.writeStoreProbe(anyString(), any(byte[].class))).thenReturn(true);
        when(second.readsStoreProbe(anyString(), any(byte[].class))).thenReturn(false);

        assertThrows(IllegalStateException.class,
            () -> new RedisAccountSecurityDeletionFenceStoreVerifier(
                beanFactory).afterSingletonsInstantiated());

        verify(first).deleteStoreProbe(anyString());
        verify(second).deleteStoreProbe(anyString());
    }

    @SuppressWarnings("unchecked")
    private static ListableBeanFactory beanFactory(
        final RedisAccountSecurityDeletionFence first,
        final RedisAccountSecurityDeletionFence second) {
        val beanFactory = mock(ListableBeanFactory.class);
        val stores = new LinkedHashMap<String, RedisAccountSecurityDeletionFence>();
        stores.put("first", first);
        stores.put("second", second);
        when(beanFactory.getBeansOfType(
            RedisAccountSecurityDeletionFence.class, false, false)).thenReturn(stores);
        return beanFactory;
    }
}
