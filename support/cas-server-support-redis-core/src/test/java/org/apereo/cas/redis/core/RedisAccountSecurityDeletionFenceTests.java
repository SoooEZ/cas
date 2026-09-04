package org.apereo.cas.redis.core;

import module java.base;

import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link RedisAccountSecurityDeletionFence}.
 *
 * @author Apereo CAS
 * @since 8.0.1
 */
@Tag("Redis")
class RedisAccountSecurityDeletionFenceTests {
    @Test
    void verifyLaterMatchingHashTagCannotBypassSlotGuard() {
        val redisTemplate = mock(CasRedisTemplate.class);
        val keyCodec = new RedisAccountSecurityKeyCodec();
        val fence = new RedisAccountSecurityDeletionFence(redisTemplate, keyCodec);
        val principal = UUID.randomUUID().toString();
        val fenceKey = keyCodec.deletionFenceKey(principal);
        val expectedHashTag = fenceKey.substring(
            fenceKey.indexOf('{'), fenceKey.indexOf('}') + 1);
        val forgedKey = "WebAuthn:{different}:" + expectedHashTag + ":records";

        assertThrows(IllegalArgumentException.class,
            () -> fence.readFromAuthority(principal, forgedKey));
        verifyNoInteractions(redisTemplate);
    }

    @Test
    void verifyEmptyFirstHashTagUsesTheWholeRedisKey() {
        val redisTemplate = mock(CasRedisTemplate.class);
        val keyCodec = new RedisAccountSecurityKeyCodec();
        val fence = new RedisAccountSecurityDeletionFence(redisTemplate, keyCodec);
        val principal = UUID.randomUUID().toString();
        val fenceKey = keyCodec.deletionFenceKey(principal);
        val expectedHashTag = fenceKey.substring(
            fenceKey.indexOf('{'), fenceKey.indexOf('}') + 1);
        val forgedKey = "WebAuthn:{}:" + expectedHashTag + ":records";

        assertThrows(IllegalArgumentException.class,
            () -> fence.readFromAuthority(principal, forgedKey));
        verifyNoInteractions(redisTemplate);
    }
}
