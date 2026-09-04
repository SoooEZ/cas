package org.apereo.cas.redis.core;

import module java.base;

import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link RedisAccountSecurityKeyCodec}.
 *
 * @author Apereo CAS
 * @since 8.0.1
 */
@Tag("Redis")
class RedisAccountSecurityKeyCodecTests {

    private final RedisAccountSecurityKeyCodec codec = new RedisAccountSecurityKeyCodec();

    @Test
    void derivesStableRawPrincipalFreeSlotLocalKeys() {
        val principal = " Alice+Sensitive@Example.ORG ";
        val fenceKey = codec.deletionFenceKey(principal);
        val dataKey = codec.dataKey("WebAuthn", principal, "records");
        val opening = fenceKey.indexOf('{');
        val closing = fenceKey.indexOf('}', opening + 1);
        val hashTag = fenceKey.substring(opening, closing + 1);

        assertEquals(fenceKey, codec.deletionFenceKey(principal.toLowerCase(Locale.ROOT)));
        assertTrue(dataKey.contains(hashTag));
        assertFalse(fenceKey.toLowerCase(Locale.ROOT).contains("alice"));
        assertFalse(dataKey.toLowerCase(Locale.ROOT).contains("sensitive"));
    }

    @Test
    void escapesEveryRedisGlobMetacharacter() {
        assertEquals("literal\\\\value\\*\\?\\[x\\]",
            codec.escapeGlobLiteral("literal\\value*?[x]"));
    }

    @Test
    void rejectsUnboundedPrincipalsAndUnsafeKeySegments() {
        assertThrows(IllegalArgumentException.class, () -> codec.deletionFenceKey(" "));
        assertThrows(IllegalArgumentException.class,
            () -> codec.deletionFenceKey("a".repeat(1_025)));
        assertThrows(IllegalArgumentException.class,
            () -> codec.dataKey("unsafe:*", "principal", "records"));
        assertThrows(IllegalArgumentException.class,
            () -> codec.dataKey("WebAuthn", "principal", "unsafe:*"));
    }
}
