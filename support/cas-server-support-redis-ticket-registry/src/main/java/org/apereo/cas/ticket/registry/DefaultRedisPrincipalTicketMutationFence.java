package org.apereo.cas.ticket.registry;

import module java.base;
import org.apereo.cas.redis.core.CasRedisTemplate;
import org.apereo.cas.ticket.registry.key.RedisPrincipalIdentifierCodec;
import org.apereo.cas.ticket.registry.key.RedisPrincipalTicketMutationFenceKeyGenerator;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.springframework.data.redis.connection.ReturnType;
import org.springframework.data.redis.core.RedisCallback;

/**
 * Default primary-routed Redis implementation of
 * {@link RedisPrincipalTicketMutationFence}.
 *
 * @author SoooEZ
 * @since 8.0.1
 */
public class DefaultRedisPrincipalTicketMutationFence
    implements RedisPrincipalTicketMutationFence {

    private static final String TEMPORARY_PREFIX = "temporary:";

    private static final String TERMINAL_PREFIX = "terminal:";

    private static final long MISSING_KEY_TIME_TO_LIVE = -2;

    private static final byte[] ACQUIRE_TEMPORARY_SCRIPT = """
        local expected = ARGV[1] .. ARGV[2]
        local current = redis.call('GET', KEYS[1])
        if not current then
          redis.call('SET', KEYS[1], expected, 'PX', ARGV[3])
          return 1
        end
        if current == expected then
          redis.call('PEXPIRE', KEYS[1], ARGV[3])
          return 2
        end
        return 0
        """.getBytes(StandardCharsets.UTF_8);

    private static final byte[] ACQUIRE_TERMINAL_SCRIPT = """
        local expected = ARGV[1] .. ARGV[3]
        local promotable = ARGV[2] .. ARGV[3]
        local current = redis.call('GET', KEYS[1])
        if not current then
          redis.call('SET', KEYS[1], expected)
          return 1
        end
        if current == expected then
          redis.call('PERSIST', KEYS[1])
          return 2
        end
        if current == promotable then
          redis.call('SET', KEYS[1], expected)
          return 3
        end
        return 0
        """.getBytes(StandardCharsets.UTF_8);

    private static final byte[] INSPECT_SCRIPT = """
        local current = redis.call('GET', KEYS[1])
        if not current then
          return {'', '-2'}
        end
        return {current, tostring(redis.call('PTTL', KEYS[1]))}
        """.getBytes(StandardCharsets.UTF_8);

    private static final byte[] RELEASE_TEMPORARY_SCRIPT = """
        local expected = ARGV[1] .. ARGV[2]
        if redis.call('GET', KEYS[1]) == expected then
          return redis.call('DEL', KEYS[1])
        end
        return 0
        """.getBytes(StandardCharsets.UTF_8);

    private final CasRedisTemplate<String, String> redisTemplate;

    /**
     * Build the default fence collaborator.
     *
     * @param redisTemplate sessions Redis template
     */
    public DefaultRedisPrincipalTicketMutationFence(
        final CasRedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = Objects.requireNonNull(redisTemplate);
    }

    /**
     * Build the default fence collaborator using the historical constructor
     * signature. Principal authority mapping is intentionally independent of
     * the registry's optional payload cipher.
     *
     * @param redisTemplate sessions Redis template
     * @param ticketRegistry retained for source and binary compatibility
     */
    public DefaultRedisPrincipalTicketMutationFence(
        final CasRedisTemplate<String, String> redisTemplate,
        final TicketRegistry ticketRegistry) {
        this(redisTemplate);
        Objects.requireNonNull(ticketRegistry, "ticketRegistry");
    }

    @Override
    public Handle acquire(final String principalId,
                          final String token,
                          final Duration leaseDuration) {
        val redisKey = keyForPrincipal(principalId);
        val ownerToken = requireToken(token);
        Objects.requireNonNull(leaseDuration, "leaseDuration");
        val leaseMillis = leaseDuration.toMillis();
        if (leaseDuration.isNegative() || leaseDuration.isZero() || leaseMillis <= 0) {
            throw new IllegalArgumentException("Principal mutation-fence lease must be positive");
        }
        val result = redisTemplate.execute(
            (RedisCallback<Long>) connection -> connection.scriptingCommands().eval(
                ACQUIRE_TEMPORARY_SCRIPT,
                ReturnType.INTEGER,
                1,
                utf8(redisKey),
                utf8(TEMPORARY_PREFIX),
                utf8(ownerToken),
                utf8(Long.toString(leaseMillis))));
        requireAcquireResult(result, redisKey);
        return new Handle(redisKey, ownerToken, Mode.TEMPORARY);
    }

    @Override
    public Handle acquireTerminal(final String principalId, final String token) {
        val redisKey = keyForPrincipal(principalId);
        val ownerToken = requireToken(token);
        val result = redisTemplate.execute(
            (RedisCallback<Long>) connection -> connection.scriptingCommands().eval(
                ACQUIRE_TERMINAL_SCRIPT,
                ReturnType.INTEGER,
                1,
                utf8(redisKey),
                utf8(TERMINAL_PREFIX),
                utf8(TEMPORARY_PREFIX),
                utf8(ownerToken)));
        requireAcquireResult(result, redisKey);
        return new Handle(redisKey, ownerToken, Mode.TERMINAL);
    }

    @Override
    public Optional<State> inspect(final String principalId) {
        val redisKey = keyForPrincipal(principalId);
        val result = redisTemplate.execute(
            (RedisCallback<List<?>>) connection -> connection.scriptingCommands().eval(
                INSPECT_SCRIPT,
                ReturnType.MULTI,
                1,
                utf8(redisKey)));
        if (result == null || result.size() != 2) {
            throw new IllegalStateException("Redis principal mutation-fence inspection returned an invalid result");
        }
        val value = asString(result.getFirst());
        val remainingMillis = Long.parseLong(asString(result.get(1)));
        if (value.isEmpty() && remainingMillis == MISSING_KEY_TIME_TO_LIVE) {
            return Optional.empty();
        }
        if (value.startsWith(TERMINAL_PREFIX) && remainingMillis == -1) {
            return Optional.of(new State(redisKey, Mode.TERMINAL, Optional.empty()));
        }
        if (value.startsWith(TEMPORARY_PREFIX) && remainingMillis >= 0) {
            return Optional.of(new State(redisKey, Mode.TEMPORARY,
                Optional.of(Duration.ofMillis(remainingMillis))));
        }
        throw new IllegalStateException("Redis principal mutation fence contains an invalid state");
    }

    @Override
    public boolean release(final String principalId, final String token) {
        val redisKey = keyForPrincipal(principalId);
        val result = redisTemplate.execute(
            (RedisCallback<Long>) connection -> connection.scriptingCommands().eval(
                RELEASE_TEMPORARY_SCRIPT,
                ReturnType.INTEGER,
                1,
                utf8(redisKey),
                utf8(TEMPORARY_PREFIX),
                utf8(requireToken(token))));
        if (result == null || result < 0 || result > 1) {
            throw new IllegalStateException("Redis principal mutation-fence release returned an invalid result");
        }
        return result == 1;
    }

    @Override
    public String keyForPrincipal(final String principalId) {
        if (StringUtils.isBlank(principalId)) {
            throw new IllegalArgumentException("Raw principal identifier must not be blank");
        }
        val mappedPrincipal = RedisPrincipalIdentifierCodec.encode(principalId);
        return RedisPrincipalTicketMutationFenceKeyGenerator.forPrincipal(mappedPrincipal);
    }

    private static void requireAcquireResult(final Long result, final String redisKey) {
        if (result == null || result < 0 || result > 3) {
            throw new IllegalStateException("Redis principal mutation-fence acquisition returned an invalid result");
        }
        if (result == 0) {
            throw new IllegalStateException(
                "Redis principal mutation fence [%s] is owned by another token or mode".formatted(redisKey));
        }
    }

    private static String requireToken(final String token) {
        if (StringUtils.isBlank(token)) {
            throw new IllegalArgumentException("Principal mutation-fence token must not be blank");
        }
        return token;
    }

    private static byte[] utf8(final String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static String asString(final Object value) {
        return value instanceof final byte[] bytes
            ? new String(bytes, StandardCharsets.UTF_8)
            : Objects.toString(value, StringUtils.EMPTY);
    }
}
