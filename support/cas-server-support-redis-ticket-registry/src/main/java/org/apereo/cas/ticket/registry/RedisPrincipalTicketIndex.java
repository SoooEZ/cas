package org.apereo.cas.ticket.registry;

import module java.base;
import org.apereo.cas.redis.core.CasRedisTemplate;
import org.apereo.cas.ticket.registry.key.RedisPrincipalTicketIndexKeyGenerator;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.springframework.data.redis.connection.ReturnType;
import org.springframework.data.redis.core.RedisCallback;

/**
 * Lifecycle support for the Redis principal-to-ticket authority index.
 *
 * <p>The index is rebuilt once when an existing Redis ticket registry is
 * upgraded. Normal principal deletion never scans the ticket keyspace: it
 * fails closed until the durable schema marker is present. Rebuild batches are
 * serialized by a renewable lease and ticket/index changes are linearized by
 * the registry write/delete scripts.</p>
 *
 * <p>A rolling deployment with an older writer is unsafe after the READY
 * marker is committed because the old process cannot maintain this index.
 * Operators must use a full-stop upgrade when adopting this schema. Redis
 * single-primary and Sentinel are supported. Redis Cluster is not supported
 * because ticket hashes, Spring keyspace sets, and principal indexes do not
 * share a hash slot.</p>
 *
 * @author SoooEZ
 * @since 8.0.1
 */
@Slf4j
final class RedisPrincipalTicketIndex implements AutoCloseable {

    private static final int REBUILD_CHUNK_SIZE = 100;

    private static final Duration REBUILD_LEASE = Duration.ofMinutes(5);

    private static final Duration REBUILD_RETRY_DELAY = Duration.ofSeconds(5);

    private static final byte[] READ_SCHEMA_SCRIPT = """
        return redis.call('GET', KEYS[1])
        """.getBytes(StandardCharsets.UTF_8);

    private static final byte[] ACQUIRE_REBUILD_LEASE_SCRIPT = """
        if redis.call('EXISTS', KEYS[2]) == 1 then
          return 0
        end
        local acquired = redis.call('SET', KEYS[1], ARGV[1],
          'PX', ARGV[2], 'NX')
        return acquired and 1 or 0
        """.getBytes(StandardCharsets.UTF_8);

    private static final byte[] ACQUIRE_MUTATION_FENCE_SCRIPT = """
        if redis.call('EXISTS', KEYS[1]) == 1 or
          redis.call('EXISTS', KEYS[2]) == 1 then
          return 0
        end
        local acquired = redis.call('SET', KEYS[1], ARGV[1],
          'PX', ARGV[2], 'NX')
        if not acquired then
          return 0
        end
        redis.call('DEL', KEYS[3])
        return 1
        """.getBytes(StandardCharsets.UTF_8);

    private static final byte[] REBUILD_PAGE_SCRIPT = """
        if redis.call('GET', KEYS[1]) ~= ARGV[1] then
          return redis.error_reply('CAS principal index rebuild lease was lost')
        end
        local function keytype(key)
          local value = redis.call('TYPE', key)
          if type(value) == 'table' then return value.ok end
          return value
        end
        local clock = redis.call('TIME')
        local now_ms = (tonumber(clock[1]) * 1000) +
          math.floor(tonumber(clock[2]) / 1000)
        local scan = redis.call('SCAN', ARGV[2], 'MATCH', ARGV[3],
          'COUNT', ARGV[4])
        local ticket_keys = scan[2]
        local expirations = {}
        local index_keys = {}
        for index = 1, #ticket_keys do
          local ticket_type = keytype(ticket_keys[index])
          if ticket_type ~= 'none' and ticket_type ~= 'hash' then
            return redis.error_reply('CAS principal index rebuild found a non-hash ticket')
          end
          if ticket_type == 'hash' then
            local principal = redis.call('HGET', ticket_keys[index], ARGV[5])
            local ttl = redis.call('PTTL', ticket_keys[index])
            if principal and principal ~= '' then
              if ttl == -1 then
                return redis.error_reply(
                  'CAS principal index rebuild found a ticket without expiration')
              end
              if ttl > 0 then
                local index_key = ARGV[6] .. principal
                local index_type = keytype(index_key)
                if index_type ~= 'none' and index_type ~= 'zset' then
                  return redis.error_reply('CAS principal ticket index has wrong type')
                end
                expirations[index] = now_ms + ttl
                index_keys[index] = index_key
              end
            end
          end
        end
        for index = 1, #ticket_keys do
          local index_key = index_keys[index]
          if index_key then
            redis.call('ZREMRANGEBYSCORE', index_key, 0, now_ms)
            redis.call('ZADD', index_key, expirations[index], ticket_keys[index])
            local last = redis.call('ZREVRANGE', index_key, 0, 0, 'WITHSCORES')
            if #last == 0 then
              redis.call('DEL', index_key)
            else
              redis.call('PEXPIREAT', index_key, math.floor(tonumber(last[2])))
            end
          end
        end
        return {tostring(scan[1]), tostring(#ticket_keys)}
        """.getBytes(StandardCharsets.UTF_8);

    private static final byte[] RENEW_LEASE_SCRIPT = """
        if redis.call('GET', KEYS[1]) == ARGV[1] then
          return redis.call('PEXPIRE', KEYS[1], ARGV[2])
        end
        return 0
        """.getBytes(StandardCharsets.UTF_8);

    private static final byte[] COMPLETE_LEASE_SCRIPT = """
        if redis.call('GET', KEYS[1]) ~= ARGV[1] then
          return 0
        end
        redis.call('SET', KEYS[2], ARGV[2])
        redis.call('DEL', KEYS[1])
        return 1
        """.getBytes(StandardCharsets.UTF_8);

    private static final byte[] RELEASE_LEASE_SCRIPT = """
        if redis.call('GET', KEYS[1]) == ARGV[1] then
          return redis.call('DEL', KEYS[1])
        end
        return 0
        """.getBytes(StandardCharsets.UTF_8);

    private static final byte[] DELETE_KEYS_PAGE_SCRIPT = """
        if redis.call('GET', KEYS[1]) ~= ARGV[1] then
          return redis.error_reply('CAS registry-wide ticket deletion lease was lost')
        end
        local scan = redis.call('SCAN', ARGV[2], 'MATCH', ARGV[3],
          'COUNT', ARGV[4])
        local keys = scan[2]
        local limit = tonumber(ARGV[4])
        local deleted = 0
        local upper = math.min(#keys, limit)
        for index = 1, upper do
          deleted = deleted + redis.call('UNLINK', keys[index])
        end
        return {tostring(scan[1]), tostring(deleted)}
        """.getBytes(StandardCharsets.UTF_8);

    private static final byte[] DELETE_EXACT_KEYS_SCRIPT = """
        if redis.call('GET', KEYS[1]) ~= ARGV[1] then
          return redis.error_reply('CAS registry-wide ticket deletion lease was lost')
        end
        local deleted = 0
        for index = 2, #KEYS do
          deleted = deleted + redis.call('UNLINK', KEYS[index])
        end
        return deleted
        """.getBytes(StandardCharsets.UTF_8);

    private final CasRedisTemplate<String, RedisTicketDocument> ticketsRedisTemplate;

    private final CasRedisTemplate<String, String> indexRedisTemplate;

    private final ScheduledExecutorService rebuildRetryExecutor =
        Executors.newSingleThreadScheduledExecutor(
            Thread.ofVirtual().name("cas-redis-principal-index-rebuild-", 0).factory());

    private final AtomicBoolean rebuildRetryScheduled = new AtomicBoolean();

    private final AtomicBoolean rebuildRecoveryActive = new AtomicBoolean();

    private volatile String authoritativeTicketPattern;

    RedisPrincipalTicketIndex(
        final CasRedisTemplate<String, RedisTicketDocument> ticketsRedisTemplate,
        final CasRedisTemplate<String, String> indexRedisTemplate) {
        this.ticketsRedisTemplate = ticketsRedisTemplate;
        this.indexRedisTemplate = indexRedisTemplate;
    }

    /**
     * Rebuild an absent schema exactly once. A node that does not own the
     * rebuild lease returns immediately; deletion remains fail-closed on that
     * node until the winning rebuilder commits READY.
     *
     * @param ticketPattern pattern covering authoritative ticket hashes
     */
    void rebuildIfNecessary(final String ticketPattern) {
        authoritativeTicketPattern = ticketPattern;
        if (isReady()) {
            if (rebuildRecoveryActive.getAndSet(false)) {
                LOGGER.info("Redis principal ticket index background recovery observed READY");
            }
            return;
        }
        val leaseToken = UUID.randomUUID().toString();
        val acquired = indexRedisTemplate.execute(
            (RedisCallback<Long>) connection -> connection.scriptingCommands().eval(
                ACQUIRE_REBUILD_LEASE_SCRIPT,
                ReturnType.INTEGER,
                2,
                utf8(RedisPrincipalTicketIndexKeyGenerator.REBUILD_LOCK_KEY),
                utf8(RedisPrincipalTicketIndexKeyGenerator.MUTATION_FENCE_KEY),
                utf8(leaseToken),
                utf8(Long.toString(REBUILD_LEASE.toMillis()))));
        if (!Long.valueOf(1).equals(acquired)) {
            if (rebuildRecoveryActive.compareAndSet(false, true)) {
                LOGGER.warn("Redis principal ticket index rebuild is fenced or owned by another CAS node; "
                    + "a background retry has been scheduled");
            }
            scheduleRebuildRetry(ticketPattern);
            return;
        }

        var completed = false;
        try {
            LOGGER.warn("Rebuilding the Redis principal ticket index before account-scoped deletion is enabled");
            var cursor = "0";
            do {
                val page = rebuildPage(cursor, ticketPattern, leaseToken);
                cursor = page.cursor();
                renewLease(RedisPrincipalTicketIndexKeyGenerator.REBUILD_LOCK_KEY,
                    leaseToken, "principal ticket index rebuild");
            } while (!"0".equals(cursor));
            completed = completeRebuild(leaseToken);
            if (!completed) {
                throw new IllegalStateException(
                    "Redis principal ticket index rebuild lease was lost before cutover");
            }
            rebuildRecoveryActive.set(false);
            LOGGER.info("Redis principal ticket index rebuild is complete");
        } finally {
            if (!completed) {
                releaseLease(RedisPrincipalTicketIndexKeyGenerator.REBUILD_LOCK_KEY, leaseToken);
            }
        }
    }

    /**
     * Require the durable rebuild cutover before an account-scoped delete.
     */
    void requireReady() {
        if (!isReady()) {
            if (authoritativeTicketPattern != null
                && !authoritativeTicketPattern.isBlank()) {
                scheduleRebuildRetry(authoritativeTicketPattern);
            }
            throw new IllegalStateException(
                "Redis principal ticket index is not ready; account-scoped deletion is disabled");
        }
    }

    /**
     * Acquire the registry-wide mutation fence and remove READY atomically.
     *
     * @return opaque lease token
     */
    String beginRegistryDelete() {
        val leaseToken = UUID.randomUUID().toString();
        val result = indexRedisTemplate.execute(
            (RedisCallback<Long>) connection -> connection.scriptingCommands().eval(
                ACQUIRE_MUTATION_FENCE_SCRIPT,
                ReturnType.INTEGER,
                3,
                utf8(RedisPrincipalTicketIndexKeyGenerator.MUTATION_FENCE_KEY),
                utf8(RedisPrincipalTicketIndexKeyGenerator.REBUILD_LOCK_KEY),
                utf8(RedisPrincipalTicketIndexKeyGenerator.READY_KEY),
                utf8(leaseToken),
                utf8(Long.toString(REBUILD_LEASE.toMillis()))));
        if (!Long.valueOf(1).equals(result)) {
            throw new IllegalStateException(
                "Redis ticket registry deletion is already running or an index rebuild is active");
        }
        return leaseToken;
    }

    /**
     * Renew the registry-wide mutation fence.
     *
     * @param leaseToken opaque lease token
     */
    void renewRegistryDelete(final String leaseToken) {
        renewLease(RedisPrincipalTicketIndexKeyGenerator.MUTATION_FENCE_KEY,
            leaseToken, "registry-wide ticket deletion");
    }

    /**
     * Atomically publish READY and release the registry-wide mutation fence.
     *
     * @param leaseToken opaque lease token
     */
    void completeRegistryDelete(final String leaseToken) {
        if (!completeLease(RedisPrincipalTicketIndexKeyGenerator.MUTATION_FENCE_KEY,
            leaseToken)) {
            throw new IllegalStateException(
                "Redis registry-wide ticket deletion lease was lost before cutover");
        }
    }

    /**
     * Release a failed registry-wide mutation fence without publishing READY.
     *
     * @param leaseToken opaque lease token
     */
    void abortRegistryDelete(final String leaseToken) {
        releaseLease(RedisPrincipalTicketIndexKeyGenerator.MUTATION_FENCE_KEY, leaseToken);
        if (authoritativeTicketPattern != null && !authoritativeTicketPattern.isBlank()) {
            scheduleRebuildRetry(authoritativeTicketPattern);
        }
    }

    /**
     * Delete every index key. This is used only by the registry-wide
     * destructive delete operation, never by principal-scoped deletion.
     *
     * @param leaseToken registry-wide mutation-fence owner token
     * @return number of Redis keys removed
     */
    long deleteAll(final String leaseToken) {
        return deleteKeysOnPrimary(indexRedisTemplate,
            RedisPrincipalTicketIndexKeyGenerator.forEverything(), leaseToken);
    }

    /**
     * Discover and unlink every matching key on the Redis primary. Both
     * discovery and deletion run in the same bounded Lua page so a replica
     * read policy cannot produce a stale empty scan and an unsafe cutover.
     *
     * @param redisTemplate template whose connection factory owns the keys
     * @param keyPattern Redis scan pattern
     * @param leaseToken registry-wide mutation-fence owner token
     * @return number of keys removed
     */
    long deleteKeysOnPrimary(final CasRedisTemplate<?, ?> redisTemplate,
                             final String keyPattern,
                             final String leaseToken) {
        var count = 0L;
        var deletedInPass = 0L;
        do {
            var cursor = "0";
            deletedInPass = 0;
            do {
                val page = deleteKeysPageOnPrimary(redisTemplate, cursor, keyPattern, leaseToken);
                cursor = page.cursor();
                count += page.deleted();
                deletedInPass += page.deleted();
                renewRegistryDelete(leaseToken);
            } while (!"0".equals(cursor));
        } while (deletedInPass > 0);
        return count;
    }

    /**
     * Unlink an exact key set on the Redis primary only while the caller still
     * owns the registry-wide mutation fence.
     *
     * @param redisTemplate template whose connection factory owns the keys
     * @param redisKeys exact Redis keys to unlink
     * @param leaseToken registry-wide mutation-fence owner token
     * @return number of Redis keys removed
     */
    long deleteExactKeysOnPrimary(final CasRedisTemplate<?, ?> redisTemplate,
                                  final Collection<String> redisKeys,
                                  final String leaseToken) {
        if (redisKeys.isEmpty()) {
            renewRegistryDelete(leaseToken);
            return 0;
        }
        val keysAndArguments = new ArrayList<byte[]>(redisKeys.size() + 2);
        keysAndArguments.add(utf8(RedisPrincipalTicketIndexKeyGenerator.MUTATION_FENCE_KEY));
        redisKeys.forEach(key -> keysAndArguments.add(utf8(key)));
        keysAndArguments.add(utf8(leaseToken));
        val result = redisTemplate.execute(
            (RedisCallback<Long>) connection -> connection.scriptingCommands().eval(
                DELETE_EXACT_KEYS_SCRIPT,
                ReturnType.INTEGER,
                redisKeys.size() + 1,
                keysAndArguments.toArray(byte[][]::new)));
        if (result == null || result < 0 || result > redisKeys.size()) {
            throw new IllegalStateException("Redis exact key deletion returned an invalid result");
        }
        renewRegistryDelete(leaseToken);
        return result;
    }

    @Override
    public void close() {
        rebuildRetryExecutor.shutdownNow();
    }

    private boolean isReady() {
        val result = indexRedisTemplate.execute(
            (RedisCallback<byte[]>) connection -> connection.scriptingCommands().eval(
                READ_SCHEMA_SCRIPT,
                ReturnType.VALUE,
                1,
                utf8(RedisPrincipalTicketIndexKeyGenerator.READY_KEY)));
        return RedisPrincipalTicketIndexKeyGenerator.SCHEMA_VERSION.equals(asString(result));
    }

    private static DeletePage deleteKeysPageOnPrimary(
        final CasRedisTemplate<?, ?> redisTemplate,
        final String cursor,
        final String keyPattern,
        final String leaseToken) {
        val result = redisTemplate.execute(
            (RedisCallback<List<?>>) connection -> connection.scriptingCommands().eval(
                DELETE_KEYS_PAGE_SCRIPT,
                ReturnType.MULTI,
                1,
                utf8(RedisPrincipalTicketIndexKeyGenerator.MUTATION_FENCE_KEY),
                utf8(leaseToken),
                utf8(cursor),
                utf8(keyPattern),
                utf8(Integer.toString(REBUILD_CHUNK_SIZE))));
        if (result == null || result.size() != 2) {
            throw new IllegalStateException("Redis primary key deletion returned an invalid page");
        }
        val nextCursor = asString(result.getFirst());
        val deleted = Long.parseLong(asString(result.get(1)));
        if (nextCursor.isBlank() || deleted < 0 || deleted > REBUILD_CHUNK_SIZE) {
            throw new IllegalStateException("Redis primary key deletion returned invalid coordinates");
        }
        return new DeletePage(nextCursor, deleted);
    }

    /**
     * Execute one bounded, lease-checked rebuild page.
     *
     * @param cursor Redis scan cursor
     * @param ticketPattern authoritative ticket-key pattern
     * @param leaseToken rebuild-lease owner token
     * @return next Redis scan cursor
     */
    RebuildPage rebuildPage(final String cursor,
                            final String ticketPattern,
                            final String leaseToken) {
        val result = ticketsRedisTemplate.execute(
            (RedisCallback<List<?>>) connection -> connection.scriptingCommands().eval(
                REBUILD_PAGE_SCRIPT,
                ReturnType.MULTI,
                1,
                utf8(RedisPrincipalTicketIndexKeyGenerator.REBUILD_LOCK_KEY),
                utf8(leaseToken),
                utf8(cursor),
                utf8(ticketPattern),
                utf8(Integer.toString(REBUILD_CHUNK_SIZE)),
                utf8(RedisTicketDocument.FIELD_NAME_PRINCIPAL),
                utf8(RedisPrincipalTicketIndexKeyGenerator.prefix())));
        if (result == null || result.size() != 2) {
            throw new IllegalStateException("Redis principal ticket index rebuild returned an invalid page");
        }
        return new RebuildPage(asString(result.getFirst()));
    }

    private void renewLease(final String leaseKey,
                            final String leaseToken,
                            final String operation) {
        val result = indexRedisTemplate.execute(
            (RedisCallback<Long>) connection -> connection.scriptingCommands().eval(
                RENEW_LEASE_SCRIPT,
                ReturnType.INTEGER,
                1,
                utf8(leaseKey),
                utf8(leaseToken),
                utf8(Long.toString(REBUILD_LEASE.toMillis()))));
        if (!Long.valueOf(1).equals(result)) {
            throw new IllegalStateException("Redis %s lease was lost".formatted(operation));
        }
    }

    private boolean completeRebuild(final String leaseToken) {
        return completeLease(RedisPrincipalTicketIndexKeyGenerator.REBUILD_LOCK_KEY,
            leaseToken);
    }

    private boolean completeLease(final String leaseKey, final String leaseToken) {
        val result = indexRedisTemplate.execute(
            (RedisCallback<Long>) connection -> connection.scriptingCommands().eval(
                COMPLETE_LEASE_SCRIPT,
                ReturnType.INTEGER,
                2,
                utf8(leaseKey),
                utf8(RedisPrincipalTicketIndexKeyGenerator.READY_KEY),
                utf8(leaseToken),
                utf8(RedisPrincipalTicketIndexKeyGenerator.SCHEMA_VERSION)));
        return Long.valueOf(1).equals(result);
    }

    private void releaseLease(final String leaseKey, final String leaseToken) {
        indexRedisTemplate.execute(
            (RedisCallback<Long>) connection -> connection.scriptingCommands().eval(
                RELEASE_LEASE_SCRIPT,
                ReturnType.INTEGER,
                1,
                utf8(leaseKey),
                utf8(leaseToken)));
    }

    @SuppressWarnings("FutureReturnValueIgnored")
    private void scheduleRebuildRetry(final String ticketPattern) {
        if (rebuildRetryExecutor.isShutdown()
            || !rebuildRetryScheduled.compareAndSet(false, true)) {
            return;
        }
        try {
            rebuildRetryExecutor.schedule(() -> {
                rebuildRetryScheduled.set(false);
                if (rebuildRetryExecutor.isShutdown()) {
                    return;
                }
                try {
                    rebuildIfNecessary(ticketPattern);
                } catch (final Exception cause) {
                    LOGGER.error("Redis principal ticket index background rebuild failed; retrying", cause);
                    scheduleRebuildRetry(ticketPattern);
                }
            }, REBUILD_RETRY_DELAY.toMillis(), TimeUnit.MILLISECONDS);
        } catch (final RejectedExecutionException cause) {
            rebuildRetryScheduled.set(false);
            if (!rebuildRetryExecutor.isShutdown()) {
                throw cause;
            }
        }
    }

    private static byte[] utf8(final String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static String asString(final Object value) {
        return value instanceof final byte[] bytes
            ? new String(bytes, StandardCharsets.UTF_8)
            : Objects.toString(value, StringUtils.EMPTY);
    }

    record RebuildPage(String cursor) {
    }

    private record DeletePage(String cursor, long deleted) {
    }
}
