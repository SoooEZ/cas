package org.apereo.cas.trusted.authentication.storage;

import module java.base;

import org.apereo.cas.redis.core.CasRedisTemplate;
import org.apereo.cas.redis.core.RedisAccountSecurityDeletionFence;
import org.apereo.cas.redis.core.RedisAccountSecurityKeyCodec;
import org.apereo.cas.trusted.authentication.api.MultifactorAuthenticationTrustRecord;
import lombok.val;
import org.springframework.data.redis.connection.ReturnType;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.serializer.RedisSerializer;

/**
 * Raw-principal-free secondary locator for Redis trusted-MFA records.
 *
 * <p>The locator is a hint and is never an authentication authority. A caller
 * must re-read the principal-owned current record through the shared deletion
 * fence and verify its principal digest, identifier, record-key digest and
 * expiry before trusting a {@link Candidate}.</p>
 *
 * <p>Writers publish a candidate before the cross-slot authority write and, in
 * the same coordinate-slot Lua operation, add a unique two-minute publication
 * intent. Completion removes only that writer's token. This protects the
 * candidate from stale-hint cleanup during the crash window without requiring
 * a cross-slot transaction or a global lock.</p>
 *
 * <p>Candidate scores are absolute record expiration times. Reads use Redis
 * {@code TIME} to atomically prune expired candidates, and every locator and
 * intent key expires no later than its greatest live score. Neither Redis keys
 * nor members contain a raw principal or record key.</p>
 *
 * @author Apereo CAS
 * @since 8.0.1
 */
public final class RedisTrustedMfaRecordLocator {
    /** Stable Spring bean name. */
    public static final String BEAN_NAME = "trustedMfaRedisRecordLocator";

    static final String REDIS_NAMESPACE = RedisTrustedMfaRecordLocator.class.getSimpleName();

    static final String LOCATOR_PATTERN = REDIS_NAMESPACE + ":*";

    static final String SCHEMA_VERSION = "1";

    static final int MAXIMUM_CANDIDATES = 256;

    static final int MAXIMUM_PUBLICATION_INTENTS = 256;

    private static final int SHA_256_HEX_LENGTH = 64;

    private static final int UUID_TEXT_LENGTH = 36;

    private static final int MAXIMUM_RECORD_KEY_LENGTH = 4_096;

    private static final long MAXIMUM_EXACT_REDIS_SCORE = 9_007_199_254_740_991L;

    private static final long PUBLICATION_INTENT_MILLIS = Duration.ofMinutes(2).toMillis();

    private static final long EXPIRED_RESULT = -1;

    private static final long CANDIDATE_CAPACITY_RESULT = -2;

    private static final long INTENT_CAPACITY_RESULT = -3;

    private static final long REMOVAL_BUSY_RESULT = -4;

    private static final long INVALID_LOCATOR_RESULT = -5;

    private static final long REMOVAL_LEASE_LOST_RESULT = -1;

    private static final long REMOVAL_CANDIDATE_LEASE_LOST_RESULT = -2;

    private static final long MAXIMUM_REMOVAL_LEASE_MILLIS = Duration.ofMinutes(5).toMillis();

    private static final byte[] BEGIN_PUBLICATION_SCRIPT = script("""
        local function valid_token(value)
          if string.len(value) ~= 36
              or string.sub(value, 9, 9) ~= '-'
              or string.sub(value, 14, 14) ~= '-'
              or string.sub(value, 19, 19) ~= '-'
              or string.sub(value, 24, 24) ~= '-' then
            return false
          end
          local compact, count = string.gsub(value, '%-', '')
          return count == 4 and compact ~= string.rep('0', 32)
              and string.match(compact, '^[0-9a-f]+$') ~= nil
        end
        local now = redis.call('TIME')
        local now_millis = (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
        local expiry = tonumber(ARGV[3])
        if redis.call('EXISTS', KEYS[4]) ~= 0 then
          return -4
        end
        redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now_millis)
        redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now_millis)
        redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now_millis)
        if not expiry or expiry <= now_millis then
          return -1
        end
        local committed_count = redis.call('ZCARD', KEYS[1])
        local pending_count = redis.call('ZCARD', KEYS[2])
        if committed_count > tonumber(ARGV[5]) or pending_count > tonumber(ARGV[6]) then
          return -5
        end
        if not redis.call('ZSCORE', KEYS[3], ARGV[2])
            and redis.call('ZCARD', KEYS[3]) >= tonumber(ARGV[6]) then
          return -3
        end
        if not redis.call('ZSCORE', KEYS[2], ARGV[2])
            and redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[6]) then
          return -3
        end
        local candidates = {}
        local committed = redis.call('ZRANGE', KEYS[1], 0, -1)
        for _, candidate in ipairs(committed) do
          candidates[candidate] = true
        end
        local pending = redis.call('ZRANGE', KEYS[2], 0, -1)
        for _, publication in ipairs(pending) do
          if string.len(publication) <= 37
              or string.sub(publication, -37, -37) ~= ':' then
            return -5
          end
          local publication_token = string.sub(publication, -36)
          if not valid_token(publication_token) then
            return -5
          end
          candidates[string.sub(publication, 1, -38)] = true
        end
        candidates[ARGV[1]] = true
        local unique_count = 0
        for _ in pairs(candidates) do
          unique_count = unique_count + 1
          if unique_count > tonumber(ARGV[5]) then
            return -2
          end
        end
        redis.call('ZADD', KEYS[2], expiry, ARGV[2])
        local intent_expiry = now_millis + tonumber(ARGV[4])
        redis.call('ZADD', KEYS[3], intent_expiry, ARGV[2])
        for index = 1, 3 do
          if redis.call('ZCARD', KEYS[index]) == 0 then
            redis.call('DEL', KEYS[index])
          else
            local latest = redis.call('ZREVRANGE', KEYS[index], 0, 0, 'WITHSCORES')
            redis.call('PEXPIREAT', KEYS[index], math.floor(tonumber(latest[2])))
          end
        end
        return 1
        """);

    private static final byte[] COMMIT_PUBLICATION_SCRIPT = script("""
        local function keytype(key)
          local value = redis.call('TYPE', key)
          if type(value) == 'table' then return value.ok end
          return value
        end
        local function valid_token(value)
          if not value or string.len(value) ~= 36
              or string.sub(value, 9, 9) ~= '-'
              or string.sub(value, 14, 14) ~= '-'
              or string.sub(value, 19, 19) ~= '-'
              or string.sub(value, 24, 24) ~= '-' then
            return false
          end
          local compact, count = string.gsub(value, '%-', '')
          return count == 4 and compact ~= string.rep('0', 32)
              and string.match(compact, '^[0-9a-f]+$') ~= nil
        end
        local function valid_candidate(value)
          local schema, digest, record_id = string.match(
              value or '', '^([^:]+):([^:]+):([^:]+)$')
          if schema ~= '1' or not digest or string.len(digest) ~= 64
              or string.match(digest, '^[0-9a-f]+$') == nil or not record_id then
            return false
          end
          local negative = string.sub(record_id, 1, 1) == '-'
          local digits = negative and string.sub(record_id, 2) or record_id
          if digits == '' or string.match(digits, '^%d+$') == nil then
            return false
          end
          if digits == '0' then
            return not negative
          end
          if string.sub(digits, 1, 1) == '0' or string.len(digits) > 19 then
            return false
          end
          if string.len(digits) == 19 then
            local limit = negative and '9223372036854775808' or '9223372036854775807'
            if digits > limit then
              return false
            end
          end
          return true
        end
        local function parse_publication(value)
          if not value or string.len(value) <= 37
              or string.sub(value, -37, -37) ~= ':' then
            return nil
          end
          local publication_token = string.sub(value, -36)
          local candidate = string.sub(value, 1, -38)
          if not valid_token(publication_token) or not valid_candidate(candidate) then
            return nil
          end
          return candidate
        end
        local committed_type = keytype(KEYS[1])
        local pending_type = keytype(KEYS[2])
        local intent_type = keytype(KEYS[3])
        local removal_type = keytype(KEYS[4])
        if (committed_type ~= 'none' and committed_type ~= 'zset')
            or (pending_type ~= 'none' and pending_type ~= 'zset')
            or (intent_type ~= 'none' and intent_type ~= 'zset')
            or (removal_type ~= 'none' and removal_type ~= 'string') then
          return -5
        end
        local now = redis.call('TIME')
        local now_millis = (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
        redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now_millis)
        redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now_millis)
        redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now_millis)
        if not valid_candidate(ARGV[2]) or parse_publication(ARGV[1]) ~= ARGV[2] then
          return -5
        end
        local committed_count = redis.call('ZCARD', KEYS[1])
        local pending_count = redis.call('ZCARD', KEYS[2])
        local intent_count = redis.call('ZCARD', KEYS[3])
        if committed_count > tonumber(ARGV[4])
            or pending_count > tonumber(ARGV[5])
            or intent_count > tonumber(ARGV[5]) then
          return -5
        end
        local candidates = {}
        local committed_candidates = redis.call('ZRANGE', KEYS[1], 0, -1)
        for _, candidate in ipairs(committed_candidates) do
          if not valid_candidate(candidate) then
            return -5
          end
          candidates[candidate] = true
        end
        local pending_publications = redis.call('ZRANGE', KEYS[2], 0, -1)
        for _, publication in ipairs(pending_publications) do
          local candidate = parse_publication(publication)
          if not candidate then
            return -5
          end
          candidates[candidate] = true
        end
        local live = redis.call('ZSCORE', KEYS[3], ARGV[1])
        local committed = 0
        local expiry = tonumber(ARGV[3])
        if live and redis.call('EXISTS', KEYS[4]) == 0
            and expiry and expiry > now_millis then
          candidates[ARGV[2]] = true
          local unique_count = 0
          for _ in pairs(candidates) do
            unique_count = unique_count + 1
          end
          if unique_count > tonumber(ARGV[4]) then
            committed = -2
          else
            local current_expiry = redis.call('ZSCORE', KEYS[1], ARGV[2])
            if current_expiry and tonumber(current_expiry) > expiry then
              expiry = tonumber(current_expiry)
            end
            redis.call('ZADD', KEYS[1], expiry, ARGV[2])
            committed = 1
          end
        end
        if committed == 1 then
          redis.call('ZREM', KEYS[2], ARGV[1])
        end
        redis.call('ZREM', KEYS[3], ARGV[1])
        for index = 1, 3 do
          if redis.call('ZCARD', KEYS[index]) == 0 then
            redis.call('DEL', KEYS[index])
          else
            local latest = redis.call('ZREVRANGE', KEYS[index], 0, 0, 'WITHSCORES')
            redis.call('PEXPIREAT', KEYS[index], math.floor(tonumber(latest[2])))
          end
        end
        return committed
        """);

    private static final byte[] COMPLETE_PUBLICATION_SCRIPT = script("""
        local now = redis.call('TIME')
        local now_millis = (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
        redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now_millis)
        redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now_millis)
        local removed = redis.call('ZREM', KEYS[1], ARGV[1])
        removed = removed + redis.call('ZREM', KEYS[2], ARGV[1])
        for index = 1, 2 do
          if redis.call('ZCARD', KEYS[index]) == 0 then
            redis.call('DEL', KEYS[index])
          else
            local latest = redis.call('ZREVRANGE', KEYS[index], 0, 0, 'WITHSCORES')
            redis.call('PEXPIREAT', KEYS[index], math.floor(tonumber(latest[2])))
          end
        end
        return removed
        """);

    private static final byte[] ADD_CANDIDATE_SCRIPT = script("""
        local function keytype(key)
          local value = redis.call('TYPE', key)
          if type(value) == 'table' then return value.ok end
          return value
        end
        local function valid_token(value)
          if not value or string.len(value) ~= 36
              or string.sub(value, 9, 9) ~= '-'
              or string.sub(value, 14, 14) ~= '-'
              or string.sub(value, 19, 19) ~= '-'
              or string.sub(value, 24, 24) ~= '-' then
            return false
          end
          local compact, count = string.gsub(value, '%-', '')
          return count == 4 and compact ~= string.rep('0', 32)
              and string.match(compact, '^[0-9a-f]+$') ~= nil
        end
        local function valid_candidate(value)
          local schema, digest, record_id = string.match(
              value or '', '^([^:]+):([^:]+):([^:]+)$')
          if schema ~= '1' or not digest or string.len(digest) ~= 64
              or string.match(digest, '^[0-9a-f]+$') == nil or not record_id then
            return false
          end
          local negative = string.sub(record_id, 1, 1) == '-'
          local digits = negative and string.sub(record_id, 2) or record_id
          if digits == '' or string.match(digits, '^%d+$') == nil then
            return false
          end
          if digits == '0' then
            return not negative
          end
          if string.sub(digits, 1, 1) == '0' or string.len(digits) > 19 then
            return false
          end
          if string.len(digits) == 19 then
            local limit = negative and '9223372036854775808' or '9223372036854775807'
            if digits > limit then
              return false
            end
          end
          return true
        end
        local function parse_publication(value)
          if not value or string.len(value) <= 37
              or string.sub(value, -37, -37) ~= ':' then
            return nil
          end
          local publication_token = string.sub(value, -36)
          local candidate = string.sub(value, 1, -38)
          if not valid_token(publication_token) or not valid_candidate(candidate) then
            return nil
          end
          return candidate
        end
        local committed_type = keytype(KEYS[1])
        local pending_type = keytype(KEYS[2])
        local removal_type = keytype(KEYS[3])
        if (committed_type ~= 'none' and committed_type ~= 'zset')
            or (pending_type ~= 'none' and pending_type ~= 'zset')
            or (removal_type ~= 'none' and removal_type ~= 'string') then
          return -5
        end
        local now = redis.call('TIME')
        local now_millis = (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
        local expiry = tonumber(ARGV[2])
        if redis.call('EXISTS', KEYS[3]) ~= 0 then
          return -4
        end
        redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now_millis)
        redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now_millis)
        if not expiry or expiry <= now_millis then
          return -1
        end
        if not valid_candidate(ARGV[1]) then
          return -5
        end
        local committed_count = redis.call('ZCARD', KEYS[1])
        local pending_count = redis.call('ZCARD', KEYS[2])
        if committed_count > tonumber(ARGV[3]) or pending_count > tonumber(ARGV[4]) then
          return -5
        end
        local candidates = {}
        local committed_candidates = redis.call('ZRANGE', KEYS[1], 0, -1)
        for _, candidate in ipairs(committed_candidates) do
          if not valid_candidate(candidate) then
            return -5
          end
          candidates[candidate] = true
        end
        local pending_publications = redis.call('ZRANGE', KEYS[2], 0, -1)
        for _, publication in ipairs(pending_publications) do
          local candidate = parse_publication(publication)
          if not candidate then
            return -5
          end
          candidates[candidate] = true
        end
        candidates[ARGV[1]] = true
        local unique_count = 0
        for _ in pairs(candidates) do
          unique_count = unique_count + 1
        end
        if unique_count > tonumber(ARGV[3]) then
          return -2
        end
        local current_expiry = redis.call('ZSCORE', KEYS[1], ARGV[1])
        if current_expiry and tonumber(current_expiry) > expiry then
          expiry = tonumber(current_expiry)
        end
        redis.call('ZADD', KEYS[1], expiry, ARGV[1])
        for index = 1, 2 do
          if redis.call('ZCARD', KEYS[index]) == 0 then
            redis.call('DEL', KEYS[index])
          else
            local latest = redis.call('ZREVRANGE', KEYS[index], 0, 0, 'WITHSCORES')
            redis.call('PEXPIREAT', KEYS[index], math.floor(tonumber(latest[2])))
          end
        end
        return 1
        """);

    private static final byte[] LOCATE_SCRIPT = script("""
        local function valid_token(value)
          if string.len(value) ~= 36
              or string.sub(value, 9, 9) ~= '-'
              or string.sub(value, 14, 14) ~= '-'
              or string.sub(value, 19, 19) ~= '-'
              or string.sub(value, 24, 24) ~= '-' then
            return false
          end
          local compact, count = string.gsub(value, '%-', '')
          return count == 4 and compact ~= string.rep('0', 32)
              and string.match(compact, '^[0-9a-f]+$') ~= nil
        end
        local now = redis.call('TIME')
        local now_millis = (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
        redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now_millis)
        redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now_millis)
        local committed_count = redis.call('ZCARD', KEYS[1])
        local pending_count = redis.call('ZCARD', KEYS[2])
        if committed_count > tonumber(ARGV[1]) or pending_count > tonumber(ARGV[2]) then
          return {'OVERFLOW'}
        end
        if committed_count == 0 and pending_count == 0 then
          redis.call('DEL', KEYS[1])
          redis.call('DEL', KEYS[2])
          return {'OK'}
        end
        local candidates = {}
        local committed = redis.call('ZRANGE', KEYS[1], 0, -1, 'WITHSCORES')
        for index = 1, #committed, 2 do
          candidates[committed[index]] = tonumber(committed[index + 1])
        end
        local pending = redis.call('ZRANGE', KEYS[2], 0, -1, 'WITHSCORES')
        for index = 1, #pending, 2 do
          local publication = pending[index]
          if string.len(publication) <= 37
              or string.sub(publication, -37, -37) ~= ':' then
            return {'INVALID'}
          end
          local publication_token = string.sub(publication, -36)
          if not valid_token(publication_token) then
            return {'INVALID'}
          end
          local candidate = string.sub(publication, 1, -38)
          local expiry = tonumber(pending[index + 1])
          if not candidates[candidate] or candidates[candidate] < expiry then
            candidates[candidate] = expiry
          end
        end
        local result = {'OK'}
        local count = 0
        for candidate, expiry in pairs(candidates) do
          count = count + 1
          if count > tonumber(ARGV[1]) then
            return {'OVERFLOW'}
          end
          table.insert(result, candidate)
          table.insert(result, tostring(expiry))
        end
        for index = 1, 2 do
          if redis.call('ZCARD', KEYS[index]) == 0 then
            redis.call('DEL', KEYS[index])
          else
            local latest = redis.call('ZREVRANGE', KEYS[index], 0, 0, 'WITHSCORES')
            redis.call('PEXPIREAT', KEYS[index], math.floor(tonumber(latest[2])))
          end
        end
        return result
        """);

    private static final byte[] HAS_LIVE_PUBLICATION_SCRIPT = script("""
        local now = redis.call('TIME')
        local now_millis = (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
        redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now_millis)
        local publications = redis.call('ZRANGE', KEYS[1], 0, -1)
        if #publications == 0 then
          redis.call('DEL', KEYS[1])
          return 0
        end
        if #publications > tonumber(ARGV[2]) then
          return -2
        end
        local latest = redis.call('ZREVRANGE', KEYS[1], 0, 0, 'WITHSCORES')
        redis.call('PEXPIREAT', KEYS[1], math.floor(tonumber(latest[2])))
        local prefix = ARGV[1] .. ':'
        for _, publication in ipairs(publications) do
          if string.sub(publication, 1, string.len(prefix)) == prefix then
            return 1
          end
        end
        return 0
        """);

    private static final byte[] REMOVE_IF_NO_PUBLICATION_SCRIPT = script("""
        local now = redis.call('TIME')
        local now_millis = (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
        local owner = redis.call('GET', KEYS[4])
        if not owner or owner ~= ARGV[2] then
          return -2
        end
        redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now_millis)
        redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now_millis)
        if redis.call('ZCARD', KEYS[2]) > tonumber(ARGV[4])
            or redis.call('ZCARD', KEYS[3]) > tonumber(ARGV[3]) then
          return -3
        end
        if redis.call('ZCARD', KEYS[3]) ~= 0 then
          local latest_intent = redis.call('ZREVRANGE', KEYS[3], 0, 0, 'WITHSCORES')
          redis.call('PEXPIREAT', KEYS[3], math.floor(tonumber(latest_intent[2])))
          return -1
        end
        redis.call('DEL', KEYS[3])
        redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now_millis)
        local removed = redis.call('ZREM', KEYS[1], ARGV[1])
        local prefix = ARGV[1] .. ':'
        local pending = redis.call('ZRANGE', KEYS[2], 0, -1)
        for _, publication in ipairs(pending) do
          if string.sub(publication, 1, string.len(prefix)) == prefix then
            removed = removed + redis.call('ZREM', KEYS[2], publication)
          end
        end
        for index = 1, 2 do
          if redis.call('ZCARD', KEYS[index]) == 0 then
            redis.call('DEL', KEYS[index])
          else
            local latest = redis.call('ZREVRANGE', KEYS[index], 0, 0, 'WITHSCORES')
            redis.call('PEXPIREAT', KEYS[index], math.floor(tonumber(latest[2])))
          end
        end
        return removed
        """);

    private static final byte[] ACQUIRE_REMOVAL_SCRIPT = script("""
        if redis.call('SET', KEYS[1], ARGV[1], 'NX', 'PX', ARGV[2]) then
          return 1
        end
        local current = redis.call('GET', KEYS[1])
        if current == ARGV[1] then
          redis.call('PEXPIRE', KEYS[1], ARGV[2])
          return 2
        end
        return 0
        """);

    private static final byte[] INSPECT_REMOVAL_PUBLICATIONS_SCRIPT = script("""
        local owner = redis.call('GET', KEYS[2])
        if not owner or owner ~= ARGV[1] then
          return -1
        end
        local now = redis.call('TIME')
        local now_millis = (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
        redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now_millis)
        local count = redis.call('ZCARD', KEYS[1])
        if count > tonumber(ARGV[2]) then
          return -2
        end
        if count == 0 then
          redis.call('DEL', KEYS[1])
          return 0
        end
        local latest = redis.call('ZREVRANGE', KEYS[1], 0, 0, 'WITHSCORES')
        redis.call('PEXPIREAT', KEYS[1], math.floor(tonumber(latest[2])))
        return 1
        """);

    private static final byte[] RELEASE_REMOVAL_SCRIPT = script("""
        local current = redis.call('GET', KEYS[1])
        if current and current == ARGV[1] then
          redis.call('DEL', KEYS[1])
          return 1
        end
        return 0
        """);

    private final CasRedisTemplate<String, List<MultifactorAuthenticationTrustRecord>> redisTemplate;

    private final RedisAccountSecurityKeyCodec keyCodec;

    /**
     * Create a locator on the exact Redis authority used by the terminal
     * deletion fence.
     *
     * @param redisTemplate trusted-MFA Redis authority
     * @param deletionFence shared terminal deletion fence
     */
    public RedisTrustedMfaRecordLocator(
        final CasRedisTemplate<String, List<MultifactorAuthenticationTrustRecord>> redisTemplate,
        final RedisAccountSecurityDeletionFence deletionFence) {
        this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate");
        val requiredFence = Objects.requireNonNull(deletionFence, "deletionFence");
        if (!Objects.equals(requiredFence.getRedisTemplate(), redisTemplate)) {
            throw new IllegalArgumentException(
                "Trusted-MFA records, locator and deletion fences must share one Redis authority");
        }
        this.keyCodec = Objects.requireNonNull(requiredFence.getKeyCodec(), "keyCodec");
    }

    /**
     * Publish a candidate and unique, short-lived publication intent in one
     * coordinate-slot operation. Call this before the authority write.
     *
     * @param record proposed authority record
     * @return publication handle to complete after the authority attempt
     */
    public Publication beginPublication(final MultifactorAuthenticationTrustRecord record) {
        val candidate = candidate(record);
        val token = UUID.randomUUID().toString();
        val result = evalInteger(
            BEGIN_PUBLICATION_SCRIPT,
            List.of(
                key(candidate.locatorKey()),
                key(pendingPublicationKey(candidate)),
                key(publicationIntentKey(candidate)),
                key(removalLeaseKey(candidate.recordDigest()))),
            ascii(candidate.member()),
            ascii(publicationIntentMember(candidate, token)),
            ascii(Long.toString(candidate.expiresAt().toEpochMilli())),
            ascii(Long.toString(PUBLICATION_INTENT_MILLIS)),
            ascii(Integer.toString(MAXIMUM_CANDIDATES)),
            ascii(Integer.toString(MAXIMUM_PUBLICATION_INTENTS)));
        requirePublicationResult(result);
        return new Publication(token, candidate);
    }

    /**
     * Complete a publication only after the caller has proved that its
     * authority write was rolled back or superseded. An unknown authority or
     * rollback outcome must retain the pending hint until its bounded expiry so
     * a remover can still discover the possibly committed authority value.
     *
     * @param publication handle returned by {@link #beginPublication}
     */
    public void completePublication(final Publication publication) {
        val requiredPublication = Objects.requireNonNull(publication, "publication");
        val candidate = requiredPublication.candidate();
        val result = evalInteger(
            COMPLETE_PUBLICATION_SCRIPT,
            List.of(
                key(pendingPublicationKey(candidate)),
                key(publicationIntentKey(candidate))),
            ascii(publicationIntentMember(candidate, requiredPublication.token())));
        if (result < 0 || result > 2) {
            throw new IllegalStateException(
                "Trusted-MFA Redis publication completion returned an invalid result");
        }
    }

    /**
     * Commit one authority publication at the coordinate linearization point.
     * A rejected commit clears only its short-lived intent and retains the
     * pending hint until the caller completes a confirmed exact rollback.
     *
     * @param publication handle returned by {@link #beginPublication}
     * @return commit result
     */
    public PublicationCommitResult commitPublication(final Publication publication) {
        val requiredPublication = Objects.requireNonNull(publication, "publication");
        val candidate = requiredPublication.candidate();
        val result = evalInteger(
            COMMIT_PUBLICATION_SCRIPT,
            List.of(
                key(candidate.locatorKey()),
                key(pendingPublicationKey(candidate)),
                key(publicationIntentKey(candidate)),
                key(removalLeaseKey(candidate.recordDigest()))),
            ascii(publicationIntentMember(candidate, requiredPublication.token())),
            ascii(candidate.member()),
            ascii(Long.toString(candidate.expiresAt().toEpochMilli())),
            ascii(Integer.toString(MAXIMUM_CANDIDATES)),
            ascii(Integer.toString(MAXIMUM_PUBLICATION_INTENTS)));
        if (result == 1) {
            return PublicationCommitResult.COMMITTED;
        }
        if (result == 0) {
            return PublicationCommitResult.REJECTED;
        }
        if (result == CANDIDATE_CAPACITY_RESULT) {
            return PublicationCommitResult.CAPACITY_REJECTED;
        }
        throw new IllegalStateException("Trusted-MFA Redis publication commit returned an invalid result");
    }

    /**
     * Publish a stable hint for an already-verified authority record.
     *
     * @param record verified authority record
     * @return published candidate
     */
    public Candidate publish(final MultifactorAuthenticationTrustRecord record) {
        val candidate = candidate(record);
        ensure(candidate);
        return candidate;
    }

    /**
     * Locate untrusted candidates for an exact record key. Expired candidates
     * are pruned atomically according to Redis server time.
     *
     * @param recordKey exact trusted-MFA record key
     * @return bounded candidates requiring authority verification
     */
    public Set<Candidate> locate(final String recordKey) {
        val recordDigest = recordDigest(recordKey);
        val locatorKey = locatorKey(recordDigest);
        val result = redisTemplate.execute(
            (RedisCallback<List<?>>) connection -> connection.scriptingCommands().eval(
                LOCATE_SCRIPT,
                ReturnType.MULTI,
                2,
                key(locatorKey),
                key(pendingPublicationKey(recordDigest)),
                ascii(Integer.toString(MAXIMUM_CANDIDATES)),
                ascii(Integer.toString(MAXIMUM_PUBLICATION_INTENTS))));
        if (result == null || result.isEmpty()) {
            throw new IllegalStateException("Trusted-MFA Redis locator returned no result");
        }
        val status = rawString(result.getFirst());
        if ("OVERFLOW".equals(status)) {
            throw new IllegalStateException("Trusted-MFA Redis locator exceeds bounded capacity");
        }
        if ("INVALID".equals(status)) {
            throw new IllegalStateException("Trusted-MFA Redis locator contains an invalid pending hint");
        }
        if (!"OK".equals(status) || (result.size() - 1) % 2 != 0) {
            throw new IllegalStateException("Trusted-MFA Redis locator returned an invalid result");
        }
        val candidates = new LinkedHashSet<Candidate>();
        for (var index = 1; index < result.size(); index += 2) {
            val member = rawBytesString(result.get(index), "candidate member");
            val expiresAt = expiration(rawBytesString(
                result.get(index + 1), "candidate expiry"));
            try {
                val parsed = parseMember(member);
                candidates.add(new Candidate(
                    locatorKey,
                    member,
                    parsed.principalDigest(),
                    parsed.recordId(),
                    recordDigest,
                    expiresAt));
            } catch (final IllegalArgumentException exception) {
                throw new IllegalStateException(
                    "Trusted-MFA Redis locator returned an invalid candidate", exception);
            }
        }
        return Set.copyOf(candidates);
    }

    /**
     * Determine whether any unexpired publication intent protects a candidate.
     * Redis server time is the sole expiry clock.
     *
     * @param candidate candidate being considered for cleanup
     * @return true when at least one live publication remains
     */
    public boolean hasLivePublication(final Candidate candidate) {
        val requiredCandidate = Objects.requireNonNull(candidate, "candidate");
        val result = evalInteger(
            HAS_LIVE_PUBLICATION_SCRIPT,
            List.of(key(publicationIntentKey(requiredCandidate))),
            ascii(requiredCandidate.member()),
            ascii(Integer.toString(MAXIMUM_PUBLICATION_INTENTS)));
        if (result != 0 && result != 1) {
            throw new IllegalStateException(
                "Trusted-MFA Redis publication inspection returned an invalid result");
        }
        return result == 1;
    }

    /**
     * Restore an exact candidate after its authority record was revalidated.
     *
     * @param candidate verified current candidate
     */
    public void ensure(final Candidate candidate) {
        val requiredCandidate = Objects.requireNonNull(candidate, "candidate");
        val result = evalInteger(
            ADD_CANDIDATE_SCRIPT,
            List.of(
                key(requiredCandidate.locatorKey()),
                key(pendingPublicationKey(requiredCandidate)),
                key(removalLeaseKey(requiredCandidate.recordDigest()))),
            ascii(requiredCandidate.member()),
            ascii(Long.toString(requiredCandidate.expiresAt().toEpochMilli())),
            ascii(Integer.toString(MAXIMUM_CANDIDATES)),
            ascii(Integer.toString(MAXIMUM_PUBLICATION_INTENTS)));
        requireCandidateResult(result);
    }

    /**
     * Restore a candidate from an already-verified authority record.
     *
     * @param record verified authority record
     * @return restored candidate
     */
    public Candidate ensure(final MultifactorAuthenticationTrustRecord record) {
        return publish(record);
    }

    /**
     * Remove a stale hint only when no publication intent protects it. A
     * caller must re-read the authority afterward and {@link #ensure(Candidate)}
     * if the record became current concurrently.
     *
     * @param candidate possibly stale candidate
     * @param removalToken removal-lease owner
     * @return true when no live publication prevented cleanup
     */
    public boolean removeIfNoPublication(
        final Candidate candidate,
        final UUID removalToken) {
        val requiredCandidate = Objects.requireNonNull(candidate, "candidate");
        val token = token(removalToken);
        val result = evalInteger(
            REMOVE_IF_NO_PUBLICATION_SCRIPT,
            List.of(
                key(requiredCandidate.locatorKey()),
                key(pendingPublicationKey(requiredCandidate)),
                key(publicationIntentKey(requiredCandidate)),
                key(removalLeaseKey(requiredCandidate.recordDigest()))),
            ascii(requiredCandidate.member()),
            ascii(token),
            ascii(Integer.toString(MAXIMUM_PUBLICATION_INTENTS)),
            ascii(Integer.toString(MAXIMUM_PUBLICATION_INTENTS)));
        if (result == REMOVAL_CANDIDATE_LEASE_LOST_RESULT) {
            throw new RemovalLeaseLostException();
        }
        if (result < -1 || result > MAXIMUM_PUBLICATION_INTENTS + 1L) {
            throw new IllegalStateException(
                "Trusted-MFA Redis candidate removal returned an invalid result");
        }
        return result >= 0;
    }

    /**
     * Acquire or renew the token-bound removal lease for one record-key
     * coordinate. The Redis-enforced TTL bounds a crashed remover.
     *
     * @param recordKey exact trusted-MFA record key
     * @param removalToken unique remover token
     * @param leaseDuration positive bounded lease duration
     * @return lease acquisition result
     */
    public RemovalLeaseResult acquireRemoval(
        final String recordKey,
        final UUID removalToken,
        final Duration leaseDuration) {
        val recordDigest = recordDigest(recordKey);
        val token = token(removalToken);
        val leaseMillis = requireRemovalLease(leaseDuration);
        val result = evalInteger(
            ACQUIRE_REMOVAL_SCRIPT,
            List.of(key(removalLeaseKey(recordDigest))),
            ascii(token),
            ascii(Long.toString(leaseMillis)));
        return switch ((int) result) {
            case 0 -> RemovalLeaseResult.BUSY;
            case 1 -> RemovalLeaseResult.ACQUIRED;
            case 2 -> RemovalLeaseResult.RENEWED;
            default -> throw new IllegalStateException(
                "Trusted-MFA Redis removal lease returned an invalid result");
        };
    }

    /**
     * Check whether publications that began before the owned removal lease
     * remain live. A lost lease fails closed.
     *
     * @param recordKey exact trusted-MFA record key
     * @param removalToken removal-lease owner
     * @return true while a publication must still drain
     */
    public boolean hasLivePublications(
        final String recordKey,
        final UUID removalToken) {
        val recordDigest = recordDigest(recordKey);
        val result = evalInteger(
            INSPECT_REMOVAL_PUBLICATIONS_SCRIPT,
            List.of(
                key(publicationIntentKey(recordDigest)),
                key(removalLeaseKey(recordDigest))),
            ascii(token(removalToken)),
            ascii(Integer.toString(MAXIMUM_PUBLICATION_INTENTS)));
        if (result == REMOVAL_LEASE_LOST_RESULT) {
            throw new RemovalLeaseLostException();
        }
        if (result != 0 && result != 1) {
            throw new IllegalStateException(
                "Trusted-MFA Redis removal inspection returned an invalid result");
        }
        return result == 1;
    }

    /**
     * Release only the caller's removal lease token.
     *
     * @param recordKey exact trusted-MFA record key
     * @param removalToken removal-lease owner
     * @return true when the owned lease was released
     */
    public boolean releaseRemoval(
        final String recordKey,
        final UUID removalToken) {
        val recordDigest = recordDigest(recordKey);
        val result = evalInteger(
            RELEASE_REMOVAL_SCRIPT,
            List.of(key(removalLeaseKey(recordDigest))),
            ascii(token(removalToken)));
        if (result != 0 && result != 1) {
            throw new IllegalStateException(
                "Trusted-MFA Redis removal release returned an invalid result");
        }
        return result == 1;
    }

    private Candidate candidate(final MultifactorAuthenticationTrustRecord record) {
        val requiredRecord = Objects.requireNonNull(record, "record");
        val principalDigest = keyCodec.principalDigest(requiredRecord.getPrincipal());
        val recordDigest = recordDigest(requiredRecord.getRecordKey());
        val expirationDate = Objects.requireNonNull(
            requiredRecord.getExpirationDate(), "record.expirationDate");
        val expiresAt = expiration(expirationDate.toInstant().toEpochMilli());
        return new Candidate(
            locatorKey(recordDigest),
            serializeMember(principalDigest, requiredRecord.getId()),
            principalDigest,
            requiredRecord.getId(),
            recordDigest,
            expiresAt);
    }

    private void requirePublicationResult(final long result) {
        if (result == EXPIRED_RESULT) {
            throw new IllegalArgumentException(
                "Trusted-MFA locator record expires before publication");
        }
        if (result == CANDIDATE_CAPACITY_RESULT) {
            throw new IllegalStateException(
                "Trusted-MFA Redis locator exceeds bounded candidate capacity");
        }
        if (result == INTENT_CAPACITY_RESULT) {
            throw new IllegalStateException(
                "Trusted-MFA Redis locator exceeds bounded publication capacity");
        }
        if (result == REMOVAL_BUSY_RESULT) {
            throw new RemovalInProgressException();
        }
        if (result == INVALID_LOCATOR_RESULT) {
            throw new IllegalStateException(
                "Trusted-MFA Redis locator contains invalid bounded state");
        }
        if (result != 1) {
            throw new IllegalStateException("Trusted-MFA Redis locator returned an invalid result");
        }
    }

    private void requireCandidateResult(final long result) {
        if (result == EXPIRED_RESULT) {
            throw new IllegalArgumentException(
                "Trusted-MFA locator record expires before publication");
        }
        if (result == CANDIDATE_CAPACITY_RESULT) {
            throw new IllegalStateException(
                "Trusted-MFA Redis locator exceeds bounded candidate capacity");
        }
        if (result == REMOVAL_BUSY_RESULT) {
            throw new RemovalInProgressException();
        }
        if (result == INVALID_LOCATOR_RESULT) {
            throw new IllegalStateException(
                "Trusted-MFA Redis locator contains invalid bounded state");
        }
        if (result != 1) {
            throw new IllegalStateException("Trusted-MFA Redis locator returned an invalid result");
        }
    }

    private long evalInteger(
        final byte[] script,
        final List<byte[]> keys,
        final byte[]... arguments) {
        val keysAndArguments = new byte[keys.size() + arguments.length][];
        for (var index = 0; index < keys.size(); index++) {
            keysAndArguments[index] = keys.get(index);
        }
        System.arraycopy(arguments, 0, keysAndArguments, keys.size(), arguments.length);
        val result = redisTemplate.execute(
            (RedisCallback<Long>) connection -> connection.scriptingCommands().eval(
                script,
                ReturnType.INTEGER,
                keys.size(),
                keysAndArguments));
        if (result == null) {
            throw new IllegalStateException("Trusted-MFA Redis locator returned no result");
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    private byte[] key(final String redisKey) {
        val serializer = (RedisSerializer<String>) redisTemplate.getKeySerializer();
        return Objects.requireNonNull(serializer.serialize(redisKey), "serializedLocatorKey");
    }

    private static ParsedMember parseMember(final String member) {
        if (member == null) {
            throw new IllegalArgumentException("Trusted-MFA locator member is invalid");
        }
        val elements = member.split(":", -1);
        if (elements.length != 3 || !SCHEMA_VERSION.equals(elements[0])
            || !isDigest(elements[1])) {
            throw new IllegalArgumentException("Trusted-MFA locator member is invalid");
        }
        try {
            val recordId = Long.parseLong(elements[2]);
            if (!Long.toString(recordId).equals(elements[2])) {
                throw new IllegalArgumentException("Trusted-MFA locator member is invalid");
            }
            return new ParsedMember(elements[1], recordId);
        } catch (final NumberFormatException exception) {
            throw new IllegalArgumentException(
                "Trusted-MFA locator member is invalid", exception);
        }
    }

    private static String serializeMember(final String principalDigest, final long recordId) {
        if (!isDigest(principalDigest)) {
            throw new IllegalArgumentException("Trusted-MFA locator principal digest is invalid");
        }
        return SCHEMA_VERSION + ':' + principalDigest + ':' + recordId;
    }

    private static String locatorKey(final String recordDigest) {
        if (!isDigest(recordDigest)) {
            throw new IllegalArgumentException("Trusted-MFA locator record digest is invalid");
        }
        return REDIS_NAMESPACE + ":record:{" + recordDigest + "}:candidates";
    }

    private static String publicationIntentKey(final Candidate candidate) {
        return publicationIntentKey(candidate.recordDigest());
    }

    private static String publicationIntentKey(final String recordDigest) {
        return locatorKey(recordDigest) + ":publications";
    }

    private static String pendingPublicationKey(final Candidate candidate) {
        return pendingPublicationKey(candidate.recordDigest());
    }

    private static String pendingPublicationKey(final String recordDigest) {
        return locatorKey(recordDigest) + ":pending";
    }

    private static String publicationIntentMember(
        final Candidate candidate,
        final String publicationToken) {
        if (!isCanonicalToken(publicationToken)) {
            throw new IllegalArgumentException("Trusted-MFA publication token is invalid");
        }
        return candidate.member() + ':' + publicationToken;
    }

    private static String removalLeaseKey(final String recordDigest) {
        return locatorKey(recordDigest) + ":removal";
    }

    private static String token(final UUID token) {
        return Objects.requireNonNull(token, "removalToken").toString();
    }

    private static long requireRemovalLease(final Duration leaseDuration) {
        val requiredDuration = Objects.requireNonNull(leaseDuration, "leaseDuration");
        try {
            val millis = requiredDuration.toMillis();
            if (millis <= 0 || millis > MAXIMUM_REMOVAL_LEASE_MILLIS) {
                throw new IllegalArgumentException(
                    "Trusted-MFA removal lease duration is outside supported bounds");
            }
            return millis;
        } catch (final ArithmeticException exception) {
            throw new IllegalArgumentException(
                "Trusted-MFA removal lease duration is outside supported bounds", exception);
        }
    }

    private static String recordDigest(final String recordKey) {
        if (recordKey == null || recordKey.isBlank()
            || recordKey.length() > MAXIMUM_RECORD_KEY_LENGTH) {
            throw new IllegalArgumentException("Trusted-MFA record key is outside supported bounds");
        }
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(
                recordKey.getBytes(StandardCharsets.UTF_8)));
        } catch (final NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static Instant expiration(final String score) {
        try {
            val numericScore = Double.parseDouble(score);
            if (!Double.isFinite(numericScore) || numericScore != Math.rint(numericScore)
                || numericScore <= 0 || numericScore > MAXIMUM_EXACT_REDIS_SCORE) {
                throw new IllegalArgumentException("Trusted-MFA locator expiry is invalid");
            }
            return expiration((long) numericScore);
        } catch (final NumberFormatException exception) {
            throw new IllegalArgumentException(
                "Trusted-MFA locator expiry is invalid", exception);
        }
    }

    private static Instant expiration(final long epochMillis) {
        if (epochMillis <= 0 || epochMillis > MAXIMUM_EXACT_REDIS_SCORE) {
            throw new IllegalArgumentException("Trusted-MFA locator expiry is invalid");
        }
        return Instant.ofEpochMilli(epochMillis);
    }

    private static boolean isDigest(final String value) {
        return value != null
            && value.length() == SHA_256_HEX_LENGTH
            && value.chars().allMatch(character -> (character >= '0' && character <= '9')
                || (character >= 'a' && character <= 'f'));
    }

    private static boolean isCanonicalToken(final String token) {
        if (token == null || token.length() != UUID_TEXT_LENGTH) {
            return false;
        }
        try {
            return UUID.fromString(token).toString().equals(token);
        } catch (final IllegalArgumentException exception) {
            return false;
        }
    }

    private static byte[] script(final String script) {
        return script.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] ascii(final String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private static String rawString(final Object value) {
        return value instanceof final byte[] bytes
            ? new String(bytes, StandardCharsets.UTF_8)
            : Objects.requireNonNull(value, "locatorValue").toString();
    }

    private static String rawBytesString(final Object value, final String description) {
        if (!(value instanceof final byte[] bytes)) {
            throw new IllegalStateException(
                "Trusted-MFA Redis locator returned an invalid " + description);
        }
        return new String(bytes, StandardCharsets.US_ASCII);
    }

    /** Untrusted locator candidate requiring authority and fence verification. */
    public record Candidate(
        String locatorKey,
        String member,
        String principalDigest,
        long recordId,
        String recordDigest,
        Instant expiresAt) {
        public Candidate {
            Objects.requireNonNull(locatorKey, "locatorKey");
            Objects.requireNonNull(member, "member");
            Objects.requireNonNull(principalDigest, "principalDigest");
            Objects.requireNonNull(recordDigest, "recordDigest");
            Objects.requireNonNull(expiresAt, "expiresAt");
            if (!RedisTrustedMfaRecordLocator.locatorKey(recordDigest).equals(locatorKey)
                || !serializeMember(principalDigest, recordId).equals(member)
                || !expiration(expiresAt.toEpochMilli()).equals(expiresAt)) {
                throw new IllegalArgumentException("Trusted-MFA locator candidate is inconsistent");
            }
        }

        /**
         * Rebuild the exact principal-owned current authority key.
         *
         * @return current trusted-MFA Redis authority key
         */
        public String authorityRedisKey() {
            return RedisMultifactorAuthenticationTrustStorage.CAS_PREFIX
                + '{' + principalDigest + "}:record-" + recordId + '-' + recordDigest;
        }
    }

    /** Unique publication attempt for one raw-free locator candidate. */
    public record Publication(String token, Candidate candidate) {
        public Publication {
            if (!isCanonicalToken(token)) {
                throw new IllegalArgumentException("Trusted-MFA publication token is invalid");
            }
            Objects.requireNonNull(candidate, "candidate");
        }

        /**
         * Return the raw-free, coordinate-slot-local intent key.
         *
         * @return publication intent key
         */
        public String intentKey() {
            return publicationIntentKey(candidate);
        }

        /**
         * Return the raw-free pending-hint key protecting a paused writer.
         *
         * @return pending publication key
         */
        public String pendingKey() {
            return pendingPublicationKey(candidate);
        }

        /**
         * Return this writer's raw-free unique intent member.
         *
         * @return publication intent member
         */
        public String intentMember() {
            return publicationIntentMember(candidate, token);
        }
    }

    /** Publication result at the coordinate-slot commit linearization point. */
    public enum PublicationCommitResult {
        /** The intent was live, no remover existed and publication committed. */
        COMMITTED,
        /** The intent expired or a remover owned the coordinate. */
        REJECTED,
        /** The bounded locator could not accept another committed candidate. */
        CAPACITY_REJECTED
    }

    /** Token-bound removal-lease acquisition outcome. */
    public enum RemovalLeaseResult {
        /** A previously unowned coordinate lease was acquired. */
        ACQUIRED,
        /** The same remover renewed its existing coordinate lease. */
        RENEWED,
        /** Another remover currently owns the coordinate lease. */
        BUSY
    }

    /** Raised when a writer encounters an active coordinate removal lease. */
    public static final class RemovalInProgressException extends IllegalStateException {
        private static final long serialVersionUID = -7506619573907913206L;

        /** Construct the stable retryable removal-in-progress failure. */
        public RemovalInProgressException() {
            super("Trusted-MFA record removal is in progress");
        }
    }

    /** Raised when a remover no longer owns its coordinate lease. */
    public static final class RemovalLeaseLostException extends IllegalStateException {
        private static final long serialVersionUID = 6912294620515059775L;

        /** Construct the stable fail-closed lost-lease failure. */
        public RemovalLeaseLostException() {
            super("Trusted-MFA record removal lease was lost");
        }
    }

    private record ParsedMember(String principalDigest, long recordId) {
    }
}
