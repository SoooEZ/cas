package org.apereo.cas.redis.core;

import module java.base;

import lombok.Getter;
import lombok.val;
import org.springframework.data.redis.connection.ReturnType;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.serializer.RedisSerializer;

/**
 * Atomic Redis authority for terminal account-security deletion fences.
 *
 * <p>Terminal markers have no TTL: deleting an SQL account must permanently
 * reject a delayed or replayed credential write. All marker operations use raw
 * Redis bytes so the public authority is independent of a feature's value
 * serializer.</p>
 *
 * @author Apereo CAS
 * @since 8.0.1
 */
@Getter
public final class RedisAccountSecurityDeletionFence {
    /** Stable WebAuthn fence bean name. */
    public static final String WEB_AUTHN_BEAN_NAME = "webAuthnRedisAccountSecurityDeletionFence";

    /** Stable trusted-MFA fence bean name. */
    public static final String TRUSTED_MFA_BEAN_NAME = "trustedMfaRedisAccountSecurityDeletionFence";

    private static final int EXPIRED_RESULT = -2;

    private static final int CORRUPT_VERSIONED_STATE_RESULT = -3;

    private static final byte[] ACQUIRE_TERMINAL_SCRIPT = script("""
        local current = redis.call('GET', KEYS[1])
        if not current then
          redis.call('SET', KEYS[1], ARGV[1])
          return 1
        end
        if current == ARGV[1] then
          redis.call('PERSIST', KEYS[1])
          return 2
        end
        return 0
        """);

    private static final byte[] VERIFY_TERMINAL_SCRIPT = script("""
        local current = redis.call('GET', KEYS[1])
        if current and current == ARGV[1]
            and redis.call('PTTL', KEYS[1]) == -1 then
          return 1
        end
        return 0
        """);

    private static final byte[] FENCED_SET_SCRIPT = script("""
        if redis.call('EXISTS', KEYS[1]) ~= 0 then
          return 0
        end
        local expires_at = nil
        if ARGV[2] ~= '' then
          expires_at = tonumber(ARGV[2])
          local now = redis.call('TIME')
          local now_millis = (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
          if not expires_at or expires_at <= now_millis then
            return -1
          end
        end
        redis.call('SET', KEYS[2], ARGV[1])
        if expires_at then
          redis.call('PEXPIREAT', KEYS[2], expires_at)
        end
        return 1
        """);

    private static final byte[] AUTHORITY_READ_SCRIPT = script("""
        return redis.call('GET', KEYS[1])
        """);

    private static final byte[] FENCED_AUTHORITY_READ_SCRIPT = script("""
        if redis.call('EXISTS', KEYS[1]) ~= 0 then
          return {'FENCED'}
        end
        local current = redis.call('GET', KEYS[2])
        if not current then
          return {'ABSENT'}
        end
        return {'PRESENT', current}
        """);

    private static final byte[] VERSIONED_FENCED_AUTHORITY_READ_SCRIPT = script("""
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
        if redis.call('EXISTS', KEYS[1]) ~= 0 then
          return {'FENCED'}
        end
        local data_type = keytype(KEYS[2])
        local token_type = keytype(KEYS[3])
        if (data_type ~= 'none' and data_type ~= 'string')
            or (token_type ~= 'none' and token_type ~= 'string') then
          return {'CORRUPT'}
        end
        local current = redis.call('GET', KEYS[2])
        local current_token = redis.call('GET', KEYS[3])
        if not current then
          if current_token then return {'CORRUPT'} end
          return {'ABSENT'}
        end
        if not current_token then
          return {'PRESENT_LEGACY', current}
        end
        if not valid_token(current_token) then
          return {'CORRUPT'}
        end
        local data_ttl = redis.call('PTTL', KEYS[2])
        local token_ttl = redis.call('PTTL', KEYS[3])
        if (data_ttl == -1 and token_ttl ~= -1)
            or (data_ttl >= 0 and token_ttl < 0) then
          return {'CORRUPT'}
        end
        return {'PRESENT', current, current_token}
        """);

    private static final byte[] COMPARE_AND_SET_IF_UNFENCED_SCRIPT = script("""
        if redis.call('EXISTS', KEYS[1]) ~= 0 then
          return -1
        end
        local current = redis.call('GET', KEYS[2])
        if ARGV[1] == '0' then
          if current then
            return 0
          end
        elseif not current or current ~= ARGV[2] then
          return 0
        end
        local expires_at = nil
        if ARGV[3] ~= '0' and ARGV[5] ~= '' then
          expires_at = tonumber(ARGV[5])
          local now = redis.call('TIME')
          local now_millis = (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
          if not expires_at or expires_at <= now_millis then
            return -2
          end
        end
        if ARGV[3] == '0' then
          redis.call('DEL', KEYS[2])
          return 1
        end
        redis.call('SET', KEYS[2], ARGV[4])
        if expires_at then
          redis.call('PEXPIREAT', KEYS[2], expires_at)
        end
        return 1
        """);

    private static final byte[] VERSIONED_COMPARE_AND_SET_IF_UNFENCED_SCRIPT = script("""
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
        if redis.call('EXISTS', KEYS[1]) ~= 0 then
          return -1
        end
        local data_type = keytype(KEYS[2])
        local token_type = keytype(KEYS[3])
        if (data_type ~= 'none' and data_type ~= 'string')
            or (token_type ~= 'none' and token_type ~= 'string') then
          return -3
        end
        if (ARGV[1] ~= '0' and ARGV[1] ~= '1')
            or (ARGV[3] ~= '0' and ARGV[3] ~= '1')
            or (ARGV[5] ~= '0' and ARGV[5] ~= '1') then
          return -3
        end
        if ARGV[1] == '0' and ARGV[3] ~= '0' then
          return -3
        end
        if ARGV[3] == '1' and not valid_token(ARGV[4]) then
          return -3
        end
        local current = redis.call('GET', KEYS[2])
        local current_token = redis.call('GET', KEYS[3])
        if not current and current_token then
          return -3
        end
        if current_token and not valid_token(current_token) then
          return -3
        end
        if ARGV[1] == '0' then
          if current then return 0 end
        elseif not current or current ~= ARGV[2] then
          return 0
        end
        if ARGV[3] == '0' then
          if current_token then return 0 end
        elseif not current_token or current_token ~= ARGV[4] then
          return 0
        end
        if ARGV[5] == '0' then
          if ARGV[7] ~= '' or ARGV[8] ~= '' then return -3 end
          redis.call('DEL', KEYS[2], KEYS[3])
          return 1
        end
        if not valid_token(ARGV[7]) then
          return -3
        end
        local expires_at = nil
        if ARGV[8] ~= '' then
          expires_at = tonumber(ARGV[8])
          local now = redis.call('TIME')
          local now_millis = (tonumber(now[1]) * 1000)
            + math.floor(tonumber(now[2]) / 1000)
          if not expires_at or expires_at <= now_millis then
            return -2
          end
        end
        redis.call('SET', KEYS[2], ARGV[6])
        redis.call('SET', KEYS[3], ARGV[7])
        if expires_at then
          redis.call('PEXPIREAT', KEYS[2], expires_at)
          redis.call('PEXPIREAT', KEYS[3], expires_at)
        end
        return 1
        """);

    private static final byte[] COMPARE_AND_DELETE_SCRIPT = script("""
        local current = redis.call('GET', KEYS[1])
        if not current then
          return 2
        end
        if current ~= ARGV[1] then
          return 0
        end
        redis.call('DEL', KEYS[1])
        return 1
        """);

    private static final byte[] DELETE_AND_VERIFY_SCRIPT = script("""
        redis.call('DEL', KEYS[1])
        if redis.call('EXISTS', KEYS[1]) == 0 then
          return 1
        end
        return 0
        """);

    private static final byte[] VERIFY_ABSENT_SCRIPT = script("""
        if redis.call('EXISTS', KEYS[1]) == 0 then
          return 1
        end
        return 0
        """);

    private static final byte[] PROBE_WRITE_SCRIPT = script("""
        redis.call('SET', KEYS[1], ARGV[1], 'PX', 30000)
        return 1
        """);

    private static final byte[] PROBE_READ_SCRIPT = script("""
        local current = redis.call('GET', KEYS[1])
        if current and current == ARGV[1] then
          return 1
        end
        return 0
        """);

    private final CasRedisTemplate<String, ?> redisTemplate;

    private final RedisAccountSecurityKeyCodec keyCodec;

    public RedisAccountSecurityDeletionFence(
        final CasRedisTemplate<String, ?> redisTemplate,
        final RedisAccountSecurityKeyCodec keyCodec) {
        this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate");
        this.keyCodec = Objects.requireNonNull(keyCodec, "keyCodec");
    }

    /**
     * Acquire or replay a permanent terminal fence.
     *
     * @param rawPrincipal account principal
     * @param closureId durable closure token
     * @return acquisition result
     */
    public TerminalFenceResult acquireTerminal(final String rawPrincipal, final UUID closureId) {
        val result = evalInteger(
            ACQUIRE_TERMINAL_SCRIPT,
            List.of(key(keyCodec.deletionFenceKey(rawPrincipal))),
            token(closureId));
        return switch (Math.toIntExact(result)) {
            case 1 -> TerminalFenceResult.ACQUIRED;
            case 2 -> TerminalFenceResult.REPLAY;
            case 0 -> TerminalFenceResult.CONFLICT;
            default -> throw new IllegalStateException("Unexpected account security fence result");
        };
    }

    /**
     * Verify exact terminal-fence ownership.
     *
     * @param rawPrincipal account principal
     * @param closureId durable closure token
     * @return true only for the same token
     */
    public boolean isTerminal(final String rawPrincipal, final UUID closureId) {
        return evalInteger(
            VERIFY_TERMINAL_SCRIPT,
            List.of(key(keyCodec.deletionFenceKey(rawPrincipal))),
            token(closureId)) == 1;
    }

    /**
     * Serialize and write a value only when the principal is not terminally
     * fenced. Fence check, SET and optional PEXPIREAT execute in one script.
     *
     * @param rawPrincipal account principal
     * @param dataKey slot-local data key from the shared codec
     * @param value value to serialize
     * @param expiresAt optional absolute expiry
     */
    public void setIfUnfenced(
        final String rawPrincipal,
        final String dataKey,
        final Object value,
        final Instant expiresAt) {
        Objects.requireNonNull(value, "value");
        requireSameSlot(rawPrincipal, dataKey);
        val serialized = value(value);
        val expiry = expiresAt == null
            ? new byte[0]
            : Long.toString(expiresAt.toEpochMilli()).getBytes(StandardCharsets.US_ASCII);
        val result = evalInteger(
            FENCED_SET_SCRIPT,
            List.of(key(keyCodec.deletionFenceKey(rawPrincipal)), key(dataKey)),
            serialized,
            expiry);
        if (result == 0) {
            throw new AccountSecurityWriteFencedException();
        }
        if (result != 1) {
            throw new IllegalArgumentException("Account security value expires before it can be stored");
        }
    }

    /**
     * Read an exact key through a Redis script. Unlike a replica-eligible
     * {@code GET}, script execution is routed to the authority node and the
     * returned serialized bytes can be used as an exact compare-and-set
     * precondition.
     *
     * @param dataKey exact Redis data key
     * @return key-bound authority value, including an explicit absent value
     */
    public AuthorityValue readFromAuthority(final String dataKey) {
        val requiredDataKey = requireDataKey(dataKey);
        val result = redisTemplate.execute(
            (RedisCallback<byte[]>) connection -> connection.scriptingCommands().eval(
                AUTHORITY_READ_SCRIPT, ReturnType.VALUE, 1, key(requiredDataKey)));
        return new AuthorityValue(requiredDataKey, result, false);
    }

    /**
     * Read a principal-owned exact key from its Redis authority. The terminal
     * fence and value are inspected at one Lua linearization point after proving
     * that both keys use the same effective Redis Cluster hash tag.
     *
     * @param rawPrincipal account principal
     * @param dataKey slot-local data key from the shared codec
     * @return key-bound authority value
     */
    public AuthorityValue readFromAuthority(final String rawPrincipal, final String dataKey) {
        val fenceKey = keyCodec.deletionFenceKey(rawPrincipal);
        requireKeysShareSlot(fenceKey, dataKey);
        return readFencedFromAuthority(fenceKey, dataKey);
    }

    /**
     * Read a principal-owned exact key using a validated, raw-principal-free
     * digest. The terminal fence and value are inspected in one same-slot Lua
     * execution.
     *
     * @param principalDigest SHA-256 principal digest
     * @param dataKey slot-local data key
     * @return key-bound authority value
     */
    public AuthorityValue readFromAuthorityByPrincipalDigest(
        final String principalDigest,
        final String dataKey) {
        val fenceKey = keyCodec.deletionFenceKeyForPrincipalDigest(principalDigest);
        requireKeysShareSlot(fenceKey, dataKey);
        return readFencedFromAuthority(fenceKey, dataKey);
    }

    /**
     * Read a principal-owned value and its independent write token at one
     * authority linearization point. A pre-token record is returned as a
     * present legacy value and is adopted by the next successful versioned
     * mutation. A token without data, a malformed token, or an incompatible
     * Redis type fails closed as corrupt authority state.
     *
     * @param rawPrincipal account principal
     * @param dataKey slot-local data key
     * @param writeTokenKey slot-local write-token key
     * @return key-bound value and write-token snapshot
     */
    public VersionedAuthorityValue readVersionedFromAuthority(
        final String rawPrincipal,
        final String dataKey,
        final String writeTokenKey) {
        val fenceKey = keyCodec.deletionFenceKey(rawPrincipal);
        requireKeysShareSlot(fenceKey, dataKey);
        requireKeysShareSlot(fenceKey, writeTokenKey);
        if (dataKey.equals(writeTokenKey)) {
            throw new IllegalArgumentException(
                "Account security data and write-token keys must be distinct");
        }
        val result = redisTemplate.execute(
            (RedisCallback<List<?>>) connection -> connection.scriptingCommands().eval(
                VERSIONED_FENCED_AUTHORITY_READ_SCRIPT,
                ReturnType.MULTI,
                3,
                key(fenceKey),
                key(dataKey),
                key(writeTokenKey)));
        if (result == null || result.isEmpty() || result.size() > 3) {
            throw new IllegalStateException(
                "Redis account security authority returned an invalid versioned read result");
        }
        return switch (utf8(result.getFirst())) {
            case "FENCED" -> {
                requireVersionedReadSize(result, 1, "fenced");
                yield new VersionedAuthorityValue(dataKey, writeTokenKey, null, null, true);
            }
            case "ABSENT" -> {
                requireVersionedReadSize(result, 1, "absent");
                yield new VersionedAuthorityValue(dataKey, writeTokenKey, null, null, false);
            }
            case "PRESENT_LEGACY" -> {
                requireVersionedReadSize(result, 2, "legacy");
                yield new VersionedAuthorityValue(
                    dataKey, writeTokenKey, versionedReadBytes(result, 1), null, false);
            }
            case "PRESENT" -> {
                requireVersionedReadSize(result, 3, "present");
                yield new VersionedAuthorityValue(
                    dataKey,
                    writeTokenKey,
                    versionedReadBytes(result, 1),
                    versionedReadBytes(result, 2),
                    false);
            }
            case "CORRUPT" -> throw new IllegalStateException(
                "Redis account security versioned authority state is corrupt");
            default -> throw new IllegalStateException(
                "Redis account security authority returned an unknown versioned read result");
        };
    }

    private AuthorityValue readFencedFromAuthority(final String fenceKey, final String dataKey) {
        val result = redisTemplate.execute(
            (RedisCallback<List<?>>) connection -> connection.scriptingCommands().eval(
                FENCED_AUTHORITY_READ_SCRIPT,
                ReturnType.MULTI,
                2,
                key(fenceKey),
                key(dataKey)));
        if (result == null || result.isEmpty() || result.size() > 2) {
            throw new IllegalStateException("Redis account security authority returned an invalid read result");
        }
        return switch (utf8(result.getFirst())) {
            case "FENCED" -> {
                if (result.size() != 1) {
                    throw new IllegalStateException(
                        "Redis account security fenced read returned an invalid result");
                }
                yield new AuthorityValue(dataKey, null, true);
            }
            case "ABSENT" -> {
                if (result.size() != 1) {
                    throw new IllegalStateException(
                        "Redis account security absent read returned an invalid result");
                }
                yield new AuthorityValue(dataKey, null, false);
            }
            case "PRESENT" -> {
                if (result.size() != 2 || !(result.get(1) instanceof final byte[] value)) {
                    throw new IllegalStateException(
                        "Redis account security present read returned an invalid result");
                }
                yield new AuthorityValue(dataKey, value, false);
            }
            default -> throw new IllegalStateException(
                "Redis account security authority returned an unknown read result");
        };
    }

    /**
     * Deserialize a value returned by {@link #readFromAuthority(String)} using
     * this authority's configured value serializer.
     *
     * @param authorityValue key-bound serialized value
     * @param valueType required runtime type
     * @param <T> value type
     * @return empty for an absent key, otherwise the deserialized value
     */
    public <T> Optional<T> deserialize(
        final AuthorityValue authorityValue,
        final Class<T> valueType) {
        val requiredValue = Objects.requireNonNull(authorityValue, "authorityValue");
        val requiredType = Objects.requireNonNull(valueType, "valueType");
        if (!requiredValue.isPresent()) {
            return Optional.empty();
        }
        val deserialized = valueSerializer().deserialize(requiredValue.serializedValue);
        if (!requiredType.isInstance(deserialized)) {
            throw new IllegalStateException("Redis account security authority returned an unexpected value type");
        }
        return Optional.of(requiredType.cast(deserialized));
    }

    /**
     * Deserialize a value returned by
     * {@link #readVersionedFromAuthority(String, String, String)}.
     *
     * @param authorityValue key- and token-bound serialized value
     * @param valueType required runtime type
     * @param <T> value type
     * @return empty for an absent key, otherwise the deserialized value
     */
    public <T> Optional<T> deserialize(
        final VersionedAuthorityValue authorityValue,
        final Class<T> valueType) {
        val requiredValue = Objects.requireNonNull(authorityValue, "authorityValue");
        val requiredType = Objects.requireNonNull(valueType, "valueType");
        if (!requiredValue.isPresent()) {
            return Optional.empty();
        }
        val deserialized = valueSerializer().deserialize(requiredValue.serializedValue);
        if (!requiredType.isInstance(deserialized)) {
            throw new IllegalStateException(
                "Redis account security authority returned an unexpected value type");
        }
        return Optional.of(requiredType.cast(deserialized));
    }

    /**
     * Compare and atomically replace or delete a principal-owned value only
     * while its terminal fence is absent. The expected value is either exact
     * serialized bytes returned by an authority read or explicit absence.
     * Fence check, comparison, replacement and optional expiry execute in one
     * same-slot Lua script.
     *
     * @param rawPrincipal account principal
     * @param dataKey slot-local data key from the shared codec
     * @param expected key-bound authority value used as the precondition
     * @param replacement replacement value, or {@code null} to delete
     * @param expiresAt optional absolute expiry for a replacement
     * @return applied, compare-mismatch, or terminally-fenced result
     */
    public CompareAndSetResult compareAndSetIfUnfenced(
        final String rawPrincipal,
        final String dataKey,
        final AuthorityValue expected,
        final Object replacement,
        final Instant expiresAt) {
        requireSameSlot(rawPrincipal, dataKey);
        val requiredExpected = Objects.requireNonNull(expected, "expected");
        if (!dataKey.equals(requiredExpected.dataKey)) {
            throw new IllegalArgumentException("Account security compare value belongs to a different key");
        }
        if (requiredExpected.isFenced()) {
            return CompareAndSetResult.FENCED;
        }
        if (replacement == null && expiresAt != null) {
            throw new IllegalArgumentException("Account security deletion cannot define an expiry");
        }
        val replacementValue = replacement == null ? new byte[0] : value(replacement);
        val expiry = expiresAt == null
            ? new byte[0]
            : Long.toString(expiresAt.toEpochMilli()).getBytes(StandardCharsets.US_ASCII);
        val result = evalInteger(
            COMPARE_AND_SET_IF_UNFENCED_SCRIPT,
            List.of(key(keyCodec.deletionFenceKey(rawPrincipal)), key(dataKey)),
            ascii(requiredExpected.isPresent() ? "1" : "0"),
            requiredExpected.serializedValueOrEmpty(),
            ascii(replacement == null ? "0" : "1"),
            replacementValue,
            expiry);
        return switch (Math.toIntExact(result)) {
            case 1 -> CompareAndSetResult.APPLIED;
            case 0 -> CompareAndSetResult.COMPARE_MISMATCH;
            case -1 -> CompareAndSetResult.FENCED;
            case EXPIRED_RESULT -> throw new IllegalArgumentException(
                "Account security value expires before it can be stored");
            default -> throw new IllegalStateException(
                "Unexpected account security compare-and-set result");
        };
    }

    /**
     * Compare and atomically replace or delete a principal-owned value using
     * both exact serialized bytes and an independent write token. A fresh token
     * is written with every replacement, so delete-and-recreate of identical
     * bytes cannot satisfy a stale compare-and-set snapshot.
     *
     * @param rawPrincipal account principal
     * @param dataKey slot-local data key
     * @param writeTokenKey slot-local write-token key
     * @param expected key- and token-bound authority snapshot
     * @param replacement replacement value, or {@code null} to delete
     * @param expiresAt optional absolute expiry for a replacement
     * @return applied, compare-mismatch, or terminally-fenced result
     */
    public CompareAndSetResult compareAndSetVersionedIfUnfenced(
        final String rawPrincipal,
        final String dataKey,
        final String writeTokenKey,
        final VersionedAuthorityValue expected,
        final Object replacement,
        final Instant expiresAt) {
        val fenceKey = keyCodec.deletionFenceKey(rawPrincipal);
        requireKeysShareSlot(fenceKey, dataKey);
        requireKeysShareSlot(fenceKey, writeTokenKey);
        if (dataKey.equals(writeTokenKey)) {
            throw new IllegalArgumentException(
                "Account security data and write-token keys must be distinct");
        }
        val requiredExpected = Objects.requireNonNull(expected, "expected");
        if (!dataKey.equals(requiredExpected.dataKey)
            || !writeTokenKey.equals(requiredExpected.writeTokenKey)) {
            throw new IllegalArgumentException(
                "Account security versioned compare value belongs to different keys");
        }
        if (requiredExpected.isFenced()) {
            return CompareAndSetResult.FENCED;
        }
        if (replacement == null && expiresAt != null) {
            throw new IllegalArgumentException("Account security deletion cannot define an expiry");
        }
        val replacementValue = replacement == null ? new byte[0] : value(replacement);
        val replacementToken = replacement == null
            ? new byte[0]
            : token(UUID.randomUUID());
        val expiry = expiresAt == null
            ? new byte[0]
            : ascii(Long.toString(expiresAt.toEpochMilli()));
        val result = evalInteger(
            VERSIONED_COMPARE_AND_SET_IF_UNFENCED_SCRIPT,
            List.of(key(fenceKey), key(dataKey), key(writeTokenKey)),
            ascii(requiredExpected.isPresent() ? "1" : "0"),
            requiredExpected.serializedValueOrEmpty(),
            ascii(requiredExpected.hasWriteToken() ? "1" : "0"),
            requiredExpected.serializedWriteTokenOrEmpty(),
            ascii(replacement == null ? "0" : "1"),
            replacementValue,
            replacementToken,
            expiry);
        return switch (Math.toIntExact(result)) {
            case 1 -> CompareAndSetResult.APPLIED;
            case 0 -> CompareAndSetResult.COMPARE_MISMATCH;
            case -1 -> CompareAndSetResult.FENCED;
            case EXPIRED_RESULT -> throw new IllegalArgumentException(
                "Account security value expires before it can be stored");
            case CORRUPT_VERSIONED_STATE_RESULT -> throw new IllegalStateException(
                "Redis account security versioned authority state is corrupt");
            default -> throw new IllegalStateException(
                "Unexpected account security versioned compare-and-set result");
        };
    }

    /**
     * Delete a legacy or otherwise non-slot-local key only if it still contains
     * the exact serialized bytes observed by an authority read. This prevents a
     * migration cleanup from deleting a concurrent replacement.
     *
     * @param expected present key-bound authority value
     * @return deleted, already-absent, or compare-mismatch result
     */
    public CompareAndDeleteResult deleteIfUnchanged(final AuthorityValue expected) {
        val requiredExpected = Objects.requireNonNull(expected, "expected");
        if (!requiredExpected.isPresent()) {
            throw new IllegalArgumentException("Account security delete precondition must be present");
        }
        val result = evalInteger(
            COMPARE_AND_DELETE_SCRIPT,
            List.of(key(requiredExpected.dataKey)),
            requiredExpected.serializedValue);
        return switch (Math.toIntExact(result)) {
            case 1 -> CompareAndDeleteResult.DELETED;
            case 2 -> CompareAndDeleteResult.ABSENT;
            case 0 -> CompareAndDeleteResult.COMPARE_MISMATCH;
            default -> throw new IllegalStateException(
                "Unexpected account security compare-and-delete result");
        };
    }

    /**
     * Delete an exact key and verify immediate absence. Deletion remains legal
     * after a terminal fence so erasure can converge.
     *
     * @param dataKey exact Redis data key
     * @return true when absent
     */
    public boolean deleteAndVerify(final String dataKey) {
        return evalInteger(DELETE_AND_VERIFY_SCRIPT, List.of(key(dataKey))) == 1;
    }

    /**
     * Delete exact keys and prove their absence under the same terminal token.
     *
     * @param rawPrincipal account principal
     * @param closureId durable closure token
     * @param dataKeys exact Redis keys
     * @return true only when exact fence and absence both hold
     */
    public boolean eraseKeysAndVerify(
        final String rawPrincipal,
        final UUID closureId,
        final Collection<String> dataKeys) {
        if (!isTerminal(rawPrincipal, closureId)) {
            return false;
        }
        requirePatterns(dataKeys).forEach(this::deleteAndVerify);
        return isTerminal(rawPrincipal, closureId) && areKeysAbsent(dataKeys);
    }

    /**
     * Verify exact-key absence without interpreting Redis glob metacharacters.
     *
     * @param dataKeys exact Redis keys
     * @return true when every key is absent
     */
    public boolean areKeysAbsent(final Collection<String> dataKeys) {
        return requirePatterns(dataKeys).stream()
            .allMatch(dataKey -> evalInteger(
                VERIFY_ABSENT_SCRIPT, List.of(key(dataKey))) == 1);
    }

    /**
     * Verify exact absence of keys or patterns under the same terminal token.
     * The permanent fence makes the two scans stable against repository writers.
     *
     * @param rawPrincipal account principal
     * @param closureId durable closure token
     * @param patterns exact keys or Redis glob patterns
     * @return true only when exact fence and absence both hold
     */
    public boolean erasePatternsAndVerify(
        final String rawPrincipal,
        final UUID closureId,
        final Collection<String> patterns) {
        if (!isTerminal(rawPrincipal, closureId)) {
            return false;
        }
        for (val pattern : requirePatterns(patterns)) {
            try (val keys = redisTemplate.scan(pattern)) {
                keys.forEach(this::deleteAndVerify);
            }
        }
        return isTerminal(rawPrincipal, closureId) && isAbsent(patterns);
    }

    /**
     * Delete all keys matching supplied patterns and verify absence. This path
     * remains available before and after fencing for ordinary credential
     * removal. Terminal account erasure must use the token-bound overload.
     *
     * @param patterns exact keys or Redis glob patterns
     * @return true when absent
     */
    public boolean erasePatternsAndVerify(final Collection<String> patterns) {
        for (val pattern : requirePatterns(patterns)) {
            try (val keys = redisTemplate.scan(pattern)) {
                keys.forEach(this::deleteAndVerify);
            }
        }
        return isAbsent(patterns);
    }

    /**
     * Verify that no key matching any supplied pattern exists.
     *
     * @param patterns exact keys or Redis glob patterns
     * @return true when absent
     */
    public boolean isAbsent(final Collection<String> patterns) {
        for (val pattern : requirePatterns(patterns)) {
            try (val keys = redisTemplate.scan(pattern)) {
                if (keys.findAny().isPresent()) {
                    return false;
                }
            }
        }
        return true;
    }

    boolean writeStoreProbe(final String probeKey, final byte[] probeToken) {
        return evalInteger(PROBE_WRITE_SCRIPT, List.of(key(probeKey)), probeToken) == 1;
    }

    boolean readsStoreProbe(final String probeKey, final byte[] probeToken) {
        return evalInteger(PROBE_READ_SCRIPT, List.of(key(probeKey)), probeToken) == 1;
    }

    void deleteStoreProbe(final String probeKey) {
        deleteAndVerify(probeKey);
    }

    private void requireSameSlot(final String rawPrincipal, final String dataKey) {
        requireKeysShareSlot(keyCodec.deletionFenceKey(rawPrincipal), dataKey);
    }

    private static void requireKeysShareSlot(final String fenceKey, final String dataKey) {
        if (!effectiveHashSlotInput(fenceKey).equals(effectiveHashSlotInput(requireDataKey(dataKey)))) {
            throw new IllegalArgumentException("Account security data key does not share the fence slot");
        }
    }

    private static String effectiveHashSlotInput(final String redisKey) {
        val opening = redisKey.indexOf('{');
        if (opening >= 0) {
            val closing = redisKey.indexOf('}', opening + 1);
            if (closing > opening + 1) {
                return redisKey.substring(opening + 1, closing);
            }
        }
        return redisKey;
    }

    private long evalInteger(final byte[] script, final List<byte[]> keys, final byte[]... arguments) {
        val keysAndArguments = new byte[keys.size() + arguments.length][];
        for (var index = 0; index < keys.size(); index++) {
            keysAndArguments[index] = keys.get(index);
        }
        System.arraycopy(arguments, 0, keysAndArguments, keys.size(), arguments.length);
        val result = redisTemplate.execute(
            (RedisCallback<Long>) connection -> connection.scriptingCommands().eval(
                script, ReturnType.INTEGER, keys.size(), keysAndArguments));
        if (result == null) {
            throw new IllegalStateException("Redis account security authority returned no result");
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    private byte[] value(final Object value) {
        return Objects.requireNonNull(valueSerializer().serialize(value), "serializedValue");
    }

    @SuppressWarnings("unchecked")
    private RedisSerializer<Object> valueSerializer() {
        return (RedisSerializer<Object>) redisTemplate.getValueSerializer();
    }

    @SuppressWarnings("unchecked")
    private byte[] key(final String key) {
        val serializer = (RedisSerializer<String>) redisTemplate.getKeySerializer();
        return Objects.requireNonNull(serializer.serialize(key), "serializedKey");
    }

    private static Collection<String> requirePatterns(final Collection<String> patterns) {
        if (patterns == null || patterns.isEmpty() || patterns.size() > 8
            || patterns.stream().anyMatch(pattern -> pattern == null || pattern.isBlank())) {
            throw new IllegalArgumentException("Account security key patterns are invalid");
        }
        return List.copyOf(patterns);
    }

    private static String requireDataKey(final String dataKey) {
        if (dataKey == null || dataKey.isBlank()) {
            throw new IllegalArgumentException("Account security data key is required");
        }
        return dataKey;
    }

    private static byte[] token(final UUID closureId) {
        val token = Objects.requireNonNull(closureId, "closureId");
        if (token.getMostSignificantBits() == 0 && token.getLeastSignificantBits() == 0) {
            throw new IllegalArgumentException("Account security closure token must not be nil");
        }
        return token.toString().getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] script(final String script) {
        return script.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] ascii(final String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private static String utf8(final Object value) {
        return value instanceof final byte[] bytes
            ? new String(bytes, StandardCharsets.UTF_8)
            : Objects.requireNonNull(value, "authorityReadStatus").toString();
    }

    private static void requireVersionedReadSize(
        final List<?> result,
        final int expectedSize,
        final String status) {
        if (result.size() != expectedSize) {
            throw new IllegalStateException(
                "Redis account security %s versioned read returned an invalid result"
                    .formatted(status));
        }
    }

    private static byte[] versionedReadBytes(final List<?> result, final int index) {
        if (!(result.get(index) instanceof final byte[] value)) {
            throw new IllegalStateException(
                "Redis account security versioned read returned an invalid value");
        }
        return value;
    }

    /** Exact serialized value returned by an authority read. */
    public static final class AuthorityValue {
        private final String dataKey;

        private final byte[] serializedValue;

        private final boolean fenced;

        private AuthorityValue(
            final String dataKey,
            final byte[] serializedValue,
            final boolean fenced) {
            this.dataKey = dataKey;
            this.serializedValue = serializedValue == null ? null : serializedValue.clone();
            this.fenced = fenced;
        }

        /**
         * Whether the key existed at the authority read's linearization point.
         *
         * @return true when serialized bytes were present
         */
        public boolean isPresent() {
            return serializedValue != null;
        }

        /**
         * Whether a terminal fence existed at the authority read's
         * linearization point.
         *
         * @return true when terminally fenced
         */
        public boolean isFenced() {
            return fenced;
        }

        /**
         * Return a defensive copy of the exact serialized authority bytes.
         *
         * @return serialized value bytes
         * @throws IllegalStateException when the authority value was absent
         */
        public byte[] serializedValue() {
            if (!isPresent()) {
                throw new IllegalStateException("Redis account security authority value is absent");
            }
            return serializedValue.clone();
        }

        private byte[] serializedValueOrEmpty() {
            return isPresent() ? serializedValue : new byte[0];
        }
    }

    /**
     * Exact serialized value and independent write token returned by one
     * authority read. Missing write-token bytes on a present value identify a
     * pre-token record that may be adopted once, while every subsequent write
     * receives a fresh token.
     */
    public static final class VersionedAuthorityValue {
        private final String dataKey;

        private final String writeTokenKey;

        private final byte[] serializedValue;

        private final byte[] serializedWriteToken;

        private final boolean fenced;

        private VersionedAuthorityValue(
            final String dataKey,
            final String writeTokenKey,
            final byte[] serializedValue,
            final byte[] serializedWriteToken,
            final boolean fenced) {
            this.dataKey = dataKey;
            this.writeTokenKey = writeTokenKey;
            this.serializedValue = serializedValue == null ? null : serializedValue.clone();
            this.serializedWriteToken = serializedWriteToken == null
                ? null
                : serializedWriteToken.clone();
            this.fenced = fenced;
        }

        /**
         * Whether data existed at the read linearization point.
         *
         * @return true when serialized data bytes were present
         */
        public boolean isPresent() {
            return serializedValue != null;
        }

        /**
         * Whether a terminal account-deletion fence existed.
         *
         * @return true when terminally fenced
         */
        public boolean isFenced() {
            return fenced;
        }

        /**
         * Whether the present data already has a write token.
         *
         * @return true when token bytes were present
         */
        public boolean hasWriteToken() {
            return serializedWriteToken != null;
        }

        /**
         * Return a defensive copy of exact serialized data bytes.
         *
         * @return serialized value bytes
         */
        public byte[] serializedValue() {
            if (!isPresent()) {
                throw new IllegalStateException(
                    "Redis account security versioned authority value is absent");
            }
            return serializedValue.clone();
        }

        private byte[] serializedValueOrEmpty() {
            return isPresent() ? serializedValue : new byte[0];
        }

        private byte[] serializedWriteTokenOrEmpty() {
            return hasWriteToken() ? serializedWriteToken : new byte[0];
        }
    }

    /** Atomic conditional-mutation outcome. */
    public enum CompareAndSetResult {
        /** Expected value matched and the replacement was applied. */
        APPLIED,
        /** Authority value no longer matched the expected serialized bytes. */
        COMPARE_MISMATCH,
        /** A terminal account-deletion fence rejected the mutation. */
        FENCED
    }

    /** Exact-value conditional-deletion outcome. */
    public enum CompareAndDeleteResult {
        /** Expected serialized value matched and was deleted. */
        DELETED,
        /** Key was already absent. */
        ABSENT,
        /** Key contained different serialized bytes. */
        COMPARE_MISMATCH
    }

    /** Terminal-fence acquisition outcome. */
    public enum TerminalFenceResult {
        /** New terminal fence was acquired. */
        ACQUIRED,
        /** Existing terminal fence already belonged to the same token. */
        REPLAY,
        /** Existing terminal fence belonged to another token. */
        CONFLICT
    }

    /** Raised when a credential writer observes a permanent terminal fence. */
    public static final class AccountSecurityWriteFencedException extends IllegalStateException {
        private static final long serialVersionUID = -2102326510531385011L;

        /** Construct the stable fenced-write failure. */
        public AccountSecurityWriteFencedException() {
            super("Account security state is terminally fenced");
        }
    }
}
