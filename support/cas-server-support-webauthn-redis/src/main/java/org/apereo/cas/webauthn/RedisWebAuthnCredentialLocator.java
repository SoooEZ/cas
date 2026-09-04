package org.apereo.cas.webauthn;

import module java.base;

import org.apereo.cas.redis.core.CasRedisTemplate;
import org.apereo.cas.redis.core.RedisAccountSecurityDeletionFence;
import com.yubico.data.CredentialRegistration;
import com.yubico.webauthn.data.ByteArray;
import lombok.val;
import org.springframework.data.redis.connection.ReturnType;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.serializer.RedisSerializer;

/**
 * Raw-principal-free secondary locator for Redis WebAuthn credentials.
 *
 * <p>A locator member is only a stable principal digest and is never an
 * authentication authority. Every candidate must be checked against the
 * principal-owned current record and terminal fence. Writers publish hints
 * before their cross-slot authority CAS. A short-lived, coordinate-slot-local
 * publication intent prevents stale-candidate cleanup from racing that window.
 * The intent uses a unique token, so concurrent writers for the same principal
 * cannot clear one another's protection.</p>
 *
 * <p>Crash residue is bounded: candidate membership is idempotent per
 * principal and publication intents have a Redis-enforced TTL. Cleanup removes
 * a candidate only when no live publication intent exists and callers then
 * recheck the authority record.</p>
 *
 * @author Apereo CAS
 * @since 8.0.1
 */
public final class RedisWebAuthnCredentialLocator {
    /** Stable Spring bean name. */
    public static final String BEAN_NAME = "webAuthnRedisCredentialLocator";

    /** Stable locator Redis-template bean name. */
    public static final String REDIS_TEMPLATE_BEAN_NAME = "webAuthnCredentialLocatorRedisTemplate";

    static final String REDIS_NAMESPACE = RedisWebAuthnCredentialLocator.class.getSimpleName();

    static final String LOCATOR_PATTERN = REDIS_NAMESPACE + ":v3:*";

    static final String SCHEMA_VERSION = "3";

    static final String SCHEMA_HASH_TAG = "{schema-v3}";

    static final String READY_KEY = REDIS_NAMESPACE + ':' + SCHEMA_HASH_TAG + ":ready";

    static final String REBUILD_LEASE_KEY = REDIS_NAMESPACE + ':' + SCHEMA_HASH_TAG + ":rebuild-lease";

    static final int MAXIMUM_CANDIDATES = 256;

    static final int MAXIMUM_PUBLICATION_INTENTS = 256;

    private static final long PUBLICATION_INTENT_MILLIS = Duration.ofMinutes(2).toMillis();

    private static final long REBUILD_LEASE_MILLIS = Duration.ofSeconds(30).toMillis();

    private static final long REBUILD_WAIT_MILLIS = Duration.ofSeconds(35).toMillis();

    private static final long REBUILD_POLL_MILLIS = 100;

    private static final int SHA_256_HEX_LENGTH = 64;

    private static final Pattern LOCATOR_KEY_PATTERN = Pattern.compile(
        "RedisWebAuthnCredentialLocator:v3:(?:credential|user-handle):"
            + "\\{[0-9a-f]{64}}:candidates");

    private static final Pattern TOKEN_PATTERN = Pattern.compile(
        "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

    private static final long CORRUPT_RESULT = -1;

    private static final long CANDIDATE_CAPACITY_RESULT = -2;

    private static final long INTENT_CAPACITY_RESULT = -3;

    private static final long PUBLICATION_BUSY_RESULT = -4;

    private static final byte[] BEGIN_PUBLICATION_SCRIPT = script("""
        local function keytype(key)
          local value = redis.call('TYPE', key)
          if type(value) == 'table' then return value.ok end
          return value
        end
        local function valid_digest(value)
          return value and string.len(value) == 64
              and string.match(value, '^[0-9a-f]+$') ~= nil
        end
        local function valid_member(value)
          local schema, digest = string.match(value or '', '^([^:]+):([^:]+)$')
          return schema == '3' and valid_digest(digest)
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
        local candidate_type = keytype(KEYS[1])
        local intent_type = keytype(KEYS[2])
        if (candidate_type ~= 'none' and candidate_type ~= 'set')
            or (intent_type ~= 'none' and intent_type ~= 'zset') then
          return -1
        end
        if not valid_member(ARGV[1]) or not valid_token(ARGV[2]) then
          return -1
        end
        local now = redis.call('TIME')
        local now_millis = (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
        local ttl = tonumber(ARGV[3])
        local candidate_limit = tonumber(ARGV[4])
        local intent_limit = tonumber(ARGV[5])
        if not ttl or ttl <= 0 or not candidate_limit or not intent_limit then
          return -1
        end
        redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now_millis)
        local candidate_count = redis.call('SCARD', KEYS[1])
        local intent_count = redis.call('ZCARD', KEYS[2])
        if candidate_count > candidate_limit then
          return -2
        end
        if intent_count > intent_limit then
          return -3
        end
        local candidates = redis.call('SMEMBERS', KEYS[1])
        for _, candidate in ipairs(candidates) do
          if not valid_member(candidate) then
            return -1
          end
        end
        local intents = redis.call('ZRANGE', KEYS[2], 0, -1)
        for _, intent in ipairs(intents) do
          if not valid_token(intent) then
            return -1
          end
        end
        if redis.call('SISMEMBER', KEYS[1], ARGV[1]) == 0
            and candidate_count >= candidate_limit then
          return -2
        end
        if not redis.call('ZSCORE', KEYS[2], ARGV[2])
            and intent_count >= intent_limit then
          return -3
        end
        redis.call('ZADD', KEYS[2], now_millis + ttl, ARGV[2])
        redis.call('SADD', KEYS[1], ARGV[1])
        local latest = redis.call('ZREVRANGE', KEYS[2], 0, 0, 'WITHSCORES')
        redis.call('PEXPIREAT', KEYS[2], math.floor(tonumber(latest[2])) + 1000)
        return 1
        """);

    private static final byte[] COMPLETE_PUBLICATION_SCRIPT = script("""
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
        local intent_type = keytype(KEYS[1])
        if intent_type ~= 'none' and intent_type ~= 'zset' then
          return -1
        end
        if not valid_token(ARGV[1]) then
          return -1
        end
        local now = redis.call('TIME')
        local now_millis = (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
        redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now_millis)
        if redis.call('ZCARD', KEYS[1]) > tonumber(ARGV[2]) then
          return -3
        end
        local intents = redis.call('ZRANGE', KEYS[1], 0, -1)
        for _, intent in ipairs(intents) do
          if not valid_token(intent) then
            return -1
          end
        end
        redis.call('ZREM', KEYS[1], ARGV[1])
        if redis.call('ZCARD', KEYS[1]) == 0 then
          redis.call('DEL', KEYS[1])
        else
          local latest = redis.call('ZREVRANGE', KEYS[1], 0, 0, 'WITHSCORES')
          redis.call('PEXPIREAT', KEYS[1], math.floor(tonumber(latest[2])) + 1000)
        end
        return 1
        """);

    private static final byte[] ADD_MEMBER_SCRIPT = script("""
        local function keytype(key)
          local value = redis.call('TYPE', key)
          if type(value) == 'table' then return value.ok end
          return value
        end
        local function valid_digest(value)
          return value and string.len(value) == 64
              and string.match(value, '^[0-9a-f]+$') ~= nil
        end
        local function valid_member(value)
          local schema, digest = string.match(value or '', '^([^:]+):([^:]+)$')
          return schema == '3' and valid_digest(digest)
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
        local candidate_type = keytype(KEYS[1])
        local intent_type = keytype(KEYS[2])
        if (candidate_type ~= 'none' and candidate_type ~= 'set')
            or (intent_type ~= 'none' and intent_type ~= 'zset') then
          return -1
        end
        if not valid_member(ARGV[1]) then
          return -1
        end
        local now = redis.call('TIME')
        local now_millis = (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
        redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now_millis)
        local candidate_count = redis.call('SCARD', KEYS[1])
        local intent_count = redis.call('ZCARD', KEYS[2])
        if candidate_count > tonumber(ARGV[2]) then
          return -2
        end
        if intent_count > tonumber(ARGV[3]) then
          return -3
        end
        local candidates = redis.call('SMEMBERS', KEYS[1])
        for _, candidate in ipairs(candidates) do
          if not valid_member(candidate) then
            return -1
          end
        end
        local intents = redis.call('ZRANGE', KEYS[2], 0, -1)
        for _, intent in ipairs(intents) do
          if not valid_token(intent) then
            return -1
          end
        end
        if redis.call('SISMEMBER', KEYS[1], ARGV[1]) == 0
            and candidate_count >= tonumber(ARGV[2]) then
          return -2
        end
        if intent_count == 0 then
          redis.call('DEL', KEYS[2])
        end
        return redis.call('SADD', KEYS[1], ARGV[1])
        """);

    private static final byte[] REMOVE_MEMBER_SCRIPT = script("""
        local function keytype(key)
          local value = redis.call('TYPE', key)
          if type(value) == 'table' then return value.ok end
          return value
        end
        local candidate_type = keytype(KEYS[1])
        if candidate_type ~= 'none' and candidate_type ~= 'set' then
          return -1
        end
        if redis.call('SCARD', KEYS[1]) > tonumber(ARGV[2]) then
          return -2
        end
        return redis.call('SREM', KEYS[1], ARGV[1])
        """);

    private static final byte[] REMOVE_IF_NO_PUBLICATION_SCRIPT = script("""
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
        local candidate_type = keytype(KEYS[1])
        local intent_type = keytype(KEYS[2])
        if (candidate_type ~= 'none' and candidate_type ~= 'set')
            or (intent_type ~= 'none' and intent_type ~= 'zset') then
          return -1
        end
        local now = redis.call('TIME')
        local now_millis = (tonumber(now[1]) * 1000) + math.floor(tonumber(now[2]) / 1000)
        redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now_millis)
        if redis.call('SCARD', KEYS[1]) > tonumber(ARGV[2]) then
          return -2
        end
        if redis.call('ZCARD', KEYS[2]) > tonumber(ARGV[3]) then
          return -3
        end
        local intents = redis.call('ZRANGE', KEYS[2], 0, -1)
        for _, intent in ipairs(intents) do
          if not valid_token(intent) then
            return -1
          end
        end
        if redis.call('ZCARD', KEYS[2]) ~= 0 then
          return -4
        end
        redis.call('DEL', KEYS[2])
        return redis.call('SREM', KEYS[1], ARGV[1])
        """);

    private static final byte[] READ_MEMBERS_SCRIPT = script("""
        local function keytype(key)
          local value = redis.call('TYPE', key)
          if type(value) == 'table' then return value.ok end
          return value
        end
        local candidate_type = keytype(KEYS[1])
        if candidate_type ~= 'none' and candidate_type ~= 'set' then
          return {'CORRUPT'}
        end
        local count = redis.call('SCARD', KEYS[1])
        if count > tonumber(ARGV[1]) then
          return {'CAPACITY'}
        end
        local members = redis.call('SMEMBERS', KEYS[1])
        table.insert(members, 1, 'MEMBERS')
        return members
        """);

    private static final byte[] VERIFY_READY_SCRIPT = script("""
        local current = redis.call('GET', KEYS[1])
        if current and current == ARGV[1] then
          return 1
        end
        return 0
        """);

    private static final byte[] ACQUIRE_REBUILD_SCRIPT = script("""
        local ready = redis.call('GET', KEYS[1])
        if ready and ready == ARGV[1] then
          return 2
        end
        if redis.call('SET', KEYS[2], ARGV[2], 'NX', 'PX', ARGV[3]) then
          return 1
        end
        return 0
        """);

    private static final byte[] RENEW_REBUILD_SCRIPT = script("""
        local current = redis.call('GET', KEYS[1])
        if current and current == ARGV[1] then
          redis.call('PEXPIRE', KEYS[1], ARGV[2])
          return 1
        end
        return 0
        """);

    private static final byte[] COMPLETE_REBUILD_SCRIPT = script("""
        local current = redis.call('GET', KEYS[2])
        if current and current == ARGV[2] then
          redis.call('SET', KEYS[1], ARGV[1])
          redis.call('DEL', KEYS[2])
          return 1
        end
        return 0
        """);

    private static final byte[] RELEASE_REBUILD_SCRIPT = script("""
        local current = redis.call('GET', KEYS[1])
        if current and current == ARGV[1] then
          redis.call('DEL', KEYS[1])
          return 1
        end
        return 0
        """);

    private final CasRedisTemplate<String, String> locatorRedisTemplate;

    private final CasRedisTemplate<String, RedisWebAuthnCredentialRegistration> recordRedisTemplate;

    private final RedisAccountSecurityDeletionFence deletionFence;

    public RedisWebAuthnCredentialLocator(
        final CasRedisTemplate<String, String> locatorRedisTemplate,
        final CasRedisTemplate<String, RedisWebAuthnCredentialRegistration> recordRedisTemplate,
        final RedisAccountSecurityDeletionFence deletionFence) {
        this.locatorRedisTemplate = Objects.requireNonNull(locatorRedisTemplate, "locatorRedisTemplate");
        this.recordRedisTemplate = Objects.requireNonNull(recordRedisTemplate, "recordRedisTemplate");
        this.deletionFence = Objects.requireNonNull(deletionFence, "deletionFence");
    }

    /**
     * Publish idempotent hints while protecting them from concurrent stale
     * cleanup until the authority CAS has completed.
     *
     * @param principalDigest principal SHA-256 digest
     * @param registrations credentials in the proposed authority record
     * @return publication handle that must be completed in a finally block
     */
    public Publication beginPublication(
        final String principalDigest,
        final Collection<CredentialRegistration> registrations) {
        val member = serializeMember(principalDigest);
        val token = UUID.randomUUID().toString();
        val coordinates = new ArrayList<PublicationCoordinate>();
        val rollback = new PublicationRollback(token, coordinates);
        try (rollback) {
            for (val locatorKey : locatorKeys(registrations)) {
                val coordinate = new PublicationCoordinate(
                    locatorKey, publicationIntentKey(locatorKey, principalDigest));
                val result = evalInteger(
                    BEGIN_PUBLICATION_SCRIPT,
                    List.of(key(coordinate.locatorKey()), key(coordinate.intentKey())),
                    value(member),
                    ascii(token),
                    ascii(Long.toString(PUBLICATION_INTENT_MILLIS)),
                    ascii(Integer.toString(MAXIMUM_CANDIDATES)),
                    ascii(Integer.toString(MAXIMUM_PUBLICATION_INTENTS)));
                requireSuccessfulMutation(result, "begin publication");
                coordinates.add(coordinate);
            }
            rollback.commit();
            return new Publication(token, coordinates);
        }
    }

    /**
     * Clear only this writer's publication intents. The operation is
     * idempotent and never clears another concurrent writer's token.
     *
     * @param publication publication returned by {@link #beginPublication}
     */
    public void completePublication(final Publication publication) {
        val requiredPublication = Objects.requireNonNull(publication, "publication");
        completePublication(requiredPublication, 0);
    }

    private void completePublication(final Publication publication, final int coordinateIndex) {
        if (coordinateIndex >= publication.coordinates().size()) {
            return;
        }
        val coordinate = publication.coordinates().get(coordinateIndex);
        try (PublicationCleanup cleanup = () -> completePublicationCoordinate(
            publication.token(), coordinate)) {
            completePublication(publication, coordinateIndex + 1);
        }
    }

    private void completePublicationCoordinate(
        final String token,
        final PublicationCoordinate coordinate) {
        val result = evalInteger(
            COMPLETE_PUBLICATION_SCRIPT,
            List.of(key(coordinate.intentKey())),
            ascii(token),
            ascii(Integer.toString(MAXIMUM_PUBLICATION_INTENTS)));
        requireSuccessfulMutation(result, "complete publication");
    }

    /**
     * Ensure stable hints exist for an already-verified authority record.
     *
     * @param principalDigest principal SHA-256 digest
     * @param registrations verified authority registrations
     */
    public void publish(
        final String principalDigest,
        final Collection<CredentialRegistration> registrations) {
        val member = serializeMember(principalDigest);
        locatorKeys(registrations).forEach(locatorKey ->
            addMember(locatorKey, member, principalDigest));
    }

    /**
     * Locate candidate authority records for a credential identifier.
     *
     * @param credentialId credential identifier
     * @return untrusted candidates requiring authority verification
     */
    public Set<Candidate> locateByCredentialId(final ByteArray credentialId) {
        return locate(credentialLocatorKey(credentialId));
    }

    /**
     * Locate candidate authority records for a user handle.
     *
     * @param userHandle user handle
     * @return untrusted candidates requiring authority verification
     */
    public Set<Candidate> locateByUserHandle(final ByteArray userHandle) {
        return locate(userHandleLocatorKey(userHandle));
    }

    /**
     * Conditionally remove a candidate after an authority read found no
     * matching current coordinate. A live publication intent prevents removal.
     * Callers must recheck authority after this cross-slot operation and
     * restore the hint if the coordinate became current.
     *
     * @param candidate possibly stale candidate
     * @return true when no publication intent prevented cleanup
     */
    public boolean removeIfNoPublication(final Candidate candidate) {
        val requiredCandidate = Objects.requireNonNull(candidate, "candidate");
        val result = evalInteger(
            REMOVE_IF_NO_PUBLICATION_SCRIPT,
            List.of(
                key(requiredCandidate.locatorKey()),
                key(publicationIntentKey(
                    requiredCandidate.locatorKey(), requiredCandidate.principalDigest()))),
            value(requiredCandidate.member()),
            ascii(Integer.toString(MAXIMUM_CANDIDATES)),
            ascii(Integer.toString(MAXIMUM_PUBLICATION_INTENTS)));
        if (result == PUBLICATION_BUSY_RESULT) {
            return false;
        }
        requireSuccessfulMutation(result, "remove candidate");
        return true;
    }

    /**
     * Restore an exact candidate after authority revalidation.
     *
     * @param candidate verified current candidate
     */
    public void ensure(final Candidate candidate) {
        val requiredCandidate = Objects.requireNonNull(candidate, "candidate");
        addMember(
            requiredCandidate.locatorKey(),
            requiredCandidate.member(),
            requiredCandidate.principalDigest());
    }

    /**
     * Ensure the locator schema is ready. Login paths fail closed instead of
     * falling back to a request-time full scan.
     */
    public void requireReady() {
        if (!isReady()) {
            throw new IllegalStateException("WebAuthn Redis credential locator is not ready");
        }
    }

    /**
     * Perform the one-time, lease-protected streaming rebuild required when the
     * schema marker is absent. A non-owner waits for READY and may acquire an
     * expired lease, avoiding simultaneous multi-node startup failure while
     * preserving a bounded fail-closed startup.
     *
     * @param repairRecord callback that validates, migrates or indexes one record
     */
    public void rebuildIfRequired(final BiConsumer<String, String> repairRecord) {
        Objects.requireNonNull(repairRecord, "repairRecord");
        val deadline = System.nanoTime() + Duration.ofMillis(REBUILD_WAIT_MILLIS).toNanos();
        while (!isReady()) {
            val token = UUID.randomUUID().toString();
            val acquireResult = evalInteger(
                ACQUIRE_REBUILD_SCRIPT,
                List.of(key(READY_KEY), key(REBUILD_LEASE_KEY)),
                ascii(SCHEMA_VERSION),
                ascii(token),
                ascii(Long.toString(REBUILD_LEASE_MILLIS)));
            if (acquireResult == 2) {
                return;
            }
            if (acquireResult == 1) {
                rebuild(token, repairRecord);
                return;
            }
            if (System.nanoTime() >= deadline) {
                throw new IllegalStateException(
                    "Timed out waiting for the WebAuthn Redis locator rebuild owner");
            }
            if (Thread.currentThread().isInterrupted()) {
                throw new IllegalStateException(
                    "Interrupted while waiting for the WebAuthn Redis locator rebuild owner");
            }
            LockSupport.parkNanos(Duration.ofMillis(REBUILD_POLL_MILLIS).toNanos());
        }
    }

    Set<String> locatorKeys(final Collection<CredentialRegistration> registrations) {
        val result = new LinkedHashSet<String>();
        Objects.requireNonNull(registrations, "registrations").forEach(registration -> {
            result.add(credentialLocatorKey(registration.getCredential().getCredentialId()));
            result.add(userHandleLocatorKey(registration.getUserIdentity().getId()));
        });
        return Set.copyOf(result);
    }

    Candidate candidate(final String locatorKey, final String principalDigest) {
        return new Candidate(locatorKey, serializeMember(principalDigest), principalDigest);
    }

    private void rebuild(
        final String token,
        final BiConsumer<String, String> repairRecord) {
        var completed = false;
        try {
            try (val keys = recordRedisTemplate.scan(
                RedisWebAuthnCredentialRepository.CAS_WEB_AUTHN_PREFIX + '*')) {
                keys.forEach(redisKey -> {
                    renewRebuildLease(token);
                    val value = deletionFence.readFromAuthority(redisKey);
                    deletionFence.deserialize(value, RedisWebAuthnCredentialRegistration.class)
                        .map(RedisWebAuthnCredentialRegistration::getUsername)
                        .filter(username -> username != null && !username.isBlank())
                        .ifPresentOrElse(
                            username -> repairRecord.accept(redisKey, username),
                            () -> {
                                throw new IllegalStateException(
                                    "WebAuthn Redis authority record has no rebuildable owner");
                            });
                });
            }
            val result = evalInteger(
                COMPLETE_REBUILD_SCRIPT,
                List.of(key(READY_KEY), key(REBUILD_LEASE_KEY)),
                ascii(SCHEMA_VERSION),
                ascii(token));
            if (result != 1) {
                throw new IllegalStateException("WebAuthn Redis locator rebuild lease was lost");
            }
            completed = true;
        } finally {
            if (!completed) {
                evalInteger(
                    RELEASE_REBUILD_SCRIPT,
                    List.of(key(REBUILD_LEASE_KEY)),
                    ascii(token));
            }
        }
    }

    private Set<Candidate> locate(final String locatorKey) {
        requireLocatorKey(locatorKey);
        requireReady();
        val result = locatorRedisTemplate.execute(
            (RedisCallback<List<?>>) connection -> connection.scriptingCommands().eval(
                READ_MEMBERS_SCRIPT,
                ReturnType.MULTI,
                1,
                key(locatorKey),
                ascii(Integer.toString(MAXIMUM_CANDIDATES))));
        if (result == null || result.isEmpty()) {
            throw new IllegalStateException("WebAuthn Redis locator returned an invalid result");
        }
        val status = rawString(result.getFirst());
        if ("CAPACITY".equals(status)) {
            throw new IllegalStateException("WebAuthn Redis locator candidate capacity was exceeded");
        }
        if ("CORRUPT".equals(status)) {
            throw new IllegalStateException("WebAuthn Redis locator has an invalid Redis type");
        }
        if (!"MEMBERS".equals(status) || result.size() - 1 > MAXIMUM_CANDIDATES) {
            throw new IllegalStateException("WebAuthn Redis locator returned an invalid result");
        }
        val candidates = new LinkedHashSet<Candidate>();
        for (var index = 1; index < result.size(); index++) {
            if (!(result.get(index) instanceof final byte[] serializedMember)) {
                throw new IllegalStateException("WebAuthn Redis locator returned an invalid member");
            }
            val member = Objects.requireNonNull(valueSerializer().deserialize(serializedMember), "locatorMember");
            parseMember(locatorKey, member).ifPresentOrElse(
                candidates::add,
                () -> removeInvalidMember(locatorKey, serializedMember));
        }
        return Set.copyOf(candidates);
    }

    private boolean isReady() {
        return evalInteger(
            VERIFY_READY_SCRIPT,
            List.of(key(READY_KEY)),
            ascii(SCHEMA_VERSION)) == 1;
    }

    private void renewRebuildLease(final String token) {
        val result = evalInteger(
            RENEW_REBUILD_SCRIPT,
            List.of(key(REBUILD_LEASE_KEY)),
            ascii(token),
            ascii(Long.toString(REBUILD_LEASE_MILLIS)));
        if (result != 1) {
            throw new IllegalStateException("WebAuthn Redis locator rebuild lease was lost");
        }
    }

    private void addMember(
        final String locatorKey,
        final String member,
        final String principalDigest) {
        val intentKey = publicationIntentKey(locatorKey, principalDigest);
        val result = evalInteger(
            ADD_MEMBER_SCRIPT,
            List.of(key(locatorKey), key(intentKey)),
            value(member),
            ascii(Integer.toString(MAXIMUM_CANDIDATES)),
            ascii(Integer.toString(MAXIMUM_PUBLICATION_INTENTS)));
        requireSuccessfulMutation(result, "publish candidate");
    }

    private void removeInvalidMember(final String locatorKey, final byte[] serializedMember) {
        val result = evalInteger(
            REMOVE_MEMBER_SCRIPT,
            List.of(key(locatorKey)),
            serializedMember,
            ascii(Integer.toString(MAXIMUM_CANDIDATES)));
        requireSuccessfulMutation(result, "remove invalid candidate");
    }

    private static Optional<Candidate> parseMember(final String locatorKey, final String member) {
        val elements = member.split(":", -1);
        if (elements.length != 2 || !SCHEMA_VERSION.equals(elements[0])) {
            return Optional.empty();
        }
        val principalDigest = elements[1];
        return isPrincipalDigest(principalDigest)
            ? Optional.of(new Candidate(locatorKey, member, principalDigest))
            : Optional.empty();
    }

    private static String serializeMember(final String principalDigest) {
        if (!isPrincipalDigest(principalDigest)) {
            throw new IllegalArgumentException("WebAuthn locator principal digest is invalid");
        }
        return SCHEMA_VERSION + ':' + principalDigest;
    }

    private static boolean isPrincipalDigest(final String principalDigest) {
        return principalDigest != null
            && principalDigest.length() == SHA_256_HEX_LENGTH
            && principalDigest.chars().allMatch(character ->
                (character >= '0' && character <= '9')
                    || (character >= 'a' && character <= 'f'));
    }

    private static String credentialLocatorKey(final ByteArray credentialId) {
        return REDIS_NAMESPACE + ":v" + SCHEMA_VERSION
            + ":credential:{" + digest(credentialId) + "}:candidates";
    }

    private static String userHandleLocatorKey(final ByteArray userHandle) {
        return REDIS_NAMESPACE + ":v" + SCHEMA_VERSION
            + ":user-handle:{" + digest(userHandle) + "}:candidates";
    }

    private static String publicationIntentKey(
        final String locatorKey,
        final String principalDigest) {
        return locatorKey + ":publication:" + principalDigest;
    }

    private static String digest(final ByteArray value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(
                Objects.requireNonNull(value, "locatorCoordinate").getBytes()));
        } catch (final NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private long evalInteger(final byte[] script, final List<byte[]> keys, final byte[]... arguments) {
        val keysAndArguments = new byte[keys.size() + arguments.length][];
        for (var index = 0; index < keys.size(); index++) {
            keysAndArguments[index] = keys.get(index);
        }
        System.arraycopy(arguments, 0, keysAndArguments, keys.size(), arguments.length);
        val result = locatorRedisTemplate.execute(
            (RedisCallback<Long>) connection -> connection.scriptingCommands().eval(
                script, ReturnType.INTEGER, keys.size(), keysAndArguments));
        if (result == null) {
            throw new IllegalStateException("WebAuthn Redis locator returned no result");
        }
        return result;
    }

    private static void requireSuccessfulMutation(final long result, final String operation) {
        if (result == CORRUPT_RESULT) {
            throw new IllegalStateException(
                "WebAuthn Redis locator is corrupt while attempting to " + operation);
        }
        if (result == CANDIDATE_CAPACITY_RESULT) {
            throw new IllegalStateException(
                "WebAuthn Redis locator candidate capacity was exceeded while attempting to "
                    + operation);
        }
        if (result == INTENT_CAPACITY_RESULT) {
            throw new IllegalStateException(
                "WebAuthn Redis locator publication capacity was exceeded while attempting to "
                    + operation);
        }
        if (result < 0 || result > 1) {
            throw new IllegalStateException(
                "WebAuthn Redis locator returned an invalid result while attempting to "
                    + operation);
        }
    }

    private static String requireLocatorKey(final String locatorKey) {
        if (locatorKey == null || !LOCATOR_KEY_PATTERN.matcher(locatorKey).matches()) {
            throw new IllegalArgumentException("WebAuthn Redis locator key is invalid");
        }
        return locatorKey;
    }

    private static String requireToken(final String token) {
        if (token == null || !TOKEN_PATTERN.matcher(token).matches()
            || "00000000-0000-0000-0000-000000000000".equals(token)) {
            throw new IllegalArgumentException("WebAuthn Redis publication token is invalid");
        }
        return token;
    }

    @SuppressWarnings("unchecked")
    private byte[] key(final String redisKey) {
        val serializer = (RedisSerializer<String>) locatorRedisTemplate.getKeySerializer();
        return Objects.requireNonNull(serializer.serialize(redisKey), "serializedLocatorKey");
    }

    private byte[] value(final String member) {
        return Objects.requireNonNull(valueSerializer().serialize(member), "serializedLocatorMember");
    }

    @SuppressWarnings("unchecked")
    private RedisSerializer<String> valueSerializer() {
        return (RedisSerializer<String>) locatorRedisTemplate.getValueSerializer();
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
            : Objects.requireNonNull(value, "locatorStatus").toString();
    }

    @FunctionalInterface
    private interface PublicationCleanup extends AutoCloseable {
        @Override
        void close();
    }

    private final class PublicationRollback implements AutoCloseable {
        private final String token;

        private final List<PublicationCoordinate> coordinates;

        private boolean committed;

        private PublicationRollback(
            final String token,
            final List<PublicationCoordinate> coordinates) {
            this.token = token;
            this.coordinates = coordinates;
        }

        private void commit() {
            committed = true;
        }

        @Override
        public void close() {
            if (!committed && !coordinates.isEmpty()) {
                completePublication(new Publication(token, coordinates));
            }
        }
    }

    /** Untrusted stable locator candidate requiring authority verification. */
    public record Candidate(String locatorKey, String member, String principalDigest) {
        public Candidate {
            requireLocatorKey(locatorKey);
            if (!serializeMember(principalDigest).equals(member)) {
                throw new IllegalArgumentException(
                    "WebAuthn Redis locator candidate is inconsistent");
            }
        }
    }

    /** Unique publication attempt and its coordinate-slot-local intents. */
    public record Publication(String token, List<PublicationCoordinate> coordinates) {
        public Publication {
            requireToken(token);
            coordinates = List.copyOf(Objects.requireNonNull(coordinates, "coordinates"));
        }
    }

    /** Locator coordinate and its principal-specific publication-intent key. */
    public record PublicationCoordinate(String locatorKey, String intentKey) {
        public PublicationCoordinate {
            requireLocatorKey(locatorKey);
            val expectedPrefix = locatorKey + ":publication:";
            if (intentKey == null || !intentKey.startsWith(expectedPrefix)
                || !isPrincipalDigest(intentKey.substring(expectedPrefix.length()))) {
                throw new IllegalArgumentException(
                    "WebAuthn Redis publication coordinate is invalid");
            }
        }
    }
}
