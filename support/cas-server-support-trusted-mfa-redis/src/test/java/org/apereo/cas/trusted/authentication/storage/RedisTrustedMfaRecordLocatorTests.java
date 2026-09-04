package org.apereo.cas.trusted.authentication.storage;

import module java.base;

import org.apereo.cas.config.CasRedisAccountSecurityAutoConfiguration;
import org.apereo.cas.config.CasRedisMultifactorAuthenticationTrustAutoConfiguration;
import org.apereo.cas.redis.core.CasRedisTemplate;
import org.apereo.cas.redis.core.RedisAccountSecurityDeletionFence;
import org.apereo.cas.redis.core.RedisAccountSecurityKeyCodec;
import org.apereo.cas.test.CasTestExtension;
import org.apereo.cas.trusted.AbstractMultifactorAuthenticationTrustStorageTests;
import org.apereo.cas.trusted.authentication.api.MultifactorAuthenticationTrustRecord;
import org.apereo.cas.util.junit.EnabledIfListeningOnPort;
import lombok.val;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.connection.ReturnType;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.test.context.TestPropertySource;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link RedisTrustedMfaRecordLocator}.
 *
 * @author Apereo CAS
 * @since 8.0.1
 */
@Tag("Redis")
@SpringBootTest(classes = AbstractMultifactorAuthenticationTrustStorageTests.SharedTestConfiguration.class)
@ExtendWith(CasTestExtension.class)
@ImportAutoConfiguration({
    CasRedisAccountSecurityAutoConfiguration.class,
    CasRedisMultifactorAuthenticationTrustAutoConfiguration.class
})
@TestPropertySource(
    properties = {
        "cas.authn.mfa.trusted.redis.host=localhost",
        "cas.authn.mfa.trusted.redis.port=6379"
    })
@EnabledIfListeningOnPort(port = 6379)
@ResourceLock("redis-trusted-mfa")
class RedisTrustedMfaRecordLocatorTests {
    private static final long FIRST_RECORD_ID = -42;

    private static final Duration RECORD_LIFETIME = Duration.ofMinutes(5);

    private static final Duration PUBLICATION_INTENT_LIFETIME = Duration.ofMinutes(2);

    private static final Duration TTL_TOLERANCE = Duration.ofSeconds(10);

    @Autowired
    @Qualifier("redisMfaTrustedAuthnTemplate")
    private CasRedisTemplate<String, List<MultifactorAuthenticationTrustRecord>> redisTemplate;

    @Autowired
    @Qualifier(RedisAccountSecurityDeletionFence.TRUSTED_MFA_BEAN_NAME)
    private RedisAccountSecurityDeletionFence deletionFence;

    private RedisTrustedMfaRecordLocator locator;

    @BeforeEach
    void initializeLocator() {
        locator = new RedisTrustedMfaRecordLocator(redisTemplate, deletionFence);
    }

    @Test
    void verifyPublicationIsRawFreeTokenBoundAndAuthorityRebuildable() {
        val principal = "trusted+" + UUID.randomUUID() + "@example.org";
        val recordKey = "opaque-record-key-" + UUID.randomUUID();
        val record = record(principal, FIRST_RECORD_ID, recordKey, RECORD_LIFETIME);

        val publication = locator.beginPublication(record);
        val candidate = publication.candidate();
        assertEquals(Set.of(candidate), locator.locate(recordKey));
        assertTrue(locator.hasLivePublication(candidate));
        assertFalse(candidate.locatorKey().contains(principal));
        assertFalse(candidate.locatorKey().contains(recordKey));
        assertFalse(candidate.member().contains(principal));
        assertFalse(candidate.member().contains(recordKey));
        assertFalse(publication.intentKey().contains(principal));
        assertFalse(publication.intentKey().contains(recordKey));
        assertFalse(publication.pendingKey().contains(principal));
        assertFalse(publication.pendingKey().contains(recordKey));
        assertEquals(deletionFence.getKeyCodec().principalDigest(principal),
            candidate.principalDigest());
        assertEquals(FIRST_RECORD_ID, candidate.recordId());
        assertEquals(record.getExpirationDate().toInstant(), candidate.expiresAt());
        assertEquals(
            deletionFence.getKeyCodec().dataKeyForPrincipalDigest(
                RedisMultifactorAuthenticationTrustStorage.class.getSimpleName(),
                candidate.principalDigest(),
                "record") + '-' + FIRST_RECORD_ID + '-' + candidate.recordDigest(),
            candidate.authorityRedisKey());

        val pendingTtl = ttl(publication.pendingKey());
        val intentTtl = ttl(publication.intentKey());
        assertTrue(pendingTtl > RECORD_LIFETIME.minus(TTL_TOLERANCE).toMillis());
        assertTrue(pendingTtl <= RECORD_LIFETIME.plus(TTL_TOLERANCE).toMillis());
        assertTrue(intentTtl > PUBLICATION_INTENT_LIFETIME.minus(TTL_TOLERANCE).toMillis());
        assertTrue(intentTtl <= PUBLICATION_INTENT_LIFETIME.toMillis());

        assertEquals(
            RedisTrustedMfaRecordLocator.PublicationCommitResult.COMMITTED,
            locator.commitPublication(publication));
        assertFalse(locator.hasLivePublication(candidate));
        assertEquals(Set.of(candidate), locator.locate(recordKey));
        assertFalse(Boolean.TRUE.equals(redisTemplate.hasKey(publication.pendingKey())));
    }

    @Test
    void verifyConcurrentPublicationCompletionOnlyRemovesItsOwnToken() {
        val record = record(
            UUID.randomUUID().toString(),
            7,
            "opaque-record-key-" + UUID.randomUUID(),
            RECORD_LIFETIME);
        val first = locator.beginPublication(record);
        val second = locator.beginPublication(record);
        assertNotEquals(first.token(), second.token());
        assertEquals(first.intentKey(), second.intentKey());

        locator.completePublication(first);
        assertTrue(locator.hasLivePublication(second.candidate()));
        locator.completePublication(second);
        assertFalse(locator.hasLivePublication(second.candidate()));
        val removalToken = UUID.randomUUID();
        assertEquals(
            RedisTrustedMfaRecordLocator.RemovalLeaseResult.ACQUIRED,
            locator.acquireRemoval(
                record.getRecordKey(), removalToken, Duration.ofSeconds(30)));
        assertTrue(locator.removeIfNoPublication(second.candidate(), removalToken));
        assertTrue(locator.releaseRemoval(record.getRecordKey(), removalToken));
        assertTrue(locator.locate(record.getRecordKey()).isEmpty());
        assertFalse(Boolean.TRUE.equals(redisTemplate.hasKey(second.candidate().locatorKey())));
    }

    @Test
    void verifyLocateAtomicallyPrunesExpiredCandidateAndEmptyKey() {
        val record = record(
            UUID.randomUUID().toString(),
            9,
            "opaque-record-key-" + UUID.randomUUID(),
            RECORD_LIFETIME);
        val candidate = locator.publish(record);
        setCandidateScore(candidate.locatorKey(), candidate.member(), 1);

        assertTrue(locator.locate(record.getRecordKey()).isEmpty());
        assertFalse(Boolean.TRUE.equals(redisTemplate.hasKey(candidate.locatorKey())));
    }

    @Test
    void verifyRemovalLeaseRejectsNewAndInFlightPublications() {
        val record = record(
            UUID.randomUUID().toString(),
            10,
            "opaque-record-key-" + UUID.randomUUID(),
            RECORD_LIFETIME);
        val publication = locator.beginPublication(record);
        val removalToken = UUID.randomUUID();
        assertEquals(
            RedisTrustedMfaRecordLocator.RemovalLeaseResult.ACQUIRED,
            locator.acquireRemoval(
                record.getRecordKey(), removalToken, Duration.ofSeconds(30)));
        assertTrue(locator.hasLivePublications(record.getRecordKey(), removalToken));
        assertThrows(
            RedisTrustedMfaRecordLocator.RemovalInProgressException.class,
            () -> locator.beginPublication(record));
        assertThrows(
            RedisTrustedMfaRecordLocator.RemovalInProgressException.class,
            () -> locator.ensure(publication.candidate()));

        assertEquals(
            RedisTrustedMfaRecordLocator.PublicationCommitResult.REJECTED,
            locator.commitPublication(publication));
        assertFalse(locator.hasLivePublications(record.getRecordKey(), removalToken));
        assertEquals(Set.of(publication.candidate()), locator.locate(record.getRecordKey()));
        assertTrue(locator.removeIfNoPublication(publication.candidate(), removalToken));
        assertTrue(locator.releaseRemoval(record.getRecordKey(), removalToken));
        assertTrue(locator.locate(record.getRecordKey()).isEmpty());
    }

    @Test
    void verifyRemovalLeaseIsTokenBoundRenewableAndIntentExpiryRejectsCommit() {
        val record = record(
            UUID.randomUUID().toString(),
            12,
            "opaque-record-key-" + UUID.randomUUID(),
            RECORD_LIFETIME);
        val publication = locator.beginPublication(record);
        setCandidateScore(publication.intentKey(), publication.intentMember(), 1);
        val owner = UUID.randomUUID();
        val other = UUID.randomUUID();
        assertEquals(
            RedisTrustedMfaRecordLocator.RemovalLeaseResult.ACQUIRED,
            locator.acquireRemoval(record.getRecordKey(), owner, Duration.ofSeconds(30)));
        assertEquals(
            RedisTrustedMfaRecordLocator.RemovalLeaseResult.RENEWED,
            locator.acquireRemoval(record.getRecordKey(), owner, Duration.ofSeconds(30)));
        assertEquals(
            RedisTrustedMfaRecordLocator.RemovalLeaseResult.BUSY,
            locator.acquireRemoval(record.getRecordKey(), other, Duration.ofSeconds(30)));
        assertThrows(
            RedisTrustedMfaRecordLocator.RemovalLeaseLostException.class,
            () -> locator.hasLivePublications(record.getRecordKey(), other));
        assertFalse(locator.hasLivePublications(record.getRecordKey(), owner));
        assertFalse(locator.releaseRemoval(record.getRecordKey(), other));
        assertTrue(locator.releaseRemoval(record.getRecordKey(), owner));
        assertEquals(
            RedisTrustedMfaRecordLocator.PublicationCommitResult.REJECTED,
            locator.commitPublication(publication));
    }

    @Test
    void verifyMalformedMemberAndInvalidInputsFailClosed() {
        val record = record(
            UUID.randomUUID().toString(),
            11,
            "opaque-record-key-" + UUID.randomUUID(),
            RECORD_LIFETIME);
        val candidate = locator.publish(record);
        setCandidateScore(
            candidate.locatorKey(),
            "1:not-a-principal-digest:11",
            record.getExpirationDate().getTime());
        assertThrows(IllegalStateException.class, () -> locator.locate(record.getRecordKey()));

        val blankKey = record(
            UUID.randomUUID().toString(), 12, " ", RECORD_LIFETIME);
        assertThrows(IllegalArgumentException.class, () -> locator.publish(blankKey));
        val blankPrincipal = record(" ", 13, "opaque", RECORD_LIFETIME);
        assertThrows(IllegalArgumentException.class, () -> locator.publish(blankPrincipal));
        val noExpiration = record(
            UUID.randomUUID().toString(), 14, "opaque", RECORD_LIFETIME);
        noExpiration.setExpirationDate(null);
        assertThrows(NullPointerException.class, () -> locator.publish(noExpiration));
        val expired = record(
            UUID.randomUUID().toString(), 15, "expired", RECORD_LIFETIME);
        expired.setExpirationDate(Date.from(Instant.ofEpochMilli(1)));
        assertThrows(IllegalArgumentException.class, () -> locator.publish(expired));
        assertThrows(IllegalArgumentException.class, () -> new RedisTrustedMfaRecordLocator(
            redisTemplate,
            new RedisAccountSecurityDeletionFence(
                spy(redisTemplate), new RedisAccountSecurityKeyCodec())));
    }

    @Test
    void verifyMalformedPendingPublicationUuidFailsClosed() {
        val record = record(
            UUID.randomUUID().toString(),
            16,
            "opaque-record-key-" + UUID.randomUUID(),
            RECORD_LIFETIME);
        val publication = locator.beginPublication(record);
        setCandidateScore(
            publication.pendingKey(),
            publication.candidate().member() + ":not-a-canonical-uuid",
            record.getExpirationDate().getTime());

        assertThrows(IllegalStateException.class, () -> locator.ensure(publication.candidate()));
        assertThrows(IllegalStateException.class, () -> locator.commitPublication(publication));
        assertThrows(IllegalStateException.class, () -> locator.locate(record.getRecordKey()));
    }

    @Test
    void verifyUppercaseDigestInPendingPublicationFailsClosed() {
        val record = record(
            UUID.randomUUID().toString(),
            17,
            "opaque-record-key-" + UUID.randomUUID(),
            RECORD_LIFETIME);
        val publication = locator.beginPublication(record);
        val candidate = publication.candidate();
        val uppercaseMember = "1:" + candidate.principalDigest().toUpperCase(Locale.ROOT)
            + ':' + candidate.recordId() + ':' + UUID.randomUUID();
        setCandidateScore(
            publication.pendingKey(),
            uppercaseMember,
            record.getExpirationDate().getTime());

        assertThrows(IllegalStateException.class, () -> locator.ensure(publication.candidate()));
        assertThrows(IllegalStateException.class, () -> locator.commitPublication(publication));
        assertThrows(IllegalStateException.class, () -> locator.locate(record.getRecordKey()));
    }

    @Test
    void verifyBoundedCapacityCountsUniqueCommittedAndPendingCandidates() {
        val recordKey = "shared-opaque-record-key-" + UUID.randomUUID();
        MultifactorAuthenticationTrustRecord firstRecord = null;
        RedisTrustedMfaRecordLocator.Candidate first = null;
        val committedCount = RedisTrustedMfaRecordLocator.MAXIMUM_CANDIDATES / 2;
        for (var index = 0; index < committedCount; index++) {
            val currentRecord = record(
                "principal-" + index + '-' + UUID.randomUUID(),
                index,
                recordKey,
                RECORD_LIFETIME);
            val candidate = locator.publish(currentRecord);
            if (first == null) {
                first = candidate;
                firstRecord = currentRecord;
            }
        }
        val requiredFirst = Objects.requireNonNull(first);
        val duplicatePublication = locator.beginPublication(
            Objects.requireNonNull(firstRecord));
        val pendingPublications = IntStream.range(
                committedCount, RedisTrustedMfaRecordLocator.MAXIMUM_CANDIDATES)
            .mapToObj(index -> locator.beginPublication(record(
                "principal-" + index + '-' + UUID.randomUUID(),
                index,
                recordKey,
                RECORD_LIFETIME)))
            .toList();

        assertEquals(
            committedCount,
            zcard(requiredFirst.locatorKey()));
        assertEquals(
            RedisTrustedMfaRecordLocator.MAXIMUM_CANDIDATES - committedCount + 1L,
            zcard(duplicatePublication.pendingKey()));
        val located = locator.locate(recordKey);
        assertEquals(RedisTrustedMfaRecordLocator.MAXIMUM_CANDIDATES, located.size());
        assertTrue(located.stream().anyMatch(candidate -> candidate.recordId() == 0));
        assertEquals(
            RedisTrustedMfaRecordLocator.MAXIMUM_CANDIDATES - committedCount,
            pendingPublications.size());

        assertThrows(IllegalStateException.class, () -> locator.beginPublication(record(
            UUID.randomUUID().toString(),
            RedisTrustedMfaRecordLocator.MAXIMUM_CANDIDATES,
            recordKey,
            RECORD_LIFETIME)));
        assertEquals(
            committedCount,
            zcard(requiredFirst.locatorKey()));
        assertEquals(
            RedisTrustedMfaRecordLocator.MAXIMUM_CANDIDATES - committedCount + 1L,
            zcard(duplicatePublication.pendingKey()));
        assertEquals(
            RedisTrustedMfaRecordLocator.MAXIMUM_CANDIDATES,
            locator.locate(recordKey).size());
        assertTrue(locator.locate(recordKey).stream().noneMatch(candidate ->
            candidate.recordId() == RedisTrustedMfaRecordLocator.MAXIMUM_CANDIDATES));
    }

    @Test
    void verifyEnsureAndCommitAtomicallyPreserveCandidateUnionCapacity() {
        val recordKey = "shared-opaque-record-key-" + UUID.randomUUID();
        val additionalPublication = locator.beginPublication(record(
            "additional-principal-" + UUID.randomUUID(),
            10_000,
            recordKey,
            RECORD_LIFETIME));
        val additionalCandidate = additionalPublication.candidate();
        locator.completePublication(additionalPublication);

        val pendingPublications = IntStream.range(
                0, RedisTrustedMfaRecordLocator.MAXIMUM_CANDIDATES)
            .mapToObj(index -> locator.beginPublication(record(
                "principal-" + index + '-' + UUID.randomUUID(),
                index,
                recordKey,
                RECORD_LIFETIME)))
            .toList();
        val first = pendingPublications.getFirst();

        assertThrows(IllegalStateException.class, () -> locator.ensure(additionalCandidate));
        assertEquals(0, zcard(first.candidate().locatorKey()));
        assertEquals(
            RedisTrustedMfaRecordLocator.MAXIMUM_CANDIDATES,
            zcard(first.pendingKey()));

        setCandidateScore(
            additionalCandidate.locatorKey(),
            additionalCandidate.member(),
            additionalCandidate.expiresAt().toEpochMilli());
        assertEquals(
            RedisTrustedMfaRecordLocator.PublicationCommitResult.CAPACITY_REJECTED,
            locator.commitPublication(first));
        assertFalse(locator.hasLivePublication(first.candidate()));
        assertEquals(1, zcard(first.candidate().locatorKey()));
        assertEquals(
            RedisTrustedMfaRecordLocator.MAXIMUM_CANDIDATES,
            zcard(first.pendingKey()));

        locator.completePublication(first);
        assertEquals(
            RedisTrustedMfaRecordLocator.MAXIMUM_CANDIDATES - 1L,
            zcard(first.pendingKey()));
        assertEquals(
            RedisTrustedMfaRecordLocator.MAXIMUM_CANDIDATES,
            locator.locate(recordKey).size());
    }

    @Test
    void verifyLocatorTtlTracksLongestRemainingCandidate() {
        val recordKey = "shared-opaque-record-key-" + UUID.randomUUID();
        val shortCandidate = locator.publish(record(
            UUID.randomUUID().toString(), 21, recordKey, Duration.ofMinutes(3)));
        val longRecord = record(
            UUID.randomUUID().toString(), 22, recordKey, Duration.ofMinutes(6));
        val longCandidate = locator.publish(longRecord);
        val longestTtl = ttl(shortCandidate.locatorKey());
        assertTrue(longestTtl > Duration.ofMinutes(5).toMillis());
        longRecord.setExpirationDate(Date.from(Instant.now().plus(Duration.ofMinutes(1))));
        locator.publish(longRecord);
        assertTrue(ttl(shortCandidate.locatorKey()) > Duration.ofMinutes(5).toMillis());

        val removalToken = UUID.randomUUID();
        assertEquals(
            RedisTrustedMfaRecordLocator.RemovalLeaseResult.ACQUIRED,
            locator.acquireRemoval(recordKey, removalToken, Duration.ofSeconds(30)));
        assertTrue(locator.removeIfNoPublication(longCandidate, removalToken));
        assertTrue(locator.releaseRemoval(recordKey, removalToken));
        val remainingTtl = ttl(shortCandidate.locatorKey());
        assertTrue(remainingTtl > Duration.ofMinutes(2).toMillis());
        assertTrue(remainingTtl < Duration.ofMinutes(4).toMillis());
        assertEquals(Set.of(shortCandidate), locator.locate(recordKey));
    }

    private static MultifactorAuthenticationTrustRecord record(
        final String principal,
        final long id,
        final String recordKey,
        final Duration lifetime) {
        val record = MultifactorAuthenticationTrustRecord.newInstance(
            principal, "geography", "fingerprint");
        record.setId(id);
        record.setRecordKey(recordKey);
        record.setExpirationDate(Date.from(Instant.now().plus(lifetime)));
        return record;
    }

    private long ttl(final String redisKey) {
        return Objects.requireNonNull(redisTemplate.getExpire(redisKey, TimeUnit.MILLISECONDS));
    }

    private void setCandidateScore(
        final String locatorKey,
        final String member,
        final long score) {
        val result = executeInteger(
            "return redis.call('ZADD', KEYS[1], ARGV[1], ARGV[2])",
            locatorKey,
            Long.toString(score),
            member);
        assertTrue(result == 0 || result == 1);
    }

    private long zcard(final String locatorKey) {
        return executeInteger(
            "return redis.call('ZCARD', KEYS[1])",
            locatorKey);
    }

    private long executeInteger(
        final String script,
        final String redisKey,
        final String... arguments) {
        val keysAndArguments = new byte[arguments.length + 1][];
        keysAndArguments[0] = serializedKey(redisKey);
        for (var index = 0; index < arguments.length; index++) {
            keysAndArguments[index + 1] = arguments[index].getBytes(StandardCharsets.US_ASCII);
        }
        return Objects.requireNonNull(redisTemplate.execute(
            (RedisCallback<Long>) connection -> connection.scriptingCommands().eval(
                script.getBytes(StandardCharsets.UTF_8),
                ReturnType.INTEGER,
                1,
                keysAndArguments)));
    }

    @SuppressWarnings("unchecked")
    private byte[] serializedKey(final String redisKey) {
        val serializer = (RedisSerializer<String>) redisTemplate.getKeySerializer();
        return Objects.requireNonNull(serializer.serialize(redisKey));
    }

}
