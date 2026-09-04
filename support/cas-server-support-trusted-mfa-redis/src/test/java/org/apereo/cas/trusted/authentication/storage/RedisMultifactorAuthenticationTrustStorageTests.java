package org.apereo.cas.trusted.authentication.storage;

import module java.base;
import org.apereo.cas.config.CasRedisAccountSecurityAutoConfiguration;
import org.apereo.cas.config.CasRedisMultifactorAuthenticationTrustAutoConfiguration;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.redis.core.CasRedisTemplate;
import org.apereo.cas.redis.core.RedisAccountSecurityDeletionFence;
import org.apereo.cas.redis.core.RedisAccountSecurityIndexedStore;
import org.apereo.cas.redis.core.RedisAccountSecurityStore;
import org.apereo.cas.trusted.AbstractMultifactorAuthenticationTrustStorageTests;
import org.apereo.cas.trusted.authentication.api.MultifactorAuthenticationTrustRecord;
import org.apereo.cas.util.DateTimeUtils;
import org.apereo.cas.util.crypto.CipherExecutor;
import org.apereo.cas.util.junit.EnabledIfListeningOnPort;
import lombok.Getter;
import lombok.val;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.test.context.TestPropertySource;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * This is {@link RedisMultifactorAuthenticationTrustStorageTests}.
 *
 * @author Misagh Moayyed
 * @since 6.4.0
 */
@Tag("Redis")
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
@Getter
class RedisMultifactorAuthenticationTrustStorageTests extends AbstractMultifactorAuthenticationTrustStorageTests {
    private static final int UNKNOWN_PRINCIPAL_COUNT = 100;

    private static final Duration TTL_COMPARISON_TOLERANCE = Duration.ofSeconds(5);

    private static final Pattern CURRENT_RECORD_SUFFIX_PATTERN = Pattern.compile(
        "-?\\d+-[0-9a-f]{64}");

    @Autowired
    @Qualifier("redisMfaTrustedAuthnTemplate")
    private CasRedisTemplate<String, List<MultifactorAuthenticationTrustRecord>> redisMfaTrustedAuthnTemplate;

    @Autowired
    private CasConfigurationProperties casProperties;

    @Autowired
    @Qualifier("mfaTrustCipherExecutor")
    private CipherExecutor<Serializable, String> cipherExecutor;

    @Autowired
    @Qualifier(RedisAccountSecurityDeletionFence.TRUSTED_MFA_BEAN_NAME)
    private RedisAccountSecurityDeletionFence deletionFence;

    @Autowired
    @Qualifier("trustedMfaRedisAccountSecurityStore")
    private RedisAccountSecurityStore accountSecurityStore;

    @BeforeEach
    void setup() {
        try (val keys = redisMfaTrustedAuthnTemplate.scan(
            RedisMultifactorAuthenticationTrustStorage.CAS_PREFIX + '*', 0L)) {
            redisMfaTrustedAuthnTemplate.delete(keys.collect(Collectors.toSet()));
        }
    }

    @Test
    void verifySetAnExpireByKey() {
        val user = UUID.randomUUID().toString();
        var record = MultifactorAuthenticationTrustRecord.newInstance(user, "geography", "fingerprint");
        record = getMfaTrustEngine().save(record);
        assertNotNull(getMfaTrustEngine().get(record.getId()));
        val dataKey = findCurrentRecordKey(user);
        
        val records = getMfaTrustEngine().get(user);
        assertEquals(1, records.size());
        getMfaTrustEngine().remove(records.stream().findFirst().get().getRecordKey());
        assertTrue(getMfaTrustEngine().get(user).isEmpty());
        val indexedStore = new RedisAccountSecurityIndexedStore<>(
            redisMfaTrustedAuthnTemplate, deletionFence);
        val savedRecord = record;
        assertThrows(
            RedisAccountSecurityIndexedStore.AccountSecurityRecordRevokedException.class,
            () -> indexedStore.setIfUnfenced(
                user,
                dataKey,
                indexKey(user),
                indexStateKey(user),
                indexLeaseKey(user),
                dataKey + ":revoked",
                UUID.randomUUID(),
                List.of(savedRecord),
                savedRecord.getExpirationDate().toInstant(),
                true));
    }

    @Test
    void verifyMultipleDevicesPerUser() {
        val user = UUID.randomUUID().toString();
        val first = getMfaTrustEngine().save(
            MultifactorAuthenticationTrustRecord.newInstance(user, "geography", "fingerprint"));
        val second = getMfaTrustEngine().save(
            MultifactorAuthenticationTrustRecord.newInstance(user, "geography bis", "fingerprint bis"));
        getMfaTrustEngine().save(MultifactorAuthenticationTrustRecord.newInstance(UUID.randomUUID().toString(), "geography2", "fingerprint2"));
        val records = getMfaTrustEngine().get(user);
        assertEquals(2, records.size());
        getMfaTrustEngine().remove(first.getRecordKey());
        val remaining = getMfaTrustEngine().get(user);
        assertEquals(1, remaining.size());
        assertEquals(second.getRecordKey(), remaining.iterator().next().getRecordKey());
    }

    @Test
    void verifyExactRemovalSupportsEmailPrincipal() {
        val user = "trusted+" + UUID.randomUUID() + "@example.org";
        val first = getMfaTrustEngine().save(
            MultifactorAuthenticationTrustRecord.newInstance(user, "geography", "fingerprint"));
        val second = getMfaTrustEngine().save(
            MultifactorAuthenticationTrustRecord.newInstance(user, "other-geography", "other-fingerprint"));

        getMfaTrustEngine().remove(first.getRecordKey());

        val remaining = getMfaTrustEngine().get(user);
        assertEquals(1, remaining.size());
        assertEquals(second.getRecordKey(), remaining.iterator().next().getRecordKey());
    }

    @Test
    void verifyExactRemovalDoesNotParsePrincipalDelimiters() {
        val user = IntStream.range(0, 40)
            .mapToObj(index -> "segment" + index)
            .collect(Collectors.joining("@"));
        val record = getMfaTrustEngine().save(
            MultifactorAuthenticationTrustRecord.newInstance(
                user, "geography", "fingerprint"));

        assertDoesNotThrow(() -> getMfaTrustEngine().remove(record.getRecordKey()));
        assertTrue(getMfaTrustEngine().get(user).isEmpty());
    }

    @Test
    void verifyLegacyBucketRemovalMigratesLiveSibling() {
        val user = UUID.randomUUID().toString();
        val first = getMfaTrustEngine().save(
            MultifactorAuthenticationTrustRecord.newInstance(
                user, "legacy-geography", "legacy-fingerprint"));
        val second = getMfaTrustEngine().save(
            MultifactorAuthenticationTrustRecord.newInstance(
                user, "second-geography", "second-fingerprint"));
        val legacyKey = moveToLegacyBucket(user, List.of(first, second));
        val storage = newStorage();

        storage.remove(first.getRecordKey());

        assertNull(redisMfaTrustedAuthnTemplate.boundValueOps(legacyKey).get());
        val remaining = storage.get(user);
        assertEquals(1, remaining.size());
        assertEquals(second.getRecordKey(), remaining.iterator().next().getRecordKey());
    }

    @Test
    void verifyMixedLegacyBucketExpirationMigratesLiveSibling() {
        val user = UUID.randomUUID().toString();
        val expired = getMfaTrustEngine().save(
            MultifactorAuthenticationTrustRecord.newInstance(
                user, "expired-geography", "expired-fingerprint"));
        val live = getMfaTrustEngine().save(
            MultifactorAuthenticationTrustRecord.newInstance(
                user, "live-geography", "live-fingerprint"));
        val now = ZonedDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.SECONDS);
        expired.setExpirationDate(DateTimeUtils.dateOf(now.minusDays(1)));
        val legacyKey = moveToLegacyBucket(user, List.of(expired, live));
        val storage = newStorage();

        storage.remove(now);

        assertNull(redisMfaTrustedAuthnTemplate.boundValueOps(legacyKey).get());
        val remaining = storage.get(user);
        assertEquals(1, remaining.size());
        assertEquals(live.getRecordKey(), remaining.iterator().next().getRecordKey());
    }

    @Test
    void verifyLegacyMigrationFailsClosedAcrossTerminalFence() throws Exception {
        val user = UUID.randomUUID().toString();
        val closureId = UUID.randomUUID();
        val target = getMfaTrustEngine().save(
            MultifactorAuthenticationTrustRecord.newInstance(
                user, "target-geography", "target-fingerprint"));
        val sibling = getMfaTrustEngine().save(
            MultifactorAuthenticationTrustRecord.newInstance(
                user, "sibling-geography", "sibling-fingerprint"));
        val legacyKey = moveToLegacyBucket(user, List.of(target, sibling));
        val entered = new CountDownLatch(1);
        val release = new CountDownLatch(1);
        val pausedIndexedStore = spy(new RedisAccountSecurityIndexedStore<>(
            redisMfaTrustedAuthnTemplate, deletionFence));
        doAnswer(invocation -> {
            entered.countDown();
            if (!release.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timed out waiting to release legacy migration");
            }
            return invocation.callRealMethod();
        }).when(pausedIndexedStore).setIfUnfenced(
            eq(user), anyString(), anyString(), anyString(), anyString(), anyString(),
            any(UUID.class), any(), any(Instant.class), anyBoolean());
        try (val executor = Executors.newSingleThreadExecutor()) {
            val result = executor.submit(() -> new RedisMultifactorAuthenticationTrustStorage(
                casProperties.getAuthn().getMfa().getTrusted(),
                cipherExecutor,
                redisMfaTrustedAuthnTemplate,
                keyGenerationStrategy,
                deletionFence,
                pausedIndexedStore));
            assertTrue(entered.await(10, TimeUnit.SECONDS));
            assertEquals(
                RedisAccountSecurityDeletionFence.TerminalFenceResult.ACQUIRED,
                accountSecurityStore.acquireTerminal(user, closureId));
            release.countDown();
            val storage = assertDoesNotThrow(() -> result.get(10, TimeUnit.SECONDS));
            assertNull(redisMfaTrustedAuthnTemplate.boundValueOps(legacyKey).get());
            assertTrue(storage.get(user).isEmpty());
            assertTrue(accountSecurityStore.eraseAndVerify(user, closureId));
            assertTrue(accountSecurityStore.isAccountSecurityDataAbsent(user));
        } finally {
            release.countDown();
            redisMfaTrustedAuthnTemplate.delete(
                deletionFence.getKeyCodec().deletionFenceKey(user));
        }
    }

    @Test
    void verifyLegacySiblingSurvivesCurrentFormatSaveUntilTerminalErasure() {
        val user = UUID.randomUUID().toString();
        val closureId = UUID.randomUUID();
        val first = getMfaTrustEngine().save(
            MultifactorAuthenticationTrustRecord.newInstance(
                user, "legacy-geography", "legacy-fingerprint"));
        val legacyKey = moveToLegacyBucket(user, List.of(first));
        val storage = new RedisMultifactorAuthenticationTrustStorage(
            casProperties.getAuthn().getMfa().getTrusted(),
            cipherExecutor,
            redisMfaTrustedAuthnTemplate,
            keyGenerationStrategy,
            deletionFence);
        try {
            assertNull(redisMfaTrustedAuthnTemplate.boundValueOps(legacyKey).get());
            assertEquals(1, storage.get(user).size());
            storage.save(MultifactorAuthenticationTrustRecord.newInstance(
                user, "current-geography", "current-fingerprint"));

            assertEquals(2, storage.get(user).size());
            assertEquals(
                RedisAccountSecurityDeletionFence.TerminalFenceResult.ACQUIRED,
                accountSecurityStore.acquireTerminal(user, closureId));
            assertTrue(accountSecurityStore.eraseAndVerify(user, closureId));
            assertTrue(accountSecurityStore.isAccountSecurityDataAbsent(user));
        } finally {
            deletionFence.deleteAndVerify(legacyKey);
            redisMfaTrustedAuthnTemplate.delete(
                deletionFence.getKeyCodec().deletionFenceKey(user));
        }
    }

    @Test
    void verifySchemaAdoptionUsesTheExactLegacyKey() {
        val user = "  Legacy." + UUID.randomUUID() + "@Example.ORG  ";
        val record = getMfaTrustEngine().save(
            MultifactorAuthenticationTrustRecord.newInstance(
                user, "legacy-geography", "legacy-fingerprint"));
        val legacyKey = moveToLegacyBucket(
            user,
            List.of(record),
            user.toLowerCase(Locale.ROOT));

        val storage = newStorage();

        assertNull(redisMfaTrustedAuthnTemplate.boundValueOps(legacyKey).get());
        val migrated = storage.get(user);
        assertEquals(1, migrated.size());
        assertEquals(record.getRecordKey(), migrated.iterator().next().getRecordKey());
    }

    @Test
    void verifyTerminalFenceIsTokenBoundAndDeletionRemainsAvailable() {
        val user = UUID.randomUUID().toString();
        val closureId = UUID.randomUUID();
        val record = MultifactorAuthenticationTrustRecord.newInstance(
            user, "geography", "fingerprint");
        try {
            getMfaTrustEngine().save(record);
            assertEquals(
                RedisAccountSecurityDeletionFence.TerminalFenceResult.ACQUIRED,
                accountSecurityStore.acquireTerminal(user, closureId));
            assertEquals(
                RedisAccountSecurityDeletionFence.TerminalFenceResult.REPLAY,
                accountSecurityStore.acquireTerminal(user, closureId));
            val fenceKey = deletionFence.getKeyCodec().deletionFenceKey(user);
            assertTrue(redisMfaTrustedAuthnTemplate.expire(
                fenceKey, Duration.ofSeconds(30)));
            assertFalse(accountSecurityStore.isTerminal(user, closureId));
            assertEquals(
                RedisAccountSecurityDeletionFence.TerminalFenceResult.REPLAY,
                accountSecurityStore.acquireTerminal(user, closureId));
            assertEquals(-1L, redisMfaTrustedAuthnTemplate.getExpire(fenceKey));
            assertTrue(accountSecurityStore.isTerminal(user, closureId));
            assertEquals(
                RedisAccountSecurityDeletionFence.TerminalFenceResult.CONFLICT,
                accountSecurityStore.acquireTerminal(user, UUID.randomUUID()));
            assertTrue(accountSecurityStore.eraseAndVerify(user, closureId));
            assertTrue(accountSecurityStore.isTerminal(user, closureId));
            assertTrue(accountSecurityStore.isAccountSecurityDataAbsent(user));
            val rejected = MultifactorAuthenticationTrustRecord.newInstance(
                user, "new-geography", "new-fingerprint");
            assertThrows(
                RedisAccountSecurityDeletionFence.AccountSecurityWriteFencedException.class,
                () -> getMfaTrustEngine().save(rejected));
            getMfaTrustEngine().remove(record.getRecordKey());
            assertTrue(accountSecurityStore.isAccountSecurityDataAbsent(user));
        } finally {
            redisMfaTrustedAuthnTemplate.delete(
                deletionFence.getKeyCodec().deletionFenceKey(user));
        }
    }

    @Test
    void verifyTrustedSaveUsesOneAtomicValueWithAbsoluteExpiry() {
        val user = UUID.randomUUID().toString();
        getMfaTrustEngine().save(
            MultifactorAuthenticationTrustRecord.newInstance(
                user, "geography", "fingerprint"));
        val redisKey = findCurrentRecordKey(user);
        val stored = redisMfaTrustedAuthnTemplate.boundValueOps(redisKey).get();
        assertNotNull(stored);
        assertEquals(1, stored.size());
        val ttl = redisMfaTrustedAuthnTemplate.getExpire(redisKey, TimeUnit.MILLISECONDS);
        assertNotNull(ttl);
        assertTrue(ttl > 0);
        assertTrue(deletionFence.deleteAndVerify(redisKey));
    }

    @Test
    void verifyReadySchemaDoesNotMaterializeUnknownPrincipalsOrScanOnLogin() {
        val template = spy(redisMfaTrustedAuthnTemplate);
        val localFence = new RedisAccountSecurityDeletionFence(
            template, deletionFence.getKeyCodec());
        val storage = new RedisMultifactorAuthenticationTrustStorage(
            casProperties.getAuthn().getMfa().getTrusted(),
            cipherExecutor,
            template,
            keyGenerationStrategy,
            localFence);
        clearInvocations(template);

        val principals = IntStream.range(0, UNKNOWN_PRINCIPAL_COUNT)
            .mapToObj(index -> "unknown-" + index + '-' + UUID.randomUUID())
            .toList();
        principals.forEach(principal -> assertTrue(storage.get(principal).isEmpty()));

        verify(template, never()).scan(anyString());
        verify(template, never()).scan(anyString(), anyLong());
        val principalHashTags = principals.stream()
            .map(principal -> '{' + deletionFence.getKeyCodec().principalDigest(principal) + '}')
            .collect(Collectors.toSet());
        try (val keys = redisMfaTrustedAuthnTemplate.scan(
            RedisMultifactorAuthenticationTrustStorage.CAS_PREFIX + '*')) {
            assertTrue(keys.noneMatch(key -> principalHashTags.stream().anyMatch(key::contains)));
        }
    }

    @Test
    void verifyTerminalFenceRejectsRebuildMarkerAfterVerifiedErasure() {
        val user = UUID.randomUUID().toString();
        val closureId = UUID.randomUUID();
        val record = getMfaTrustEngine().save(
            MultifactorAuthenticationTrustRecord.newInstance(
                user, "geography", "fingerprint"));
        val indexedStore = new RedisAccountSecurityIndexedStore<>(
            redisMfaTrustedAuthnTemplate, deletionFence);
        val stateKey = indexStateKey(user);
        try {
            assertEquals(
                RedisAccountSecurityDeletionFence.TerminalFenceResult.ACQUIRED,
                accountSecurityStore.acquireTerminal(user, closureId));
            assertEquals(
                RedisAccountSecurityIndexedStore.MarkRebuildResult.FENCED,
                indexedStore.markRebuildRequired(
                    user, stateKey, record.getExpirationDate().toInstant()));
            assertTrue(accountSecurityStore.eraseAndVerify(user, closureId));
            assertFalse(Boolean.TRUE.equals(redisMfaTrustedAuthnTemplate.hasKey(stateKey)));

            assertEquals(
                RedisAccountSecurityIndexedStore.MarkRebuildResult.FENCED,
                indexedStore.markRebuildRequired(
                    user, stateKey, record.getExpirationDate().toInstant()));
            assertFalse(Boolean.TRUE.equals(redisMfaTrustedAuthnTemplate.hasKey(stateKey)));
            assertTrue(accountSecurityStore.isAccountSecurityDataAbsent(user));
        } finally {
            redisMfaTrustedAuthnTemplate.delete(
                deletionFence.getKeyCodec().deletionFenceKey(user));
        }
    }

    @Test
    void verifyDeletionPreservesNonReadyIndexState() {
        val user = UUID.randomUUID().toString();
        val record = getMfaTrustEngine().save(
            MultifactorAuthenticationTrustRecord.newInstance(
                user, "geography", "fingerprint"));
        val indexedStore = new RedisAccountSecurityIndexedStore<>(
            redisMfaTrustedAuthnTemplate, deletionFence);
        val dataKey = findCurrentRecordKey(user);
        val stateKey = indexStateKey(user);
        assertEquals(
            RedisAccountSecurityIndexedStore.MarkRebuildResult.MARKED,
            indexedStore.markRebuildRequired(
                user, stateKey, record.getExpirationDate().toInstant()));

        assertTrue(indexedStore.deleteAndVerify(dataKey, indexKey(user), stateKey));

        assertFalse(Boolean.TRUE.equals(redisMfaTrustedAuthnTemplate.hasKey(dataKey)));
        assertFalse(Boolean.TRUE.equals(redisMfaTrustedAuthnTemplate.hasKey(indexKey(user))));
        assertTrue(Boolean.TRUE.equals(redisMfaTrustedAuthnTemplate.hasKey(stateKey)));
    }

    @Test
    void verifyStaleCleanupCannotDeleteARefreshedRecord() {
        val user = UUID.randomUUID().toString();
        val record = getMfaTrustEngine().save(
            MultifactorAuthenticationTrustRecord.newInstance(
                user, "geography", "fingerprint"));
        val indexedStore = new RedisAccountSecurityIndexedStore<>(
            redisMfaTrustedAuthnTemplate, deletionFence);
        val dataKey = findCurrentRecordKey(user);
        val staleRead = indexedStore.read(
            user, indexKey(user), indexStateKey(user), currentRecordPrefix(user), true)
            .values().getFirst();
        val refreshedExpiry = Instant.now().plus(Duration.ofDays(30));
        record.setExpirationDate(DateTimeUtils.dateOf(refreshedExpiry));
        indexedStore.setIfUnfenced(
            user,
            dataKey,
            indexKey(user),
            indexStateKey(user),
            indexLeaseKey(user),
            dataKey + ":revoked",
            UUID.randomUUID(),
            List.of(record),
            refreshedExpiry,
            true);

        assertEquals(
            RedisAccountSecurityIndexedStore.CompareAndDeleteIndexedResult.COMPARE_MISMATCH,
            indexedStore.deleteIfUnchanged(
                dataKey,
                indexKey(user),
                indexStateKey(user),
                staleRead.serializedValue(),
                staleRead.writeToken()));
        assertEquals(1, getMfaTrustEngine().get(user).size());
    }

    @Test
    void verifyRepeatedAdoptionPreservesWriteTokenAndSameBytesRefreshRejectsStaleDelete() {
        val user = UUID.randomUUID().toString();
        getMfaTrustEngine().save(
            MultifactorAuthenticationTrustRecord.newInstance(
                user, "geography", "fingerprint"));
        val indexedStore = new RedisAccountSecurityIndexedStore<>(
            redisMfaTrustedAuthnTemplate, deletionFence);
        val dataKey = findCurrentRecordKey(user);
        val indexKey = indexKey(user);
        val stateKey = indexStateKey(user);
        val initial = indexedStore.read(
            user, indexKey, stateKey, currentRecordPrefix(user), true)
            .values().getFirst();

        assertEquals(
            RedisAccountSecurityIndexedStore.IndexExistingResult.INDEXED,
            indexedStore.indexExistingIfUnfenced(
                user, dataKey, indexKey, stateKey, UUID.randomUUID()));
        assertEquals(
            RedisAccountSecurityIndexedStore.IndexExistingResult.INDEXED,
            indexedStore.indexExistingIfUnfenced(
                user, dataKey, indexKey, stateKey, UUID.randomUUID()));
        val afterRepeatedAdoption = indexedStore.read(
            user, indexKey, stateKey, currentRecordPrefix(user), true)
            .values().getFirst();
        assertEquals(initial.writeToken(), afterRepeatedAdoption.writeToken());
        assertArrayEquals(initial.serializedValue(), afterRepeatedAdoption.serializedValue());

        val refreshedWriteToken = UUID.randomUUID();
        val expiresAt = initial.value().stream()
            .map(MultifactorAuthenticationTrustRecord::getExpirationDate)
            .max(Date::compareTo)
            .orElseThrow()
            .toInstant();
        val refreshedBytes = indexedStore.setIfUnfenced(
            user,
            dataKey,
            indexKey,
            stateKey,
            indexLeaseKey(user),
            dataKey + ":revoked",
            refreshedWriteToken,
            initial.value(),
            expiresAt,
            true);
        assertArrayEquals(initial.serializedValue(), refreshedBytes);

        assertEquals(
            RedisAccountSecurityIndexedStore.IndexExistingResult.INDEXED,
            indexedStore.indexExistingIfUnfenced(
                user, dataKey, indexKey, stateKey, UUID.randomUUID()));
        assertEquals(
            RedisAccountSecurityIndexedStore.IndexExistingResult.INDEXED,
            indexedStore.indexExistingIfUnfenced(
                user, dataKey, indexKey, stateKey, UUID.randomUUID()));
        val afterRefreshAdoption = indexedStore.read(
            user, indexKey, stateKey, currentRecordPrefix(user), true)
            .values().getFirst();
        assertEquals(refreshedWriteToken, afterRefreshAdoption.writeToken());
        assertArrayEquals(initial.serializedValue(), afterRefreshAdoption.serializedValue());

        assertEquals(
            RedisAccountSecurityIndexedStore.CompareAndDeleteIndexedResult.COMPARE_MISMATCH,
            indexedStore.deleteIfUnchanged(
                dataKey,
                indexKey,
                stateKey,
                initial.serializedValue(),
                initial.writeToken()));
        assertEquals(1, getMfaTrustEngine().get(user).size());
    }

    @Test
    void verifyExpiredReplacementPreservesCurrentAuthorityTtlAndMembership() {
        val user = UUID.randomUUID().toString();
        getMfaTrustEngine().save(
            MultifactorAuthenticationTrustRecord.newInstance(
                user, "geography", "fingerprint"));
        val dataKey = findCurrentRecordKey(user);
        val indexKey = indexKey(user);
        val stateKey = indexStateKey(user);
        val indexedStore = new RedisAccountSecurityIndexedStore<>(
            redisMfaTrustedAuthnTemplate, deletionFence);
        val storedBefore = Objects.requireNonNull(
            redisMfaTrustedAuthnTemplate.boundValueOps(dataKey).get());
        val ttlBefore = Objects.requireNonNull(
            redisMfaTrustedAuthnTemplate.getExpire(dataKey, TimeUnit.MILLISECONDS));
        assertTrue(ttlBefore > 0);

        val replacement = MultifactorAuthenticationTrustRecord.newInstance(
            user, "replacement-geography", "replacement-fingerprint");
        assertThrows(IllegalArgumentException.class, () -> indexedStore.setIfUnfenced(
            user,
            dataKey,
            indexKey,
            stateKey,
            indexLeaseKey(user),
            dataKey + ":revoked",
            UUID.randomUUID(),
            List.of(replacement),
            Instant.now().minusSeconds(1),
            true));

        val storedAfter = Objects.requireNonNull(
            redisMfaTrustedAuthnTemplate.boundValueOps(dataKey).get());
        val ttlAfter = Objects.requireNonNull(
            redisMfaTrustedAuthnTemplate.getExpire(dataKey, TimeUnit.MILLISECONDS));
        assertEquals(storedBefore, storedAfter);
        assertTrue(ttlAfter > 0);
        assertTrue(Math.abs(ttlBefore - ttlAfter) < TTL_COMPARISON_TOLERANCE.toMillis());
        val read = indexedStore.read(
            user, indexKey, stateKey, currentRecordPrefix(user), true);
        assertEquals(RedisAccountSecurityIndexedStore.IndexedReadStatus.READY, read.status());
        assertEquals(1, read.values().size());
        assertEquals(dataKey, read.values().getFirst().dataKey());
        assertEquals(storedBefore, read.values().getFirst().value());
    }

    @Test
    void verifyCapacityFailurePreservesUnindexedAuthorityAndCardinality() {
        val user = UUID.randomUUID().toString();
        getMfaTrustEngine().save(
            MultifactorAuthenticationTrustRecord.newInstance(
                user, "geography", "fingerprint"));
        val indexKey = indexKey(user);
        val dummyMembers = IntStream.range(
                0, RedisAccountSecurityIndexedStore.MAXIMUM_INDEX_ENTRIES - 1)
            .mapToObj(index -> serializedKey(deletionFence.getKeyCodec().dataKey(
                RedisMultifactorAuthenticationTrustStorage.class.getSimpleName(),
                user,
                "capacity-" + index)))
            .toArray(byte[][]::new);
        assertEquals(
            RedisAccountSecurityIndexedStore.MAXIMUM_INDEX_ENTRIES - 1L,
            addSetMembers(indexKey, dummyMembers));
        assertEquals(
            RedisAccountSecurityIndexedStore.MAXIMUM_INDEX_ENTRIES,
            setCardinality(indexKey));

        val protectedKey = deletionFence.getKeyCodec().dataKey(
            RedisMultifactorAuthenticationTrustStorage.class.getSimpleName(),
            user,
            "record-9223372036854775807-" + "f".repeat(64));
        val protectedRecord = MultifactorAuthenticationTrustRecord.newInstance(
            user, "protected-geography", "protected-fingerprint");
        val protectedValue = List.of(protectedRecord);
        val protectedExpiry = Instant.now().plus(Duration.ofHours(1));
        redisMfaTrustedAuthnTemplate.boundValueOps(protectedKey).set(protectedValue);
        redisMfaTrustedAuthnTemplate.boundValueOps(protectedKey).expireAt(protectedExpiry);
        val ttlBefore = Objects.requireNonNull(
            redisMfaTrustedAuthnTemplate.getExpire(protectedKey, TimeUnit.MILLISECONDS));
        val indexedStore = new RedisAccountSecurityIndexedStore<>(
            redisMfaTrustedAuthnTemplate, deletionFence);

        assertThrows(IllegalStateException.class, () -> indexedStore.setIfUnfenced(
            user,
            protectedKey,
            indexKey,
            indexStateKey(user),
            indexLeaseKey(user),
            protectedKey + ":revoked",
            UUID.randomUUID(),
            List.of(MultifactorAuthenticationTrustRecord.newInstance(
                user, "replacement-geography", "replacement-fingerprint")),
            protectedExpiry,
            true));

        assertEquals(
            protectedValue,
            redisMfaTrustedAuthnTemplate.boundValueOps(protectedKey).get());
        val ttlAfter = Objects.requireNonNull(
            redisMfaTrustedAuthnTemplate.getExpire(protectedKey, TimeUnit.MILLISECONDS));
        assertTrue(ttlAfter > 0);
        assertTrue(Math.abs(ttlBefore - ttlAfter) < TTL_COMPARISON_TOLERANCE.toMillis());
        assertEquals(
            RedisAccountSecurityIndexedStore.MAXIMUM_INDEX_ENTRIES,
            setCardinality(indexKey));
    }

    @Test
    void verifyUnknownRecordKeyIsAnExactNoOpWithoutScanning() {
        val user = UUID.randomUUID().toString();
        val existing = getMfaTrustEngine().save(
            MultifactorAuthenticationTrustRecord.newInstance(
                user, "geography", "fingerprint"));
        val template = spy(redisMfaTrustedAuthnTemplate);
        val localFence = new RedisAccountSecurityDeletionFence(
            template, deletionFence.getKeyCodec());
        val storage = new RedisMultifactorAuthenticationTrustStorage(
            casProperties.getAuthn().getMfa().getTrusted(),
            cipherExecutor,
            template,
            keyGenerationStrategy,
            localFence);
        clearInvocations(template);

        val unknownRecordKey = cipherExecutor.encode("   ");
        assertDoesNotThrow(() -> storage.remove(unknownRecordKey));
        verify(template, never()).scan(anyString());
        verify(template, never()).scan(anyString(), anyLong());
        val remaining = getMfaTrustEngine().get(user);
        assertEquals(1, remaining.size());
        assertEquals(existing.getRecordKey(), remaining.iterator().next().getRecordKey());
    }

    @Test
    void verifyPausedWriterCannotCrossTerminalFence() throws Exception {
        val user = UUID.randomUUID().toString();
        val closureId = UUID.randomUUID();
        val entered = new CountDownLatch(1);
        val release = new CountDownLatch(1);
        val pausedIndexedStore = spy(new RedisAccountSecurityIndexedStore<>(
            redisMfaTrustedAuthnTemplate, deletionFence));
        doAnswer(invocation -> {
            entered.countDown();
            if (!release.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timed out waiting to release trusted-MFA writer");
            }
            return invocation.callRealMethod();
        }).when(pausedIndexedStore).setIfUnfenced(
            eq(user), anyString(), anyString(), anyString(), anyString(), anyString(),
            any(UUID.class), any(), any(Instant.class), anyBoolean());
        val storage = new RedisMultifactorAuthenticationTrustStorage(
            casProperties.getAuthn().getMfa().getTrusted(),
            cipherExecutor,
            redisMfaTrustedAuthnTemplate,
            keyGenerationStrategy,
            deletionFence,
            pausedIndexedStore);
        try (val executor = Executors.newSingleThreadExecutor()) {
            val result = executor.submit(() -> storage.save(
                MultifactorAuthenticationTrustRecord.newInstance(
                    user, "geography", "fingerprint")));
            assertTrue(entered.await(10, TimeUnit.SECONDS));
            assertEquals(
                RedisAccountSecurityDeletionFence.TerminalFenceResult.ACQUIRED,
                accountSecurityStore.acquireTerminal(user, closureId));
            release.countDown();
            val exception = assertThrows(ExecutionException.class,
                () -> result.get(10, TimeUnit.SECONDS));
            assertInstanceOf(
                RedisAccountSecurityDeletionFence.AccountSecurityWriteFencedException.class,
                exception.getCause());
            assertTrue(accountSecurityStore.eraseAndVerify(user, closureId));
            assertTrue(accountSecurityStore.isAccountSecurityDataAbsent(user));
        } finally {
            release.countDown();
            redisMfaTrustedAuthnTemplate.delete(
                deletionFence.getKeyCodec().deletionFenceKey(user));
        }
    }


    @Test
    void verifyExpireByDate() {
        val user = UUID.randomUUID().toString();
        val record = MultifactorAuthenticationTrustRecord.newInstance(user, "geography", "fingerprint");
        val now = ZonedDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.SECONDS);
        record.setRecordDate(now.minusDays(2));
        getMfaTrustEngine().save(record);
        assertEquals(1, getMfaTrustEngine().get(now.minusDays(30)).size());
        assertEquals(0, getMfaTrustEngine().get(now.minusDays(1)).size());
    }

    @BeforeEach
    void emptyTrustEngine() {
        getMfaTrustEngine().getAll().forEach(r -> getMfaTrustEngine().remove(r.getRecordKey()));
    }

    private String moveToLegacyBucket(
        final String user,
        final List<MultifactorAuthenticationTrustRecord> records) {
        return moveToLegacyBucket(
            user,
            records,
            deletionFence.getKeyCodec().normalizePrincipal(user));
    }

    private String moveToLegacyBucket(
        final String user,
        final List<MultifactorAuthenticationTrustRecord> records,
        final String legacyPrincipalSegment) {
        val legacyKey = RedisMultifactorAuthenticationTrustStorage.CAS_PREFIX
            + legacyPrincipalSegment + ':' + records.getFirst().getId();
        redisMfaTrustedAuthnTemplate.boundValueOps(legacyKey).set(List.copyOf(records));
        val expiresAt = records.stream()
            .map(MultifactorAuthenticationTrustRecord::getExpirationDate)
            .max(Date::compareTo)
            .orElseThrow()
            .toInstant();
        redisMfaTrustedAuthnTemplate.boundValueOps(legacyKey).expireAt(expiresAt);
        try (val keys = redisMfaTrustedAuthnTemplate.scan(
            deletionFence.getKeyCodec().dataPattern(
                RedisMultifactorAuthenticationTrustStorage.class.getSimpleName(), user))) {
            keys.forEach(redisKey -> assertTrue(deletionFence.deleteAndVerify(redisKey)));
        }
        try (val keys = redisMfaTrustedAuthnTemplate.scan(
            RedisMultifactorAuthenticationTrustStorage.CAS_PREFIX
                + "{trusted-mfa-record-index-schema-v3}:*")) {
            redisMfaTrustedAuthnTemplate.delete(keys.collect(Collectors.toSet()));
        }
        return legacyKey;
    }

    private RedisMultifactorAuthenticationTrustStorage newStorage() {
        return new RedisMultifactorAuthenticationTrustStorage(
            casProperties.getAuthn().getMfa().getTrusted(),
            cipherExecutor,
            redisMfaTrustedAuthnTemplate,
            keyGenerationStrategy,
            deletionFence);
    }

    private String findCurrentRecordKey(final String user) {
        val prefix = currentRecordPrefix(user);
        try (val keys = redisMfaTrustedAuthnTemplate.scan(currentRecordPattern(user))) {
            return keys
                .filter(key -> key.startsWith(prefix))
                .filter(key -> CURRENT_RECORD_SUFFIX_PATTERN.matcher(
                    key.substring(prefix.length())).matches())
                .findFirst()
                .orElseThrow();
        }
    }

    private String currentRecordPattern(final String user) {
        return currentRecordPrefix(user) + '*';
    }

    private String currentRecordPrefix(final String user) {
        return deletionFence.getKeyCodec().dataKey(
            RedisMultifactorAuthenticationTrustStorage.class.getSimpleName(), user, "record") + '-';
    }

    private String indexKey(final String user) {
        return deletionFence.getKeyCodec().dataKey(
            RedisMultifactorAuthenticationTrustStorage.class.getSimpleName(), user, "record-index-v3");
    }

    private String indexStateKey(final String user) {
        return deletionFence.getKeyCodec().dataKey(
            RedisMultifactorAuthenticationTrustStorage.class.getSimpleName(), user, "record-index-state-v3");
    }

    private String indexLeaseKey(final String user) {
        return deletionFence.getKeyCodec().dataKey(
            RedisMultifactorAuthenticationTrustStorage.class.getSimpleName(), user, "record-index-lease-v3");
    }

    private long addSetMembers(final String redisKey, final byte[][] members) {
        try (val connection = Objects.requireNonNull(
            redisMfaTrustedAuthnTemplate.getConnectionFactory()).getConnection()) {
            return Objects.requireNonNull(
                connection.setCommands().sAdd(serializedKey(redisKey), members));
        }
    }

    private long setCardinality(final String redisKey) {
        try (val connection = Objects.requireNonNull(
            redisMfaTrustedAuthnTemplate.getConnectionFactory()).getConnection()) {
            return Objects.requireNonNull(
                connection.setCommands().sCard(serializedKey(redisKey)));
        }
    }

    @SuppressWarnings("unchecked")
    private byte[] serializedKey(final String redisKey) {
        val serializer = (RedisSerializer<String>) redisMfaTrustedAuthnTemplate.getKeySerializer();
        return Objects.requireNonNull(serializer.serialize(redisKey));
    }
}
