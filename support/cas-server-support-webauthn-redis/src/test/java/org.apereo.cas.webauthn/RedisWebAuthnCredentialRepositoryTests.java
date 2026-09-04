package org.apereo.cas.webauthn;

import module java.base;
import org.apereo.cas.config.CasRedisAccountSecurityAutoConfiguration;
import org.apereo.cas.config.CasRedisWebAuthnAutoConfiguration;
import org.apereo.cas.redis.core.CasRedisTemplate;
import org.apereo.cas.redis.core.RedisAccountSecurityDeletionFence;
import org.apereo.cas.redis.core.RedisAccountSecurityStore;
import org.apereo.cas.util.junit.EnabledIfListeningOnPort;
import org.apereo.cas.webauthn.storage.BaseWebAuthnCredentialRepositoryTests;
import com.yubico.data.CredentialRegistration;
import com.yubico.webauthn.AssertionResult;
import lombok.Getter;
import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.test.context.TestPropertySource;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * This is {@link RedisWebAuthnCredentialRepositoryTests}.
 *
 * @author Misagh Moayyed
 * @since 6.3.0
 */
@TestPropertySource(
    properties = {
        "cas.authn.mfa.web-authn.redis.host=localhost",
        "cas.authn.mfa.web-authn.redis.port=6379",
        "cas.authn.mfa.web-authn.core.trust-source.fido.legal-header="
    })
@Tag("Redis")
@Getter
@EnabledIfListeningOnPort(port = 6379)
@ImportAutoConfiguration({
    CasRedisAccountSecurityAutoConfiguration.class,
    CasRedisWebAuthnAutoConfiguration.class
})
class RedisWebAuthnCredentialRepositoryTests extends BaseWebAuthnCredentialRepositoryTests {

    @Autowired
    @Qualifier("webAuthnRedisTemplate")
    private CasRedisTemplate<String, RedisWebAuthnCredentialRegistration> redisTemplate;

    @Autowired
    @Qualifier(RedisAccountSecurityDeletionFence.WEB_AUTHN_BEAN_NAME)
    private RedisAccountSecurityDeletionFence deletionFence;

    @Autowired
    @Qualifier("webAuthnRedisAccountSecurityStore")
    private RedisAccountSecurityStore accountSecurityStore;

    @Autowired
    @Qualifier(RedisWebAuthnCredentialLocator.BEAN_NAME)
    private RedisWebAuthnCredentialLocator credentialLocator;

    @Autowired
    @Qualifier(RedisWebAuthnCredentialLocator.REDIS_TEMPLATE_BEAN_NAME)
    private CasRedisTemplate<String, String> locatorRedisTemplate;

    @Test
    void verifyLegacyRecordIsReadAndMigratedWithoutCredentialLoss() throws Exception {
        val username = UUID.randomUUID().toString();
        val currentKey = currentKey(username);
        val legacyKey = legacyKey(username);
        try {
            assertTrue(webAuthnCredentialRepository.addRegistrationByUsername(
                username, getCredentialRegistration(username)));
            val stored = redisTemplate.boundValueOps(currentKey).get();
            assertNotNull(stored);
            redisTemplate.boundValueOps(legacyKey).set(stored);
            assertTrue(deletionFence.deleteAndVerify(currentKey));
            assertTrue(deletionFence.deleteAndVerify(writeTokenKey(username)));

            assertEquals(1,
                webAuthnCredentialRepository.getRegistrationsByUsername(username).size());
            assertTrue(webAuthnCredentialRepository.addRegistrationByUsername(
                username, getCredentialRegistration(UUID.randomUUID().toString())));

            assertEquals(2,
                webAuthnCredentialRepository.getRegistrationsByUsername(username).size());
            assertNotNull(redisTemplate.boundValueOps(currentKey).get());
            assertNull(redisTemplate.boundValueOps(legacyKey).get());
        } finally {
            deleteState(username);
        }
    }

    @Test
    void verifyConcurrentAddsAreRebasedWithoutLostUpdates() throws Exception {
        val username = UUID.randomUUID().toString();
        val first = getCredentialRegistration(UUID.randomUUID().toString());
        val second = getCredentialRegistration(UUID.randomUUID().toString());
        val repository = newRepositoryWithFirstComparisonsSynchronized();
        try (val executor = Executors.newFixedThreadPool(2)) {
            val firstResult = executor.submit(
                () -> repository.addRegistrationByUsername(username, first));
            val secondResult = executor.submit(
                () -> repository.addRegistrationByUsername(username, second));
            assertTrue(firstResult.get(10, TimeUnit.SECONDS));
            assertTrue(secondResult.get(10, TimeUnit.SECONDS));
            assertEquals(2, repository.getRegistrationsByUsername(username).size());
        } finally {
            deleteState(username);
        }
    }

    @Test
    void verifyWriteTokenRejectsSameValueDeleteAndRecreateAba() throws Exception {
        val username = UUID.randomUUID().toString();
        val registration = getCredentialRegistration(UUID.randomUUID().toString());
        val dataKey = currentKey(username);
        val tokenKey = writeTokenKey(username);
        try {
            assertTrue(webAuthnCredentialRepository.addRegistrationByUsername(
                username, registration));
            val stale = deletionFence.readVersionedFromAuthority(
                username, dataKey, tokenKey);
            assertTrue(stale.isPresent());
            assertTrue(stale.hasWriteToken());
            val exactValue = deletionFence.deserialize(
                stale, RedisWebAuthnCredentialRegistration.class).orElseThrow();

            assertEquals(
                RedisAccountSecurityDeletionFence.CompareAndSetResult.APPLIED,
                deletionFence.compareAndSetVersionedIfUnfenced(
                    username, dataKey, tokenKey, stale, null, null));
            val absent = deletionFence.readVersionedFromAuthority(
                username, dataKey, tokenKey);
            assertFalse(absent.isPresent());
            assertEquals(
                RedisAccountSecurityDeletionFence.CompareAndSetResult.APPLIED,
                deletionFence.compareAndSetVersionedIfUnfenced(
                    username, dataKey, tokenKey, absent, exactValue, null));
            val recreated = deletionFence.readVersionedFromAuthority(
                username, dataKey, tokenKey);
            assertArrayEquals(stale.serializedValue(), recreated.serializedValue(),
                "the regression must exercise equal authority bytes");

            assertEquals(
                RedisAccountSecurityDeletionFence.CompareAndSetResult.COMPARE_MISMATCH,
                deletionFence.compareAndSetVersionedIfUnfenced(
                    username, dataKey, tokenKey, stale, null, null));
            assertTrue(deletionFence.readVersionedFromAuthority(
                username, dataKey, tokenKey).isPresent());
        } finally {
            deleteState(username);
            credentialLocator.locatorKeys(List.of(registration))
                .forEach(locatorRedisTemplate::delete);
        }
    }

    @Test
    void verifyConcurrentAddAndRemoveAreRebasedWithoutLostUpdates() throws Exception {
        val username = UUID.randomUUID().toString();
        val removed = getCredentialRegistration(UUID.randomUUID().toString());
        val added = getCredentialRegistration(UUID.randomUUID().toString());
        assertTrue(webAuthnCredentialRepository.addRegistrationByUsername(username, removed));
        val repository = newRepositoryWithFirstComparisonsSynchronized();
        try (val executor = Executors.newFixedThreadPool(2)) {
            val addResult = executor.submit(
                () -> repository.addRegistrationByUsername(username, added));
            val removeResult = executor.submit(
                () -> repository.removeRegistrationByUsername(username, removed));
            assertTrue(addResult.get(10, TimeUnit.SECONDS));
            assertTrue(removeResult.get(10, TimeUnit.SECONDS));
            val registrations = repository.getRegistrationsByUsername(username);
            assertEquals(Set.of(added), new HashSet<>(registrations));
        } finally {
            deleteState(username);
        }
    }

    @Test
    void verifyConcurrentSignatureCountsRemainMonotonic() throws Exception {
        val username = UUID.randomUUID().toString();
        val registration = getCredentialRegistration(UUID.randomUUID().toString());
        assertTrue(webAuthnCredentialRepository.addRegistrationByUsername(username, registration));
        val repository = newRepositoryWithFirstComparisonsSynchronized();
        try (val executor = Executors.newFixedThreadPool(2)) {
            val lower = executor.submit(() -> repository.updateSignatureCount(
                assertionResult(username, registration, 5)));
            val higher = executor.submit(() -> repository.updateSignatureCount(
                assertionResult(username, registration, 7)));
            lower.get(10, TimeUnit.SECONDS);
            higher.get(10, TimeUnit.SECONDS);
            assertEquals(7, signatureCount(repository, username, registration));

            repository.updateSignatureCount(assertionResult(username, registration, 6));
            assertEquals(7, signatureCount(repository, username, registration));
        } finally {
            deleteState(username);
        }
    }

    @Test
    void verifyChangedLegacyValueIsNotDeletedDuringMigration() throws Exception {
        val username = UUID.randomUUID().toString();
        val currentKey = currentKey(username);
        val legacyKey = legacyKey(username);
        val otherUsername = UUID.randomUUID().toString();
        val otherCurrentKey = currentKey(otherUsername);
        val entered = new CountDownLatch(1);
        val release = new CountDownLatch(1);
        try {
            assertTrue(webAuthnCredentialRepository.addRegistrationByUsername(
                username, getCredentialRegistration(UUID.randomUUID().toString())));
            val original = redisTemplate.boundValueOps(currentKey).get();
            assertNotNull(original);
            redisTemplate.boundValueOps(legacyKey).set(original);
            assertTrue(deletionFence.deleteAndVerify(currentKey));
            assertTrue(deletionFence.deleteAndVerify(writeTokenKey(username)));

            assertTrue(webAuthnCredentialRepository.addRegistrationByUsername(
                otherUsername, getCredentialRegistration(UUID.randomUUID().toString())));
            val replacement = redisTemplate.boundValueOps(otherCurrentKey).get();
            assertNotNull(replacement);

            val pausedFence = spy(deletionFence);
            doAnswer(invocation -> {
                entered.countDown();
                if (!release.await(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("Timed out waiting to release legacy cleanup");
                }
                return invocation.callRealMethod();
            }).when(pausedFence).deleteIfUnchanged(
                any(RedisAccountSecurityDeletionFence.AuthorityValue.class));
            val repository = new RedisWebAuthnCredentialRepository(
                redisTemplate, casProperties, cipherExecutor, pausedFence, credentialLocator);
            try (val executor = Executors.newSingleThreadExecutor()) {
                val result = executor.submit(() -> repository.addRegistrationByUsername(
                    username, getCredentialRegistration(UUID.randomUUID().toString())));
                assertTrue(entered.await(10, TimeUnit.SECONDS));
                redisTemplate.boundValueOps(legacyKey).set(replacement);
                release.countDown();
                val exception = assertThrows(ExecutionException.class,
                    () -> result.get(10, TimeUnit.SECONDS));
                assertInstanceOf(ConcurrentModificationException.class, exception.getCause());
                val retained = redisTemplate.boundValueOps(legacyKey).get();
                assertNotNull(retained);
                assertEquals(replacement.getRecords(), retained.getRecords());
            }
        } finally {
            release.countDown();
            deleteState(username);
            deleteState(otherUsername);
        }
    }

    @Test
    void verifyTerminalFenceIsTokenBoundAndDeletionRemainsAvailable() throws Exception {
        val username = UUID.randomUUID().toString();
        val closureId = UUID.randomUUID();
        val registration = getCredentialRegistration(username);
        try {
            assertTrue(webAuthnCredentialRepository.addRegistrationByUsername(username, registration));
            assertEquals(
                RedisAccountSecurityDeletionFence.TerminalFenceResult.ACQUIRED,
                accountSecurityStore.acquireTerminal(username, closureId));
            val fenceKey = deletionFence.getKeyCodec().deletionFenceKey(username);
            assertTrue(redisTemplate.expire(fenceKey, 5, TimeUnit.SECONDS));
            assertFalse(accountSecurityStore.isTerminal(username, closureId));
            assertEquals(
                RedisAccountSecurityDeletionFence.TerminalFenceResult.REPLAY,
                accountSecurityStore.acquireTerminal(username, closureId));
            assertEquals(-1, redisTemplate.getExpire(fenceKey));
            assertTrue(accountSecurityStore.isTerminal(username, closureId));
            assertEquals(
                RedisAccountSecurityDeletionFence.TerminalFenceResult.CONFLICT,
                accountSecurityStore.acquireTerminal(username, UUID.randomUUID()));
            assertTrue(webAuthnCredentialRepository.getRegistrationsByUsername(username).isEmpty());
            assertTrue(webAuthnCredentialRepository.lookup(
                registration.getCredential().getCredentialId(),
                registration.getCredential().getUserHandle()).isEmpty());
            assertTrue(accountSecurityStore.eraseAndVerify(username, closureId));
            assertTrue(accountSecurityStore.isTerminal(username, closureId));
            assertTrue(accountSecurityStore.isAccountSecurityDataAbsent(username));
            assertThrows(
                RedisAccountSecurityDeletionFence.AccountSecurityWriteFencedException.class,
                () -> webAuthnCredentialRepository.addRegistrationByUsername(
                    username, registration));
            assertThrows(
                RedisAccountSecurityDeletionFence.AccountSecurityWriteFencedException.class,
                () -> webAuthnCredentialRepository.removeAllRegistrations(username));
            assertTrue(accountSecurityStore.isAccountSecurityDataAbsent(username));
        } finally {
            redisTemplate.delete(deletionFence.getKeyCodec().deletionFenceKey(username));
        }
    }

    @Test
    void verifyPausedReaderObservesTerminalFenceAtAuthority() throws Exception {
        val username = UUID.randomUUID().toString();
        val closureId = UUID.randomUUID();
        val entered = new CountDownLatch(1);
        val release = new CountDownLatch(1);
        val currentKey = currentKey(username);
        assertTrue(webAuthnCredentialRepository.addRegistrationByUsername(
            username, getCredentialRegistration(username)));
        val pausedFence = spy(deletionFence);
        doAnswer(invocation -> {
            entered.countDown();
            if (!release.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timed out waiting to release WebAuthn reader");
            }
            return invocation.callRealMethod();
        }).when(pausedFence).readFromAuthority(username, currentKey);
        val repository = new RedisWebAuthnCredentialRepository(
            redisTemplate, casProperties, cipherExecutor, pausedFence, credentialLocator);
        try (val executor = Executors.newSingleThreadExecutor()) {
            val result = executor.submit(() -> repository.getRegistrationsByUsername(username));
            assertTrue(entered.await(10, TimeUnit.SECONDS));
            assertEquals(
                RedisAccountSecurityDeletionFence.TerminalFenceResult.ACQUIRED,
                accountSecurityStore.acquireTerminal(username, closureId));
            release.countDown();
            assertTrue(result.get(10, TimeUnit.SECONDS).isEmpty());
            assertTrue(accountSecurityStore.eraseAndVerify(username, closureId));
        } finally {
            release.countDown();
            deleteState(username);
        }
    }

    @Test
    void verifyPausedWriterCannotCrossTerminalFence() throws Exception {
        val username = UUID.randomUUID().toString();
        val closureId = UUID.randomUUID();
        val entered = new CountDownLatch(1);
        val release = new CountDownLatch(1);
        val pausedFence = spy(deletionFence);
        doAnswer(invocation -> {
            entered.countDown();
            if (!release.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timed out waiting to release WebAuthn writer");
            }
            return invocation.callRealMethod();
        }).when(pausedFence).compareAndSetVersionedIfUnfenced(
            eq(username), anyString(), anyString(),
            any(RedisAccountSecurityDeletionFence.VersionedAuthorityValue.class),
            nullable(Object.class), isNull());
        val repository = new RedisWebAuthnCredentialRepository(
            redisTemplate, casProperties, cipherExecutor, pausedFence, credentialLocator);
        try (val executor = Executors.newSingleThreadExecutor()) {
            val result = executor.submit(() -> repository.addRegistrationByUsername(
                username, getCredentialRegistration(username)));
            assertTrue(entered.await(10, TimeUnit.SECONDS));
            assertEquals(
                RedisAccountSecurityDeletionFence.TerminalFenceResult.ACQUIRED,
                accountSecurityStore.acquireTerminal(username, closureId));
            release.countDown();
            val exception = assertThrows(ExecutionException.class,
                () -> result.get(10, TimeUnit.SECONDS));
            assertInstanceOf(
                RedisAccountSecurityDeletionFence.AccountSecurityWriteFencedException.class,
                exception.getCause());
            assertTrue(accountSecurityStore.eraseAndVerify(username, closureId));
            assertTrue(accountSecurityStore.isAccountSecurityDataAbsent(username));
        } finally {
            release.countDown();
            redisTemplate.delete(deletionFence.getKeyCodec().deletionFenceKey(username));
        }
    }

    @Test
    void verifyOversizedLocatorFailsClosedBeforeReadingMembers() throws Exception {
        val username = UUID.randomUUID().toString();
        val registration = getCredentialRegistration(UUID.randomUUID().toString());
        val principalDigest = deletionFence.getKeyCodec().principalDigest(username);
        val locatorKeys = credentialLocator.locatorKeys(List.of(registration));
        val credentialLocatorKey = locatorKeys.stream()
            .filter(key -> key.contains(":credential:"))
            .findFirst()
            .orElseThrow();
        try {
            for (var attempt = 0;
                 attempt <= RedisWebAuthnCredentialLocator.MAXIMUM_CANDIDATES;
                 attempt++) {
                val candidateDigest = deletionFence.getKeyCodec().principalDigest(
                    principalDigest + ':' + attempt);
                locatorRedisTemplate.boundSetOps(credentialLocatorKey).add(
                    RedisWebAuthnCredentialLocator.SCHEMA_VERSION + ':' + candidateDigest);
            }
            assertTrue(Objects.requireNonNull(
                locatorRedisTemplate.boundSetOps(credentialLocatorKey).size())
                > RedisWebAuthnCredentialLocator.MAXIMUM_CANDIDATES);
            assertThrows(IllegalStateException.class, () ->
                credentialLocator.locateByCredentialId(
                    registration.getCredential().getCredentialId()));
            locatorRedisTemplate.delete(credentialLocatorKey);
            assertTrue(credentialLocator.locateByCredentialId(
                registration.getCredential().getCredentialId()).isEmpty());
        } finally {
            locatorKeys.forEach(locatorRedisTemplate::delete);
            deleteState(username);
        }
    }

    @Test
    void verifyLivePublicationPreventsStaleCleanup() throws Exception {
        val username = UUID.randomUUID().toString();
        val registration = getCredentialRegistration(UUID.randomUUID().toString());
        val principalDigest = deletionFence.getKeyCodec().principalDigest(username);
        val publication = credentialLocator.beginPublication(
            principalDigest, List.of(registration));
        try {
            assertTrue(webAuthnCredentialRepository.lookupAll(
                registration.getCredential().getCredentialId()).isEmpty());
            assertEquals(1, credentialLocator.locateByCredentialId(
                registration.getCredential().getCredentialId()).size());

            assertTrue(webAuthnCredentialRepository.addRegistrationByUsername(
                username, registration));
            assertFalse(webAuthnCredentialRepository.lookup(
                registration.getCredential().getCredentialId(),
                registration.getUserIdentity().getId()).isEmpty());
        } finally {
            credentialLocator.completePublication(publication);
            deleteState(username);
            credentialLocator.locatorKeys(List.of(registration)).forEach(locatorRedisTemplate::delete);
        }
    }

    @Test
    void verifyStaleAndSharedCoordinateCandidatesNeverCrossAccountAuthority() throws Exception {
        val firstUsername = UUID.randomUUID().toString();
        val secondUsername = UUID.randomUUID().toString();
        val firstRegistration = getCredentialRegistration(UUID.randomUUID().toString());
        val secondRegistration = getCredentialRegistration(UUID.randomUUID().toString());
        val sharedRegistration = getCredentialRegistration(UUID.randomUUID().toString());
        val firstDigest = deletionFence.getKeyCodec().principalDigest(firstUsername);
        try {
            assertTrue(webAuthnCredentialRepository.addRegistrationByUsername(
                firstUsername, firstRegistration));
            val stale = credentialLocator.beginPublication(
                firstDigest, List.of(secondRegistration));
            credentialLocator.completePublication(stale);
            assertTrue(webAuthnCredentialRepository.lookupAll(
                secondRegistration.getCredential().getCredentialId()).isEmpty());

            assertTrue(webAuthnCredentialRepository.addRegistrationByUsername(
                secondUsername, secondRegistration));
            assertFalse(webAuthnCredentialRepository.lookup(
                secondRegistration.getCredential().getCredentialId(),
                secondRegistration.getUserIdentity().getId()).isEmpty());
            assertEquals(1, credentialLocator.locateByCredentialId(
                secondRegistration.getCredential().getCredentialId()).size());

            assertTrue(webAuthnCredentialRepository.addRegistrationByUsername(
                firstUsername, sharedRegistration));
            assertTrue(webAuthnCredentialRepository.addRegistrationByUsername(
                secondUsername, sharedRegistration));
            assertEquals(2, credentialLocator.locateByCredentialId(
                sharedRegistration.getCredential().getCredentialId()).size());
            assertTrue(webAuthnCredentialRepository.removeAllRegistrations(firstUsername));
            assertFalse(webAuthnCredentialRepository.lookupAll(
                sharedRegistration.getCredential().getCredentialId()).isEmpty());
            assertEquals(1, credentialLocator.locateByCredentialId(
                sharedRegistration.getCredential().getCredentialId()).size());
        } finally {
            deleteState(firstUsername);
            deleteState(secondUsername);
            Stream.of(firstRegistration, secondRegistration, sharedRegistration)
                .flatMap(registration -> credentialLocator.locatorKeys(List.of(registration)).stream())
                .forEach(locatorRedisTemplate::delete);
        }
    }

    @Test
    void verifyLoginLocatorPathsNeverScanTheAuthorityKeyspace() throws Exception {
        val username = UUID.randomUUID().toString();
        val registration = getCredentialRegistration(UUID.randomUUID().toString());
        assertTrue(webAuthnCredentialRepository.addRegistrationByUsername(username, registration));
        val template = spy(redisTemplate);
        val repository = new RedisWebAuthnCredentialRepository(
            template, casProperties, cipherExecutor, deletionFence, credentialLocator);
        try {
            assertFalse(repository.getRegistrationsByUserHandle(
                registration.getUserIdentity().getId()).isEmpty());
            assertFalse(repository.lookup(
                registration.getCredential().getCredentialId(),
                registration.getUserIdentity().getId()).isEmpty());
            assertFalse(repository.lookupAll(
                registration.getCredential().getCredentialId()).isEmpty());
            verify(template, never()).scan(anyString());
        } finally {
            deleteState(username);
            credentialLocator.locatorKeys(List.of(registration)).forEach(locatorRedisTemplate::delete);
        }
    }

    @Test
    void verifyRebuildMigratesLegacyAuthorityAndRestoresLocatorReadiness() throws Exception {
        val username = UUID.randomUUID().toString();
        val registration = getCredentialRegistration(UUID.randomUUID().toString());
        val currentKey = currentKey(username);
        val legacyKey = legacyKey(username);
        val locatorKeys = credentialLocator.locatorKeys(List.of(registration));
        try {
            assertTrue(webAuthnCredentialRepository.addRegistrationByUsername(username, registration));
            val stored = redisTemplate.boundValueOps(currentKey).get();
            assertNotNull(stored);
            redisTemplate.boundValueOps(legacyKey).set(stored);
            assertTrue(deletionFence.deleteAndVerify(currentKey));
            assertTrue(deletionFence.deleteAndVerify(writeTokenKey(username)));
            locatorKeys.forEach(locatorRedisTemplate::delete);
            locatorRedisTemplate.delete(RedisWebAuthnCredentialLocator.READY_KEY);
            locatorRedisTemplate.delete(RedisWebAuthnCredentialLocator.REBUILD_LEASE_KEY);

            val rebuildingLocator = new RedisWebAuthnCredentialLocator(
                locatorRedisTemplate, redisTemplate, deletionFence);
            val rebuildingRepository = new RedisWebAuthnCredentialRepository(
                redisTemplate, casProperties, cipherExecutor, deletionFence, rebuildingLocator);
            rebuildingRepository.afterPropertiesSet();

            assertNotNull(redisTemplate.boundValueOps(currentKey).get());
            assertNull(redisTemplate.boundValueOps(legacyKey).get());
            assertFalse(rebuildingRepository.lookup(
                registration.getCredential().getCredentialId(),
                registration.getUserIdentity().getId()).isEmpty());
        } finally {
            locatorRedisTemplate.delete(RedisWebAuthnCredentialLocator.REBUILD_LEASE_KEY);
            deleteState(username);
            locatorKeys.forEach(locatorRedisTemplate::delete);
            credentialLocator.rebuildIfRequired((_, _) -> { });
        }
    }

    @Test
    void verifyRebuildRemovesLegacyResidueWhenCurrentAuthorityAlreadyExists() throws Exception {
        val username = UUID.randomUUID().toString();
        val registration = getCredentialRegistration(UUID.randomUUID().toString());
        val currentKey = currentKey(username);
        val legacyKey = legacyKey(username);
        val locatorKeys = credentialLocator.locatorKeys(List.of(registration));
        try {
            assertTrue(webAuthnCredentialRepository.addRegistrationByUsername(
                username, registration));
            val stored = redisTemplate.boundValueOps(currentKey).get();
            assertNotNull(stored);
            redisTemplate.boundValueOps(legacyKey).set(stored);
            locatorKeys.forEach(locatorRedisTemplate::delete);
            locatorRedisTemplate.delete(RedisWebAuthnCredentialLocator.READY_KEY);
            locatorRedisTemplate.delete(RedisWebAuthnCredentialLocator.REBUILD_LEASE_KEY);

            val rebuildingLocator = new RedisWebAuthnCredentialLocator(
                locatorRedisTemplate, redisTemplate, deletionFence);
            val rebuildingRepository = new RedisWebAuthnCredentialRepository(
                redisTemplate, casProperties, cipherExecutor, deletionFence, rebuildingLocator);
            rebuildingRepository.afterPropertiesSet();

            assertNotNull(redisTemplate.boundValueOps(currentKey).get());
            assertNull(redisTemplate.boundValueOps(legacyKey).get());
            assertFalse(rebuildingRepository.lookup(
                registration.getCredential().getCredentialId(),
                registration.getUserIdentity().getId()).isEmpty());
        } finally {
            locatorRedisTemplate.delete(RedisWebAuthnCredentialLocator.REBUILD_LEASE_KEY);
            deleteState(username);
            locatorKeys.forEach(locatorRedisTemplate::delete);
            credentialLocator.rebuildIfRequired((_, _) -> { });
        }
    }

    @Test
    void verifyLocatorReadWaitsForAnotherRebuildOwner() throws Exception {
        locatorRedisTemplate.delete(RedisWebAuthnCredentialLocator.READY_KEY);
        locatorRedisTemplate.boundValueOps(RedisWebAuthnCredentialLocator.REBUILD_LEASE_KEY)
            .set("another-node", Duration.ofSeconds(5));
        try (val executor = Executors.newSingleThreadExecutor()) {
            val waiting = executor.submit(() -> credentialLocator.rebuildIfRequired((_, _) -> { }));
            assertThrows(TimeoutException.class, () -> waiting.get(250, TimeUnit.MILLISECONDS));
            markLocatorReady();
            assertDoesNotThrow(() -> waiting.get(10, TimeUnit.SECONDS));
        } finally {
            locatorRedisTemplate.delete(RedisWebAuthnCredentialLocator.REBUILD_LEASE_KEY);
            markLocatorReady();
        }
    }

    @Test
    void verifyLocatorAuthorityReadCannotCrossTerminalFence() throws Exception {
        val username = UUID.randomUUID().toString();
        val closureId = UUID.randomUUID();
        val registration = getCredentialRegistration(UUID.randomUUID().toString());
        val principalDigest = deletionFence.getKeyCodec().principalDigest(username);
        val entered = new CountDownLatch(1);
        val release = new CountDownLatch(1);
        assertTrue(webAuthnCredentialRepository.addRegistrationByUsername(username, registration));
        val pausedFence = spy(deletionFence);
        val firstRead = new AtomicBoolean(true);
        doAnswer(invocation -> {
            if (firstRead.compareAndSet(true, false)) {
                entered.countDown();
                if (!release.await(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("Timed out waiting to release locator authority read");
                }
            }
            return invocation.callRealMethod();
        }).when(pausedFence).readFromAuthorityByPrincipalDigest(
            eq(principalDigest), anyString());
        val repository = new RedisWebAuthnCredentialRepository(
            redisTemplate, casProperties, cipherExecutor, pausedFence, credentialLocator);
        try (val executor = Executors.newSingleThreadExecutor()) {
            val lookup = executor.submit(() -> repository.lookupAll(
                registration.getCredential().getCredentialId()));
            assertTrue(entered.await(10, TimeUnit.SECONDS));
            assertEquals(
                RedisAccountSecurityDeletionFence.TerminalFenceResult.ACQUIRED,
                accountSecurityStore.acquireTerminal(username, closureId));
            release.countDown();
            assertTrue(lookup.get(10, TimeUnit.SECONDS).isEmpty());
            assertTrue(credentialLocator.locateByCredentialId(
                registration.getCredential().getCredentialId()).isEmpty());
            assertTrue(accountSecurityStore.eraseAndVerify(username, closureId));
        } finally {
            release.countDown();
            redisTemplate.delete(deletionFence.getKeyCodec().deletionFenceKey(username));
            credentialLocator.locatorKeys(List.of(registration)).forEach(locatorRedisTemplate::delete);
        }
    }

    private RedisWebAuthnCredentialRepository newRepositoryWithFirstComparisonsSynchronized() {
        val barrier = new CyclicBarrier(2);
        val comparisons = new AtomicInteger();
        val synchronizedFence = spy(deletionFence);
        doAnswer(invocation -> {
            if (comparisons.incrementAndGet() <= 2) {
                barrier.await(10, TimeUnit.SECONDS);
            }
            return invocation.callRealMethod();
        }).when(synchronizedFence).compareAndSetVersionedIfUnfenced(
            anyString(), anyString(), anyString(),
            any(RedisAccountSecurityDeletionFence.VersionedAuthorityValue.class),
            nullable(Object.class), isNull());
        return new RedisWebAuthnCredentialRepository(
            redisTemplate, casProperties, cipherExecutor, synchronizedFence, credentialLocator);
    }

    private static AssertionResult assertionResult(
        final String username,
        final CredentialRegistration registration,
        final long signatureCount) {
        val result = mock(AssertionResult.class);
        when(result.getUsername()).thenReturn(username);
        when(result.getCredential()).thenReturn(registration.getCredential());
        when(result.getSignatureCount()).thenReturn(signatureCount);
        return result;
    }

    private static long signatureCount(
        final RedisWebAuthnCredentialRepository repository,
        final String username,
        final CredentialRegistration registration) {
        return repository.getRegistrationsByUsername(username).stream()
            .filter(candidate -> candidate.getCredential().getCredentialId()
                .equals(registration.getCredential().getCredentialId()))
            .findFirst()
            .orElseThrow()
            .getCredential()
            .getSignatureCount();
    }

    private String currentKey(final String username) {
        return deletionFence.getKeyCodec().dataKey(
            RedisWebAuthnCredentialRepository.class.getSimpleName(), username, "records");
    }

    private String writeTokenKey(final String username) {
        return deletionFence.getKeyCodec().dataKey(
            RedisWebAuthnCredentialRepository.WRITE_TOKEN_NAMESPACE, username, "revision");
    }

    private String legacyKey(final String username) {
        return RedisWebAuthnCredentialRepository.CAS_WEB_AUTHN_PREFIX
            + deletionFence.getKeyCodec().normalizePrincipal(username);
    }

    private void deleteState(final String username) {
        deletionFence.deleteAndVerify(currentKey(username));
        deletionFence.deleteAndVerify(writeTokenKey(username));
        deletionFence.deleteAndVerify(legacyKey(username));
        redisTemplate.delete(deletionFence.getKeyCodec().deletionFenceKey(username));
    }

    @SuppressWarnings("unchecked")
    private void markLocatorReady() {
        val keySerializer = (RedisSerializer<String>) locatorRedisTemplate.getKeySerializer();
        val result = locatorRedisTemplate.execute(
            (RedisCallback<Boolean>) connection -> connection.stringCommands().set(
                Objects.requireNonNull(
                    keySerializer.serialize(RedisWebAuthnCredentialLocator.READY_KEY)),
                RedisWebAuthnCredentialLocator.SCHEMA_VERSION.getBytes(StandardCharsets.US_ASCII)));
        assertTrue(result);
    }
}
