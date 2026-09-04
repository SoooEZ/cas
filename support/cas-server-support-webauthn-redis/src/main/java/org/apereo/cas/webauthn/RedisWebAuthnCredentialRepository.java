package org.apereo.cas.webauthn;

import module java.base;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.redis.core.CasRedisTemplate;
import org.apereo.cas.redis.core.RedisAccountSecurityDeletionFence;
import org.apereo.cas.redis.core.RedisAccountSecurityStore;
import org.apereo.cas.util.crypto.CipherExecutor;
import org.apereo.cas.util.function.FunctionUtils;
import org.apereo.cas.webauthn.storage.BaseWebAuthnCredentialRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.yubico.data.CredentialRegistration;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import lombok.val;
import org.jooq.lambda.Unchecked;
import org.springframework.beans.factory.InitializingBean;

/**
 * This is {@link RedisWebAuthnCredentialRepository}.
 *
 * @author Misagh Moayyed
 * @since 6.3.0
 */
public class RedisWebAuthnCredentialRepository extends BaseWebAuthnCredentialRepository
    implements RedisAccountSecurityStore, InitializingBean {
    /**
     * Redis key prefix.
     */
    public static final String CAS_WEB_AUTHN_PREFIX = RedisWebAuthnCredentialRepository.class.getSimpleName() + ':';

    /** Stable account-security store identifier. */
    public static final String ACCOUNT_SECURITY_STORE_ID = "webauthn-redis";

    static final String WRITE_TOKEN_NAMESPACE =
        RedisWebAuthnCredentialRepository.class.getSimpleName() + "WriteToken";

    private static final String REDIS_NAMESPACE = RedisWebAuthnCredentialRepository.class.getSimpleName();

    private static final String RECORD_SUFFIX = "records";

    private static final String WRITE_TOKEN_SUFFIX = "revision";

    private static final int MAXIMUM_MUTATION_ATTEMPTS = 64;

    private final CasRedisTemplate<String, RedisWebAuthnCredentialRegistration> redisTemplate;

    private final RedisAccountSecurityDeletionFence accountSecurityDeletionFence;

    private final RedisWebAuthnCredentialLocator credentialLocator;

    public RedisWebAuthnCredentialRepository(
        final CasRedisTemplate<String, RedisWebAuthnCredentialRegistration> redisTemplate,
        final CasConfigurationProperties properties,
        final CipherExecutor<String, String> cipherExecutor,
        final RedisAccountSecurityDeletionFence accountSecurityDeletionFence,
        final RedisWebAuthnCredentialLocator credentialLocator) {
        super(properties, cipherExecutor);
        this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate");
        this.accountSecurityDeletionFence = Objects.requireNonNull(
            accountSecurityDeletionFence, "accountSecurityDeletionFence");
        this.credentialLocator = Objects.requireNonNull(credentialLocator, "credentialLocator");
    }

    @Override
    public void afterPropertiesSet() {
        credentialLocator.rebuildIfRequired(this::repairLocatorRecord);
    }

    @Override
    public Collection<CredentialRegistration> getRegistrationsByUsername(final String username) {
        val currentKey = buildRedisKeyForRecord(username);
        val current = accountSecurityDeletionFence.readFromAuthority(username, currentKey);
        if (current.isFenced()) {
            return new LinkedHashSet<>();
        }
        if (current.isPresent()) {
            return readRegistrations(current);
        }
        val legacy = accountSecurityDeletionFence.readFromAuthority(
            buildLegacyRedisKeyForRecord(username));
        val confirmedCurrent = accountSecurityDeletionFence.readFromAuthority(username, currentKey);
        if (confirmedCurrent.isFenced()) {
            return new LinkedHashSet<>();
        }
        return confirmedCurrent.isPresent() ? readRegistrations(confirmedCurrent) : readRegistrations(legacy);
    }

    @Override
    public Collection<CredentialRegistration> getRegistrationsByUserHandle(final ByteArray userHandle) {
        return credentialLocator.locateByUserHandle(userHandle).stream()
            .flatMap(candidate -> matchingRegistrations(
                candidate,
                registration -> userHandle.equals(registration.getUserIdentity().getId())))
            .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    @Override
    public Optional<RegisteredCredential> lookup(
        final ByteArray credentialId,
        final ByteArray userHandle) {
        return credentialLocator.locateByCredentialId(credentialId).stream()
            .flatMap(candidate -> matchingRegistrations(
                candidate,
                registration -> credentialId.equals(registration.getCredential().getCredentialId())
                    && userHandle.equals(registration.getUserIdentity().getId())))
            .findFirst()
            .map(RedisWebAuthnCredentialRepository::toRegisteredCredential);
    }

    @Override
    public Set<RegisteredCredential> lookupAll(final ByteArray credentialId) {
        return credentialLocator.locateByCredentialId(credentialId).stream()
            .flatMap(candidate -> matchingRegistrations(
                candidate,
                registration -> credentialId.equals(registration.getCredential().getCredentialId())))
            .map(RedisWebAuthnCredentialRepository::toRegisteredCredential)
            .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    @Override
    public Stream<CredentialRegistration> stream() {
        try (val keys = redisTemplate.scan(getPatternRedisKey())) {
            return toCredentialRegistrationsAsStream(keys);
        }
    }

    @Override
    public boolean addRegistrationByUsername(
        final String username,
        final CredentialRegistration credentialRegistration) {
        val registration = withRegistrationTime(
            Objects.requireNonNull(credentialRegistration, "credentialRegistration"));
        return mutate(username, registrations -> {
            registrations.add(registration);
            return true;
        });
    }

    @Override
    public boolean removeRegistrationByUsername(
        final String username,
        final CredentialRegistration credentialRegistration) {
        return mutate(username, registrations -> registrations.remove(credentialRegistration));
    }

    @Override
    public boolean removeRegistrationByUsernameAndCredentialId(
        final String username,
        final ByteArray credentialId) {
        return mutate(username, registrations -> registrations.removeIf(
            registration -> registration.getCredential().getCredentialId().equals(credentialId)));
    }

    @Override
    public boolean removeAllRegistrations(final String username) {
        return mutate(username, registrations -> {
            registrations.clear();
            return true;
        });
    }

    @Override
    public void updateSignatureCount(final AssertionResult result) {
        val username = result.getUsername();
        val credentialId = result.getCredential().getCredentialId();
        val requestedSignatureCount = result.getSignatureCount();
        mutate(username, registrations -> {
            val registration = registrations.stream()
                .filter(candidate -> candidate.getCredential().getCredentialId().equals(credentialId))
                .findFirst()
                .orElseThrow(() -> new NoSuchElementException(String.format(
                    "Credential \"%s\" is not registered to user \"%s\"", credentialId, username)));
            if (requestedSignatureCount > registration.getCredential().getSignatureCount()) {
                registrations.remove(registration);
                registrations.add(registration.withCredential(registration.getCredential().toBuilder()
                    .signatureCount(requestedSignatureCount)
                    .build()));
            }
            return null;
        });
    }

    @Override
    protected void update(final String username, final Collection<CredentialRegistration> givenRecords) {
        val replacement = givenRecords.stream()
            .map(this::withRegistrationTime)
            .collect(Collectors.toCollection(LinkedHashSet::new));
        mutate(username, registrations -> {
            registrations.clear();
            registrations.addAll(replacement);
            return null;
        });
    }

    private Stream<CredentialRegistration> toCredentialRegistrationsAsStream(final Stream<String> keys) {
        return keys
            .map(accountSecurityDeletionFence::readFromAuthority)
            .filter(RedisAccountSecurityDeletionFence.AuthorityValue::isPresent)
            .flatMap(value -> accountSecurityDeletionFence.deserialize(
                value, RedisWebAuthnCredentialRegistration.class).stream())
            .map(RedisWebAuthnCredentialRegistration::getUsername)
            .filter(username -> username != null && !username.isBlank())
            .distinct()
            .flatMap(username -> getRegistrationsByUsername(username).stream())
            .collect(Collectors.toSet())
            .stream();
    }

    private <T> T mutate(
        final String username,
        final Function<Set<CredentialRegistration>, T> mutation) {
        Objects.requireNonNull(mutation, "mutation");
        val redisKey = buildRedisKeyForRecord(username);
        val writeTokenKey = buildWriteTokenKey(username);
        val principalDigest = accountSecurityDeletionFence.getKeyCodec().principalDigest(username);
        for (var attempt = 0; attempt < MAXIMUM_MUTATION_ATTEMPTS; attempt++) {
            val snapshot = readMutationSnapshot(username, redisKey, writeTokenKey);
            val registrations = new LinkedHashSet<>(snapshot.registrations());
            val result = mutation.apply(registrations);
            val replacement = registrations.isEmpty()
                ? null
                : buildEntry(username, registrations);
            val publication = credentialLocator.beginPublication(principalDigest, registrations);
            RedisAccountSecurityDeletionFence.CompareAndSetResult compareResult;
            try {
                compareResult = accountSecurityDeletionFence.compareAndSetVersionedIfUnfenced(
                    username,
                    redisKey,
                    writeTokenKey,
                    snapshot.current(),
                    replacement,
                    null);
            } finally {
                credentialLocator.completePublication(publication);
            }
            val affectedLocatorKeys = new LinkedHashSet<>(
                credentialLocator.locatorKeys(snapshot.registrations()));
            affectedLocatorKeys.addAll(credentialLocator.locatorKeys(registrations));
            reconcileLocatorCandidates(principalDigest, affectedLocatorKeys);
            if (compareResult == RedisAccountSecurityDeletionFence.CompareAndSetResult.FENCED) {
                throw new RedisAccountSecurityDeletionFence.AccountSecurityWriteFencedException();
            }
            if (compareResult == RedisAccountSecurityDeletionFence.CompareAndSetResult.APPLIED) {
                deleteMigratedLegacyValue(snapshot.legacy());
                return result;
            }
            Thread.onSpinWait();
        }
        throw new ConcurrentModificationException(
            "WebAuthn credentials changed during every bounded compare-and-set attempt");
    }

    private RegistrationSnapshot readMutationSnapshot(
        final String username,
        final String redisKey,
        final String writeTokenKey) {
        val current = accountSecurityDeletionFence.readVersionedFromAuthority(
            username, redisKey, writeTokenKey);
        requireUnfenced(current);
        if (current.isPresent()) {
            return registrationSnapshot(current, Optional.empty());
        }
        val legacy = accountSecurityDeletionFence.readFromAuthority(
            buildLegacyRedisKeyForRecord(username));
        val confirmedCurrent = accountSecurityDeletionFence.readVersionedFromAuthority(
            username, redisKey, writeTokenKey);
        requireUnfenced(confirmedCurrent);
        if (confirmedCurrent.isPresent()) {
            return registrationSnapshot(confirmedCurrent, Optional.empty());
        }
        return registrationSnapshot(
            confirmedCurrent, legacy.isPresent() ? Optional.of(legacy) : Optional.empty());
    }

    private RegistrationSnapshot registrationSnapshot(
        final RedisAccountSecurityDeletionFence.VersionedAuthorityValue current,
        final Optional<RedisAccountSecurityDeletionFence.AuthorityValue> legacy) {
        val entry = current.isPresent()
            ? readEntry(current)
            : legacy.flatMap(this::readEntry);
        return new RegistrationSnapshot(
            current,
            legacy,
            entry.stream()
                .flatMap(this::toCredentialRegistrations)
                .collect(Collectors.toCollection(LinkedHashSet::new)));
    }

    private static void requireUnfenced(
        final RedisAccountSecurityDeletionFence.VersionedAuthorityValue authorityValue) {
        if (authorityValue.isFenced()) {
            throw new RedisAccountSecurityDeletionFence.AccountSecurityWriteFencedException();
        }
    }

    private void deleteMigratedLegacyValue(
        final Optional<RedisAccountSecurityDeletionFence.AuthorityValue> legacy) {
        legacy.ifPresent(value -> {
            val result = accountSecurityDeletionFence.deleteIfUnchanged(value);
            if (result == RedisAccountSecurityDeletionFence.CompareAndDeleteResult.COMPARE_MISMATCH) {
                throw new ConcurrentModificationException(
                    "Legacy WebAuthn credentials changed while they were being migrated");
            }
        });
    }

    private RedisWebAuthnCredentialRegistration buildEntry(
        final String username,
        final Collection<CredentialRegistration> registrations) {
        val records = registrations.stream()
            .map(this::withRegistrationTime)
            .collect(Collectors.toCollection(LinkedHashSet::new));
        val jsonRecords = FunctionUtils.doUnchecked(() -> getCipherExecutor().encode(
            WebAuthnUtils.getObjectMapper().writeValueAsString(records)));
        return RedisWebAuthnCredentialRegistration.builder()
            .records(jsonRecords)
            .username(accountSecurityDeletionFence.getKeyCodec().normalizePrincipal(username))
            .build();
    }

    private Set<CredentialRegistration> readRegistrations(
        final RedisAccountSecurityDeletionFence.AuthorityValue authorityValue) {
        return readEntry(authorityValue)
            .stream()
            .flatMap(this::toCredentialRegistrations)
            .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private Optional<RedisWebAuthnCredentialRegistration> readEntry(
        final RedisAccountSecurityDeletionFence.AuthorityValue authorityValue) {
        return accountSecurityDeletionFence.deserialize(
            authorityValue, RedisWebAuthnCredentialRegistration.class);
    }

    private Optional<RedisWebAuthnCredentialRegistration> readEntry(
        final RedisAccountSecurityDeletionFence.VersionedAuthorityValue authorityValue) {
        return accountSecurityDeletionFence.deserialize(
            authorityValue, RedisWebAuthnCredentialRegistration.class);
    }

    private Stream<CredentialRegistration> matchingRegistrations(
        final RedisWebAuthnCredentialLocator.Candidate candidate,
        final Predicate<CredentialRegistration> matcher) {
        var registrations = readMatchingAuthorityRegistrations(candidate, matcher);
        if (!registrations.isEmpty()) {
            return registrations.stream();
        }
        credentialLocator.removeIfNoPublication(candidate);
        registrations = readMatchingAuthorityRegistrations(candidate, matcher);
        if (!registrations.isEmpty()) {
            credentialLocator.ensure(candidate);
        }
        return registrations.stream();
    }

    private Set<CredentialRegistration> readMatchingAuthorityRegistrations(
        final RedisWebAuthnCredentialLocator.Candidate candidate,
        final Predicate<CredentialRegistration> matcher) {
        val redisKey = accountSecurityDeletionFence.getKeyCodec().dataKeyForPrincipalDigest(
            REDIS_NAMESPACE, candidate.principalDigest(), RECORD_SUFFIX);
        val authorityValue = accountSecurityDeletionFence.readFromAuthorityByPrincipalDigest(
            candidate.principalDigest(), redisKey);
        if (authorityValue.isFenced() || !authorityValue.isPresent()) {
            return Set.of();
        }
        val entry = readEntry(authorityValue);
        if (entry.isEmpty()) {
            return Set.of();
        }
        val stored = entry.orElseThrow();
        val storedPrincipalDigest = accountSecurityDeletionFence.getKeyCodec()
            .principalDigest(stored.getUsername());
        if (!storedPrincipalDigest.equals(candidate.principalDigest())) {
            throw new IllegalStateException(
                "WebAuthn Redis authority owner does not match its principal slot");
        }
        return toCredentialRegistrations(stored)
            .filter(matcher)
            .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private void reconcileLocatorCandidates(
        final String principalDigest,
        final Collection<String> candidateKeys) {
        val initialCurrentKeys = readAuthorityLocatorKeys(principalDigest);
        val candidates = candidateKeys.stream()
            .map(locatorKey -> credentialLocator.candidate(locatorKey, principalDigest))
            .toList();
        candidates.forEach(candidate -> {
            if (initialCurrentKeys.contains(candidate.locatorKey())) {
                credentialLocator.ensure(candidate);
            } else {
                credentialLocator.removeIfNoPublication(candidate);
            }
        });
        val confirmedCurrentKeys = readAuthorityLocatorKeys(principalDigest);
        candidates.stream()
            .filter(candidate -> confirmedCurrentKeys.contains(candidate.locatorKey()))
            .forEach(credentialLocator::ensure);
    }

    private Set<String> readAuthorityLocatorKeys(final String principalDigest) {
        val redisKey = accountSecurityDeletionFence.getKeyCodec().dataKeyForPrincipalDigest(
            REDIS_NAMESPACE, principalDigest, RECORD_SUFFIX);
        val authorityValue = accountSecurityDeletionFence.readFromAuthorityByPrincipalDigest(
            principalDigest, redisKey);
        if (authorityValue.isFenced() || !authorityValue.isPresent()) {
            return Set.of();
        }
        val entry = readEntry(authorityValue).orElseThrow();
        val storedPrincipalDigest = accountSecurityDeletionFence.getKeyCodec()
            .principalDigest(entry.getUsername());
        if (!storedPrincipalDigest.equals(principalDigest)) {
            throw new IllegalStateException(
                "WebAuthn Redis authority owner does not match its principal slot");
        }
        return credentialLocator.locatorKeys(toCredentialRegistrations(entry).toList());
    }

    private void repairLocatorRecord(final String scannedRedisKey, final String username) {
        val currentKey = buildRedisKeyForRecord(username);
        val legacyKey = buildLegacyRedisKeyForRecord(username);
        if (!scannedRedisKey.equals(currentKey) && !scannedRedisKey.equals(legacyKey)) {
            throw new IllegalStateException(
                "WebAuthn Redis authority owner does not match the scanned record key");
        }
        val current = accountSecurityDeletionFence.readFromAuthority(username, currentKey);
        if (current.isFenced()) {
            return;
        }
        if (current.isPresent()) {
            val entry = readEntry(current).orElseThrow();
            val principalDigest = accountSecurityDeletionFence.getKeyCodec()
                .principalDigest(username);
            credentialLocator.publish(
                principalDigest,
                toCredentialRegistrations(entry).toList());
            if (scannedRedisKey.equals(legacyKey)) {
                val legacy = accountSecurityDeletionFence.readFromAuthority(legacyKey);
                if (legacy.isPresent()
                    && accountSecurityDeletionFence.deleteIfUnchanged(legacy)
                    == RedisAccountSecurityDeletionFence.CompareAndDeleteResult.COMPARE_MISMATCH) {
                    throw new ConcurrentModificationException(
                        "Legacy WebAuthn credentials changed during locator rebuild");
                }
            }
            return;
        } else {
            val legacy = accountSecurityDeletionFence.readFromAuthority(legacyKey);
            val confirmedCurrent = accountSecurityDeletionFence.readFromAuthority(username, currentKey);
            if (confirmedCurrent.isFenced()) {
                return;
            }
            if (!legacy.isPresent() && !confirmedCurrent.isPresent()) {
                return;
            }
        }
        try {
            mutate(username, _ -> null);
        } catch (final RedisAccountSecurityDeletionFence.AccountSecurityWriteFencedException exception) {
            return;
        }
    }

    private static RegisteredCredential toRegisteredCredential(
        final CredentialRegistration registration) {
        return RegisteredCredential.builder()
            .credentialId(registration.getCredential().getCredentialId())
            .userHandle(registration.getUserIdentity().getId())
            .publicKeyCose(registration.getCredential().getPublicKeyCose())
            .signatureCount(registration.getCredential().getSignatureCount())
            .build();
    }

    private CredentialRegistration withRegistrationTime(final CredentialRegistration record) {
        return record.getRegistrationTime() == null
            ? record.withRegistrationTime(Instant.now(Clock.systemUTC()))
            : record;
    }

    private Stream<CredentialRegistration> toCredentialRegistrations(
        final RedisWebAuthnCredentialRegistration record) {
        return Stream.of(record)
            .map(stored -> getCipherExecutor().decode(stored.getRecords()))
            .filter(Objects::nonNull)
            .map(Unchecked.function(encoded -> WebAuthnUtils.getObjectMapper().readValue(encoded, new TypeReference<Set<CredentialRegistration>>() {
            })))
            .flatMap(Collection::stream);
    }

    private static String getPatternRedisKey() {
        return CAS_WEB_AUTHN_PREFIX + '*';
    }

    private String buildRedisKeyForRecord(final String username) {
        return accountSecurityDeletionFence.getKeyCodec()
            .dataKey(REDIS_NAMESPACE, username, RECORD_SUFFIX);
    }

    private String buildWriteTokenKey(final String username) {
        return accountSecurityDeletionFence.getKeyCodec()
            .dataKey(WRITE_TOKEN_NAMESPACE, username, WRITE_TOKEN_SUFFIX);
    }

    private String buildLegacyRedisKeyForRecord(final String username) {
        return CAS_WEB_AUTHN_PREFIX
            + accountSecurityDeletionFence.getKeyCodec().normalizePrincipal(username);
    }

    @Override
    public String getAccountSecurityStoreId() {
        return ACCOUNT_SECURITY_STORE_ID;
    }

    @Override
    public RedisAccountSecurityDeletionFence.TerminalFenceResult acquireTerminal(
        final String rawPrincipal, final UUID closureId) {
        return accountSecurityDeletionFence.acquireTerminal(rawPrincipal, closureId);
    }

    @Override
    public boolean isTerminal(final String rawPrincipal, final UUID closureId) {
        return accountSecurityDeletionFence.isTerminal(rawPrincipal, closureId);
    }

    @Override
    public boolean eraseAndVerify(final String rawPrincipal, final UUID closureId) {
        return accountSecurityDeletionFence.eraseKeysAndVerify(
            rawPrincipal,
            closureId,
            List.of(
                buildRedisKeyForRecord(rawPrincipal),
                buildWriteTokenKey(rawPrincipal),
                buildLegacyRedisKeyForRecord(rawPrincipal)));
    }

    @Override
    public boolean isAccountSecurityDataAbsent(final String rawPrincipal) {
        return accountSecurityDeletionFence.areKeysAbsent(List.of(
            buildRedisKeyForRecord(rawPrincipal),
            buildWriteTokenKey(rawPrincipal),
            buildLegacyRedisKeyForRecord(rawPrincipal)));
    }

    private record RegistrationSnapshot(
        RedisAccountSecurityDeletionFence.VersionedAuthorityValue current,
        Optional<RedisAccountSecurityDeletionFence.AuthorityValue> legacy,
        Set<CredentialRegistration> registrations) {
    }
}
