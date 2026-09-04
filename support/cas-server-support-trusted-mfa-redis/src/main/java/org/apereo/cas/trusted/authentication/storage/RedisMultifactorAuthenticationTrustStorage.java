package org.apereo.cas.trusted.authentication.storage;

import module java.base;
import org.apereo.cas.configuration.model.support.mfa.trusteddevice.TrustedDevicesMultifactorProperties;
import org.apereo.cas.redis.core.CasRedisTemplate;
import org.apereo.cas.redis.core.RedisAccountSecurityDeletionFence;
import org.apereo.cas.redis.core.RedisAccountSecurityIndexedStore;
import org.apereo.cas.redis.core.RedisAccountSecurityKeyCodec;
import org.apereo.cas.redis.core.RedisAccountSecurityStore;
import org.apereo.cas.trusted.authentication.api.MultifactorAuthenticationTrustRecord;
import org.apereo.cas.trusted.authentication.api.MultifactorAuthenticationTrustRecordKeyGenerator;
import org.apereo.cas.util.DateTimeUtils;
import org.apereo.cas.util.crypto.CipherExecutor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;

/**
 * This is {@link RedisMultifactorAuthenticationTrustStorage}.
 *
 * @author Misagh Moayyed
 * @since 6.4.0
 */
@Slf4j
public class RedisMultifactorAuthenticationTrustStorage
    extends BaseMultifactorAuthenticationTrustStorage
    implements RedisAccountSecurityStore {
    /**
     * Redis key prefix.
     */
    public static final String CAS_PREFIX = RedisMultifactorAuthenticationTrustStorage.class.getSimpleName() + ':';

    /** Stable account-security store identifier. */
    public static final String ACCOUNT_SECURITY_STORE_ID = "trusted-mfa-redis";

    private static final String REDIS_NAMESPACE =
        RedisMultifactorAuthenticationTrustStorage.class.getSimpleName();

    private static final String INDEX_SUFFIX = "record-index-v3";

    private static final String INDEX_STATE_SUFFIX = "record-index-state-v3";

    private static final String INDEX_LEASE_SUFFIX = "record-index-lease-v3";

    private static final Duration INDEX_REBUILD_RETRY_DELAY = Duration.ofMillis(20);

    private static final Duration INDEX_READ_RETRY_DURATION = Duration.ofSeconds(5);

    private static final Duration LOCATOR_PUBLICATION_WAIT_DURATION = Duration.ofMinutes(3);

    private static final Duration RECORD_REMOVAL_LEASE_DURATION = Duration.ofSeconds(30);

    private static final Duration INDEX_SCHEMA_LEASE_DURATION = Duration.ofMinutes(5);

    private static final Duration INDEX_SCHEMA_WAIT_DURATION = Duration.ofMinutes(6);

    private static final int INDEX_SCHEMA_LEASE_RENEWAL_INTERVAL = 256;

    private static final String INDEX_SCHEMA_HASH_TAG = "{trusted-mfa-record-index-schema-v3}";

    private static final int MAXIMUM_RECORD_KEY_LENGTH = 4_096;

    private static final String INDEX_SCHEMA_STATE_KEY =
        REDIS_NAMESPACE + ':' + INDEX_SCHEMA_HASH_TAG + ":state";

    private static final String INDEX_SCHEMA_LEASE_KEY =
        REDIS_NAMESPACE + ':' + INDEX_SCHEMA_HASH_TAG + ":lease";

    private static final Pattern CURRENT_RECORD_KEY_PATTERN = Pattern.compile(
        Pattern.quote(CAS_PREFIX) + "\\{([0-9a-f]{64})\\}:record--?\\d+-[0-9a-f]{64}");

    private static final Pattern RECORD_REVOCATION_KEY_PATTERN = Pattern.compile(
        Pattern.quote(CAS_PREFIX)
            + "\\{[0-9a-f]{64}\\}:record--?\\d+-[0-9a-f]{64}:revoked");

    private static final Pattern WRITE_TOKEN_KEY_PATTERN = Pattern.compile(
        Pattern.quote(CAS_PREFIX)
            + "\\{[0-9a-f]{64}\\}:record--?\\d+-[0-9a-f]{64}:write-token");

    private static final Pattern LEGACY_RECORD_KEY_PATTERN = Pattern.compile(
        Pattern.quote(CAS_PREFIX) + ".+:-?\\d+");

    private static final Pattern INDEX_KEY_PATTERN = Pattern.compile(
        Pattern.quote(CAS_PREFIX) + "\\{([0-9a-f]{64})\\}:" + INDEX_SUFFIX);

    private static final Pattern INDEX_STATE_KEY_PATTERN = Pattern.compile(
        Pattern.quote(CAS_PREFIX) + "\\{([0-9a-f]{64})\\}:" + INDEX_STATE_SUFFIX);

    private static final Pattern INDEX_LEASE_KEY_PATTERN = Pattern.compile(
        Pattern.quote(CAS_PREFIX) + "\\{([0-9a-f]{64})\\}:" + INDEX_LEASE_SUFFIX);

    private static final Pattern INDEX_SCHEMA_METADATA_KEY_PATTERN = Pattern.compile(
        Pattern.quote(CAS_PREFIX)
            + "\\{trusted-mfa-record-index-schema-v[23]\\}:(?:state|lease)");

    private static final Pattern LEGACY_INDEX_METADATA_KEY_PATTERN = Pattern.compile(
        Pattern.quote(CAS_PREFIX)
            + "\\{[0-9a-f]{64}\\}:record-index(?:-state|-lease)?");

    private final CasRedisTemplate<String, List<MultifactorAuthenticationTrustRecord>> redisTemplate;

    private final RedisAccountSecurityDeletionFence accountSecurityDeletionFence;

    private final RedisAccountSecurityIndexedStore<List<MultifactorAuthenticationTrustRecord>> indexedStore;

    private final RedisTrustedMfaRecordLocator recordLocator;

    private volatile boolean indexSchemaReady;

    /**
     * Construct the storage with the stable default account-security key
     * codec. Kept for source compatibility with integrations that instantiate
     * the CAS 8.0.1 repository directly; Spring-managed deployments use the
     * explicit shared-fence constructor below.
     *
     * @param properties trusted-device properties
     * @param cipherExecutor record cipher
     * @param redisTemplate Redis authority
     * @param keyGenerationStrategy record-key strategy
     * @deprecated inject the shared deletion fence so startup can verify that
     * every security repository uses one authority
     */
    @Deprecated(since = "8.0.1")
    public RedisMultifactorAuthenticationTrustStorage(
        final TrustedDevicesMultifactorProperties properties,
        final CipherExecutor<Serializable, String> cipherExecutor,
        final CasRedisTemplate<String, List<MultifactorAuthenticationTrustRecord>> redisTemplate,
        final MultifactorAuthenticationTrustRecordKeyGenerator keyGenerationStrategy) {
        this(properties, cipherExecutor, redisTemplate, keyGenerationStrategy,
            new RedisAccountSecurityDeletionFence(
                redisTemplate, new RedisAccountSecurityKeyCodec()));
    }

    public RedisMultifactorAuthenticationTrustStorage(
        final TrustedDevicesMultifactorProperties properties,
        final CipherExecutor<Serializable, String> cipherExecutor,
        final CasRedisTemplate<String, List<MultifactorAuthenticationTrustRecord>> redisTemplate,
        final MultifactorAuthenticationTrustRecordKeyGenerator keyGenerationStrategy,
        final RedisAccountSecurityDeletionFence accountSecurityDeletionFence) {
        this(properties, cipherExecutor, redisTemplate, keyGenerationStrategy,
            accountSecurityDeletionFence,
            new RedisAccountSecurityIndexedStore<>(redisTemplate, accountSecurityDeletionFence),
            new RedisTrustedMfaRecordLocator(redisTemplate, accountSecurityDeletionFence));
    }

    RedisMultifactorAuthenticationTrustStorage(
        final TrustedDevicesMultifactorProperties properties,
        final CipherExecutor<Serializable, String> cipherExecutor,
        final CasRedisTemplate<String, List<MultifactorAuthenticationTrustRecord>> redisTemplate,
        final MultifactorAuthenticationTrustRecordKeyGenerator keyGenerationStrategy,
        final RedisAccountSecurityDeletionFence accountSecurityDeletionFence,
        final RedisAccountSecurityIndexedStore<List<MultifactorAuthenticationTrustRecord>> indexedStore) {
        this(properties, cipherExecutor, redisTemplate, keyGenerationStrategy,
            accountSecurityDeletionFence, indexedStore,
            new RedisTrustedMfaRecordLocator(redisTemplate, accountSecurityDeletionFence));
    }

    RedisMultifactorAuthenticationTrustStorage(
        final TrustedDevicesMultifactorProperties properties,
        final CipherExecutor<Serializable, String> cipherExecutor,
        final CasRedisTemplate<String, List<MultifactorAuthenticationTrustRecord>> redisTemplate,
        final MultifactorAuthenticationTrustRecordKeyGenerator keyGenerationStrategy,
        final RedisAccountSecurityDeletionFence accountSecurityDeletionFence,
        final RedisAccountSecurityIndexedStore<List<MultifactorAuthenticationTrustRecord>> indexedStore,
        final RedisTrustedMfaRecordLocator recordLocator) {
        super(properties, cipherExecutor, keyGenerationStrategy);
        this.redisTemplate = Objects.requireNonNull(redisTemplate, "redisTemplate");
        this.accountSecurityDeletionFence = Objects.requireNonNull(
            accountSecurityDeletionFence, "accountSecurityDeletionFence");
        this.indexedStore = Objects.requireNonNull(indexedStore, "indexedStore");
        this.recordLocator = Objects.requireNonNull(recordLocator, "recordLocator");
        if (!Objects.equals(accountSecurityDeletionFence.getRedisTemplate(), redisTemplate)) {
            throw new IllegalArgumentException(
                "Trusted-MFA records and deletion fences must share one Redis authority");
        }
        initializeIndexSchema();
    }

    private static String getPatternRedisKey() {
        return CAS_PREFIX + '*';
    }

    private String buildRedisKeyForRecord(final MultifactorAuthenticationTrustRecord record) {
        return accountSecurityDeletionFence.getKeyCodec().dataKey(
            REDIS_NAMESPACE,
            record.getPrincipal(),
            "record-" + record.getId() + '-' + recordIdentityDigest(record));
    }

    private String buildRedisKeyForPrincipal(final String principal) {
        return accountSecurityDeletionFence.getKeyCodec().dataPattern(REDIS_NAMESPACE, principal);
    }

    private static String buildRedisRecordRevocationKey(final String redisKey) {
        return redisKey + ":revoked";
    }

    private String buildRedisRecordKeyPrefix(final String principal) {
        return buildRedisRecordKeyPrefixByPrincipalDigest(principalDigest(principal));
    }

    private String buildRedisRecordKeyPrefixByPrincipalDigest(final String principalDigest) {
        return accountSecurityDeletionFence.getKeyCodec().dataKeyForPrincipalDigest(
            REDIS_NAMESPACE, principalDigest, "record") + '-';
    }

    private String buildRedisIndexKey(final String principal) {
        return buildRedisIndexKeyByPrincipalDigest(principalDigest(principal));
    }

    private String buildRedisIndexKeyByPrincipalDigest(final String principalDigest) {
        return accountSecurityDeletionFence.getKeyCodec().dataKeyForPrincipalDigest(
            REDIS_NAMESPACE, principalDigest, INDEX_SUFFIX);
    }

    private String buildRedisIndexStateKey(final String principal) {
        return buildRedisIndexStateKeyByPrincipalDigest(principalDigest(principal));
    }

    private String buildRedisIndexStateKeyByPrincipalDigest(final String principalDigest) {
        return accountSecurityDeletionFence.getKeyCodec().dataKeyForPrincipalDigest(
            REDIS_NAMESPACE, principalDigest, INDEX_STATE_SUFFIX);
    }

    private String buildRedisIndexLeaseKey(final String principal) {
        return accountSecurityDeletionFence.getKeyCodec().dataKey(
            REDIS_NAMESPACE, principal, INDEX_LEASE_SUFFIX);
    }

    private String buildLegacyRedisKeyForPrincipal(final String principal) {
        val codec = accountSecurityDeletionFence.getKeyCodec();
        return CAS_PREFIX + codec.escapeGlobLiteral(codec.normalizePrincipal(principal)) + ":*";
    }

    @Override
    public void remove(final String key) {
        val recordKey = requireRecordKey(key);
        val removalToken = UUID.randomUUID();
        val deadline = System.nanoTime() + LOCATOR_PUBLICATION_WAIT_DURATION.toNanos();
        while (true) {
            val lease = recordLocator.acquireRemoval(
                recordKey, removalToken, RECORD_REMOVAL_LEASE_DURATION);
            if (lease == RedisTrustedMfaRecordLocator.RemovalLeaseResult.BUSY) {
                if (System.nanoTime() >= deadline) {
                    throw new IllegalStateException(
                        "Timed out acquiring trusted-MFA record-removal lease");
                }
                parkForIndexWork("record-removal lease");
                continue;
            }
            try {
                removeWhileLeaseOwned(recordKey, removalToken, deadline);
                return;
            } catch (final RedisTrustedMfaRecordLocator.RemovalLeaseLostException exception) {
                if (System.nanoTime() >= deadline) {
                    throw new IllegalStateException(
                        "Timed out retrying trusted-MFA record removal", exception);
                }
            } finally {
                recordLocator.releaseRemoval(recordKey, removalToken);
            }
        }
    }

    @Override
    public void remove(final ZonedDateTime expirationDate) {
        Objects.requireNonNull(expirationDate, "expirationDate");
        getAll().stream()
            .filter(record -> expiresBefore(record, expirationDate))
            .map(MultifactorAuthenticationTrustRecord::getRecordKey)
            .distinct()
            .forEach(this::remove);
    }

    private void removeWhileLeaseOwned(
        final String recordKey,
        final UUID removalToken,
        final long deadline) {
        while (true) {
            if (System.nanoTime() >= deadline) {
                throw new IllegalStateException(
                    "Timed out converging trusted-MFA record removal");
            }
            while (recordLocator.hasLivePublications(recordKey, removalToken)) {
                renewRemovalLease(recordKey, removalToken);
                if (System.nanoTime() >= deadline) {
                    throw new IllegalStateException(
                        "Timed out draining trusted-MFA record publications");
                }
                parkForIndexWork("record publication drain");
            }
            renewRemovalLease(recordKey, removalToken);
            val candidates = recordLocator.locate(recordKey);
            if (candidates.isEmpty()) {
                return;
            }
            for (val candidate : candidates) {
                if (System.nanoTime() >= deadline) {
                    throw new IllegalStateException(
                        "Timed out converging trusted-MFA record removal");
                }
                renewRemovalLease(recordKey, removalToken);
                revokeLocatedCandidate(recordKey, candidate);
                if (!recordLocator.removeIfNoPublication(candidate, removalToken)) {
                    break;
                }
            }
        }
    }

    private void revokeLocatedCandidate(
        final String recordKey,
        final RedisTrustedMfaRecordLocator.Candidate candidate) {
        val redisKey = candidate.authorityRedisKey();
        val authority = accountSecurityDeletionFence.readFromAuthorityByPrincipalDigest(
            candidate.principalDigest(), redisKey);
        if (authority.isFenced()) {
            return;
        }
        var expiresAt = candidate.expiresAt();
        if (authority.isPresent()) {
            val records = deserializeRecords(authority);
            requireSingleCurrentRecord(redisKey, records);
            val record = records.getFirst();
            validateRecordOwnerDigest(record, candidate.principalDigest());
            if (record.getId() != candidate.recordId()
                || !recordIdentity(record).equals(recordKey)
                || !recordIdentityDigest(record).equals(candidate.recordDigest())
                || !redisKey.equals(buildRedisKeyForRecord(record))) {
                throw new IllegalStateException(
                    "Trusted-MFA locator candidate does not match its authority record");
            }
            val authorityExpiry = record.getExpirationDate().toInstant();
            if (authorityExpiry.isAfter(expiresAt)) {
                expiresAt = authorityExpiry;
            }
        }
        indexedStore.revokeAndVerify(
            redisKey,
            buildRedisIndexKeyByPrincipalDigest(candidate.principalDigest()),
            buildRedisIndexStateKeyByPrincipalDigest(candidate.principalDigest()),
            buildRedisRecordRevocationKey(redisKey),
            expiresAt);
    }

    private void renewRemovalLease(final String recordKey, final UUID removalToken) {
        if (recordLocator.acquireRemoval(
            recordKey, removalToken, RECORD_REMOVAL_LEASE_DURATION)
            != RedisTrustedMfaRecordLocator.RemovalLeaseResult.RENEWED) {
            throw new RedisTrustedMfaRecordLocator.RemovalLeaseLostException();
        }
    }

    @Override
    public Set<? extends MultifactorAuthenticationTrustRecord> getAll() {
        return getFromRedisKeys(scanKeys(getPatternRedisKey()).stream()
            .filter(redisKey -> isCurrentRecordKey(redisKey) || isLegacyRecordKey(redisKey)));
    }

    @Override
    public Set<? extends MultifactorAuthenticationTrustRecord> get(final ZonedDateTime onOrAfterDate) {
        return getAll()
            .stream()
            .filter(record -> record.getRecordDate().isAfter(onOrAfterDate))
            .collect(Collectors.toSet());
    }

    @Override
    public Set<? extends MultifactorAuthenticationTrustRecord> get(final String principal) {
        return readIndexedRecords(principal).records();
    }

    @Override
    public MultifactorAuthenticationTrustRecord get(final long id) {
        val redisKeys = new LinkedHashSet<String>();
        redisKeys.addAll(scanKeys(CAS_PREFIX + "{*}:record-" + id + "-*"));
        redisKeys.addAll(scanKeys(CAS_PREFIX + "*:" + id));
        return getFromRedisKeys(redisKeys.stream()
            .filter(redisKey -> !RECORD_REVOCATION_KEY_PATTERN.matcher(redisKey).matches())
            .filter(redisKey -> !WRITE_TOKEN_KEY_PATTERN.matcher(redisKey).matches()))
            .stream()
            .findFirst()
            .orElse(null);
    }

    @Override
    protected MultifactorAuthenticationTrustRecord saveInternal(final MultifactorAuthenticationTrustRecord record) {
        val redisKey = buildRedisKeyForRecord(record);
        val deadline = System.nanoTime() + LOCATOR_PUBLICATION_WAIT_DURATION.toNanos();
        while (true) {
            final RedisTrustedMfaRecordLocator.Publication publication;
            try {
                publication = recordLocator.beginPublication(record);
            } catch (final RedisTrustedMfaRecordLocator.RemovalInProgressException exception) {
                if (System.nanoTime() >= deadline) {
                    throw new IllegalStateException(
                        "Timed out waiting for trusted-MFA record removal", exception);
                }
                parkForIndexWork("record removal");
                continue;
            }
            final byte[] serializedValue;
            try {
                serializedValue = indexedStore.setIfUnfenced(
                    record.getPrincipal(),
                    redisKey,
                    buildRedisIndexKey(record.getPrincipal()),
                    buildRedisIndexStateKey(record.getPrincipal()),
                    buildRedisIndexLeaseKey(record.getPrincipal()),
                    buildRedisRecordRevocationKey(redisKey),
                    UUID.fromString(publication.token()),
                    List.of(record),
                    record.getExpirationDate().toInstant(),
                    indexSchemaReady);
            } catch (final IllegalArgumentException
                           | RedisAccountSecurityDeletionFence.AccountSecurityWriteFencedException
                           | RedisAccountSecurityIndexedStore.AccountSecurityRecordRevokedException
                           | RedisAccountSecurityIndexedStore.AccountSecurityIndexedWriteRejectedException exception) {
                recordLocator.completePublication(publication);
                throw exception;
            }
            val commit = recordLocator.commitPublication(publication);
            if (commit == RedisTrustedMfaRecordLocator.PublicationCommitResult.COMMITTED) {
                return record;
            }
            val rollback = indexedStore.deleteIfUnchanged(
                redisKey,
                buildRedisIndexKey(record.getPrincipal()),
                buildRedisIndexStateKey(record.getPrincipal()),
                serializedValue,
                UUID.fromString(publication.token()));
            if (rollback == RedisAccountSecurityIndexedStore.CompareAndDeleteIndexedResult.DELETED
                || rollback == RedisAccountSecurityIndexedStore.CompareAndDeleteIndexedResult.ABSENT) {
                recordLocator.completePublication(publication);
            }
            if (commit == RedisTrustedMfaRecordLocator.PublicationCommitResult.CAPACITY_REJECTED) {
                throw new IllegalStateException(
                    "Trusted-MFA Redis locator exceeds bounded candidate capacity");
            }
            if (System.nanoTime() >= deadline) {
                throw new IllegalStateException(
                    "Timed out committing trusted-MFA record publication");
            }
            parkForIndexWork("record publication");
        }
    }

    private void initializeIndexSchema() {
        if (indexSchemaReady) {
            return;
        }
        val leaseToken = UUID.randomUUID();
        val deadline = System.nanoTime() + INDEX_SCHEMA_WAIT_DURATION.toNanos();
        while (true) {
            val lease = indexedStore.acquireSchemaLease(
                INDEX_SCHEMA_STATE_KEY,
                INDEX_SCHEMA_LEASE_KEY,
                leaseToken,
                INDEX_SCHEMA_LEASE_DURATION);
            if (lease == RedisAccountSecurityIndexedStore.SchemaLeaseResult.READY) {
                indexSchemaReady = true;
                return;
            }
            if (lease == RedisAccountSecurityIndexedStore.SchemaLeaseResult.ACQUIRED) {
                try {
                    if (inventoryExistingPrincipals(leaseToken)
                        && indexedStore.completeSchemaAdoption(
                            INDEX_SCHEMA_STATE_KEY,
                            INDEX_SCHEMA_LEASE_KEY,
                            leaseToken)) {
                        indexSchemaReady = true;
                        return;
                    }
                } finally {
                    indexedStore.releaseRebuildLease(INDEX_SCHEMA_LEASE_KEY, leaseToken);
                }
            }
            if (System.nanoTime() >= deadline) {
                throw new IllegalStateException("Timed out waiting for trusted-MFA index schema adoption");
            }
            parkForIndexWork("schema adoption");
        }
    }

    private boolean inventoryExistingPrincipals(final UUID leaseToken) {
        var processedKeys = 0;
        var nextRenewal = System.nanoTime() + INDEX_SCHEMA_LEASE_DURATION.toNanos() / 3;
        try (val keys = redisTemplate.scan(getPatternRedisKey())) {
            val iterator = keys.iterator();
            while (iterator.hasNext()) {
                val redisKey = iterator.next();
                val currentMatcher = CURRENT_RECORD_KEY_PATTERN.matcher(redisKey);
                if (currentMatcher.matches()) {
                    adoptCurrentRecord(redisKey, currentMatcher.group(1), leaseToken);
                } else if (isLegacyRecordKey(redisKey)) {
                    adoptLegacyBucket(redisKey, leaseToken);
                } else if (!adoptOrDiscardIndexedMetadata(redisKey, leaseToken)) {
                    throw new IllegalStateException(
                        "Trusted-MFA schema-v3 adoption found an invalid repository key");
                }
                processedKeys++;
                if (processedKeys % INDEX_SCHEMA_LEASE_RENEWAL_INTERVAL == 0
                    || System.nanoTime() >= nextRenewal) {
                    if (!renewSchemaLease(leaseToken)) {
                        return false;
                    }
                    nextRenewal = System.nanoTime() + INDEX_SCHEMA_LEASE_DURATION.toNanos() / 3;
                }
            }
        }
        return renewSchemaLease(leaseToken) && completeAdoptedPrincipalIndexes(leaseToken);
    }

    private void adoptCurrentRecord(
        final String redisKey,
        final String principalDigest,
        final UUID adoptionToken) {
        val authority = accountSecurityDeletionFence.readFromAuthorityByPrincipalDigest(
            principalDigest, redisKey);
        if (authority.isFenced()) {
            accountSecurityDeletionFence.deleteAndVerify(redisKey);
            return;
        }
        val records = deserializeRecords(authority);
        if (records.isEmpty()) {
            return;
        }
        requireSingleCurrentRecord(redisKey, records);
        val record = records.getFirst();
        validateRecordOwnerDigest(record, principalDigest);
        if (!redisKey.equals(buildRedisKeyForRecord(record))) {
            throw new IllegalStateException(
                "Trusted-MFA current key does not match its record identity");
        }
        val mark = indexedStore.markAdoptionRequiredByPrincipalDigest(
            principalDigest,
            buildRedisIndexStateKeyByPrincipalDigest(principalDigest),
            adoptionToken,
            record.getExpirationDate().toInstant());
        if (mark == RedisAccountSecurityIndexedStore.MarkAdoptionResult.FENCED) {
            accountSecurityDeletionFence.deleteIfUnchanged(authority);
            return;
        }
        if (mark == RedisAccountSecurityIndexedStore.MarkAdoptionResult.EXPIRED) {
            accountSecurityDeletionFence.deleteIfUnchanged(authority);
            return;
        }
        val indexed = indexedStore.indexExistingIfUnfenced(
            record.getPrincipal(),
            redisKey,
            buildRedisIndexKeyByPrincipalDigest(principalDigest),
            buildRedisIndexStateKeyByPrincipalDigest(principalDigest),
            UUID.randomUUID());
        if (indexed == RedisAccountSecurityIndexedStore.IndexExistingResult.FENCED) {
            accountSecurityDeletionFence.deleteIfUnchanged(authority);
        } else if (indexed == RedisAccountSecurityIndexedStore.IndexExistingResult.REVOKED) {
            indexedStore.deleteAndVerify(
                redisKey,
                buildRedisIndexKeyByPrincipalDigest(principalDigest),
                buildRedisIndexStateKeyByPrincipalDigest(principalDigest));
        } else if (indexed == RedisAccountSecurityIndexedStore.IndexExistingResult.INDEXED) {
            publishAdoptedRecord(record, principalDigest, redisKey);
        }
    }

    private void adoptLegacyBucket(final String legacyKey, final UUID adoptionToken) {
        val authority = accountSecurityDeletionFence.readFromAuthority(legacyKey);
        val records = deserializeRecords(authority);
        if (records.isEmpty()) {
            return;
        }
        if (records.size() > RedisAccountSecurityIndexedStore.MAXIMUM_INDEX_ENTRIES) {
            throw new IllegalStateException("Trusted-MFA legacy bucket exceeds migration capacity");
        }
        val principalDigest = principalDigest(records.getFirst().getPrincipal());
        records.forEach(record -> validateRecordOwnerDigest(record, principalDigest));
        val fenceKey = accountSecurityDeletionFence.getKeyCodec()
            .deletionFenceKeyForPrincipalDigest(principalDigest);
        if (accountSecurityDeletionFence.readFromAuthority(fenceKey).isPresent()) {
            accountSecurityDeletionFence.deleteIfUnchanged(authority);
            return;
        }
        try {
            for (val record : records) {
                val mark = indexedStore.markAdoptionRequiredByPrincipalDigest(
                    principalDigest,
                    buildRedisIndexStateKeyByPrincipalDigest(principalDigest),
                    adoptionToken,
                    record.getExpirationDate().toInstant());
                if (mark == RedisAccountSecurityIndexedStore.MarkAdoptionResult.FENCED) {
                    accountSecurityDeletionFence.deleteIfUnchanged(authority);
                    return;
                }
                if (mark == RedisAccountSecurityIndexedStore.MarkAdoptionResult.MARKED
                    || mark == RedisAccountSecurityIndexedStore.MarkAdoptionResult.READY) {
                    try {
                        saveInternal(record);
                    } catch (final RedisAccountSecurityIndexedStore.AccountSecurityRecordRevokedException exception) {
                        LOGGER.debug(
                            "Skipping exact-record-revoked trusted-MFA legacy authority", exception);
                    }
                }
            }
        } catch (final RedisAccountSecurityDeletionFence.AccountSecurityWriteFencedException exception) {
            accountSecurityDeletionFence.deleteIfUnchanged(authority);
            return;
        }
        val result = accountSecurityDeletionFence.deleteIfUnchanged(authority);
        if (result == RedisAccountSecurityDeletionFence.CompareAndDeleteResult.COMPARE_MISMATCH) {
            throw new IllegalStateException(
                "Trusted-MFA legacy bucket changed during schema-v3 adoption");
        }
    }

    private void publishAdoptedRecord(
        final MultifactorAuthenticationTrustRecord record,
        final String principalDigest,
        final String redisKey) {
        try {
            recordLocator.publish(record);
        } catch (final IllegalArgumentException exception) {
            val current = accountSecurityDeletionFence.readFromAuthorityByPrincipalDigest(
                principalDigest, redisKey);
            if (current.isPresent()) {
                throw exception;
            }
        }
    }

    private boolean adoptOrDiscardIndexedMetadata(
        final String redisKey,
        final UUID adoptionToken) {
        var matcher = INDEX_KEY_PATTERN.matcher(redisKey);
        if (!matcher.matches()) {
            matcher = INDEX_STATE_KEY_PATTERN.matcher(redisKey);
        }
        if (matcher.matches()) {
            val principalDigest = matcher.group(1);
            indexedStore.markAdoptionRequiredByPrincipalDigest(
                principalDigest,
                buildRedisIndexStateKeyByPrincipalDigest(principalDigest),
                adoptionToken,
                null);
            return true;
        }
        if (INDEX_LEASE_KEY_PATTERN.matcher(redisKey).matches()) {
            accountSecurityDeletionFence.deleteAndVerify(redisKey);
            return true;
        }
        if (LEGACY_INDEX_METADATA_KEY_PATTERN.matcher(redisKey).matches()) {
            accountSecurityDeletionFence.deleteAndVerify(redisKey);
            return true;
        }
        return INDEX_SCHEMA_METADATA_KEY_PATTERN.matcher(redisKey).matches()
            || RECORD_REVOCATION_KEY_PATTERN.matcher(redisKey).matches()
            || WRITE_TOKEN_KEY_PATTERN.matcher(redisKey).matches();
    }

    private boolean completeAdoptedPrincipalIndexes(final UUID leaseToken) {
        var processedKeys = 0;
        var nextRenewal = System.nanoTime() + INDEX_SCHEMA_LEASE_DURATION.toNanos() / 3;
        try (val keys = redisTemplate.scan(getPatternRedisKey())) {
            val iterator = keys.iterator();
            while (iterator.hasNext()) {
                val redisKey = iterator.next();
                val matcher = INDEX_STATE_KEY_PATTERN.matcher(redisKey);
                if (matcher.matches()) {
                    val principalDigest = matcher.group(1);
                    val completion = indexedStore.completeAdoptionByPrincipalDigest(
                        principalDigest,
                        buildRedisIndexKeyByPrincipalDigest(principalDigest),
                        redisKey,
                        buildRedisRecordKeyPrefixByPrincipalDigest(principalDigest),
                        leaseToken);
                    if (completion
                        == RedisAccountSecurityIndexedStore.AdoptionCompletionResult.CAPACITY_EXCEEDED) {
                        throw new IllegalStateException(
                            "Trusted-MFA principal exceeds schema-v3 adoption capacity");
                    }
                    if (completion
                        == RedisAccountSecurityIndexedStore.AdoptionCompletionResult.STALE_OWNER) {
                        return false;
                    }
                }
                processedKeys++;
                if (processedKeys % INDEX_SCHEMA_LEASE_RENEWAL_INTERVAL == 0
                    || System.nanoTime() >= nextRenewal) {
                    if (!renewSchemaLease(leaseToken)) {
                        return false;
                    }
                    nextRenewal = System.nanoTime() + INDEX_SCHEMA_LEASE_DURATION.toNanos() / 3;
                }
            }
        }
        return renewSchemaLease(leaseToken);
    }

    private boolean renewSchemaLease(final UUID leaseToken) {
        return indexedStore.acquireSchemaLease(
            INDEX_SCHEMA_STATE_KEY,
            INDEX_SCHEMA_LEASE_KEY,
            leaseToken,
            INDEX_SCHEMA_LEASE_DURATION)
            == RedisAccountSecurityIndexedStore.SchemaLeaseResult.ACQUIRED;
    }

    private PrincipalRead readIndexedRecords(final String principal) {
        val deadline = System.nanoTime() + INDEX_READ_RETRY_DURATION.toNanos();
        while (true) {
            val read = indexedStore.read(
                principal,
                buildRedisIndexKey(principal),
                buildRedisIndexStateKey(principal),
                buildRedisRecordKeyPrefix(principal),
                indexSchemaReady);
            if (read.status() == RedisAccountSecurityIndexedStore.IndexedReadStatus.FENCED) {
                return new PrincipalRead(true, Set.of());
            }
            if (read.status() == RedisAccountSecurityIndexedStore.IndexedReadStatus.REBUILD_REQUIRED) {
                throw new IllegalStateException(
                    "Trusted-MFA index requires offline schema-v3 repair");
            }
            try {
                return new PrincipalRead(false, recordsFromIndexedRead(principal, read));
            } catch (final ConcurrentModificationException exception) {
                if (System.nanoTime() >= deadline) {
                    throw new IllegalStateException(
                        "Timed out retrying a concurrent trusted-MFA index read", exception);
                }
                parkForIndexWork("concurrent index read");
            }
        }
    }

    private Set<? extends MultifactorAuthenticationTrustRecord> recordsFromIndexedRead(
        final String principal,
        final RedisAccountSecurityIndexedStore.IndexedReadResult<
            List<MultifactorAuthenticationTrustRecord>> read) {
        val records = new LinkedHashMap<String, MultifactorAuthenticationTrustRecord>();
        for (val indexed : read.values()) {
            requireSingleCurrentRecord(indexed.dataKey(), indexed.value());
            val record = indexed.value().getFirst();
            validateRecordOwner(record, principal);
            if (!indexed.dataKey().equals(buildRedisKeyForRecord(record))) {
                throw new IllegalStateException("Trusted-MFA index member does not match its record identity");
            }
            if (record.isExpired()) {
                val deletion = indexedStore.deleteIfUnchanged(
                    indexed.dataKey(),
                    buildRedisIndexKey(principal),
                    buildRedisIndexStateKey(principal),
                    indexed.serializedValue(),
                    indexed.writeToken());
                if (deletion
                    == RedisAccountSecurityIndexedStore.CompareAndDeleteIndexedResult.COMPARE_MISMATCH) {
                    throw new ConcurrentModificationException(
                        "Trusted-MFA record changed during expired-record cleanup");
                }
            } else {
                records.put(recordIdentity(record), record);
            }
        }
        return new LinkedHashSet<>(records.values());
    }

    private Set<? extends MultifactorAuthenticationTrustRecord> getFromRedisKeys(final Stream<String> keys) {
        val expirationDate = ZonedDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.SECONDS);
        return keys
            .map(redisKey -> new StoredRecords(redisKey, readRecordsFromAuthority(redisKey)))
            .flatMap(stored -> stored.records().stream()
                .map(record -> new StoredRecord(stored.redisKey(), record)))
            .filter(stored -> DateTimeUtils.zonedDateTimeOf(
                stored.record().getExpirationDate()).isAfter(expirationDate))
            .collect(Collectors.toMap(
                stored -> recordIdentity(stored.record()),
                Function.identity(),
                RedisMultifactorAuthenticationTrustStorage::preferCurrentRecord))
            .values()
            .stream()
            .map(StoredRecord::record)
            .collect(Collectors.toSet());
    }

    private List<MultifactorAuthenticationTrustRecord> readRecordsFromAuthority(final String redisKey) {
        val currentMatcher = CURRENT_RECORD_KEY_PATTERN.matcher(redisKey);
        if (currentMatcher.matches()) {
            val ownerDigest = currentMatcher.group(1);
            val records = deserializeRecords(
                accountSecurityDeletionFence.readFromAuthorityByPrincipalDigest(
                    ownerDigest, redisKey));
            records.forEach(record -> {
                if (!principalDigest(record.getPrincipal()).equals(ownerDigest)) {
                    throw new IllegalStateException(
                        "Trusted-MFA current record belongs to a different principal slot");
                }
            });
            return records;
        }
        if (isLegacyRecordKey(redisKey)) {
            if (indexSchemaReady) {
                throw new IllegalStateException(
                    "Trusted-MFA legacy data appeared after schema-v3 adoption");
            }
            val initial = deserializeRecords(accountSecurityDeletionFence.readFromAuthority(redisKey));
            if (initial.isEmpty()) {
                return List.of();
            }
            val principal = initial.getFirst().getPrincipal();
            initial.forEach(record -> validateRecordOwner(record, principal));
            val fenceKey = accountSecurityDeletionFence.getKeyCodec().deletionFenceKey(principal);
            if (accountSecurityDeletionFence.readFromAuthority(fenceKey).isPresent()) {
                return List.of();
            }
            return initial;
        }
        throw new IllegalArgumentException("Redis trusted-MFA record key has an invalid format");
    }

    private List<MultifactorAuthenticationTrustRecord> deserializeRecords(
        final RedisAccountSecurityDeletionFence.AuthorityValue authority) {
        val value = accountSecurityDeletionFence.deserialize(authority, List.class);
        if (value.isEmpty()) {
            return List.of();
        }
        val records = new ArrayList<MultifactorAuthenticationTrustRecord>();
        for (val item : value.orElseThrow()) {
            if (!(item instanceof final MultifactorAuthenticationTrustRecord record)) {
                throw new IllegalStateException("Redis trusted-MFA value contains an unexpected record type");
            }
            records.add(record);
        }
        return List.copyOf(records);
    }

    private Set<String> scanKeys(final String pattern) {
        try (val keys = redisTemplate.scan(pattern)) {
            return keys.collect(Collectors.toCollection(LinkedHashSet::new));
        }
    }

    private static void parkForIndexWork(final String operation) {
        LockSupport.parkNanos(INDEX_REBUILD_RETRY_DELAY.toNanos());
        if (Thread.currentThread().isInterrupted()) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for trusted-MFA " + operation);
        }
    }

    private String principalDigest(final String principal) {
        return accountSecurityDeletionFence.getKeyCodec().principalDigest(principal);
    }

    private void validateRecordOwner(
        final MultifactorAuthenticationTrustRecord record,
        final String principal) {
        validateRecordOwnerDigest(record, principalDigest(principal));
    }

    private void validateRecordOwnerDigest(
        final MultifactorAuthenticationTrustRecord record,
        final String expectedPrincipalDigest) {
        if (!principalDigest(record.getPrincipal()).equals(expectedPrincipalDigest)) {
            throw new IllegalStateException("Trusted-MFA record belongs to a different principal");
        }
        recordIdentity(record);
    }

    private static boolean expiresBefore(
        final MultifactorAuthenticationTrustRecord record,
        final ZonedDateTime expirationDate) {
        return DateTimeUtils.zonedDateTimeOf(record.getExpirationDate()).isBefore(expirationDate);
    }

    private static String recordIdentity(final MultifactorAuthenticationTrustRecord record) {
        val recordKey = record.getRecordKey();
        if (recordKey == null || recordKey.isBlank()) {
            throw new IllegalStateException("Trusted-MFA record has no stable record key");
        }
        return recordKey;
    }

    private static String recordIdentityDigest(final MultifactorAuthenticationTrustRecord record) {
        return recordIdentityDigest(recordIdentity(record));
    }

    private static String recordIdentityDigest(final String recordKey) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(
                requireRecordKey(recordKey).getBytes(StandardCharsets.UTF_8)));
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    private static void requireSingleCurrentRecord(
        final String redisKey,
        final List<MultifactorAuthenticationTrustRecord> records) {
        if (records.size() != 1) {
            throw new IllegalStateException(
                "Current trusted-MFA key contains an invalid record count: " + redisKey);
        }
    }

    private static boolean isCurrentRecordKey(final String redisKey) {
        return CURRENT_RECORD_KEY_PATTERN.matcher(redisKey).matches();
    }

    private static boolean isLegacyRecordKey(final String redisKey) {
        return LEGACY_RECORD_KEY_PATTERN.matcher(redisKey).matches();
    }

    private static String requireRecordKey(final String recordKey) {
        if (recordKey == null || recordKey.isBlank()
            || recordKey.length() > MAXIMUM_RECORD_KEY_LENGTH) {
            throw new IllegalArgumentException("Trusted-MFA record key is required");
        }
        return recordKey;
    }

    private static StoredRecord preferCurrentRecord(
        final StoredRecord first,
        final StoredRecord second) {
        return isCurrentRecordKey(second.redisKey()) ? second : first;
    }

    @Override
    public String getAccountSecurityStoreId() {
        return ACCOUNT_SECURITY_STORE_ID;
    }

    @Override
    public RedisAccountSecurityDeletionFence.TerminalFenceResult acquireTerminal(
        final String rawPrincipal,
        final UUID closureId) {
        return accountSecurityDeletionFence.acquireTerminal(rawPrincipal, closureId);
    }

    @Override
    public boolean isTerminal(final String rawPrincipal, final UUID closureId) {
        return accountSecurityDeletionFence.isTerminal(rawPrincipal, closureId);
    }

    @Override
    public boolean eraseAndVerify(final String rawPrincipal, final UUID closureId) {
        return accountSecurityDeletionFence.erasePatternsAndVerify(
            rawPrincipal,
            closureId,
            List.of(
                buildRedisKeyForPrincipal(rawPrincipal),
                buildLegacyRedisKeyForPrincipal(rawPrincipal)));
    }

    @Override
    public boolean isAccountSecurityDataAbsent(final String rawPrincipal) {
        return accountSecurityDeletionFence.isAbsent(List.of(
            buildRedisKeyForPrincipal(rawPrincipal),
            buildLegacyRedisKeyForPrincipal(rawPrincipal)));
    }

    private record PrincipalRead(
        boolean fenced,
        Set<? extends MultifactorAuthenticationTrustRecord> records) {
    }

    private record StoredRecords(
        String redisKey,
        List<MultifactorAuthenticationTrustRecord> records) {
    }

    private record StoredRecord(
        String redisKey,
        MultifactorAuthenticationTrustRecord record) {
    }
}
