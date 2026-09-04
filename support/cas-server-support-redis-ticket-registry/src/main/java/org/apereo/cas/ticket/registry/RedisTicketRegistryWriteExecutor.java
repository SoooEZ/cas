package org.apereo.cas.ticket.registry;

import module java.base;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.ticket.registry.key.RedisPrincipalTicketIndexKeyGenerator;
import org.apereo.cas.ticket.registry.key.RedisPrincipalTicketMutationFenceKeyGenerator;
import lombok.val;
import org.springframework.data.redis.core.convert.RedisData;

/**
 * Strategy for replacing one Redis ticket persistence operation.
 *
 * <p>This seam lets a deployment atomically combine its own resource-side
 * generation fence with the authoritative Redis hash write. An executor must
 * either perform the complete persistence described by {@link WriteCommand},
 * or invoke {@code defaultPersistence} exactly once. Returning normally means
 * the write is durable enough for post-write callbacks to run. An exception
 * may represent an unknown distributed outcome, so durable interceptors must
 * reconcile rather than blindly retry. A replacing executor must check both
 * the registry-wide and supplied principal-scoped mutation fence inside the
 * same Redis EVAL that mutates ticket state.</p>
 *
 * <p>Only one executor may be registered. The default registry behavior is
 * unchanged when none is present.</p>
 *
 * @author SoooEZ
 * @since 8.0.0
 */
@FunctionalInterface
public interface RedisTicketRegistryWriteExecutor {

    /**
     * Execute one complete persistence operation.
     *
     * @param command prepared Redis write data
     * @param defaultPersistence original CAS persistence operation
     */
    TicketRegistryWriteReceipt execute(WriteCommand command, Runnable defaultPersistence);

    /**
     * Immutable coordinates and prepared mapping data for one Redis write.
     * Implementations must not retain or mutate {@code redisData} after return.
     *
     * @param ticket source ticket
     * @param operation operation type
     * @param redisKey authoritative Redis ticket key
     * @param keyspace Spring Data Redis keyspace
     * @param documentId mapped document identifier
     * @param timeToLiveSeconds ticket time to live
     * @param expiresAtEpochMilli exact absolute expiration used by the resource writer
     * @param redisData fully converted Redis hash data
     * @param issuanceContext exact protocol context, or empty for a legacy write
     * @param mutationFenceKey key whose presence rejects writes during registry-wide deletion
     * @param principalMutationFenceKey principal-scoped key whose presence rejects this write,
     *                                  or empty when the ticket has no principal
     * @param principalIndex authoritative principal-to-ticket index mutation, or empty
     *                       when the ticket has no authentication principal
     * @param principalSessionIndex legacy principal-to-session index mutation, or empty
     *                              when the ticket is not a session ticket
     */
    record WriteCommand(Ticket ticket,
                        TicketRegistryWriteInterceptor.Operation operation,
                        String redisKey,
                        String keyspace,
                        String documentId,
                        long timeToLiveSeconds,
                        long expiresAtEpochMilli,
                        RedisData redisData,
                        Optional<TicketIssuanceWriteContext> issuanceContext,
                        String mutationFenceKey,
                        Optional<String> principalMutationFenceKey,
                        Optional<PrincipalIndexEntry> principalIndex,
                        Optional<PrincipalSessionIndexEntry> principalSessionIndex) {
        /**
         * Construct a backwards-compatible command for a legacy write.
         *
         * @param ticket source ticket
         * @param operation operation type
         * @param redisKey authoritative Redis ticket key
         * @param keyspace Spring Data Redis keyspace
         * @param documentId mapped document identifier
         * @param timeToLiveSeconds ticket time to live
         * @param expiresAtEpochMilli exact absolute expiration
         * @param redisData fully converted Redis hash data
         */
        public WriteCommand(
            final Ticket ticket,
            final TicketRegistryWriteInterceptor.Operation operation,
            final String redisKey,
            final String keyspace,
            final String documentId,
            final long timeToLiveSeconds,
            final long expiresAtEpochMilli,
            final RedisData redisData) {
            this(ticket, operation, redisKey, keyspace, documentId,
                timeToLiveSeconds, expiresAtEpochMilli, redisData, Optional.empty());
        }

        /**
         * Construct a command for an explicit-context write.
         *
         * @param ticket source ticket
         * @param operation operation type
         * @param redisKey authoritative Redis ticket key
         * @param keyspace Spring Data Redis keyspace
         * @param documentId mapped document identifier
         * @param timeToLiveSeconds ticket time to live
         * @param expiresAtEpochMilli exact absolute expiration
         * @param redisData fully converted Redis hash data
         * @param issuanceContext exact protocol context
         */
        public WriteCommand(
            final Ticket ticket,
            final TicketRegistryWriteInterceptor.Operation operation,
            final String redisKey,
            final String keyspace,
            final String documentId,
            final long timeToLiveSeconds,
            final long expiresAtEpochMilli,
            final RedisData redisData,
            final TicketIssuanceWriteContext issuanceContext) {
            this(ticket, operation, redisKey, keyspace, documentId,
                timeToLiveSeconds, expiresAtEpochMilli, redisData,
                Optional.of(Objects.requireNonNull(issuanceContext, "issuanceContext")));
        }

        /**
         * Construct a command with the original optional issuance-context
         * signature. This keeps source compatibility for executors that build
         * commands in tests while the registry supplies principal-index data
         * through the canonical constructor.
         *
         * @param ticket source ticket
         * @param operation operation type
         * @param redisKey authoritative Redis ticket key
         * @param keyspace Spring Data Redis keyspace
         * @param documentId mapped document identifier
         * @param timeToLiveSeconds ticket time to live
         * @param expiresAtEpochMilli exact absolute expiration
         * @param redisData fully converted Redis hash data
         * @param issuanceContext exact protocol context, or empty
         */
        public WriteCommand(
            final Ticket ticket,
            final TicketRegistryWriteInterceptor.Operation operation,
            final String redisKey,
            final String keyspace,
            final String documentId,
            final long timeToLiveSeconds,
            final long expiresAtEpochMilli,
            final RedisData redisData,
            final Optional<TicketIssuanceWriteContext> issuanceContext) {
            this(ticket, operation, redisKey, keyspace, documentId,
                timeToLiveSeconds, expiresAtEpochMilli, redisData,
                issuanceContext,
                RedisPrincipalTicketIndexKeyGenerator.MUTATION_FENCE_KEY,
                Optional.empty(),
                Optional.empty(),
                Optional.empty());
        }

        public WriteCommand {
            Objects.requireNonNull(ticket);
            Objects.requireNonNull(operation);
            Objects.requireNonNull(redisKey);
            Objects.requireNonNull(keyspace);
            Objects.requireNonNull(documentId);
            Objects.requireNonNull(redisData);
            Objects.requireNonNull(issuanceContext, "issuanceContext");
            if (!RedisPrincipalTicketIndexKeyGenerator.MUTATION_FENCE_KEY.equals(
                mutationFenceKey)) {
                throw new IllegalArgumentException("Redis mutation fence key is invalid");
            }
            Objects.requireNonNull(principalMutationFenceKey, "principalMutationFenceKey");
            Objects.requireNonNull(principalIndex, "principalIndex");
            Objects.requireNonNull(principalSessionIndex, "principalSessionIndex");
            if (principalMutationFenceKey.isPresent() != principalIndex.isPresent()) {
                throw new IllegalArgumentException(
                    "A principal mutation fence and principal ticket index must be supplied together");
            }
            principalIndex.ifPresent(index -> {
                val mappedPrincipal = index.redisKey().substring(index.redisKeyPrefix().length());
                val expectedFenceKey = RedisPrincipalTicketMutationFenceKeyGenerator
                    .forPrincipal(mappedPrincipal);
                if (!expectedFenceKey.equals(principalMutationFenceKey.orElseThrow())) {
                    throw new IllegalArgumentException(
                        "Principal mutation-fence coordinates are inconsistent");
                }
            });
            if (principalSessionIndex.isPresent() && principalIndex.isEmpty()) {
                throw new IllegalArgumentException(
                    "A principal session index requires a principal ticket index");
            }
            if (timeToLiveSeconds <= 0) {
                throw new IllegalArgumentException("Ticket time to live must be positive");
            }
            if (expiresAtEpochMilli <= 0) {
                throw new IllegalArgumentException("Ticket expiration instant must be positive");
            }
        }
    }

    /**
     * Coordinates for the Redis principal-to-ticket index that must be
     * persisted in the same atomic operation as its ticket hash. An executor
     * that replaces the default persistence operation is responsible for
     * removing the ticket member from an old principal index on update and for
     * adding this member to {@code redisKey} with
     * {@code expiresAtEpochMilli} as its score.
     *
     * <p>The index spans keys in different Redis hash slots. It therefore
     * follows the Redis ticket registry's single-primary/Sentinel contract and
     * is not compatible with Redis Cluster.</p>
     *
     * @param redisKeyPrefix stable prefix prepended to a mapped principal
     * @param redisKey principal index key
     * @param member complete authoritative Redis ticket key
     * @param expiresAtEpochMilli exact ticket expiration used as the ZSET score
     */
    record PrincipalIndexEntry(String redisKeyPrefix,
                               String redisKey,
                               String member,
                               long expiresAtEpochMilli) {
        public PrincipalIndexEntry {
            if (redisKeyPrefix == null || redisKeyPrefix.isBlank()) {
                throw new IllegalArgumentException("Principal index key prefix must not be blank");
            }
            if (redisKey == null || redisKey.isBlank()) {
                throw new IllegalArgumentException("Principal index key must not be blank");
            }
            if (!redisKey.startsWith(redisKeyPrefix)
                || redisKey.length() == redisKeyPrefix.length()) {
                throw new IllegalArgumentException("Principal index key must include a mapped principal");
            }
            if (member == null || member.isBlank()) {
                throw new IllegalArgumentException("Principal index member must not be blank");
            }
            if (expiresAtEpochMilli <= 0) {
                throw new IllegalArgumentException("Principal index expiration must be positive");
            }
        }
    }

    /**
     * Coordinates for the legacy Redis principal-to-session sorted set. A
     * replacing executor must apply this mutation in the same Lua command as
     * the ticket hash, principal ticket index, and registry-wide mutation-fence
     * check. The serialized member is supplied exactly as expected by the
     * sessions Redis template and is defensively copied.
     *
     * <p>A generation-aware executor that recognizes an idempotent replay may
     * safely repair an {@link PrincipalSessionIndexMode#ALL} entry. It must not
     * reapply {@link PrincipalSessionIndexMode#MOST_RECENT} for an older replay,
     * because that would replace a newer session as the most recent one.</p>
     *
     * <p>For {@code ALL}, prune old scores before adding the supplied member,
     * then refresh the ZSET expiration without pruning again. Because scores
     * truncate expiration milliseconds to whole seconds, only scores through
     * {@code nowSecond - 1} are certainly expired. Pruning the current or next
     * second can remove a valid short-lived ticket. The same safe cutoff applies
     * when refreshing an old principal's session index. For {@code MOST_RECENT},
     * delete the old ZSET, add the supplied member, and then set its expiration.</p>
     *
     */
    final class PrincipalSessionIndexEntry {
        private final String redisKeyPrefix;

        private final String redisKey;

        private final byte[] serializedMember;

        private final long expiresAtEpochSecond;

        private final PrincipalSessionIndexMode mode;

        /**
         * Build legacy session-index coordinates.
         *
         * @param redisKeyPrefix stable prefix prepended to a mapped principal
         * @param redisKey principal session-index key
         * @param serializedMember serialized, digested ticket identifier
         * @param expiresAtEpochSecond session member expiration score
         * @param mode session tracking policy
         */
        public PrincipalSessionIndexEntry(final String redisKeyPrefix,
                                          final String redisKey,
                                          final byte[] serializedMember,
                                          final long expiresAtEpochSecond,
                                          final PrincipalSessionIndexMode mode) {
            if (redisKeyPrefix == null || redisKeyPrefix.isBlank()) {
                throw new IllegalArgumentException("Principal session index key prefix must not be blank");
            }
            if (redisKey == null || redisKey.isBlank()) {
                throw new IllegalArgumentException("Principal session index key must not be blank");
            }
            if (!redisKey.startsWith(redisKeyPrefix)
                || redisKey.length() == redisKeyPrefix.length()) {
                throw new IllegalArgumentException(
                    "Principal session index key must include a mapped principal");
            }
            if (serializedMember == null || serializedMember.length == 0) {
                throw new IllegalArgumentException("Principal session index member must not be empty");
            }
            if (expiresAtEpochSecond <= 0) {
                throw new IllegalArgumentException("Principal session index expiration must be positive");
            }
            this.redisKeyPrefix = redisKeyPrefix;
            this.redisKey = redisKey;
            this.serializedMember = serializedMember.clone();
            this.expiresAtEpochSecond = expiresAtEpochSecond;
            this.mode = Objects.requireNonNull(mode, "mode");
        }

        /**
         * Gets the stable prefix prepended to the mapped principal.
         *
         * @return stable prefix prepended to the mapped principal
         */
        public String redisKeyPrefix() {
            return redisKeyPrefix;
        }

        /**
         * Gets the principal session-index key.
         *
         * @return principal session-index key
         */
        public String redisKey() {
            return redisKey;
        }

        /**
         * Gets a defensive copy of the serialized session member.
         *
         * @return defensive copy of the serialized session member
         */
        public byte[] serializedMember() {
            return serializedMember.clone();
        }

        /**
         * Gets the session member expiration score.
         *
         * @return session member expiration score
         */
        public long expiresAtEpochSecond() {
            return expiresAtEpochSecond;
        }

        /**
         * Gets the session tracking policy.
         *
         * @return session tracking policy
         */
        public PrincipalSessionIndexMode mode() {
            return mode;
        }
    }

    /**
     * Legacy principal session tracking behavior.
     */
    enum PrincipalSessionIndexMode {
        /**
         * Retain every live session ticket for the principal.
         */
        ALL,
        /**
         * Retain only the most recently written session ticket.
         */
        MOST_RECENT
    }
}
