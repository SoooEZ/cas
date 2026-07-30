package org.apereo.cas.ticket.registry;

import module java.base;
import org.apereo.cas.ticket.Ticket;
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
 * reconcile rather than blindly retry.</p>
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
     */
    record WriteCommand(Ticket ticket,
                        TicketRegistryWriteInterceptor.Operation operation,
                        String redisKey,
                        String keyspace,
                        String documentId,
                        long timeToLiveSeconds,
                        long expiresAtEpochMilli,
                        RedisData redisData,
                        Optional<TicketIssuanceWriteContext> issuanceContext) {
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

        public WriteCommand {
            Objects.requireNonNull(ticket);
            Objects.requireNonNull(operation);
            Objects.requireNonNull(redisKey);
            Objects.requireNonNull(keyspace);
            Objects.requireNonNull(documentId);
            Objects.requireNonNull(redisData);
            Objects.requireNonNull(issuanceContext, "issuanceContext");
            if (timeToLiveSeconds <= 0) {
                throw new IllegalArgumentException("Ticket time to live must be positive");
            }
            if (expiresAtEpochMilli <= 0) {
                throw new IllegalArgumentException("Ticket expiration instant must be positive");
            }
        }
    }
}
