package org.apereo.cas.ticket.registry;

import module java.base;
import org.apereo.cas.ticket.Ticket;

/**
 * Intercepts a ticket-registry write around the exact persistence operation.
 *
 * <p>The callback is deliberately storage-agnostic. Deployments may use it to
 * establish a durable issuance intent, acquire a distributed lifecycle fence,
 * attach storage metadata, or reject a write whose security generation is no
 * longer current. Implementations must be thread-safe. A context returned by
 * {@link #beforeWrite(Ticket, Operation)} belongs to exactly one write and is
 * completed once through either {@link WriteContext#succeeded(Ticket)} or
 * {@link WriteContext#failed(Ticket, Throwable)}. A completion callback runs in
 * reverse acquisition order. If {@code succeeded} fails, the ticket remains
 * persisted and the registry reports {@link TicketRegistryWriteCompletionException};
 * {@code failed} is reserved for admission or storage operations that did not
 * return success. A distributed storage failure may have an unknown outcome;
 * durable implementations must reconcile it rather than blindly retry.</p>
 *
 * @author SoooEZ
 * @since 8.0.0
 */
@FunctionalInterface
public interface TicketRegistryWriteInterceptor {

    /**
     * Invoked immediately before persistent ticket state is changed.
     * Throwing an exception prevents the registry write.
     *
     * @param ticket ticket being written
     * @param operation write operation
     * @return per-write completion context; never {@code null}
     */
    WriteContext beforeWrite(Ticket ticket, Operation operation);

    /**
     * Invoked before persistence with exact protocol-supplied coordinates.
     *
     * <p>The compatibility default fails closed. Existing implementations and
     * callers of the original functional callback remain unchanged, while an
     * explicit caller cannot silently lose its security coordinates.
     * Context-aware interceptors must override this method and treat the
     * supplied value as the authority rather than infer protocol semantics
     * from the ticket Java type.</p>
     *
     * @param ticket ticket being written
     * @param operation write operation
     * @param context exact issuance write context
     * @return per-write completion context; never {@code null}
     */
    default WriteContext beforeWrite(
        final Ticket ticket,
        final Operation operation,
        final TicketIssuanceWriteContext context) {
        Objects.requireNonNull(context, "context");
        throw new UnsupportedOperationException(
            "This write interceptor does not support an explicit issuance context");
    }

    /** Ticket-registry write kind. */
    enum Operation {
        /** Add a newly issued ticket. */
        ADD,
        /** Update an existing ticket. */
        UPDATE
    }

    /**
     * Completion callbacks paired with one successful admission.
     */
    interface WriteContext {

        /**
         * Invoked only after the complete storage write succeeds.
         *
         * @param ticket persisted ticket
         */
        default void succeeded(final Ticket ticket) {
        }

        /**
         * Invoked after persistence with its resource-side acknowledgement.
         * Existing interceptors remain source compatible through delegation to
         * the original callback.
         *
         * @param ticket persisted ticket
         * @param receipt storage acknowledgement
         */
        default void succeeded(final Ticket ticket,
                               final TicketRegistryWriteReceipt receipt) {
            Objects.requireNonNull(receipt, "receipt");
            succeeded(ticket);
        }

        /**
         * Invoked after explicit-context persistence and its acknowledgement.
         *
         * @param ticket persisted ticket
         * @param receipt storage acknowledgement
         * @param context exact issuance write context used for persistence
         */
        default void succeeded(
            final Ticket ticket,
            final TicketRegistryWriteReceipt receipt,
            final TicketIssuanceWriteContext context) {
            Objects.requireNonNull(context, "context");
            succeeded(ticket, receipt);
        }

        /**
         * Invoked if admission or persistence does not return success.
         * Implementations must not mask the original failure.
         *
         * @param ticket ticket whose write failed
         * @param cause original failure
         */
        default void failed(final Ticket ticket, final Throwable cause) {
        }

        /**
         * Invoked after an explicit-context write fails before successful
         * completion.
         *
         * @param ticket ticket whose write failed
         * @param cause original failure
         * @param context exact issuance write context used for admission
         */
        default void failed(
            final Ticket ticket,
            final Throwable cause,
            final TicketIssuanceWriteContext context) {
            Objects.requireNonNull(context, "context");
            failed(ticket, cause);
        }

        /** Return a context that performs no work. */
        static WriteContext noOp() {
            return new WriteContext() {
            };
        }
    }

    /** Return an interceptor that admits every operation. */
    static TicketRegistryWriteInterceptor noOp() {
        return new TicketRegistryWriteInterceptor() {
            @Override
            public WriteContext beforeWrite(final Ticket ticket, final Operation operation) {
                return WriteContext.noOp();
            }

            @Override
            public WriteContext beforeWrite(
                final Ticket ticket,
                final Operation operation,
                final TicketIssuanceWriteContext context) {
                Objects.requireNonNull(context, "context");
                return WriteContext.noOp();
            }
        };
    }
}
