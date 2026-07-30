package org.apereo.cas.ticket.registry;

import module java.base;
import org.apereo.cas.ticket.Ticket;

/**
 * Central policy for ticket issuance metadata and lifecycle-aware reads.
 *
 * <p>Implementations are expected to consult an authoritative durable lifecycle
 * store. Returning no metadata leaves a ticket unmanaged. Returning
 * {@code false}, or throwing from either callback, prevents the requested
 * operation. Implementations must be thread-safe and must not rely on a
 * thread-local value as their only authorization boundary.</p>
 *
 * @author SoooEZ
 * @since 8.0.0
 */
public interface TicketIssuancePolicy {

    /** Default Spring bean name for the authoritative issuance policy. */
    String BEAN_NAME = "ticketIssuancePolicy";

    /**
     * Prepare immutable lifecycle metadata before a ticket is persisted.
     * The registry attaches returned metadata before invoking its backend.
     *
     * @param ticket ticket about to be issued
     * @param operation registry write operation
     * @return metadata to attach, or empty when this ticket is unmanaged
     */
    default Optional<TicketIssuanceMetadata> prepareForWrite(final Ticket ticket, final Operation operation) {
        return Optional.empty();
    }

    /**
     * Prepare lifecycle metadata using exact protocol-supplied coordinates.
     *
     * <p>The compatibility default fails closed. Existing implementations and
     * callers of the original callback remain unchanged, while an explicit
     * caller cannot silently lose purpose, manifest, generation, or
     * relying-party coordinates. Context-aware policies must override this
     * method and authorize the supplied coordinates against their durable
     * lifecycle store.</p>
     *
     * @param ticket ticket about to be issued
     * @param operation registry write operation
     * @param context exact issuance write context
     * @return metadata to attach, or empty when explicitly unmanaged
     */
    default Optional<TicketIssuanceMetadata> prepareForWrite(
        final Ticket ticket,
        final Operation operation,
        final TicketIssuanceWriteContext context) {
        Objects.requireNonNull(context, "context");
        throw new UnsupportedOperationException(
            "This issuance policy does not support an explicit write context");
    }

    /**
     * Decide whether a ticket may be returned to the caller.
     *
     * <p>Implementations that permit an uncommitted ticket to its own issuance
     * flow must verify the supplied intent against durable ACTIVE intent state;
     * matching identifiers alone are insufficient. The compatibility default
     * admits only tickets that carry no lifecycle metadata. A policy that
     * prepares managed metadata but does not implement a durable read decision
     * therefore fails closed instead of exposing the managed ticket.</p>
     *
     * @param ticket ticket loaded from the backend
     * @param context explicit caller context
     * @return true when the ticket may be returned
     */
    default boolean isTicketReadable(final Ticket ticket, final TicketIssuanceReadContext context) {
        Objects.requireNonNull(context, "context");
        return TicketIssuanceMetadata.from(ticket).isEmpty();
    }

    /**
     * Decide whether a raw registry query result may be returned.
     *
     * <p>Decoded {@link Ticket} results are always checked with
     * {@link #isTicketReadable(Ticket, TicketIssuanceReadContext)} first. This
     * callback also covers backend-specific summaries and encoded payloads that
     * do not expose lifecycle metadata directly.</p>
     *
     * @param result backend query result
     * @param criteria registry query criteria
     * @return true when the result may be returned
     */
    default boolean isQueryResultReadable(final Serializable result,
                                          final TicketRegistryQueryCriteria criteria) {
        return false;
    }

    /**
     * Create a backwards-compatible policy that manages no tickets and admits
     * reads of unmanaged tickets.
     *
     * @return no-op issuance policy
     */
    static TicketIssuancePolicy noOp() {
        return new TicketIssuancePolicy() {
            @Override
            public Optional<TicketIssuanceMetadata> prepareForWrite(
                final Ticket ticket,
                final Operation operation,
                final TicketIssuanceWriteContext context) {
                Objects.requireNonNull(context, "context");
                if (context.isManaged()) {
                    throw new SecurityException(
                        "A no-op issuance policy cannot authorize a managed write context");
                }
                return Optional.empty();
            }

            @Override
            public boolean isQueryResultReadable(final Serializable result,
                                                 final TicketRegistryQueryCriteria criteria) {
                return true;
            }
        };
    }

    /** Ticket-registry write operation guarded by this policy. */
    enum Operation {
        /** Issue a new ticket. */
        ADD,
        /** Persist a change to an existing ticket. */
        UPDATE
    }
}
