package org.apereo.cas.ticket.registry;

import module java.base;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.util.crypto.CipherExecutor;
import lombok.val;
import org.jooq.lambda.Unchecked;
import org.jspecify.annotations.Nullable;

/**
 * Interface for a registry that stores tickets. The underlying registry can be
 * backed by anything from a normal HashMap to JGroups for having distributed
 * registries. It is up to specific implementations to determine their clean up
 * strategy. Strategies can include a manual clean up by a registry cleaner or a
 * more sophisticated strategy such as LRU.
 *
 * @author Scott Battaglia
 * @since 3.0.0
 */
public interface TicketRegistry {

    /**
     * Default bean name.
     */
    String BEAN_NAME = "ticketRegistry";

    /**
     * Ticket transaction manager bean name.
     */
    String TICKET_TRANSACTION_MANAGER = "ticketTransactionManager";
    
    /**
     * Add a ticket to the registry. Ticket storage is based on the ticket id.
     *
     * @param ticket The ticket we wish to add to the cache.
     * @return ticket
     * @throws Exception the exception
     */
    @Nullable Ticket addTicket(Ticket ticket) throws Exception;

    /**
     * Add a ticket using exact protocol-supplied issuance coordinates.
     *
     * <p>The default fails closed because a custom registry that has not opted
     * into this contract cannot prove that it preserved the context. Existing
     * callers and implementations of {@link #addTicket(Ticket)} are unchanged.</p>
     *
     * @param ticket ticket to add
     * @param context exact issuance write context
     * @return ticket
     * @throws Exception the exception
     */
    default @Nullable Ticket addTicket(
        final Ticket ticket,
        final TicketIssuanceWriteContext context) throws Exception {
        Objects.requireNonNull(context, "context");
        throw new UnsupportedOperationException(
            "This ticket registry does not support an explicit issuance write context");
    }

    /**
     * Save.
     *
     * @param toSave the to save
     */
    default @Nullable List<? extends Ticket> addTicket(final Stream<? extends Ticket> toSave) {
        return toSave.parallel().map(Unchecked.function(this::addTicket)).filter(Objects::nonNull).collect(Collectors.toList());
    }

    /**
     * Retrieve a ticket from the registry. If the ticket retrieved does not
     * match the expected class, an InvalidTicketException is thrown.
     *
     * @param <T>      the generic ticket type to return that extends {@link Ticket}
     * @param ticketId the id of the ticket we wish to retrieve.
     * @param clazz    The expected class of the ticket we wish to retrieve.
     * @return the requested ticket.
     */
    <T extends Ticket> @Nullable T getTicket(String ticketId, Class<T> clazz);

    /**
     * Retrieve a ticket from the registry.
     *
     * @param ticketId the id of the ticket we wish to retrieve
     * @return the requested ticket.
     */
    @Nullable Ticket getTicket(String ticketId);

    /**
     * Retrieve a ticket using an explicit issuance read context.
     *
     * <p>The default preserves compatibility only for a standard read. An
     * intent-aware read fails closed because a custom registry that has not
     * opted into this contract cannot prove that it enforced same-intent
     * visibility. Registries extending {@code AbstractTicketRegistry} apply
     * the configured {@link TicketIssuancePolicy} to every context.</p>
     *
     * @param ticketId the id of the ticket to retrieve
     * @param context explicit issuance context
     * @return the requested ticket
     */
    default @Nullable Ticket getTicket(final String ticketId, final TicketIssuanceReadContext context) {
        Objects.requireNonNull(context, "context");
        if (context.intentId() != null) {
            throw new UnsupportedOperationException(
                "This ticket registry does not support an intent-aware issuance read context");
        }
        return getTicket(ticketId);
    }

    /**
     * Retrieve a typed ticket using an explicit issuance read context.
     *
     * @param <T> ticket type
     * @param ticketId ticket identifier
     * @param clazz expected ticket class
     * @param context explicit issuance context
     * @return requested ticket
     */
    default <T extends Ticket> @Nullable T getTicket(final String ticketId, final Class<T> clazz,
                                                     final TicketIssuanceReadContext context) {
        Objects.requireNonNull(context, "context");
        if (context.intentId() != null) {
            throw new UnsupportedOperationException(
                "This ticket registry does not support an intent-aware issuance read context");
        }
        return getTicket(ticketId, clazz);
    }

    /**
     * Gets ticket from registry using a predicate.
     *
     * @param ticketId  the ticket id
     * @param predicate the predicate that tests the ticket
     * @return the ticket
     * @apiNote This overload represents a standard read without an issuance
     * intent. Application and protocol code that needs same-intent semantics
     * should call a context-aware overload instead.
     */
    @Nullable Ticket getTicket(String ticketId, Predicate<Ticket> predicate);

    /**
     * Retrieve a ticket from the authoritative registry source, bypassing any
     * optional process-local near cache.
     *
     * <p>The default fails closed because a custom registry cannot otherwise
     * prove that a normal read reaches its storage authority. Registries whose
     * normal read is already authoritative may explicitly delegate to
     * {@link #getTicket(String, TicketIssuanceReadContext)}.</p>
     *
     * @param ticketId the id of the ticket to retrieve
     * @param context explicit issuance context
     * @return the requested ticket
     */
    default @Nullable Ticket getTicketFromSource(
        final String ticketId,
        final TicketIssuanceReadContext context) {
        Objects.requireNonNull(context, "context");
        throw new UnsupportedOperationException(
            "This ticket registry does not support authoritative source reads");
    }

    /**
     * Retrieve a ticket from the authoritative registry source using a
     * standard read context.
     *
     * @param ticketId the id of the ticket to retrieve
     * @return the requested ticket
     */
    default @Nullable Ticket getTicketFromSource(final String ticketId) {
        return getTicketFromSource(ticketId, TicketIssuanceReadContext.standard());
    }

    /**
     * Retrieve a typed ticket from the authoritative registry source.
     *
     * @param <T> ticket type
     * @param ticketId ticket identifier
     * @param clazz expected ticket class
     * @param context explicit issuance context
     * @return requested ticket
     */
    default <T extends Ticket> @Nullable T getTicketFromSource(
        final String ticketId,
        final Class<T> clazz,
        final TicketIssuanceReadContext context) {
        Objects.requireNonNull(clazz, "clazz");
        val ticket = getTicketFromSource(ticketId, context);
        if (ticket == null) {
            return null;
        }
        if (!clazz.isAssignableFrom(ticket.getClass())) {
            throw new ClassCastException("Ticket [" + ticket.getId() + " is of type "
                + ticket.getClass() + " when we were expecting " + clazz);
        }
        return clazz.cast(ticket);
    }

    /**
     * Retrieve a typed ticket from the authoritative registry source using a
     * standard read context.
     *
     * @param <T> ticket type
     * @param ticketId ticket identifier
     * @param clazz expected ticket class
     * @return requested ticket
     */
    default <T extends Ticket> @Nullable T getTicketFromSource(
        final String ticketId,
        final Class<T> clazz) {
        return getTicketFromSource(
            ticketId, clazz, TicketIssuanceReadContext.standard());
    }

    /**
     * Remove a specific ticket from the registry.
     * If ticket to delete is TGT then related service tickets are removed as well.
     *
     * @param ticketId The id of the ticket to delete.
     * @return the number of tickets deleted including children.
     * @throws Exception the exception
     */
    int deleteTicket(String ticketId) throws Exception;

    /**
     * Remove a specific ticket from the registry.
     * If ticket to delete is TGT then related service tickets, etc are removed as well.
     *
     * @param ticketId The id of the ticket to delete.
     * @return the number of tickets deleted including children.
     * @throws Exception the exception
     */
    int deleteTicket(Ticket ticketId) throws Exception;

    /**
     * Delete all tickets from the registry.
     *
     * @return the number of tickets deleted.
     */
    default long deleteAll() {
        return 0;
    }

    /**
     * Retrieve all tickets from the registry.
     *
     * @return collection of tickets currently stored in the registry. Tickets might or might not be valid i.e. expired.
     */
    default Collection<? extends Ticket> getTickets() {
        return List.of();
    }

    /**
     * Gets tickets as a stream having applied a predicate.
     * <p>
     * The returning stream may be bound to an IO channel (such as database connection),
     * so it should be properly closed after usage.
     *
     * @param predicate the predicate
     * @return the tickets
     */
    default Stream<? extends Ticket> getTickets(final Predicate<Ticket> predicate) {
        return stream().filter(predicate);
    }

    /**
     * Update the received ticket.
     *
     * @param ticket the ticket
     * @return the updated ticket
     * @throws Exception the exception
     */
    @Nullable Ticket updateTicket(Ticket ticket) throws Exception;

    /**
     * Update a ticket using exact protocol-supplied issuance coordinates.
     *
     * <p>The default fails closed because a custom registry that has not opted
     * into this contract cannot prove that it preserved the context. Existing
     * callers and implementations of {@link #updateTicket(Ticket)} are unchanged.</p>
     *
     * @param ticket ticket to update
     * @param context exact issuance write context
     * @return updated ticket
     * @throws Exception the exception
     */
    default @Nullable Ticket updateTicket(
        final Ticket ticket,
        final TicketIssuanceWriteContext context) throws Exception {
        Objects.requireNonNull(context, "context");
        throw new UnsupportedOperationException(
            "This ticket registry does not support an explicit issuance write context");
    }

    /**
     * Computes the number of SSO sessions stored in the ticket registry.
     *
     * @return Number of ticket-granting tickets in the registry at time of invocation or {@link Integer#MIN_VALUE} if unknown.
     */
    long sessionCount();

    /**
     * Computes the number of service tickets stored in the ticket registry.
     *
     * @return Number of service tickets in the registry at time of invocation or {@link Integer#MIN_VALUE} if unknown.
     */
    long serviceTicketCount();

    /**
     * Gets tickets stream.
     * <p>
     * The returning stream may be bound to an IO channel (such as database connection),
     * so it should be properly closed after usage.
     *
     * @return the tickets stream
     */
    default Stream<? extends Ticket> stream(final TicketRegistryStreamCriteria criteria) {
        return getTickets().parallelStream();
    }

    /**
     * Stream stream.
     *
     * @return the stream
     */
    default Stream<? extends Ticket> stream() {
        return stream(TicketRegistryStreamCriteria.builder().build());
    }

    /**
     * Count the number of single sign-on sessions
     * that are recorded in the ticket registry for
     * the given user name.
     *
     * @param principalId the principal id
     * @return the count
     */
    long countSessionsFor(String principalId);

    /**
     * Gets sessions for principal.
     *
     * @param principalId the principal id
     * @return the sessions for
     */
    default Stream<? extends Ticket> getSessionsFor(final String principalId) {
        return getTickets(ticket -> ticket instanceof final TicketGrantingTicket ticketGrantingTicket
            && !ticket.isExpired()
            && ticketGrantingTicket.getAuthentication().getPrincipal().getId().equals(principalId));
    }

    /**
     * Gets sessions for an application.
     *
     * @param service the service
     * @return the sessions for
     */
    default Stream<? extends Ticket> getTicketsFor(final Service service) {
        return Stream.empty();
    }

    /**
     * Gets tickets with authentication attributes.
     *
     * @param queryAttributes the query attributes
     * @return the tickets with authentication attributes
     */
    Stream<? extends Ticket> getSessionsWithAttributes(Map<String, List<Object>> queryAttributes);

    /**
     * Allows the registry to hash the given identifier, which may be the ticket id or the principdl id, etc.
     *
     * @param id the id
     * @return the string
     */
    String digestIdentifier(String id);

    /**
     * Query the registry and return the results.
     * This operations allows one to interact with the registry
     * in raw form without a lot of post-processing of the ticket objects.
     * Registry implementations are to decide which criteria options they wish to support.
     *
     * @param criteria the criteria
     * @return the results
     */
    default List<? extends Serializable> query(final TicketRegistryQueryCriteria criteria) {
        return new ArrayList<>();
    }

    /**
     * Count the number of tickets, given a type or prefix
     * that might have been issued for given application.
     *
     * @param service the service
     * @return total count
     */
    default long countTicketsFor(final Service service) {
        return getTicketsFor(service).count();
    }

    /**
     * Count all tickets.
     *
     * @return the total count.
     */
    default long countTickets() {
        return stream().count();
    }

    /**
     * Gets cipher executor.
     *
     * @return the cipher executor
     */
    CipherExecutor getCipherExecutor();

    /**
     * Delete tickets for given principal.
     *
     * @param principalId the principal id
     * @return deleted tickets count
     */
    long deleteTicketsFor(String principalId);
}
