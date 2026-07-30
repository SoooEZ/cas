package org.apereo.cas.ticket.registry;

import module java.base;

/**
 * Signals that ticket persistence completed but a post-write interceptor could not complete.
 *
 * <p>The stored ticket may be visible. Callers must not blindly retry the write; the
 * interceptor implementation is responsible for reconciling its durable write context.</p>
 *
 * @author SoooEZ
 * @since 8.0.0
 */
public final class TicketRegistryWriteCompletionException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1704774381902898936L;

    private final String ticketId;

    private final TicketRegistryWriteInterceptor.Operation operation;

    public TicketRegistryWriteCompletionException(final String ticketId,
                                                   final TicketRegistryWriteInterceptor.Operation operation,
                                                   final Throwable cause) {
        super("Ticket %s was persisted, but its %s completion callback failed".formatted(ticketId, operation), cause);
        this.ticketId = ticketId;
        this.operation = operation;
    }

    public String getTicketId() {
        return ticketId;
    }

    public TicketRegistryWriteInterceptor.Operation getOperation() {
        return operation;
    }
}
