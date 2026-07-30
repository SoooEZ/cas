package org.apereo.cas.ticket.registry.sub;

import module java.base;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.ticket.registry.pub.RedisMessagePayload;
import org.apereo.cas.util.PublisherIdentifier;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.val;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests authoritative cache refresh for out-of-order Redis messages.
 *
 * @author SoooEZ
 * @since 8.0.0
 */
@Tag("Redis")
class DefaultRedisTicketRegistryMessageListenerTests {

    private static final String TICKET_ID = "TGT-message-ticket";

    private static final String CACHE_KEY = "ticket-digest";

    private final TicketRegistry ticketRegistry = mock(TicketRegistry.class);

    private final Cache<String, Ticket> cache = Caffeine.newBuilder().build();

    private final PublisherIdentifier localIdentifier = new PublisherIdentifier("local");

    private DefaultRedisTicketRegistryMessageListener listener;

    @BeforeEach
    void initialize() {
        cache.invalidateAll();
        reset(ticketRegistry);
        when(ticketRegistry.digestIdentifier(TICKET_ID)).thenReturn(CACHE_KEY);
        listener = new DefaultRedisTicketRegistryMessageListener(ticketRegistry,
            localIdentifier, cache);
    }

    @Test
    void verifyDelayedAddCannotResurrectADeletedAuthoritativeTicket() {
        val stalePayload = ticket();
        cache.put(CACHE_KEY, stalePayload);
        listener.handleMessage(command(RedisMessagePayload.RedisMessageTypes.ADD, stalePayload), "tickets");

        assertNull(cache.getIfPresent(CACHE_KEY));
        verify(ticketRegistry, never()).getTicket(anyString());
    }

    @Test
    void verifyUpdateInvalidatesWithoutRacingAnAuthoritativeRefill() {
        val stalePayload = ticket();
        cache.put(CACHE_KEY, stalePayload);

        listener.handleMessage(command(RedisMessagePayload.RedisMessageTypes.UPDATE, stalePayload), "tickets");

        assertNull(cache.getIfPresent(CACHE_KEY));
        verify(ticketRegistry, never()).getTicket(anyString());
    }

    private static Ticket ticket() {
        val ticket = mock(Ticket.class);
        when(ticket.getId()).thenReturn(TICKET_ID);
        when(ticket.getPrefix()).thenReturn("TGT");
        return ticket;
    }

    private static RedisMessagePayload<Ticket> command(
        final RedisMessagePayload.RedisMessageTypes type, final Ticket ticket) {
        return RedisMessagePayload.<Ticket>builder()
            .identifier(new PublisherIdentifier("remote"))
            .messageType(type)
            .ticket(ticket)
            .build();
    }
}
