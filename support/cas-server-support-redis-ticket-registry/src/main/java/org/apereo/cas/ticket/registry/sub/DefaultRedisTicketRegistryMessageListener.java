package org.apereo.cas.ticket.registry.sub;

import module java.base;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.ticket.registry.pub.RedisMessagePayload;
import org.apereo.cas.util.PublisherIdentifier;
import com.github.benmanes.caffeine.cache.Cache;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;

/**
 * This is {@link DefaultRedisTicketRegistryMessageListener}.
 *
 * @author Misagh Moayyed
 * @since 7.0.0
 */
@RequiredArgsConstructor
@Slf4j
public class DefaultRedisTicketRegistryMessageListener implements RedisTicketRegistryMessageListener {
    private final TicketRegistry ticketRegistry;
    private final PublisherIdentifier publisherIdentifier;
    private final Cache<String, Ticket> ticketCache;

    @Override
    public void handleMessage(final RedisMessagePayload command, final String topic) {
        if (!publisherIdentifier.equals(command.getIdentifier())) {
            LOGGER.trace("Processing Redis message payload [{}] at [{}]", command, publisherIdentifier);
            switch (command.getMessageType()) {
                case ADD, UPDATE -> {
                    val result = getMessageResultForAddOrUpdate(command);
                    ticketCache.invalidate(result.cacheKey());
                }
                case DELETE -> {
                    val result = getMessageResultForDelete(command);
                    ticketCache.invalidate(result.cacheKey());
                }
                case DELETE_ALL -> ticketCache.invalidateAll();
            }
        }
    }

    private MessageResult getMessageResultForAddOrUpdate(final RedisMessagePayload command) {
        val ticket = Objects.requireNonNull((Ticket) command.getTicket(),
            "Redis message payload is missing the ticket to add/update in the cache");
        val cacheKey = ticketRegistry.digestIdentifier(ticket.getId());
        return new MessageResult(cacheKey);
    }

    private static MessageResult getMessageResultForDelete(final RedisMessagePayload command) {
        return new MessageResult(command.getCacheKey());
    }

    private record MessageResult(String cacheKey) {
    }
}
