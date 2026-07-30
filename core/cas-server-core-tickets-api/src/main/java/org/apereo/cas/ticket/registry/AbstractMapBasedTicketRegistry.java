package org.apereo.cas.ticket.registry;

import module java.base;
import org.apereo.cas.ticket.AuthenticationAwareTicket;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.ticket.TicketCatalog;
import org.apereo.cas.ticket.registry.pubsub.QueueableTicketRegistry;
import org.apereo.cas.ticket.registry.pubsub.commands.AddTicketMessageQueueCommand;
import org.apereo.cas.ticket.registry.pubsub.commands.DeleteTicketMessageQueueCommand;
import org.apereo.cas.ticket.registry.pubsub.commands.DeleteTicketsMessageQueueCommand;
import org.apereo.cas.ticket.registry.pubsub.commands.UpdateTicketMessageQueueCommand;
import org.apereo.cas.ticket.registry.pubsub.queue.QueueableTicketRegistryMessagePublisher;
import org.apereo.cas.ticket.serialization.TicketSerializationManager;
import org.apereo.cas.util.PublisherIdentifier;
import org.apereo.cas.util.crypto.CipherExecutor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.springframework.context.ApplicationContext;

/**
 * This is {@link AbstractMapBasedTicketRegistry}.
 *
 * @author Misagh Moayyed
 * @since 5.2.0
 */
@Slf4j
public abstract class AbstractMapBasedTicketRegistry extends AbstractTicketRegistry implements QueueableTicketRegistry {

    protected final QueueableTicketRegistryMessagePublisher ticketPublisher;

    protected final PublisherIdentifier publisherIdentifier;

    public AbstractMapBasedTicketRegistry(final CipherExecutor cipherExecutor,
                                          final TicketSerializationManager ticketSerializationManager,
                                          final TicketCatalog ticketCatalog,
                                          final ApplicationContext applicationContext,
                                          final QueueableTicketRegistryMessagePublisher ticketPublisher,
                                          final PublisherIdentifier publisherIdentifier) {
        super(cipherExecutor, ticketSerializationManager, ticketCatalog, applicationContext);
        this.ticketPublisher = ticketPublisher;
        this.publisherIdentifier = publisherIdentifier;
    }

    @Override
    protected Ticket getSingleTicket(final String ticketId, final Predicate<Ticket> predicate) {
        val encTicketId = digestIdentifier(ticketId);
        if (StringUtils.isBlank(ticketId)) {
            return null;
        }
        val found = getMapInstance().get(encTicketId);
        if (found == null) {
            LOGGER.debug("Ticket [{}] could not be found", encTicketId);
            return null;
        }

        val result = decodeTicket(found);
        if (!predicate.test(result)) {
            LOGGER.debug("Cannot successfully fetch ticket [{}]", ticketId);
            return null;
        }
        return result;
    }

    @Override
    public long deleteAll() {
        val result = deleteAllFromQueue();
        if (ticketPublisher.isEnabled()) {
            ticketPublisher.publishMessageToQueue(new DeleteTicketsMessageQueueCommand(publisherIdentifier));
        }
        return result;
    }

    @Override
    protected Collection<? extends Ticket> getAllTickets() {
        return decodeTickets(getMapInstance().values());
    }

    @Override
    protected Ticket updateSingleTicket(final Ticket ticket) throws Exception {
        val result = writeTicketToQueue(ticket);

        if (ticketPublisher.isEnabled()) {
            LOGGER.trace("Publishing update command for id [{}] and ticket [{}]", publisherIdentifier, ticket.getId());
            val command = new UpdateTicketMessageQueueCommand(publisherIdentifier, ticket);
            ticketPublisher.publishMessageToQueue(command);
        }
        return result;
    }

    @Override
    public long deleteSingleTicket(final Ticket ticket) {
        val result = ticket != null ? deleteTicketFromQueue(ticket.getId()) : 0;
        if (ticketPublisher.isEnabled()) {
            LOGGER.trace("Publishing delete command for id [{}] and ticket [{}]", publisherIdentifier, ticket.getId());
            ticketPublisher.publishMessageToQueue(new DeleteTicketMessageQueueCommand(publisherIdentifier, ticket.getId()));
        }
        return result;
    }

    @Override
    protected Ticket addSingleTicket(final Ticket ticket) throws Exception {
        writeTicketToQueue(ticket);

        if (ticketPublisher.isEnabled()) {
            LOGGER.trace("Publishing add command for id [{}] and ticket [{}]", publisherIdentifier, ticket.getId());
            val command = new AddTicketMessageQueueCommand(publisherIdentifier, ticket);
            ticketPublisher.publishMessageToQueue(command);
        }
        return ticket;
    }

    @Override
    public void addTicketToQueue(final Ticket ticket) throws Exception {
        if (ticket == null || ticket.isExpired()) {
            return;
        }
        prepareTicketForWrite(ticket, TicketIssuancePolicy.Operation.ADD);
        writeTicketToQueue(ticket);
    }

    private Ticket writeTicketToQueue(final Ticket ticket) throws Exception {
        val encTicket = encodeTicket(ticket);
        LOGGER.debug("Putting ticket [{}] in registry.", ticket.getId());
        getMapInstance().put(encTicket.getId(), encTicket);
        return ticket;
    }

    @Override
    public Ticket updateTicketInQueue(final Ticket ticket) throws Exception {
        if (ticket == null || ticket.isExpired()) {
            return null;
        }
        prepareTicketForWrite(ticket, TicketIssuancePolicy.Operation.UPDATE);
        LOGGER.trace("Updating ticket [{}] in registry...", ticket.getId());
        return writeTicketToQueue(ticket);
    }

    @Override
    public long deleteTicketFromQueue(final String ticketId) {
        val encTicketId = digestIdentifier(ticketId);
        return !StringUtils.isBlank(encTicketId) && getMapInstance().remove(encTicketId) != null ? 1 : 0;
    }

    @Override
    public long deleteAllFromQueue() {
        val size = getMapInstance().size();
        getMapInstance().clear();
        return size;
    }

    @Override
    protected List<? extends Serializable> queryTickets(final TicketRegistryQueryCriteria criteria) {
        return getMapInstance()
            .values()
            .parallelStream()
            .filter(ticket -> criteria.getType().equals(ticket.getPrefix())
                && (StringUtils.isBlank(criteria.getId()) || digestIdentifier(criteria.getId()).equals(ticket.getId())))
            .map(ticket -> criteria.isDecode() ? decodeTicket(ticket) : ticket)
            .filter(ticket -> StringUtils.isBlank(criteria.getPrincipal())
                || (ticket instanceof final AuthenticationAwareTicket aat
                    && Strings.CI.equals(criteria.getPrincipal(), aat.getAuthentication().getPrincipal().getId())))
            .limit(criteria.getCount() > 0 ? criteria.getCount() : Long.MAX_VALUE)
            .collect(Collectors.toList());
    }

    /**
     * Create map instance, which must ben created during initialization phases
     * and always be the same instance.
     *
     * @return the map
     */
    public abstract Map<String, Ticket> getMapInstance();
}
