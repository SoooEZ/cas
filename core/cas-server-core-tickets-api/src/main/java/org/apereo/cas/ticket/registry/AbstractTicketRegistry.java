package org.apereo.cas.ticket.registry;

import module java.base;
import org.apereo.cas.authentication.CoreAuthenticationUtils;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.support.events.logout.CasRequestSingleLogoutEvent;
import org.apereo.cas.support.events.ticket.CasTicketGrantingTicketDestroyedEvent;
import org.apereo.cas.ticket.AuthenticationAwareTicket;
import org.apereo.cas.ticket.EncodedTicket;
import org.apereo.cas.ticket.InvalidTicketException;
import org.apereo.cas.ticket.ServiceAwareTicket;
import org.apereo.cas.ticket.ServiceTicket;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.ticket.TicketCatalog;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.ticket.proxy.ProxyGrantingTicket;
import org.apereo.cas.ticket.serialization.TicketSerializationManager;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.util.DigestUtils;
import org.apereo.cas.util.LoggingUtils;
import org.apereo.cas.util.crypto.CipherExecutor;
import org.apereo.cas.util.function.FunctionUtils;
import org.apereo.cas.util.serialization.SerializationUtils;
import com.google.common.io.ByteSource;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.apereo.inspektr.common.web.ClientInfoHolder;
import org.jooq.lambda.Unchecked;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.context.ApplicationContext;

/**
 * Base ticket registry class that implements common ticket-related ops.
 *
 * @author Scott Battaglia
 * @since 3.0.0
 */
@Slf4j
public abstract class AbstractTicketRegistry implements TicketRegistry {

    private static final String TICKET_ENCRYPTION_LOG_MESSAGE = "Ticket encryption is not enabled. Falling back to default behavior";

    @Setter
    @Getter
    protected CipherExecutor cipherExecutor;

    protected final TicketSerializationManager ticketSerializationManager;

    protected final TicketCatalog ticketCatalog;

    protected final ApplicationContext applicationContext;

    private volatile TicketIssuancePolicy ticketIssuancePolicy;

    public AbstractTicketRegistry(final CipherExecutor cipherExecutor,
                                  final TicketSerializationManager ticketSerializationManager,
                                  final TicketCatalog ticketCatalog,
                                  final ApplicationContext applicationContext) {
        this.cipherExecutor = cipherExecutor;
        this.ticketSerializationManager = ticketSerializationManager;
        this.ticketCatalog = ticketCatalog;
        this.applicationContext = applicationContext;
    }

    protected String getPrincipalIdFrom(final Ticket ticket) {
        return ticket instanceof final AuthenticationAwareTicket authenticationAwareTicket
            ? Optional.ofNullable(authenticationAwareTicket.getAuthentication())
            .map(auth -> auth.getPrincipal().getId()).orElse(StringUtils.EMPTY)
            : StringUtils.EMPTY;
    }

    protected Map collectAndDigestTicketAttributes(final Ticket ticket) {
        val currentAttributes = getCombinedTicketAttributes(ticket);
        if (isCipherExecutorEnabled()) {
            val encodedAttributes = new HashMap<String, Object>(currentAttributes.size());
            currentAttributes.forEach((key, value) -> {
                val allValues = digestIdentifier(value);
                if (!allValues.isEmpty()) {
                    encodedAttributes.put(digestIdentifier(key), allValues);
                }
            });
            return encodedAttributes;
        }
        return currentAttributes;
    }

    private static Map<String, List<Object>> getCombinedTicketAttributes(final Ticket ticket) {
        if (ticket instanceof final AuthenticationAwareTicket authnTicket) {
            val authentication = authnTicket.getAuthentication();
            if (authentication != null) {
                val attributes = new HashMap<>(authentication.getAttributes());
                val principal = authentication.getPrincipal();
                return CoreAuthenticationUtils.mergeAttributes(attributes, principal.getAttributes());
            }
        }
        return new HashMap<>();
    }

    @Override
    public long deleteTicketsFor(final String principalId) {
        try (val tickets = streamTickets(TicketRegistryStreamCriteria.builder().build())) {
            return tickets
                .filter(ticket -> ticket instanceof final AuthenticationAwareTicket aat
                    && Strings.CI.equals(aat.getAuthentication().getPrincipal().getId(), principalId))
                .mapToLong(ticket -> FunctionUtils.doAndHandle(() -> deleteTicket(ticket), t -> 0).get())
                .sum();
        }
    }

    @Override
    public final Ticket addTicket(final Ticket ticket) throws Exception {
        if (ticket == null || ticket.isExpired()) {
            return null;
        }
        prepareTicketForWrite(ticket, TicketIssuancePolicy.Operation.ADD);
        return addSingleTicket(ticket);
    }

    @Override
    public final Ticket addTicket(
        final Ticket ticket,
        final TicketIssuanceWriteContext context) throws Exception {
        Objects.requireNonNull(context, "context");
        if (ticket == null || ticket.isExpired()) {
            return null;
        }
        prepareTicketForWrite(ticket, TicketIssuancePolicy.Operation.ADD, context);
        return addSingleTicket(ticket, context);
    }

    @Override
    public final List<? extends Ticket> addTicket(final Stream<? extends Ticket> toSave) {
        val tickets = toSave
            .filter(Objects::nonNull)
            .filter(ticket -> !ticket.isExpired())
            .map(ticket -> prepareTicketForWrite(ticket, TicketIssuancePolicy.Operation.ADD));
        return addTickets(tickets);
    }

    protected List<? extends Ticket> addTickets(final Stream<? extends Ticket> tickets) {
        return tickets.map(Unchecked.function(this::addSingleTicket)).filter(Objects::nonNull).toList();
    }

    @Override
    public final @Nullable Ticket getTicket(final String ticketId) {
        return getTicket(ticketId, TicketIssuanceReadContext.standard());
    }

    @Override
    public final @Nullable Ticket getTicket(final String ticketId, final TicketIssuanceReadContext context) {
        return readTicket(ticketId, context, false);
    }

    @Override
    public final <T extends Ticket> T getTicket(final String ticketId, final @NonNull Class<T> clazz) {
        return getTicket(ticketId, clazz, TicketIssuanceReadContext.standard());
    }

    @Override
    public final <T extends Ticket> T getTicket(final String ticketId, final @NonNull Class<T> clazz,
                                                final TicketIssuanceReadContext context) {
        val ticket = getTicket(ticketId, context);
        return requireTicketType(ticketId, clazz, ticket);
    }

    @Override
    public final @Nullable Ticket getTicket(final String ticketId, final Predicate<Ticket> predicate) {
        return readTicketMatching(
            ticketId, predicate, TicketIssuanceReadContext.standard(), false);
    }

    @Override
    public final @Nullable Ticket getTicketFromSource(final String ticketId) {
        return getTicketFromSource(
            ticketId, TicketIssuanceReadContext.standard());
    }

    @Override
    public final @Nullable Ticket getTicketFromSource(
        final String ticketId,
        final TicketIssuanceReadContext context) {
        return readTicket(ticketId, context, true);
    }

    @Override
    public final <T extends Ticket> T getTicketFromSource(
        final String ticketId,
        final @NonNull Class<T> clazz) {
        return getTicketFromSource(
            ticketId, clazz, TicketIssuanceReadContext.standard());
    }

    @Override
    public final <T extends Ticket> T getTicketFromSource(
        final String ticketId,
        final @NonNull Class<T> clazz,
        final TicketIssuanceReadContext context) {
        val ticket = getTicketFromSource(ticketId, context);
        return requireTicketType(ticketId, clazz, ticket);
    }

    private static <T extends Ticket> T requireTicketType(
        final String ticketId,
        final Class<T> clazz,
        final @Nullable Ticket ticket) {
        if (ticket == null) {
            LOGGER.debug("Ticket [{}] with type [{}] cannot be found", ticketId, clazz.getSimpleName());
            throw new InvalidTicketException(ticketId);
        }
        if (!clazz.isAssignableFrom(ticket.getClass())) {
            throw new ClassCastException("Ticket [" + ticket.getId() + " is of type "
                + ticket.getClass() + " when we were expecting " + clazz);
        }
        return clazz.cast(ticket);
    }

    private @Nullable Ticket readTicket(
        final String ticketId,
        final TicketIssuanceReadContext context,
        final boolean authoritativeSource) {
        Objects.requireNonNull(context, "context");
        val returnTicket = readTicketMatching(ticketId, ticket -> {
            if (ticket.isExpired()) {
                val ticketAgeSeconds = getTicketAgeSeconds(ticket);
                LOGGER.debug("Ticket [{}] has expired according to policy [{}] after [{}] seconds and [{}] uses and will be removed from the ticket registry",
                    ticketId, ticket.getExpirationPolicy().getName(), ticketAgeSeconds, ticket.getCountOfUses());
                val clientInfo = ClientInfoHolder.getClientInfo();
                if (ticket instanceof final TicketGrantingTicket tgt) {
                    applicationContext.publishEvent(new CasRequestSingleLogoutEvent(this, tgt, clientInfo));
                }
                try {
                    deleteTicket(ticket);
                    if (ticket instanceof final TicketGrantingTicket tgt) {
                        applicationContext.publishEvent(new CasTicketGrantingTicketDestroyedEvent(this, tgt, clientInfo));
                    }
                } catch (final Exception e) {
                    LoggingUtils.warn(LOGGER, e);
                }
                return false;
            }
            return true;
        }, context, authoritativeSource);
        if (returnTicket != null) {
            val ticketAgeSeconds = getTicketAgeSeconds(returnTicket);
            if (ticketAgeSeconds < -1) {
                LOGGER.warn("Ticket created [{}] second(s) in the future. Check time synchronization on all servers.", ticketAgeSeconds * -1);
            }
        }
        return returnTicket;
    }

    private @Nullable Ticket readTicketMatching(
        final String ticketId,
        final Predicate<Ticket> predicate,
        final TicketIssuanceReadContext context,
        final boolean authoritativeSource) {
        Objects.requireNonNull(predicate, "predicate");
        val policyPredicate = (Predicate<Ticket>) ticket ->
            getTicketIssuancePolicy().isTicketReadable(ticket, context)
                && predicate.test(ticket);
        return authoritativeSource
            ? getSingleTicketFromSource(ticketId, policyPredicate)
            : getSingleTicket(ticketId, policyPredicate);
    }

    @Override
    public final @Nullable Ticket updateTicket(final Ticket ticket) throws Exception {
        if (ticket == null || ticket.isExpired()) {
            return null;
        }
        prepareTicketForWrite(ticket, TicketIssuancePolicy.Operation.UPDATE);
        return updateSingleTicket(ticket);
    }

    @Override
    public final @Nullable Ticket updateTicket(
        final Ticket ticket,
        final TicketIssuanceWriteContext context) throws Exception {
        Objects.requireNonNull(context, "context");
        if (ticket == null || ticket.isExpired()) {
            return null;
        }
        prepareTicketForWrite(ticket, TicketIssuancePolicy.Operation.UPDATE, context);
        return updateSingleTicket(ticket, context);
    }

    @Override
    public final Collection<? extends Ticket> getTickets() {
        return filterReadable(getAllTickets().stream(), TicketIssuanceReadContext.standard())
            .collect(Collectors.toList());
    }

    @Override
    public final Stream<? extends Ticket> getTickets(final Predicate<Ticket> predicate) {
        return stream().filter(predicate);
    }

    @Override
    public final Stream<? extends Ticket> stream() {
        return stream(TicketRegistryStreamCriteria.builder().build());
    }

    @Override
    public final Stream<? extends Ticket> stream(final TicketRegistryStreamCriteria criteria) {
        return filterReadable(streamTickets(criteria), TicketIssuanceReadContext.standard());
    }

    protected Stream<? extends Ticket> streamTickets(final TicketRegistryStreamCriteria criteria) {
        return getAllTickets().parallelStream();
    }

    protected Collection<? extends Ticket> getAllTickets() {
        return List.of();
    }

    @Override
    public final Stream<? extends Ticket> getSessionsFor(final String principalId) {
        return filterReadable(streamSessionsFor(principalId), TicketIssuanceReadContext.standard());
    }

    protected Stream<? extends Ticket> streamSessionsFor(final String principalId) {
        return streamTickets(TicketRegistryStreamCriteria.builder().build())
            .filter(ticket -> ticket instanceof final TicketGrantingTicket ticketGrantingTicket
                && !ticket.isExpired()
                && ticketGrantingTicket.getAuthentication().getPrincipal().getId().equals(principalId));
    }

    protected final TicketIssuancePolicy getTicketIssuancePolicy() {
        var policy = ticketIssuancePolicy;
        if (policy == null) {
            val provider = applicationContext != null
                ? applicationContext.getBeanProvider(TicketIssuancePolicy.class)
                : null;
            policy = provider != null
                ? provider.getIfAvailable(TicketIssuancePolicy::noOp)
                : TicketIssuancePolicy.noOp();
            ticketIssuancePolicy = policy;
        }
        return policy;
    }

    protected final Ticket prepareTicketForWrite(final Ticket ticket, final TicketIssuancePolicy.Operation operation) {
        getTicketIssuancePolicy().prepareForWrite(ticket, operation).ifPresent(metadata -> metadata.writeTo(ticket));
        return ticket;
    }

    protected final Ticket prepareTicketForWrite(
        final Ticket ticket,
        final TicketIssuancePolicy.Operation operation,
        final TicketIssuanceWriteContext context) {
        Objects.requireNonNull(context, "context");
        val persistedMetadata = TicketIssuanceMetadata.from(ticket);
        if (operation == TicketIssuancePolicy.Operation.UPDATE) {
            if (context.isManaged()) {
                context.requireConsistentWith(persistedMetadata.orElseThrow(() ->
                    new SecurityException(
                        "A managed ticket update requires persisted lifecycle metadata")));
            } else if (persistedMetadata.isPresent()) {
                throw new SecurityException(
                    "Managed ticket metadata cannot be downgraded to a non-capability write");
            }
        }

        val preparedMetadata = getTicketIssuancePolicy().prepareForWrite(ticket, operation, context);
        if (context.isManaged()) {
            val metadata = preparedMetadata.orElseThrow(() ->
                new SecurityException(
                    "A managed issuance context requires durable lifecycle metadata"));
            context.requireConsistentWith(metadata);
            metadata.writeTo(ticket);
        } else if (preparedMetadata.isPresent()) {
            throw new SecurityException(
                "A non-capability issuance context cannot produce managed lifecycle metadata");
        }
        return ticket;
    }

    @Override
    public int deleteTicket(final String ticketId) throws Exception {
        if (StringUtils.isBlank(ticketId)) {
            LOGGER.trace("No ticket id is provided for deletion");
            return 0;
        }
        val ticket = getSingleTicket(ticketId, _ -> true);
        if (ticket == null) {
            LOGGER.debug("Ticket [{}] could not be fetched from the registry; it may have been expired and deleted.", ticketId);
            return 0;
        }
        return deleteTicket(ticket);
    }

    @Override
    public int deleteTicket(final Ticket ticket) throws Exception {
        val count = new AtomicLong(0);
        if (ticket instanceof final TicketGrantingTicket tgt) {
            LOGGER.debug("Removing children of ticket [{}] from the registry.", ticket.getId());
            count.getAndAdd(deleteServiceTickets(tgt));
            if (ticket instanceof final ProxyGrantingTicket pgt) {
                deleteProxyGrantingTicketFromParent(pgt);
            } else {
                deleteLinkedProxyGrantingTickets(count, tgt);
            }
        }
        LOGGER.debug("Removing ticket [{}] from the registry.", ticket);
        count.getAndAdd(deleteSingleTicket(ticket));
        return count.intValue();
    }

    @Override
    public long sessionCount() {
        try (val tgtStream = stream().filter(TicketGrantingTicket.class::isInstance)) {
            return tgtStream.count();
        } catch (final Exception t) {
            LOGGER.trace("sessionCount() operation is not implemented by the ticket registry instance [{}]. "
                + "Message is: [{}] Returning unknown as [{}]", this.getClass().getName(), t.getMessage(), Long.MIN_VALUE);
            return Long.MIN_VALUE;
        }
    }

    @Override
    public long serviceTicketCount() {
        try (val stStream = stream().filter(ServiceTicket.class::isInstance)) {
            return stStream.count();
        } catch (final Exception t) {
            LOGGER.trace("serviceTicketCount() operation is not implemented by the ticket registry instance [{}]. "
                + "Message is: [{}] Returning unknown as [{}]", this.getClass().getName(), t.getMessage(), Long.MIN_VALUE);
            return Long.MIN_VALUE;
        }
    }

    @Override
    public long countSessionsFor(final String principalId) {
        val ticketPredicate = (Predicate<Ticket>) t -> {
            if (t instanceof final TicketGrantingTicket ticket) {
                return ticket.getAuthentication().getPrincipal().getId().equalsIgnoreCase(principalId);
            }
            return false;
        };
        return getTickets(ticketPredicate).count();
    }

    @Override
    public String digestIdentifier(final String identifier) {
        if (StringUtils.isBlank(identifier)) {
            return identifier;
        }
        if (!isCipherExecutorEnabled()) {
            LOGGER.trace(TICKET_ENCRYPTION_LOG_MESSAGE);
            return identifier;
        }
        val encodedId = DigestUtils.sha512(identifier);
        LOGGER.debug("Digested original ticket id [{}] to [{}]", identifier, encodedId);
        return encodedId;
    }

    protected List<String> digestIdentifier(final Collection<Object> identifiers) {
        return identifiers
            .stream()
            .map(Object::toString)
            .map(this::digestIdentifier)
            .collect(Collectors.toList());
    }

    @Override
    public final Stream<? extends Ticket> getTicketsFor(final Service service) {
        return filterReadable(streamTicketsFor(service), TicketIssuanceReadContext.standard());
    }

    protected Stream<? extends Ticket> streamTicketsFor(final Service service) {
        return streamTickets(TicketRegistryStreamCriteria.builder().build())
            .map(this::decodeTicket)
            .filter(ServiceAwareTicket.class::isInstance)
            .filter(ticket -> !ticket.isExpired())
            .map(ServiceAwareTicket.class::cast)
            .filter(ticket -> Objects.nonNull(ticket.getService()))
            .filter(ticket -> ticket.getService().getId().equals(service.getId()));
    }

    @Override
    public final Stream<? extends Ticket> getSessionsWithAttributes(final Map<String, List<Object>> queryAttributes) {
        return filterReadable(streamSessionsWithAttributes(queryAttributes), TicketIssuanceReadContext.standard());
    }

    protected Stream<? extends Ticket> streamSessionsWithAttributes(final Map<String, List<Object>> queryAttributes) {
        return streamTickets(TicketRegistryStreamCriteria.builder().build()).filter(ticket -> {
            if (ticket instanceof final TicketGrantingTicket ticketGrantingTicket && !ticket.isExpired()
                && ticketGrantingTicket.getAuthentication() != null) {
                val attributes = collectAndDigestTicketAttributes(ticketGrantingTicket);

                return queryAttributes.entrySet().stream().anyMatch(queryEntry -> {
                    val attributeKey = digestIdentifier(queryEntry.getKey());

                    if (attributes.containsKey(attributeKey)) {

                        val authnAttributeValues = CollectionUtils.toCollection(attributes.get(attributeKey));

                        return authnAttributeValues.stream().anyMatch(value -> {
                            val attributeValue = value.toString();
                            return queryEntry.getValue()
                                .stream()
                                .map(queryValue -> digestIdentifier(queryValue.toString()))
                                .anyMatch(attributeValue::equalsIgnoreCase);
                        });
                    }
                    return false;
                });
            }
            return false;
        });
    }

    @Override
    public final List<? extends Serializable> query(final TicketRegistryQueryCriteria criteria) {
        val policy = getTicketIssuancePolicy();
        return queryTickets(criteria)
            .stream()
            .filter(Objects::nonNull)
            .filter(result -> result instanceof final Ticket ticket
                ? policy.isTicketReadable(ticket, TicketIssuanceReadContext.standard())
                : policy.isQueryResultReadable(result, criteria))
            .collect(Collectors.toList());
    }

    protected List<? extends Serializable> queryTickets(final TicketRegistryQueryCriteria criteria) {
        return List.of();
    }

    private Stream<? extends Ticket> filterReadable(final Stream<? extends Ticket> tickets,
                                                    final TicketIssuanceReadContext context) {
        return tickets
            .filter(Objects::nonNull)
            .filter(ticket -> getTicketIssuancePolicy().isTicketReadable(ticket, context));
    }

    protected long deleteSingleTicket(final Ticket ticket) {
        return 0;
    }

    protected abstract Ticket addSingleTicket(Ticket ticket) throws Exception;

    /**
     * Persist one ticket with exact protocol-supplied issuance coordinates.
     * Storage implementations that need the context should override this
     * method; the compatibility default delegates to the original persistence
     * method after the policy has received the context.
     *
     * @param ticket ticket to add
     * @param context exact issuance write context
     * @return persisted ticket
     * @throws Exception the exception
     */
    protected Ticket addSingleTicket(
        final Ticket ticket,
        final TicketIssuanceWriteContext context) throws Exception {
        Objects.requireNonNull(context, "context");
        return addSingleTicket(ticket);
    }

    protected abstract @Nullable Ticket getSingleTicket(String ticketId, Predicate<Ticket> predicate);

    /**
     * Read one ticket from the authoritative storage source. Implementations
     * with a process-local near cache must override this method and bypass it.
     * For registries without a separate near cache, the normal read is already
     * authoritative.
     *
     * @param ticketId ticket identifier
     * @param predicate ticket filter
     * @return ticket, or {@code null}
     */
    protected @Nullable Ticket getSingleTicketFromSource(
        final String ticketId,
        final Predicate<Ticket> predicate) {
        return getSingleTicket(ticketId, predicate);
    }

    protected abstract @Nullable Ticket updateSingleTicket(Ticket ticket) throws Exception;

    /**
     * Persist one ticket update with exact protocol-supplied issuance
     * coordinates.
     *
     * @param ticket ticket to update
     * @param context exact issuance write context
     * @return persisted ticket
     * @throws Exception the exception
     */
    protected @Nullable Ticket updateSingleTicket(
        final Ticket ticket,
        final TicketIssuanceWriteContext context) throws Exception {
        Objects.requireNonNull(context, "context");
        return updateSingleTicket(ticket);
    }

    protected int deleteTickets(final Set<String> tickets) {
        return deleteTickets(tickets.stream());
    }

    protected int deleteTickets(final Stream<String> tickets) {
        return tickets.mapToInt(Unchecked.toIntFunction(this::deleteTicket)).sum();
    }

    /**
     * Delete ticket-granting ticket's service tickets.
     *
     * @param ticket the ticket
     * @return the count of tickets that were removed including child tickets and zero if the ticket was not deleted
     */
    protected int deleteServiceTickets(final TicketGrantingTicket ticket) {
        val count = new AtomicLong(0);
        val services = ticket.getServices();
        if (services != null && !services.isEmpty()) {
            services.keySet()
                .stream()
                .map(ticketId -> getSingleTicket(ticketId, _ -> true))
                .filter(Objects::nonNull)
                .forEach(serviceTicket -> {
                    val deleteCount = deleteSingleTicket(serviceTicket);
                    if (deleteCount > 0) {
                        LOGGER.debug("Removed ticket [{}]", serviceTicket.getId());
                        count.getAndAdd(deleteCount);
                    } else {
                        LOGGER.debug("Unable to remove ticket [{}]", serviceTicket.getId());
                    }
                });
        }
        return count.intValue();
    }

    protected @Nullable Ticket encodeTicket(final Ticket ticket) throws Exception {
        if (!isCipherExecutorEnabled()) {
            LOGGER.trace(TICKET_ENCRYPTION_LOG_MESSAGE);
            return ticket;
        }
        if (ticket == null) {
            LOGGER.debug("Ticket passed is null and cannot be encoded");
            return null;
        }
        val encodedTicket = createEncodedTicket(ticket);
        LOGGER.debug("Created encoded ticket [{}]", encodedTicket);
        return encodedTicket;
    }

    protected @Nullable Ticket decodeTicket(final Ticket ticketToProcess) {
        if (ticketToProcess instanceof EncodedTicket && !isCipherExecutorEnabled()) {
            LOGGER.warn("Found removable encoded ticket [{}] yet cipher operations are disabled.", ticketToProcess.getId());
            FunctionUtils.doUnchecked(_ -> deleteTicket(ticketToProcess));
            return null;
        }

        if (!isCipherExecutorEnabled()) {
            LOGGER.trace(TICKET_ENCRYPTION_LOG_MESSAGE);
            return ticketToProcess;
        }
        if (ticketToProcess == null) {
            LOGGER.warn("Ticket passed is null and cannot be decoded");
            return null;
        }
        if (!(ticketToProcess instanceof final EncodedTicket encodedTicket)) {
            LOGGER.debug("Ticket passed is not an encoded ticket: [{}], no decoding is necessary.",
                ticketToProcess.getClass().getSimpleName());
            return ticketToProcess;
        }
        LOGGER.debug("Attempting to decode [{}]", ticketToProcess);
        val ticket = decodeAndDeserialize(encodedTicket.getEncodedTicket());
        LOGGER.debug("Decoded ticket to [{}]", ticket);
        return ticket;
    }

    protected Ticket decodeAndDeserialize(final byte[] encodedTicket) {
        return SerializationUtils.decodeAndDeserializeObject(encodedTicket, this.cipherExecutor, Ticket.class);
    }

    protected Collection<Ticket> decodeTickets(final Collection<Ticket> items) {
        return decodeTickets(items.stream()).collect(Collectors.toSet());
    }

    protected Stream<Ticket> decodeTickets(final Stream<Ticket> items) {
        if (!isCipherExecutorEnabled()) {
            LOGGER.trace(TICKET_ENCRYPTION_LOG_MESSAGE);
            return items;
        }
        return items.map(this::decodeTicket);
    }

    protected boolean isCipherExecutorEnabled() {
        return this.cipherExecutor != null && this.cipherExecutor.isEnabled();
    }

    protected String serializeTicket(final Ticket ticket) {
        return ticketSerializationManager.serializeTicket(ticket);
    }

    protected Ticket createEncodedTicket(final Ticket ticket) throws Exception {
        LOGGER.debug("Encoding ticket [{}]", ticket);
        val encodedTicketObject = serializeAndEncodeTicket(ticket);
        return toEncodedTicket(ticket, encodedTicketObject);
    }

    protected byte[] serializeAndEncodeTicket(final Ticket ticket) {
        return SerializationUtils.serializeAndEncodeObject(cipherExecutor, ticket);
    }

    protected Ticket toEncodedTicket(final Ticket ticket, final byte[] encodedTicketObject) throws Exception {
        val encodedTicketId = digestIdentifier(ticket.getId());
        return new DefaultEncodedTicket(encodedTicketId,
            ByteSource.wrap(encodedTicketObject).read(), ticket.getPrefix());
    }

    private void deleteLinkedProxyGrantingTickets(final AtomicLong count,
                                                  final TicketGrantingTicket tgt) throws Exception {
        val pgts = new LinkedHashSet<>(tgt.getProxyGrantingTickets().keySet());
        val hasPgts = !pgts.isEmpty();
        count.getAndAdd(deleteTickets(pgts));
        if (hasPgts) {
            LOGGER.debug("Removing proxy-granting tickets from parent ticket-granting ticket");
            tgt.getProxyGrantingTickets().clear();
            updateTicket(tgt);
        }
    }

    private void deleteProxyGrantingTicketFromParent(final ProxyGrantingTicket ticket) throws Exception {
        if (ticket.getTicketGrantingTicket() instanceof final TicketGrantingTicket tgt) {
            tgt.getProxyGrantingTickets().remove(ticket.getId());
            updateTicket(tgt);
        }
    }

    private static long getTicketAgeSeconds(final @NonNull Ticket ticket) {
        return ZonedDateTime.now(ticket.getExpirationPolicy().getClock()).toEpochSecond() - ticket.getCreationTime().toEpochSecond();
    }

    protected Ticket deserializeTicket(final String ticketContent, final String type) {
        return ticketSerializationManager.deserializeTicket(ticketContent, type);
    }
}
