package org.apereo.cas.ticket.registry;

import module java.base;
import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.ticket.DefaultTicketCatalog;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.ticket.TicketGrantingTicketImpl;
import org.apereo.cas.ticket.TransientSessionTicketImpl;
import org.apereo.cas.ticket.expiration.NeverExpiresExpirationPolicy;
import org.apereo.cas.ticket.serialization.TicketSerializationManager;
import org.apereo.cas.util.crypto.CipherExecutor;
import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.GenericApplicationContext;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link TicketIssuancePolicy} integration with {@link AbstractTicketRegistry}.
 *
 * @author SoooEZ
 * @since 8.0.0
 */
@Tag("Tickets")
class AbstractTicketRegistryIssuancePolicyTests {

    @Test
    void verifyNoOpPolicyPreservesDefaultBehavior() throws Throwable {
        try (val context = new GenericApplicationContext()) {
            context.refresh();
            val registry = new MemoryTicketRegistry(context);
            val ticket = newTicket("TST-default");

            assertSame(ticket, registry.addTicket(ticket));
            assertSame(ticket, registry.getTicket(ticket.getId()));
            assertTrue(TicketIssuanceMetadata.from(ticket).isEmpty());
            assertEquals(List.of("opaque"), registry.query(
                TicketRegistryQueryCriteria.builder().decode(false).build()));
        }
    }

    @Test
    void verifyAuthoritativeSourceReadUsesDedicatedStorageSeam() throws Throwable {
        try (val context = new GenericApplicationContext()) {
            context.refresh();
            val registry = new MemoryTicketRegistry(context);
            val ticket = newTicket("TST-authoritative-source");
            registry.addTicket(ticket);

            assertSame(ticket, registry.getTicketFromSource(ticket.getId()));
            assertSame(ticket, registry.getTicketFromSource(
                ticket.getId(), TransientSessionTicketImpl.class));
            assertEquals(2, registry.authoritativeSourceReads.get());
        }
    }

    @Test
    void verifyMetadataAndExplicitActiveIntentRead() throws Throwable {
        val policy = new TestIssuancePolicy();
        try (val context = applicationContextWith(policy)) {
            val registry = new MemoryTicketRegistry(context);
            val ticket = newTicket("TST-managed");

            assertSame(ticket, registry.addTicket(ticket));
            assertEquals(policy.metadata, TicketIssuanceMetadata.from(ticket).orElseThrow());
            assertNull(registry.getTicket(ticket.getId()));
            assertNull(registry.getTicket(ticket.getId(), _ -> true));
            assertTrue(registry.getTickets().isEmpty());
            assertEquals(0, registry.stream().count());
            assertEquals(0, registry.getSessionsFor("subject-1").count());
            assertEquals(0, registry.getTicketsFor(mock(Service.class)).count());
            assertEquals(0, registry.getSessionsWithAttributes(Map.of()).count());
            assertTrue(registry.query(TicketRegistryQueryCriteria.builder().decode(true).build()).isEmpty());
            assertNull(registry.getTicket(ticket.getId(), TicketIssuanceReadContext.forIntent("another-intent")));

            val issuanceContext = TicketIssuanceReadContext.forIntent(policy.metadata.intentId());
            assertSame(ticket, registry.getTicket(ticket.getId(), issuanceContext));
            assertSame(ticket, registry.getTicket(ticket.getId(), TransientSessionTicketImpl.class, issuanceContext));
            assertSame(ticket, registry.updateTicket(ticket));
            assertEquals(TicketIssuancePolicy.Operation.UPDATE, policy.operations.getLast());

            policy.intentActive.set(false);
            assertNull(registry.getTicket(ticket.getId(), issuanceContext));
            policy.committed.set(true);
            assertSame(ticket, registry.getTicket(ticket.getId()));
            assertEquals(1, registry.getSessionsFor("subject-1").count());
            assertEquals(1, registry.getTicketsFor(mock(Service.class)).count());
            assertEquals(1, registry.getSessionsWithAttributes(Map.of()).count());
            assertEquals(1, registry.query(TicketRegistryQueryCriteria.builder().decode(true).build()).size());
        }
    }

    @Test
    void verifyPolicyFailuresAreFailClosed() throws Throwable {
        val policy = new TestIssuancePolicy();
        try (val context = applicationContextWith(policy)) {
            val registry = new MemoryTicketRegistry(context);
            val rejected = newTicket("TST-rejected");
            policy.failIssuance.set(true);

            assertThrows(SecurityException.class, () -> registry.addTicket(rejected));
            assertFalse(registry.contains(rejected.getId()));

            policy.failIssuance.set(false);
            val ticket = newTicket("TST-read-failure");
            registry.addTicket(ticket);
            policy.failRead.set(true);
            assertThrows(SecurityException.class, () -> registry.getTicket(ticket.getId()));
        }
    }

    @Test
    void verifyExplicitContextIsPassedUnchangedForAddAndUpdate() throws Throwable {
        val policy = new TestIssuancePolicy();
        val writeContext = accountWriteContext(7, "intent-1");
        try (val context = applicationContextWith(policy)) {
            val registry = new MemoryTicketRegistry(context);
            val ticket = newTicket("TST-explicit-context");

            assertSame(ticket, registry.addTicket(ticket, writeContext));
            assertSame(ticket, registry.updateTicket(ticket, writeContext));

            assertEquals(List.of(
                TicketIssuancePolicy.Operation.ADD,
                TicketIssuancePolicy.Operation.UPDATE), policy.explicitOperations);
            assertEquals(2, policy.explicitContexts.size());
            assertSame(writeContext, policy.explicitContexts.getFirst());
            assertSame(writeContext, policy.explicitContexts.getLast());
            assertEquals(2, registry.writeContexts.size());
            assertSame(writeContext, registry.writeContexts.getFirst());
            assertSame(writeContext, registry.writeContexts.getLast());
        }
    }

    @Test
    void verifyExplicitManagedContextRequiresPolicyMetadata() throws Throwable {
        try (val context = new GenericApplicationContext()) {
            context.refresh();
            val registry = new MemoryTicketRegistry(context);
            val ticket = newTicket("TST-explicit-no-policy");

            assertThrows(SecurityException.class,
                () -> registry.addTicket(ticket, accountWriteContext(7, "intent-1")));
            assertFalse(registry.contains(ticket.getId()));
        }
    }

    @Test
    void verifyLegacyPolicyCannotSilentlyIgnoreExplicitContext() throws Throwable {
        val legacyPolicy = new TicketIssuancePolicy() {
            @Override
            public Optional<TicketIssuanceMetadata> prepareForWrite(
                final Ticket ticket,
                final Operation operation) {
                return Optional.of(new TicketIssuanceMetadata("subject-1", 7, "intent-1"));
            }
        };
        try (val context = applicationContextWith(legacyPolicy)) {
            val registry = new MemoryTicketRegistry(context);
            val legacyTicket = newTicket("TST-legacy-policy");
            val explicitTicket = newTicket("TST-legacy-policy-explicit");

            assertSame(legacyTicket, registry.addTicket(legacyTicket));
            assertThrows(UnsupportedOperationException.class,
                () -> registry.addTicket(explicitTicket, accountWriteContext(7, "intent-1")));
            assertFalse(registry.contains(explicitTicket.getId()));
        }
    }

    @Test
    void verifyNoOpPolicyExplicitlyAdmitsOnlyNonCapabilityContext() throws Throwable {
        try (val context = new GenericApplicationContext()) {
            context.refresh();
            val registry = new MemoryTicketRegistry(context);
            val ticket = newTicket("TST-explicit-non-capability");
            val writeContext = TicketIssuanceWriteContext.explicitNonCapability(
                TicketIssuanceWriteContext.ProtocolFamily.CUSTOM,
                "AUDIT_RECORD",
                "CUSTOM_STATE",
                null);

            assertSame(ticket, registry.addTicket(ticket, writeContext));
            assertSame(writeContext, registry.writeContexts.getFirst());
            assertTrue(TicketIssuanceMetadata.from(ticket).isEmpty());
        }
    }

    @Test
    void verifyExplicitUpdateCannotChangePersistedLifecycleCoordinates() throws Throwable {
        val policy = new TestIssuancePolicy();
        val writeContext = accountWriteContext(7, "intent-1");
        try (val context = applicationContextWith(policy)) {
            val registry = new MemoryTicketRegistry(context);
            val ticket = newTicket("TST-explicit-update");
            registry.addTicket(ticket, writeContext);

            assertThrows(IllegalStateException.class,
                () -> registry.updateTicket(ticket, accountWriteContext(8, "intent-1")));
            assertThrows(IllegalStateException.class,
                () -> registry.updateTicket(ticket, accountWriteContext(7, "intent-2")));
            assertThrows(SecurityException.class, () -> registry.updateTicket(ticket,
                TicketIssuanceWriteContext.explicitNonCapability(
                    TicketIssuanceWriteContext.ProtocolFamily.CUSTOM,
                    "AUDIT_RECORD",
                    "CUSTOM_STATE",
                    null)));
            assertEquals(1, registry.writeContexts.size());
        }
    }

    @Test
    void verifyManagedUpdateCannotRetrofitUnmanagedTicket() throws Throwable {
        val policy = new TestIssuancePolicy();
        try (val context = applicationContextWith(policy)) {
            val registry = new MemoryTicketRegistry(context);
            val ticket = newTicket("TST-unmanaged-update");

            assertThrows(SecurityException.class,
                () -> registry.updateTicket(ticket, accountWriteContext(7, "intent-1")));
            assertFalse(registry.contains(ticket.getId()));
            assertTrue(policy.explicitContexts.isEmpty());
        }
    }

    @Test
    void verifyOpaqueQueryResultsFailClosedForManagedPolicy() throws Throwable {
        val policy = new TestIssuancePolicy();
        try (val context = applicationContextWith(policy)) {
            val registry = new MemoryTicketRegistry(context);
            registry.addTicket(newTicket("TST-opaque"));

            assertTrue(registry.query(
                TicketRegistryQueryCriteria.builder().decode(false).build()).isEmpty());
        }
    }

    @Test
    void verifyExpiredUpdatesCannotReachStorage() throws Throwable {
        try (val context = new GenericApplicationContext()) {
            context.refresh();
            val registry = new MemoryTicketRegistry(context);
            val expired = mock(Ticket.class);
            when(expired.getId()).thenReturn("TST-expired-update");
            when(expired.isExpired()).thenReturn(true);

            assertNull(registry.updateTicket(expired));
            assertFalse(registry.contains("TST-expired-update"));
        }
    }

    @Test
    void verifyPartialMetadataCannotBeInterpretedAsUnmanaged() {
        val ticket = newTicket("TST-partial");
        ticket.putProperty(TicketIssuanceMetadata.PROPERTY_SUBJECT_ID, "subject-1");
        assertThrows(IllegalStateException.class, () -> TicketIssuanceMetadata.from(ticket));
    }

    @Test
    void verifyMetadataRejectsInvalidGenerationAndOversizedIdentifiers() {
        assertThrows(IllegalArgumentException.class, () -> new TicketIssuanceMetadata("subject", 0, "intent"));
        assertThrows(IllegalArgumentException.class, () -> new TicketIssuanceMetadata("subject", -1, "intent"));
        assertThrows(IllegalArgumentException.class, () -> new TicketIssuanceMetadata(
            "s".repeat(TicketIssuanceMetadata.MAX_SUBJECT_ID_UTF8_BYTES + 1), 1, "intent"));
        assertThrows(IllegalArgumentException.class, () -> new TicketIssuanceMetadata(
            "subject", 1, "i".repeat(TicketIssuanceMetadata.MAX_INTENT_ID_UTF8_BYTES + 1)));
        assertThrows(IllegalArgumentException.class, () -> new TicketIssuanceMetadata(
            "界".repeat(TicketIssuanceMetadata.MAX_SUBJECT_ID_UTF8_BYTES / 3 + 1), 1, "intent"));
        assertThrows(IllegalArgumentException.class, () -> new TicketIssuanceMetadata("\uD800", 1, "intent"));
    }

    @Test
    void verifyMetadataRejectsMalformedAndOverflowingPersistedGeneration() {
        val malformed = newTicket("TST-malformed-generation");
        putMetadata(malformed, 1.5D);
        assertThrows(IllegalStateException.class, () -> TicketIssuanceMetadata.from(malformed));

        val overflowing = newTicket("TST-overflow-generation");
        putMetadata(overflowing, BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE));
        assertThrows(IllegalStateException.class, () -> TicketIssuanceMetadata.from(overflowing));
    }

    @Test
    void verifyUpdateCannotReplaceIssuanceMetadata() throws Throwable {
        val policy = new TestIssuancePolicy();
        try (val context = applicationContextWith(policy)) {
            val registry = new MemoryTicketRegistry(context);
            val ticket = newTicket("TST-immutable");
            registry.addTicket(ticket);
            policy.updateMetadata = new TicketIssuanceMetadata("subject-1", 8, "intent-2");

            assertThrows(IllegalStateException.class, () -> registry.updateTicket(ticket));
            assertEquals(policy.metadata, TicketIssuanceMetadata.from(ticket).orElseThrow());
        }
    }

    @Test
    void verifyAdministrativeDeletionBypassesReadDenial() throws Throwable {
        val policy = new TestIssuancePolicy();
        try (val context = applicationContextWith(policy)) {
            val registry = new MemoryTicketRegistry(context);
            val authentication = mock(Authentication.class);
            val principal = mock(Principal.class);
            when(authentication.getPrincipal()).thenReturn(principal);
            when(principal.getId()).thenReturn("subject-1");
            val ticket = new TicketGrantingTicketImpl("TGT-managed", authentication,
                NeverExpiresExpirationPolicy.INSTANCE);
            registry.addTicket(ticket);

            assertNull(registry.getTicket(ticket.getId()));
            assertEquals(1, registry.deleteTicketsFor("subject-1"));
            assertFalse(registry.contains(ticket.getId()));
        }
    }

    private static GenericApplicationContext applicationContextWith(final TicketIssuancePolicy policy) {
        val context = new GenericApplicationContext();
        context.registerBean(TicketIssuancePolicy.BEAN_NAME, TicketIssuancePolicy.class, () -> policy);
        context.refresh();
        return context;
    }

    private static TransientSessionTicketImpl newTicket(final String id) {
        return new TransientSessionTicketImpl(id, NeverExpiresExpirationPolicy.INSTANCE, null, Map.of());
    }

    private static TicketIssuanceWriteContext accountWriteContext(
        final long generation,
        final String intentId) {
        return TicketIssuanceWriteContext.managed(
            TicketIssuanceWriteContext.Classification.ACCOUNT_CAPABILITY,
            TicketIssuanceWriteContext.ProtocolFamily.CAS,
            "LOGIN",
            "CAS_TGT",
            0,
            1,
            intentId,
            new TicketIssuanceWriteContext.GenerationBinding(
                TicketIssuanceWriteContext.GenerationOwnerType.SUBJECT,
                "subject-1",
                generation),
            null);
    }

    private static void putMetadata(final TransientSessionTicketImpl ticket, final Serializable generation) {
        ticket.putProperty(TicketIssuanceMetadata.PROPERTY_SUBJECT_ID, "subject-1");
        ticket.putProperty(TicketIssuanceMetadata.PROPERTY_GENERATION, generation);
        ticket.putProperty(TicketIssuanceMetadata.PROPERTY_INTENT_ID, "intent-1");
    }

    private static final class TestIssuancePolicy implements TicketIssuancePolicy {
        private final TicketIssuanceMetadata metadata = new TicketIssuanceMetadata("subject-1", 7, "intent-1");

        private final AtomicBoolean intentActive = new AtomicBoolean(true);

        private final AtomicBoolean committed = new AtomicBoolean();

        private final AtomicBoolean failIssuance = new AtomicBoolean();

        private final AtomicBoolean failRead = new AtomicBoolean();

        private final List<TicketIssuancePolicy.Operation> operations = new CopyOnWriteArrayList<>();

        private final List<TicketIssuancePolicy.Operation> explicitOperations = new CopyOnWriteArrayList<>();

        private final List<TicketIssuanceWriteContext> explicitContexts = new CopyOnWriteArrayList<>();

        private volatile TicketIssuanceMetadata updateMetadata;

        @Override
        public Optional<TicketIssuanceMetadata> prepareForWrite(final Ticket ticket,
                                                                 final TicketIssuancePolicy.Operation operation) {
            if (failIssuance.get()) {
                throw new SecurityException("Issuance rejected");
            }
            operations.add(operation);
            return Optional.of(operation == TicketIssuancePolicy.Operation.UPDATE && updateMetadata != null
                ? updateMetadata
                : metadata);
        }

        @Override
        public Optional<TicketIssuanceMetadata> prepareForWrite(
            final Ticket ticket,
            final TicketIssuancePolicy.Operation operation,
            final TicketIssuanceWriteContext context) {
            explicitOperations.add(operation);
            explicitContexts.add(context);
            return prepareForWrite(ticket, operation);
        }

        @Override
        public boolean isTicketReadable(final Ticket ticket, final TicketIssuanceReadContext context) {
            if (failRead.get()) {
                throw new SecurityException("Read rejected");
            }
            val ticketMetadata = TicketIssuanceMetadata.from(ticket).orElseThrow();
            return committed.get() || (intentActive.get() && context.references(ticketMetadata));
        }
    }

    private static final class MemoryTicketRegistry extends AbstractTicketRegistry {
        private final Map<String, Ticket> tickets = new ConcurrentHashMap<>();

        private final List<TicketIssuanceWriteContext> writeContexts = new CopyOnWriteArrayList<>();

        private final AtomicInteger authoritativeSourceReads = new AtomicInteger();

        MemoryTicketRegistry(final ApplicationContext applicationContext) {
            super(CipherExecutor.noOp(), mock(TicketSerializationManager.class),
                new DefaultTicketCatalog(), applicationContext);
        }

        @Override
        protected Ticket addSingleTicket(final Ticket ticket) {
            tickets.put(ticket.getId(), ticket);
            return ticket;
        }

        @Override
        protected Ticket addSingleTicket(
            final Ticket ticket,
            final TicketIssuanceWriteContext context) {
            writeContexts.add(context);
            return addSingleTicket(ticket);
        }

        @Override
        protected Ticket getSingleTicket(final String ticketId, final Predicate<Ticket> predicate) {
            val ticket = tickets.get(ticketId);
            return ticket != null && predicate.test(ticket) ? ticket : null;
        }

        @Override
        protected Ticket getSingleTicketFromSource(
            final String ticketId,
            final Predicate<Ticket> predicate) {
            authoritativeSourceReads.incrementAndGet();
            return getSingleTicket(ticketId, predicate);
        }

        @Override
        protected Ticket updateSingleTicket(final Ticket ticket) {
            tickets.put(ticket.getId(), ticket);
            return ticket;
        }

        @Override
        protected Ticket updateSingleTicket(
            final Ticket ticket,
            final TicketIssuanceWriteContext context) {
            writeContexts.add(context);
            return updateSingleTicket(ticket);
        }

        @Override
        protected Collection<? extends Ticket> getAllTickets() {
            return List.copyOf(tickets.values());
        }

        @Override
        protected Stream<? extends Ticket> streamSessionsFor(final String principalId) {
            return tickets.values().stream();
        }

        @Override
        protected Stream<? extends Ticket> streamTicketsFor(final Service service) {
            return tickets.values().stream();
        }

        @Override
        protected Stream<? extends Ticket> streamSessionsWithAttributes(final Map<String, List<Object>> queryAttributes) {
            return tickets.values().stream();
        }

        @Override
        protected List<? extends Serializable> queryTickets(final TicketRegistryQueryCriteria criteria) {
            return criteria.isDecode() ? List.copyOf(tickets.values()) : List.of("opaque");
        }

        @Override
        protected long deleteSingleTicket(final Ticket ticket) {
            return tickets.remove(ticket.getId()) != null ? 1 : 0;
        }

        boolean contains(final String ticketId) {
            return tickets.containsKey(ticketId);
        }
    }
}
