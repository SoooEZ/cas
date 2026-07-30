package org.apereo.cas.ticket.registry;

import module java.base;
import org.apereo.cas.authentication.CoreAuthenticationTestUtils;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.ticket.TicketGrantingTicketImpl;
import org.apereo.cas.ticket.expiration.NeverExpiresExpirationPolicy;
import org.apereo.cas.ticket.registry.pub.RedisTicketRegistryMessagePublisher;
import org.apereo.cas.util.TicketGrantingTicketIdGenerator;
import org.apereo.cas.util.junit.EnabledIfListeningOnPort;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.test.context.TestPropertySource;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests the exact Redis persistence interception boundary.
 *
 * @author SoooEZ
 * @since 8.0.0
 */
@EnabledIfListeningOnPort(port = 6379)
@Tag("Redis")
@Import(RedisTicketRegistryWriteInterceptorTests.InterceptorConfiguration.class)
@TestPropertySource(properties = {
    "cas.ticket.registry.redis.host=localhost",
    "cas.ticket.registry.redis.port=6379",
    "cas.ticket.registry.redis.cache.cache-size=0",
    "cas.ticket.registry.redis.enable-redis-search=false"
})
class RedisTicketRegistryWriteInterceptorTests extends BaseRedisSentinelTicketRegistryTests {

    @Autowired
    @Qualifier("firstTicketRegistryWriteInterceptor")
    private RecordingInterceptor firstInterceptor;

    @Autowired
    @Qualifier("secondTicketRegistryWriteInterceptor")
    private RecordingInterceptor secondInterceptor;

    @Autowired
    @Qualifier("ticketRegistryWriteEventLog")
    private EventLog eventLog;

    @Autowired
    @Qualifier("redisTicketRegistryWriteExecutor")
    private RecordingWriteExecutor writeExecutor;

    @Autowired
    @Qualifier("redisTicketRegistryMessagePublisher")
    private RecordingPublisher messagePublisher;

    @Autowired
    @Qualifier("explicitContextIssuancePolicy")
    private ExplicitContextIssuancePolicy issuancePolicy;

    @BeforeEach
    void resetInterceptor() {
        eventLog.reset();
        firstInterceptor.reset();
        secondInterceptor.reset();
        writeExecutor.reset();
        messagePublisher.reset();
        issuancePolicy.reset();
    }

    @RepeatedTest(1)
    void verifyAddAndUpdateAreInterceptedAroundPersistence() throws Throwable {
        val ticket = ticket();
        getNewTicketRegistry().addTicket(ticket);
        getNewTicketRegistry().updateTicket(ticket);

        assertEquals(List.of(
            "first:before:ADD:" + ticket.getId(),
            "second:before:ADD:" + ticket.getId(),
            "second:success:ADD:" + ticket.getId(),
            "first:success:ADD:" + ticket.getId(),
            "first:before:UPDATE:" + ticket.getId(),
            "second:before:UPDATE:" + ticket.getId(),
            "second:success:UPDATE:" + ticket.getId(),
            "first:success:UPDATE:" + ticket.getId()), eventLog.events());
        assertEquals(List.of(
            TicketRegistryWriteInterceptor.Operation.ADD,
            TicketRegistryWriteInterceptor.Operation.UPDATE), writeExecutor.operations());
        assertEquals(List.of("ADD:" + ticket.getId(), "UPDATE:" + ticket.getId()),
            messagePublisher.operations());
        assertTrue(writeExecutor.issuanceContexts().stream().allMatch(Optional::isEmpty));
        assertTrue(firstInterceptor.admittedContexts().isEmpty());
        assertTrue(secondInterceptor.admittedContexts().isEmpty());
    }

    @RepeatedTest(1)
    void verifyExplicitContextIdentityReachesEntireWriteAndReceiptChain() throws Throwable {
        val ticket = ticket();
        val context = TicketIssuanceWriteContext.managed(
            TicketIssuanceWriteContext.Classification.ACCOUNT_CAPABILITY,
            TicketIssuanceWriteContext.ProtocolFamily.CAS,
            "LOGIN",
            "CAS_TGT",
            0,
            1,
            "intent-1",
            new TicketIssuanceWriteContext.GenerationBinding(
                TicketIssuanceWriteContext.GenerationOwnerType.SUBJECT,
                CoreAuthenticationTestUtils.CONST_USERNAME,
                7),
            null);

        getNewTicketRegistry().addTicket(ticket, context);
        getNewTicketRegistry().updateTicket(ticket, context);

        assertEquals(2, issuancePolicy.contexts().size());
        issuancePolicy.contexts().forEach(value -> assertSame(context, value));
        assertEquals(2, writeExecutor.issuanceContexts().size());
        writeExecutor.issuanceContexts()
            .forEach(value -> assertSame(context, value.orElseThrow()));
        assertEquals(2, firstInterceptor.admittedContexts().size());
        assertEquals(2, secondInterceptor.admittedContexts().size());
        firstInterceptor.admittedContexts().forEach(value -> assertSame(context, value));
        secondInterceptor.admittedContexts().forEach(value -> assertSame(context, value));
        firstInterceptor.completedContexts().forEach(value -> assertSame(context, value));
        secondInterceptor.completedContexts().forEach(value -> assertSame(context, value));
        assertSame(writeExecutor.receipts().getFirst(), firstInterceptor.receipts().getFirst());
        assertSame(writeExecutor.receipts().getFirst(), secondInterceptor.receipts().getFirst());
        assertSame(writeExecutor.receipts().getLast(), firstInterceptor.receipts().getLast());
        assertSame(writeExecutor.receipts().getLast(), secondInterceptor.receipts().getLast());
    }

    @RepeatedTest(1)
    void verifyRejectedAdmissionCannotReachRedis() {
        val ticket = ticket();
        secondInterceptor.setReject(true);

        assertThrows(IllegalStateException.class,
            () -> getNewTicketRegistry().addTicket(ticket));
        assertNull(getNewTicketRegistry().getTicket(ticket.getId()));
        assertEquals(List.of(
            "first:before:ADD:" + ticket.getId(),
            "second:before:ADD:" + ticket.getId(),
            "first:failure:ADD:" + ticket.getId()), eventLog.events());
        assertTrue(writeExecutor.operations().isEmpty());
    }

    @RepeatedTest(1)
    void verifyCompletionFailureReportsPersistedOutcomeAndCompletesOuterContext() throws Throwable {
        val ticket = ticket();
        secondInterceptor.setFailCompletion(true);

        val exception = assertThrows(TicketRegistryWriteCompletionException.class,
            () -> getNewTicketRegistry().addTicket(ticket));
        assertEquals(ticket.getId(), exception.getTicketId());
        assertEquals(TicketRegistryWriteInterceptor.Operation.ADD, exception.getOperation());
        assertNotNull(getNewTicketRegistry().getTicket(ticket.getId()));
        assertEquals(List.of(
            "first:before:ADD:" + ticket.getId(),
            "second:before:ADD:" + ticket.getId(),
            "second:success:ADD:" + ticket.getId(),
            "first:success:ADD:" + ticket.getId()), eventLog.events());
        assertEquals(List.of(TicketRegistryWriteInterceptor.Operation.ADD), writeExecutor.operations());
        assertEquals(List.of("ADD:" + ticket.getId()), messagePublisher.operations());
    }

    @RepeatedTest(1)
    void verifyBulkWritesCompleteEachPersistenceBoundary() throws Throwable {
        val first = ticket();
        val second = ticket();

        val saved = getNewTicketRegistry().addTicket(Stream.of(first, second));

        assertEquals(2, saved.size());
        assertNotNull(getNewTicketRegistry().getTicket(first.getId()));
        assertNotNull(getNewTicketRegistry().getTicket(second.getId()));
        assertEquals("first:before:ADD:" + first.getId(), eventLog.events().getFirst());
        assertEquals("first:success:ADD:" + second.getId(), eventLog.events().getLast());
        assertEquals(2, writeExecutor.operations().size());
    }

    @RepeatedTest(1)
    void verifyExecutorFailureRunsInterceptorFailureCallbacksInReverseOrder() {
        val ticket = ticket();
        writeExecutor.setReject(true);

        assertThrows(IllegalStateException.class,
            () -> getNewTicketRegistry().addTicket(ticket));
        assertNull(getNewTicketRegistry().getTicket(ticket.getId()));
        assertEquals(List.of(
            "first:before:ADD:" + ticket.getId(),
            "second:before:ADD:" + ticket.getId(),
            "second:failure:ADD:" + ticket.getId(),
            "first:failure:ADD:" + ticket.getId()), eventLog.events());
    }

    private static Ticket ticket() {
        val id = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
            .getNewTicketId(TicketGrantingTicket.PREFIX);
        return new TicketGrantingTicketImpl(id,
            CoreAuthenticationTestUtils.getAuthentication(), NeverExpiresExpirationPolicy.INSTANCE);
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class InterceptorConfiguration {

        @Bean
        EventLog ticketRegistryWriteEventLog() {
            return new EventLog();
        }

        @Bean
        RecordingInterceptor firstTicketRegistryWriteInterceptor(final EventLog eventLog) {
            return new RecordingInterceptor("first", Ordered.HIGHEST_PRECEDENCE + 10, eventLog);
        }

        @Bean
        RecordingInterceptor secondTicketRegistryWriteInterceptor(final EventLog eventLog) {
            return new RecordingInterceptor("second", Ordered.HIGHEST_PRECEDENCE + 20, eventLog);
        }

        @Bean
        RecordingWriteExecutor redisTicketRegistryWriteExecutor() {
            return new RecordingWriteExecutor();
        }

        @Bean
        RecordingPublisher redisTicketRegistryMessagePublisher() {
            return new RecordingPublisher();
        }

        @Bean
        ExplicitContextIssuancePolicy explicitContextIssuancePolicy() {
            return new ExplicitContextIssuancePolicy();
        }
    }

    static final class EventLog {
        private final List<String> events = new CopyOnWriteArrayList<>();

        List<String> events() {
            return events;
        }

        void reset() {
            events.clear();
        }
    }

    static final class RecordingWriteExecutor implements RedisTicketRegistryWriteExecutor {
        private final List<TicketRegistryWriteInterceptor.Operation> operations = new CopyOnWriteArrayList<>();

        private final List<Optional<TicketIssuanceWriteContext>> issuanceContexts = new CopyOnWriteArrayList<>();

        private final List<TicketRegistryWriteReceipt> receipts = new CopyOnWriteArrayList<>();

        private volatile boolean reject;

        List<TicketRegistryWriteInterceptor.Operation> operations() {
            return operations;
        }

        List<Optional<TicketIssuanceWriteContext>> issuanceContexts() {
            return issuanceContexts;
        }

        List<TicketRegistryWriteReceipt> receipts() {
            return receipts;
        }

        void reset() {
            operations.clear();
            issuanceContexts.clear();
            receipts.clear();
            reject = false;
        }

        void setReject(final boolean value) {
            reject = value;
        }

        @Override
        public TicketRegistryWriteReceipt execute(final WriteCommand command,
                                                  final Runnable defaultPersistence) {
            operations.add(command.operation());
            issuanceContexts.add(command.issuanceContext());
            assertFalse(command.redisKey().isBlank());
            assertFalse(command.keyspace().isBlank());
            assertFalse(command.documentId().isBlank());
            assertTrue(command.timeToLiveSeconds() > 0);
            assertTrue(command.expiresAtEpochMilli() > 0);
            if (reject) {
                throw new IllegalStateException("resource_fence_closed");
            }
            defaultPersistence.run();
            val receipt = new TicketRegistryWriteReceipt("ticket-redis", 1, 1, false);
            receipts.add(receipt);
            return receipt;
        }
    }

    static final class RecordingPublisher implements RedisTicketRegistryMessagePublisher {
        private final List<String> operations = new CopyOnWriteArrayList<>();

        List<String> operations() {
            return operations;
        }

        void reset() {
            operations.clear();
        }

        @Override
        public void deleteAll() {
            operations.add("DELETE_ALL");
        }

        @Override
        public void delete(final Ticket ticket) {
            operations.add("DELETE:" + ticket.getId());
        }

        @Override
        public void deleteByKey(final String key) {
            operations.add("DELETE_KEY:" + key);
        }

        @Override
        public void add(final Ticket ticket) {
            operations.add("ADD:" + ticket.getId());
        }

        @Override
        public void update(final Ticket ticket) {
            operations.add("UPDATE:" + ticket.getId());
        }
    }

    static final class RecordingInterceptor implements TicketRegistryWriteInterceptor, Ordered {
        private final String name;

        private final int order;

        private final EventLog eventLog;

        private final List<TicketIssuanceWriteContext> admittedContexts = new CopyOnWriteArrayList<>();

        private final List<TicketIssuanceWriteContext> completedContexts = new CopyOnWriteArrayList<>();

        private final List<TicketIssuanceWriteContext> failedContexts = new CopyOnWriteArrayList<>();

        private final List<TicketRegistryWriteReceipt> receipts = new CopyOnWriteArrayList<>();

        private volatile boolean reject;

        private volatile boolean failCompletion;

        RecordingInterceptor(final String name, final int order, final EventLog eventLog) {
            this.name = name;
            this.order = order;
            this.eventLog = eventLog;
        }

        void reset() {
            reject = false;
            failCompletion = false;
            admittedContexts.clear();
            completedContexts.clear();
            failedContexts.clear();
            receipts.clear();
        }

        void setReject(final boolean value) {
            reject = value;
        }

        void setFailCompletion(final boolean value) {
            failCompletion = value;
        }

        List<TicketIssuanceWriteContext> admittedContexts() {
            return admittedContexts;
        }

        List<TicketIssuanceWriteContext> completedContexts() {
            return completedContexts;
        }

        List<TicketRegistryWriteReceipt> receipts() {
            return receipts;
        }

        @Override
        public int getOrder() {
            return order;
        }

        @Override
        public WriteContext beforeWrite(
            final Ticket ticket,
            final TicketRegistryWriteInterceptor.Operation operation) {
            return admit(ticket, operation, Optional.empty());
        }

        @Override
        public WriteContext beforeWrite(
            final Ticket ticket,
            final TicketRegistryWriteInterceptor.Operation operation,
            final TicketIssuanceWriteContext context) {
            admittedContexts.add(context);
            return admit(ticket, operation, Optional.of(context));
        }

        private WriteContext admit(
            final Ticket ticket,
            final TicketRegistryWriteInterceptor.Operation operation,
            final Optional<TicketIssuanceWriteContext> issuanceContext) {
            eventLog.events().add(name + ":before:" + operation + ':' + ticket.getId());
            if (reject) {
                throw new IllegalStateException("generation_closed");
            }
            return new WriteContext() {
                @Override
                public void succeeded(final Ticket persistedTicket) {
                    eventLog.events().add(name + ":success:" + operation + ':' + persistedTicket.getId());
                    if (failCompletion) {
                        throw new IllegalStateException("completion_failed");
                    }
                }

                @Override
                public void succeeded(
                    final Ticket persistedTicket,
                    final TicketRegistryWriteReceipt receipt,
                    final TicketIssuanceWriteContext context) {
                    assertSame(issuanceContext.orElseThrow(), context);
                    completedContexts.add(context);
                    receipts.add(receipt);
                    succeeded(persistedTicket);
                }

                @Override
                public void failed(final Ticket failedTicket, final Throwable cause) {
                    eventLog.events().add(name + ":failure:" + operation + ':' + failedTicket.getId());
                }

                @Override
                public void failed(
                    final Ticket failedTicket,
                    final Throwable cause,
                    final TicketIssuanceWriteContext context) {
                    assertSame(issuanceContext.orElseThrow(), context);
                    failedContexts.add(context);
                    failed(failedTicket, cause);
                }
            };
        }
    }

    static final class ExplicitContextIssuancePolicy implements TicketIssuancePolicy {
        private final List<TicketIssuanceWriteContext> contexts = new CopyOnWriteArrayList<>();

        List<TicketIssuanceWriteContext> contexts() {
            return contexts;
        }

        void reset() {
            contexts.clear();
        }

        @Override
        public Optional<TicketIssuanceMetadata> prepareForWrite(
            final Ticket ticket,
            final TicketIssuancePolicy.Operation operation,
            final TicketIssuanceWriteContext context) {
            contexts.add(context);
            return Optional.of(new TicketIssuanceMetadata(
                CoreAuthenticationTestUtils.CONST_USERNAME, 7, "intent-1"));
        }
    }
}
