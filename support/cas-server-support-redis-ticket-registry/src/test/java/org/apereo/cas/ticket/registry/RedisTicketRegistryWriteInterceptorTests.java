package org.apereo.cas.ticket.registry;

import module java.base;
import org.apereo.cas.authentication.CoreAuthenticationTestUtils;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.ticket.TicketGrantingTicketImpl;
import org.apereo.cas.ticket.expiration.NeverExpiresExpirationPolicy;
import org.apereo.cas.ticket.expiration.TimeoutExpirationPolicy;
import org.apereo.cas.ticket.registry.key.RedisPrincipalTicketIndexKeyGenerator;
import org.apereo.cas.ticket.registry.key.RedisPrincipalTicketMutationFenceKeyGenerator;
import org.apereo.cas.ticket.registry.pub.RedisTicketRegistryMessagePublisher;
import org.apereo.cas.util.TicketGrantingTicketIdGenerator;
import org.apereo.cas.util.junit.EnabledIfListeningOnPort;
import com.github.benmanes.caffeine.cache.Cache;
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
import org.springframework.data.redis.core.RedisCallback;
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
    "cas.ticket.registry.redis.cache.cache-size=100",
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

    @Autowired
    @Qualifier("redisTicketRegistryCache")
    private Cache<String, Ticket> redisTicketRegistryCache;

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
    void verifyCompletedDeleteAllCannotBeUndoneByPreFenceWriteTail() throws Throwable {
        val ticket = ticket();
        val failure = new AtomicReference<Throwable>();
        writeExecutor.pauseAfterPersistence();
        val writer = Thread.ofVirtual().start(() -> {
            try {
                getNewTicketRegistry().addTicket(ticket);
            } catch (final Throwable cause) {
                failure.set(cause);
            }
        });
        try {
            assertTrue(writeExecutor.awaitPersistence(10, TimeUnit.SECONDS));
            val command = writeExecutor.commands().getFirst();
            val sessionIndex = command.principalSessionIndex().orElseThrow();
            assertTrue(getTicketRedisTemplate().hasKey(command.redisKey()));
            assertTrue(getCasRedisTemplates().getSessionsRedisTemplate()
                .hasKey(sessionIndex.redisKey()));

            assertEquals(1, getNewTicketRegistry().deleteAll());
            assertFalse(getCasRedisTemplates().getSessionsRedisTemplate()
                .hasKey(sessionIndex.redisKey()));
        } finally {
            writeExecutor.resumeAfterPersistence();
            writer.join();
        }

        assertNull(failure.get());
        assertNull(redisTicketRegistryCache.getIfPresent(
            getNewTicketRegistry().digestIdentifier(ticket.getId())));
        assertNull(getNewTicketRegistry().getTicket(ticket.getId()));
        assertFalse(getCasRedisTemplates().getSessionsRedisTemplate().hasKey(
            writeExecutor.commands().getFirst().principalSessionIndex().orElseThrow().redisKey()));
    }

    @RepeatedTest(1)
    void verifyExpiredAbsoluteWriteLeavesNoRedisState() throws Throwable {
        val ticket = new TicketGrantingTicketImpl(
            new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                .getNewTicketId(TicketGrantingTicket.PREFIX),
            CoreAuthenticationTestUtils.getAuthentication(),
            new TimeoutExpirationPolicy(1));
        val failure = new AtomicReference<Throwable>();
        secondInterceptor.pauseAdmission();
        val writer = Thread.ofVirtual().start(() -> {
            try {
                getNewTicketRegistry().addTicket(ticket);
            } catch (final Throwable cause) {
                failure.set(cause);
            }
        });
        try {
            assertTrue(secondInterceptor.awaitAdmission(10, TimeUnit.SECONDS));
            Thread.sleep(1_100);
        } finally {
            secondInterceptor.resumeAdmission();
            writer.join();
        }

        assertNotNull(failure.get());
        val command = writeExecutor.commands().getFirst();
        assertFalse(getTicketRedisTemplate().hasKey(command.redisKey()));
        assertFalse(getTicketRedisTemplate().hasKey(command.keyspace()));
        assertFalse(getCasRedisTemplates().getSessionsRedisTemplate().hasKey(
            command.principalIndex().orElseThrow().redisKey()));
        assertFalse(getCasRedisTemplates().getSessionsRedisTemplate().hasKey(
            command.principalSessionIndex().orElseThrow().redisKey()));
    }

    @RepeatedTest(1)
    void verifyShortLivedTicketIsNotPrunedAfterItsSessionIndexWrite() throws Throwable {
        val ticket = new TicketGrantingTicketImpl(
            new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                .getNewTicketId(TicketGrantingTicket.PREFIX),
            CoreAuthenticationTestUtils.getAuthentication(),
            new TimeoutExpirationPolicy(1));

        getNewTicketRegistry().addTicket(ticket);

        val command = writeExecutor.commands().getFirst();
        val sessionIndex = command.principalSessionIndex().orElseThrow();
        val redisNow = getCasRedisTemplates().getSessionsRedisTemplate().execute(
            (RedisCallback<Long>) connection -> connection.serverCommands().time(TimeUnit.MILLISECONDS));
        assertNotNull(redisNow);
        assertTrue(command.expiresAtEpochMilli() > redisNow);
        assertTrue(sessionIndex.expiresAtEpochSecond() <= Math.floorDiv(redisNow, 1000) + 1,
            "The ticket must exercise the session-index prune boundary");
        assertEquals(1, getCasRedisTemplates().getSessionsRedisTemplate()
            .boundZSetOps(sessionIndex.redisKey()).zCard());
    }

    @RepeatedTest(1)
    void verifyExistingBoundarySessionSurvivesSubsequentWritesAndCleanup() throws Throwable {
        val oldPrincipal = UUID.randomUUID().toString();
        val newPrincipal = UUID.randomUUID().toString();
        val first = ticket(oldPrincipal);
        val second = ticket(oldPrincipal);
        val registry = getNewTicketRegistry();
        registry.addTicket(first);
        val firstSessionIndex = writeExecutor.commands().getFirst()
            .principalSessionIndex().orElseThrow();

        val redisNow = getCasRedisTemplates().getSessionsRedisTemplate().execute(
            (RedisCallback<Long>) connection -> connection.serverCommands().time(TimeUnit.MILLISECONDS));
        assertNotNull(redisNow);
        val nextSecondScore = Math.floorDiv(redisNow, 1000) + 1;
        setRawSessionIndexScore(firstSessionIndex, nextSecondScore);

        registry.addTicket(second);
        assertEquals(Double.valueOf((double) nextSecondScore), rawSessionIndexScore(firstSessionIndex),
            "A later ADD must not prune an existing member in the next boundary second");

        setRawSessionIndexScore(firstSessionIndex, nextSecondScore);
        registry.updateTicket(new TicketGrantingTicketImpl(
            second.getId(),
            CoreAuthenticationTestUtils.getAuthentication(newPrincipal),
            NeverExpiresExpirationPolicy.INSTANCE));
        assertEquals(Double.valueOf((double) nextSecondScore), rawSessionIndexScore(firstSessionIndex),
            "Refreshing the old principal after an update must retain a boundary member");

        val currentSecond = awaitStartOfJvmSecond();
        setRawSessionIndexScore(firstSessionIndex, currentSecond);
        assertEquals(1, registry.countSessionsFor(oldPrincipal));
        assertEquals(currentSecond, Math.floorDiv(System.currentTimeMillis(), 1000),
            "The cleanup assertion must finish while the boundary member is still valid");
        assertEquals(Double.valueOf((double) currentSecond), rawSessionIndexScore(firstSessionIndex),
            "Session inventory cleanup must not prune a member in the current second");
    }

    @RepeatedTest(1)
    void verifyPrincipalDeleteInvalidatesBatchBeforeAggregatingPublisherFailure() throws Throwable {
        val principalId = UUID.randomUUID().toString();
        val tickets = IntStream.range(0, 3)
            .mapToObj(_ -> new TicketGrantingTicketImpl(
                new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                    .getNewTicketId(TicketGrantingTicket.PREFIX),
                CoreAuthenticationTestUtils.getAuthentication(principalId),
                NeverExpiresExpirationPolicy.INSTANCE))
            .toList();
        for (val ticket : tickets) {
            getNewTicketRegistry().addTicket(ticket);
            assertNotNull(getNewTicketRegistry().getTicket(ticket.getId()));
        }
        messagePublisher.failOnDeleteByKeyAttempt(2);

        assertThrows(IllegalStateException.class,
            () -> getNewTicketRegistry().deleteTicketsFor(principalId));
        assertEquals(3, messagePublisher.deleteByKeyAttempts());
        for (val ticket : tickets) {
            val cacheKey = getNewTicketRegistry().digestIdentifier(ticket.getId());
            assertNull(redisTicketRegistryCache.getIfPresent(cacheKey));
            assertNull(getNewTicketRegistry().getTicket(ticket.getId()));
        }
        assertEquals(0, getNewTicketRegistry().deleteTicketsFor(principalId));
    }

    @RepeatedTest(1)
    void verifyRepeatedPublisherFailureInstanceDoesNotSelfSuppress() throws Throwable {
        val principalId = UUID.randomUUID().toString();
        val tickets = IntStream.range(0, 2)
            .mapToObj(_ -> new TicketGrantingTicketImpl(
                new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                    .getNewTicketId(TicketGrantingTicket.PREFIX),
                CoreAuthenticationTestUtils.getAuthentication(principalId),
                NeverExpiresExpirationPolicy.INSTANCE))
            .toList();
        tickets.forEach(ticket -> assertDoesNotThrow(
            () -> getNewTicketRegistry().addTicket(ticket)));
        val failure = new IllegalStateException("same_delete_by_key_failure");
        messagePublisher.failEveryDeleteByKeyWith(failure);

        assertSame(failure, assertThrows(IllegalStateException.class,
            () -> getNewTicketRegistry().deleteTicketsFor(principalId)));
        assertEquals(tickets.size(), messagePublisher.deleteByKeyAttempts());
        assertEquals(0, failure.getSuppressed().length);
    }

    @RepeatedTest(1)
    void verifyPublisherErrorEscapesWithoutAggregation() throws Throwable {
        val principalId = UUID.randomUUID().toString();
        val tickets = IntStream.range(0, 2)
            .mapToObj(_ -> new TicketGrantingTicketImpl(
                new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                    .getNewTicketId(TicketGrantingTicket.PREFIX),
                CoreAuthenticationTestUtils.getAuthentication(principalId),
                NeverExpiresExpirationPolicy.INSTANCE))
            .toList();
        tickets.forEach(ticket -> assertDoesNotThrow(
            () -> getNewTicketRegistry().addTicket(ticket)));
        val failure = new AssertionError("delete_by_key_error");
        messagePublisher.failEveryDeleteByKeyWith(failure);

        assertSame(failure, assertThrows(AssertionError.class,
            () -> getNewTicketRegistry().deleteTicketsFor(principalId)));
        assertEquals(1, messagePublisher.deleteByKeyAttempts());
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
        return ticket(CoreAuthenticationTestUtils.CONST_USERNAME);
    }

    private static Ticket ticket(final String principalId) {
        val id = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
            .getNewTicketId(TicketGrantingTicket.PREFIX);
        return new TicketGrantingTicketImpl(id,
            CoreAuthenticationTestUtils.getAuthentication(principalId), NeverExpiresExpirationPolicy.INSTANCE);
    }

    private void setRawSessionIndexScore(
        final RedisTicketRegistryWriteExecutor.PrincipalSessionIndexEntry sessionIndex,
        final long score) {
        getCasRedisTemplates().getSessionsRedisTemplate().execute(
            (RedisCallback<Boolean>) connection -> connection.zSetCommands().zAdd(
                sessionIndex.redisKey().getBytes(StandardCharsets.UTF_8),
                (double) score,
                sessionIndex.serializedMember()));
    }

    private Double rawSessionIndexScore(
        final RedisTicketRegistryWriteExecutor.PrincipalSessionIndexEntry sessionIndex) {
        return getCasRedisTemplates().getSessionsRedisTemplate().execute(
            (RedisCallback<Double>) connection -> connection.zSetCommands().zScore(
                sessionIndex.redisKey().getBytes(StandardCharsets.UTF_8),
                sessionIndex.serializedMember()));
    }

    private static long awaitStartOfJvmSecond() throws InterruptedException {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (System.nanoTime() < deadline) {
            val now = System.currentTimeMillis();
            if (Math.floorMod(now, 1000) < 100) {
                return Math.floorDiv(now, 1000);
            }
            Thread.sleep(5);
        }
        throw new AssertionError("Timed out waiting for the start of a JVM clock second");
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

        private final List<WriteCommand> commands = new CopyOnWriteArrayList<>();

        private final AtomicReference<CountDownLatch> persistenceReached = new AtomicReference<>();

        private final AtomicReference<CountDownLatch> resumePersistence = new AtomicReference<>();

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

        List<WriteCommand> commands() {
            return commands;
        }

        void reset() {
            resumeAfterPersistence();
            operations.clear();
            issuanceContexts.clear();
            receipts.clear();
            commands.clear();
            reject = false;
        }

        void pauseAfterPersistence() {
            persistenceReached.set(new CountDownLatch(1));
            resumePersistence.set(new CountDownLatch(1));
        }

        boolean awaitPersistence(final long timeout, final TimeUnit unit)
            throws InterruptedException {
            return Objects.requireNonNull(persistenceReached.get()).await(timeout, unit);
        }

        void resumeAfterPersistence() {
            val latch = resumePersistence.getAndSet(null);
            if (latch != null) {
                latch.countDown();
            }
            persistenceReached.set(null);
        }

        void setReject(final boolean value) {
            reject = value;
        }

        @Override
        public TicketRegistryWriteReceipt execute(final WriteCommand command,
                                                  final Runnable defaultPersistence) {
            operations.add(command.operation());
            commands.add(command);
            issuanceContexts.add(command.issuanceContext());
            assertFalse(command.redisKey().isBlank());
            assertFalse(command.keyspace().isBlank());
            assertFalse(command.documentId().isBlank());
            assertTrue(command.timeToLiveSeconds() > 0);
            assertTrue(command.expiresAtEpochMilli() > 0);
            assertEquals(RedisPrincipalTicketIndexKeyGenerator.MUTATION_FENCE_KEY,
                command.mutationFenceKey());
            command.principalIndex().ifPresent(principalIndex -> {
                assertEquals(command.redisKey(), principalIndex.member());
                assertEquals(command.expiresAtEpochMilli(), principalIndex.expiresAtEpochMilli());
                assertTrue(principalIndex.redisKey().startsWith(principalIndex.redisKeyPrefix()));
                val mappedPrincipal = principalIndex.redisKey()
                    .substring(principalIndex.redisKeyPrefix().length());
                assertEquals(
                    RedisPrincipalTicketMutationFenceKeyGenerator.forPrincipal(mappedPrincipal),
                    command.principalMutationFenceKey().orElseThrow());
            });
            if (command.principalIndex().isEmpty()) {
                assertTrue(command.principalMutationFenceKey().isEmpty());
            }
            command.principalSessionIndex().ifPresent(sessionIndex -> {
                assertTrue(command.principalIndex().isPresent());
                assertTrue(sessionIndex.redisKey().startsWith(sessionIndex.redisKeyPrefix()));
                assertTrue(sessionIndex.serializedMember().length > 0);
                assertTrue(sessionIndex.expiresAtEpochSecond() > 0);
            });
            if (reject) {
                throw new IllegalStateException("resource_fence_closed");
            }
            defaultPersistence.run();
            val resume = resumePersistence.get();
            if (resume != null) {
                Objects.requireNonNull(persistenceReached.get()).countDown();
                try {
                    if (!resume.await(10, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("Timed out waiting to resume Redis persistence");
                    }
                } catch (final InterruptedException cause) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(cause);
                }
            }
            val receipt = new TicketRegistryWriteReceipt("ticket-redis", 1, 1, false);
            receipts.add(receipt);
            return receipt;
        }
    }

    static final class RecordingPublisher implements RedisTicketRegistryMessagePublisher {
        private final List<String> operations = new CopyOnWriteArrayList<>();

        private final AtomicInteger deleteByKeyAttempts = new AtomicInteger();

        private volatile int failingDeleteByKeyAttempt;

        private volatile RuntimeException repeatedDeleteByKeyFailure;

        private volatile Error deleteByKeyError;

        List<String> operations() {
            return operations;
        }

        void reset() {
            operations.clear();
            deleteByKeyAttempts.set(0);
            failingDeleteByKeyAttempt = 0;
            repeatedDeleteByKeyFailure = null;
            deleteByKeyError = null;
        }

        void failOnDeleteByKeyAttempt(final int attempt) {
            failingDeleteByKeyAttempt = attempt;
        }

        void failEveryDeleteByKeyWith(final RuntimeException failure) {
            repeatedDeleteByKeyFailure = failure;
        }

        void failEveryDeleteByKeyWith(final Error failure) {
            deleteByKeyError = failure;
        }

        int deleteByKeyAttempts() {
            return deleteByKeyAttempts.get();
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
            val attempt = deleteByKeyAttempts.incrementAndGet();
            if (deleteByKeyError != null) {
                throw deleteByKeyError;
            }
            if (repeatedDeleteByKeyFailure != null) {
                throw repeatedDeleteByKeyFailure;
            }
            if (attempt == failingDeleteByKeyAttempt) {
                throw new IllegalStateException("delete_by_key_failed");
            }
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

        private final AtomicReference<CountDownLatch> admissionReached = new AtomicReference<>();

        private final AtomicReference<CountDownLatch> resumeAdmission = new AtomicReference<>();

        private volatile boolean reject;

        private volatile boolean failCompletion;

        RecordingInterceptor(final String name, final int order, final EventLog eventLog) {
            this.name = name;
            this.order = order;
            this.eventLog = eventLog;
        }

        void reset() {
            resumeAdmission();
            reject = false;
            failCompletion = false;
            admittedContexts.clear();
            completedContexts.clear();
            failedContexts.clear();
            receipts.clear();
        }

        void pauseAdmission() {
            admissionReached.set(new CountDownLatch(1));
            resumeAdmission.set(new CountDownLatch(1));
        }

        boolean awaitAdmission(final long timeout, final TimeUnit unit)
            throws InterruptedException {
            return Objects.requireNonNull(admissionReached.get()).await(timeout, unit);
        }

        void resumeAdmission() {
            val latch = resumeAdmission.getAndSet(null);
            if (latch != null) {
                latch.countDown();
            }
            admissionReached.set(null);
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
            val resume = resumeAdmission.get();
            if (resume != null) {
                Objects.requireNonNull(admissionReached.get()).countDown();
                try {
                    if (!resume.await(10, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("Timed out waiting to resume ticket admission");
                    }
                } catch (final InterruptedException cause) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(cause);
                }
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
