package org.apereo.cas.ticket.registry;

import module java.base;
import org.apereo.cas.CasProtocolConstants;
import org.apereo.cas.authentication.CoreAuthenticationTestUtils;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.config.CasRedisCoreAutoConfiguration;
import org.apereo.cas.config.CasRedisTicketRegistryAutoConfiguration;
import org.apereo.cas.redis.core.CasRedisTemplate;
import org.apereo.cas.services.RegisteredServiceTestUtils;
import org.apereo.cas.test.CasTestExtension;
import org.apereo.cas.ticket.InvalidTicketException;
import org.apereo.cas.ticket.ProxyGrantingTicketImpl;
import org.apereo.cas.ticket.ServiceTicket;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.ticket.TicketGrantingTicketImpl;
import org.apereo.cas.ticket.expiration.HardTimeoutExpirationPolicy;
import org.apereo.cas.ticket.expiration.NeverExpiresExpirationPolicy;
import org.apereo.cas.ticket.expiration.TimeoutExpirationPolicy;
import org.apereo.cas.ticket.proxy.ProxyGrantingTicket;
import org.apereo.cas.ticket.proxy.ProxyTicket;
import org.apereo.cas.ticket.registry.key.RedisKeyGenerator;
import org.apereo.cas.ticket.registry.key.RedisKeyGeneratorFactory;
import org.apereo.cas.ticket.registry.key.RedisPrincipalIdentifierCodec;
import org.apereo.cas.ticket.registry.key.RedisPrincipalTicketIndexKeyGenerator;
import org.apereo.cas.ticket.registry.key.RedisPrincipalTicketMutationFenceKeyGenerator;
import org.apereo.cas.ticket.tracking.TicketTrackingPolicy;
import org.apereo.cas.util.LoggingUtils;
import org.apereo.cas.util.ProxyGrantingTicketIdGenerator;
import org.apereo.cas.util.ProxyTicketIdGenerator;
import org.apereo.cas.util.ServiceTicketIdGenerator;
import org.apereo.cas.util.TicketGrantingTicketIdGenerator;
import org.apereo.cas.util.function.FunctionUtils;
import org.apereo.cas.util.junit.EnabledIfListeningOnPort;
import org.apereo.cas.util.thread.Cleanable;
import com.github.benmanes.caffeine.cache.Cache;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.StopWatch;
import org.jooq.lambda.Unchecked;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junitpioneer.jupiter.RetryingTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.AopTestUtils;
import static org.awaitility.Awaitility.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit test for {@link RedisTicketRegistry}.
 *
 * @author Misagh Moayyed
 * @since 5.0.0
 */
@EnabledIfListeningOnPort(port = 6379)
@Tag("Redis")
@Slf4j
@ResourceLock(value = "redis-ticket-registry", mode = ResourceAccessMode.READ_WRITE)
class RedisServerTicketRegistryTests {

    @Nested
    @TestPropertySource(properties = {
        "cas.ticket.registry.redis.queue-identifier=cas-node-100",
        "cas.ticket.registry.redis.host=localhost",
        "cas.ticket.registry.redis.port=6379",
        "cas.ticket.registry.redis.cache.cache-size=0",
        "cas.ticket.registry.redis.enable-redis-search=false",
        "cas.ticket.registry.redis.crypto.encryption.key=AZ5y4I9qzKPYUVNL2Td4RMbpg6Z-ldui8VEFg8hsj1M",
        "cas.ticket.registry.redis.crypto.signing.key=cAPyoHMrOMWrwydOXzBA-ufZQM-TilnLjbRgMQWlUlwFmy07bOtAgCIdNBma3c5P4ae_JV6n1OpOAYqSh2NkmQ"
    })
    class WithoutCachingTests extends BaseRedisSentinelTicketRegistryTests {
        @RepeatedTest(2)
        void verifyTrackingUsersAndPrefixes() throws Throwable {
            val authentication = CoreAuthenticationTestUtils.getAuthentication(UUID.randomUUID().toString());
            val runnable = new Runnable() {
                @Override
                public void run() {
                    try {
                        val tgtId = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                            .getNewTicketId(TicketGrantingTicket.PREFIX);
                        val tgt = new TicketGrantingTicketImpl(tgtId, authentication, NeverExpiresExpirationPolicy.INSTANCE);
                        getNewTicketRegistry().addTicket(tgt);

                        val service = RegisteredServiceTestUtils.getService(UUID.randomUUID().toString());
                        val stId = new ServiceTicketIdGenerator(10, StringUtils.EMPTY)
                            .getNewTicketId(ServiceTicket.PREFIX);

                        val st = tgt.grantServiceTicket(stId, service, NeverExpiresExpirationPolicy.INSTANCE,
                            false, serviceTicketSessionTrackingPolicy);
                        getNewTicketRegistry().addTicket(st);
                        getNewTicketRegistry().updateTicket(tgt);

                        assertNotNull(getNewTicketRegistry().getTicket(tgtId));
                        assertNotNull(getNewTicketRegistry().getTicket(stId));
                    } catch (final Exception e) {
                        throw new RuntimeException(e);
                    }
                }
            };

            val totalThreads = 1;
            val threads = new Thread[totalThreads];
            for (var i = 0; i < threads.length; i++) {
                threads[i] = new Thread(runnable);
                threads[i].start();
            }
            for (val thread : threads) {
                try {
                    thread.join();
                } catch (final Exception e) {
                    throw new RuntimeException(e);
                }
            }

            val sessionCount = getNewTicketRegistry().sessionCount();
            assertEquals(totalThreads, sessionCount);

            val serviceTicketCount = getNewTicketRegistry().serviceTicketCount();
            assertEquals(totalThreads, serviceTicketCount);

            val sessions = getNewTicketRegistry().getSessionsFor(authentication.getPrincipal().getId()).toList();
            assertEquals(totalThreads, sessions.size());

            val firstTicket = sessions.getFirst();
            assertInstanceOf(TicketGrantingTicket.class, firstTicket);
            getNewTicketRegistry().deleteTicket(firstTicket);
            assertEquals(totalThreads - 1, getNewTicketRegistry().sessionCount());
            assertEquals(totalThreads - 1, getNewTicketRegistry().serviceTicketCount());
            val sessionsReduced = getNewTicketRegistry().getSessionsFor(authentication.getPrincipal().getId()).toList();
            assertEquals(totalThreads - 1, sessionsReduced.size());

            sessionsReduced.forEach(Unchecked.consumer(ticket -> {
                assertInstanceOf(TicketGrantingTicket.class, ticket);
                getNewTicketRegistry().deleteTicket(ticket);
            }));
            assertEquals(0, getNewTicketRegistry().getSessionsFor(authentication.getPrincipal().getId()).count());
            assertEquals(0, getNewTicketRegistry().sessionCount());
            assertEquals(0, getNewTicketRegistry().serviceTicketCount());
        }
    }

    @Nested
    @TestPropertySource(properties = {
        "cas.ticket.registry.redis.queue-identifier=cas-node-100",
        "cas.ticket.registry.redis.host=localhost",
        "cas.ticket.registry.redis.port=6379",
        "cas.ticket.registry.redis.enable-redis-search=false",
        "cas.ticket.registry.redis.crypto.encryption.key=AZ5y4I9qzKPYUVNL2Td4RMbpg6Z-ldui8VEFg8hsj1M",
        "cas.ticket.registry.redis.crypto.signing.key=cAPyoHMrOMWrwydOXzBA-ufZQM-TilnLjbRgMQWlUlwFmy07bOtAgCIdNBma3c5P4ae_JV6n1OpOAYqSh2NkmQ"
    })
    class WithoutRedisModulesTests extends BaseRedisSentinelTicketRegistryTests {
        @Autowired
        @Qualifier("redisTicketRegistryCache")
        private Cache<String, Ticket> redisTicketRegistryCache;

        @Autowired
        @Qualifier(RedisKeyGeneratorFactory.BEAN_NAME)
        private RedisKeyGeneratorFactory redisKeyGeneratorFactory;

        @Autowired
        @Qualifier(RedisPrincipalTicketMutationFence.BEAN_NAME)
        private RedisPrincipalTicketMutationFence principalMutationFence;

        @RepeatedTest(1)
        void verifyTemporaryPrincipalFenceIsReplaySafeAndBlocksOnlyWrites() throws Throwable {
            val principalId = "Case.Sensitive+" + UUID.randomUUID() + "@Example.ORG";
            val distinctPrincipal = principalId.toLowerCase(Locale.ROOT);
            val token = UUID.randomUUID().toString();
            val registry = getNewTicketRegistry();
            val existingTicket = new TicketGrantingTicketImpl(
                new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                    .getNewTicketId(TicketGrantingTicket.PREFIX),
                CoreAuthenticationTestUtils.getAuthentication(principalId),
                NeverExpiresExpirationPolicy.INSTANCE);
            val blockedTicket = new TicketGrantingTicketImpl(
                new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                    .getNewTicketId(TicketGrantingTicket.PREFIX),
                CoreAuthenticationTestUtils.getAuthentication(principalId),
                NeverExpiresExpirationPolicy.INSTANCE);
            registry.addTicket(existingTicket);

            val handle = principalMutationFence.acquire(
                principalId, token, Duration.ofSeconds(30));
            assertEquals(handle, principalMutationFence.acquire(
                principalId, token, Duration.ofSeconds(30)));
            assertNotEquals(handle.redisKey(),
                principalMutationFence.keyForPrincipal(distinctPrincipal));
            assertTrue(principalMutationFence.inspect(distinctPrincipal).isEmpty());
            assertEquals(
                RedisPrincipalTicketMutationFence.Mode.TEMPORARY,
                principalMutationFence.inspect(principalId).orElseThrow().mode());
            assertEquals(
                RedisPrincipalTicketMutationFenceKeyGenerator.forPrincipal(
                    RedisPrincipalIdentifierCodec.encode(principalId)),
                handle.redisKey());
            assertFalse(handle.redisKey().toLowerCase(Locale.ROOT)
                .contains("case.sensitive"));
            assertThrows(IllegalStateException.class,
                () -> principalMutationFence.acquire(
                    principalId, UUID.randomUUID().toString(), Duration.ofSeconds(30)));

            assertThrows(RuntimeException.class, () -> registry.addTicket(blockedTicket));
            assertNull(registry.getTicket(blockedTicket.getId()));
            assertEquals(1, registry.deleteTicketsFor(principalId),
                "A principal fence must not obstruct authoritative deletion");
            assertNull(registry.getTicket(existingTicket.getId()));
            assertFalse(principalMutationFence.release(principalId, "wrong-token"));
            assertTrue(principalMutationFence.release(principalId, token));
            assertTrue(principalMutationFence.inspect(principalId).isEmpty());

            registry.addTicket(blockedTicket);
            assertNotNull(registry.getTicket(blockedTicket.getId()));
        }

        @RepeatedTest(1)
        void verifyTerminalPrincipalFenceIsPermanentAndPromotable() {
            val principalId = UUID.randomUUID().toString();
            val token = UUID.randomUUID().toString();
            val temporary = principalMutationFence.acquire(
                principalId, token, Duration.ofSeconds(30));
            try {
                val terminal = principalMutationFence.acquireTerminal(principalId, token);
                assertEquals(temporary.redisKey(), terminal.redisKey());
                assertEquals(RedisPrincipalTicketMutationFence.Mode.TERMINAL, terminal.mode());
                assertEquals(terminal, principalMutationFence.acquireTerminal(principalId, token));
                val state = principalMutationFence.inspect(principalId).orElseThrow();
                assertEquals(RedisPrincipalTicketMutationFence.Mode.TERMINAL, state.mode());
                assertTrue(state.remainingLease().isEmpty());
                assertEquals(-1, getCasRedisTemplates().getSessionsRedisTemplate()
                    .getExpire(terminal.redisKey()));
                assertThrows(IllegalStateException.class,
                    () -> principalMutationFence.acquireTerminal(
                        principalId, UUID.randomUUID().toString()));
                assertThrows(IllegalStateException.class,
                    () -> principalMutationFence.acquire(
                        principalId, token, Duration.ofSeconds(30)));
                assertFalse(principalMutationFence.release(principalId, token),
                    "The temporary-release operation must never remove a terminal fence");
                assertTrue(principalMutationFence.inspect(principalId).isPresent());
            } finally {
                getCasRedisTemplates().getSessionsRedisTemplate().delete(temporary.redisKey());
            }
        }

        @RepeatedTest(1)
        void verifyAuthoritativeSourceReadBypassesStaleNearCache() throws Throwable {
            val authentication = CoreAuthenticationTestUtils.getAuthentication(
                UUID.randomUUID().toString());
            val ticketId = new TicketGrantingTicketIdGenerator(
                10, StringUtils.EMPTY)
                .getNewTicketId(TicketGrantingTicket.PREFIX);
            val ticket = new TicketGrantingTicketImpl(
                ticketId, authentication, NeverExpiresExpirationPolicy.INSTANCE);
            val registry = getNewTicketRegistry();
            registry.addTicket(ticket);

            assertNotNull(registry.getTicket(ticketId));
            val keyGenerator = redisKeyGeneratorFactory
                .getRedisKeyGenerator(ticket.getPrefix())
                .orElseThrow();
            val redisKey = keyGenerator.forPrefixAndId(
                ticket.getPrefix(), registry.digestIdentifier(ticketId));
            assertTrue(ticketRedisTemplate.delete(redisKey));

            assertNotNull(registry.getTicket(ticketId));
            assertThrows(InvalidTicketException.class,
                () -> registry.getTicketFromSource(
                    ticketId, TicketGrantingTicket.class));
            assertNull(redisTicketRegistryCache.getIfPresent(
                registry.digestIdentifier(ticketId)));
        }

        @RepeatedTest(2)
        void verifyDeleteTicketsForUsesCompletePrincipalIndex() throws Throwable {
            val principalId = UUID.randomUUID().toString();
            val authentication = CoreAuthenticationTestUtils.getAuthentication(principalId);
            val tgtId = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                .getNewTicketId(TicketGrantingTicket.PREFIX);
            val tgt = new TicketGrantingTicketImpl(
                tgtId, authentication, NeverExpiresExpirationPolicy.INSTANCE);
            val pgtId = new ProxyGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                .getNewTicketId(ProxyGrantingTicket.PROXY_GRANTING_TICKET_PREFIX);
            val pgt = new ProxyGrantingTicketImpl(
                pgtId, authentication, NeverExpiresExpirationPolicy.INSTANCE);
            val service = RegisteredServiceTestUtils.getService(UUID.randomUUID().toString());
            val stId = new ServiceTicketIdGenerator(10, StringUtils.EMPTY)
                .getNewTicketId(ServiceTicket.PREFIX);
            val st = tgt.grantServiceTicket(
                stId,
                service,
                NeverExpiresExpirationPolicy.INSTANCE,
                false,
                serviceTicketSessionTrackingPolicy);
            val ptId = new ProxyTicketIdGenerator(10, StringUtils.EMPTY)
                .getNewTicketId(ProxyTicket.PROXY_TICKET_PREFIX);
            val pt = pgt.grantProxyTicket(
                ptId,
                service,
                NeverExpiresExpirationPolicy.INSTANCE,
                serviceTicketSessionTrackingPolicy);
            val registry = getNewTicketRegistry();
            registry.addTicket(tgt);
            registry.addTicket(pgt);
            registry.addTicket(st);
            registry.addTicket(pt);

            assertEquals(2, registry.countSessionsFor(principalId));
            val principalIndexKey = RedisPrincipalTicketIndexKeyGenerator.forPrincipal(
                RedisPrincipalIdentifierCodec.encode(principalId));
            assertEquals(4, getCasRedisTemplates().getSessionsRedisTemplate()
                .boundZSetOps(principalIndexKey).zCard());
            assertEquals(4, registry.deleteTicketsFor(principalId));
            assertEquals(0, registry.countSessionsFor(principalId));
            assertNull(registry.getTicket(tgtId));
            assertNull(registry.getTicket(pgtId));
            assertNull(registry.getTicket(stId));
            assertNull(registry.getTicket(ptId));
            assertFalse(getCasRedisTemplates().getSessionsRedisTemplate().hasKey(principalIndexKey));

            assertEquals(0, registry.deleteTicketsFor(principalId));
            assertEquals(0, registry.countSessionsFor(principalId));
        }

        @RepeatedTest(1)
        void verifyBulkWriteMaintainsPrincipalIndex() throws Throwable {
            val principalId = UUID.randomUUID().toString();
            val authentication = CoreAuthenticationTestUtils.getAuthentication(principalId);
            val tickets = IntStream.range(0, 3)
                .mapToObj(_ -> new TicketGrantingTicketImpl(
                    new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                        .getNewTicketId(TicketGrantingTicket.PREFIX),
                    authentication,
                    NeverExpiresExpirationPolicy.INSTANCE))
                .toList();
            val registry = getNewTicketRegistry();

            assertEquals(tickets, registry.addTicket(tickets.stream()));
            val principalIndexKey = RedisPrincipalTicketIndexKeyGenerator.forPrincipal(
                RedisPrincipalIdentifierCodec.encode(principalId));
            assertEquals(3, getCasRedisTemplates().getSessionsRedisTemplate()
                .boundZSetOps(principalIndexKey).zCard());
            assertEquals(3, registry.deleteTicketsFor(principalId));
            tickets.forEach(ticket -> assertNull(registry.getTicket(ticket.getId())));
        }

        @RepeatedTest(1)
        void verifyDeleteScriptResultsFailClosed() {
            assertEquals(0, RedisTicketRegistry.requireDeleteScriptResult(
                0L, 1, "test delete"));
            assertEquals(1, RedisTicketRegistry.requireDeleteScriptResult(
                1L, 1, "test delete"));
            assertThrows(IllegalStateException.class,
                () -> RedisTicketRegistry.requireDeleteScriptResult(
                    null, 1, "test delete"));
            assertThrows(IllegalStateException.class,
                () -> RedisTicketRegistry.requireDeleteScriptResult(
                    2L, 1, "test delete"));
        }

        @RepeatedTest(1)
        void verifyPrincipalChangeMovesIndexAtomically() throws Throwable {
            val oldPrincipal = UUID.randomUUID().toString();
            val newPrincipal = UUID.randomUUID().toString();
            val ticketId = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                .getNewTicketId(TicketGrantingTicket.PREFIX);
            val registry = getNewTicketRegistry();
            registry.addTicket(new TicketGrantingTicketImpl(
                ticketId,
                CoreAuthenticationTestUtils.getAuthentication(oldPrincipal),
                NeverExpiresExpirationPolicy.INSTANCE));
            registry.updateTicket(new TicketGrantingTicketImpl(
                ticketId,
                CoreAuthenticationTestUtils.getAuthentication(newPrincipal),
                NeverExpiresExpirationPolicy.INSTANCE));

            val oldIndex = RedisPrincipalTicketIndexKeyGenerator.forPrincipal(
                RedisPrincipalIdentifierCodec.encode(oldPrincipal));
            val newIndex = RedisPrincipalTicketIndexKeyGenerator.forPrincipal(
                RedisPrincipalIdentifierCodec.encode(newPrincipal));
            assertFalse(getCasRedisTemplates().getSessionsRedisTemplate().hasKey(oldIndex));
            assertEquals(1, getCasRedisTemplates().getSessionsRedisTemplate()
                .boundZSetOps(newIndex).zCard());
            assertEquals(0, registry.countSessionsFor(oldPrincipal));
            assertEquals(1, registry.countSessionsFor(newPrincipal));
            assertEquals(0, registry.deleteTicketsFor(oldPrincipal));
            assertEquals(1, registry.deleteTicketsFor(newPrincipal));
            assertNull(registry.getTicket(ticketId));
        }

        @RepeatedTest(1)
        void verifyPrincipalChangeCannotEscapePreviousPrincipalFence() throws Throwable {
            val oldPrincipal = UUID.randomUUID().toString();
            val newPrincipal = UUID.randomUUID().toString();
            val ticketId = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                .getNewTicketId(TicketGrantingTicket.PREFIX);
            val registry = getNewTicketRegistry();
            registry.addTicket(new TicketGrantingTicketImpl(
                ticketId,
                CoreAuthenticationTestUtils.getAuthentication(oldPrincipal),
                NeverExpiresExpirationPolicy.INSTANCE));
            val token = UUID.randomUUID().toString();
            principalMutationFence.acquire(oldPrincipal, token, Duration.ofSeconds(30));
            val mappedOldPrincipal = RedisPrincipalIdentifierCodec.encode(oldPrincipal);
            assertTrue(principalMutationFence.inspect(oldPrincipal).isPresent());
            val storedOldPrincipal = getCasRedisTemplates().getTicketsRedisTemplate().execute(
                (RedisCallback<byte[]>) connection -> connection.hashCommands().hGet(
                    redisTicketKey(registry, ticketId).getBytes(StandardCharsets.UTF_8),
                    RedisTicketDocument.FIELD_NAME_PRINCIPAL.getBytes(StandardCharsets.UTF_8)));
            assertNotNull(storedOldPrincipal);
            assertEquals(mappedOldPrincipal,
                new String(storedOldPrincipal, StandardCharsets.UTF_8));
            assertTrue(getCasRedisTemplates().getTicketsRedisTemplate().hasKey(
                RedisPrincipalTicketMutationFenceKeyGenerator.forPrincipal(
                    mappedOldPrincipal)));

            assertThrows(RuntimeException.class, () -> registry.updateTicket(
                new TicketGrantingTicketImpl(
                    ticketId,
                    CoreAuthenticationTestUtils.getAuthentication(newPrincipal),
                    NeverExpiresExpirationPolicy.INSTANCE)));

            val oldIndex = RedisPrincipalTicketIndexKeyGenerator.forPrincipal(
                mappedOldPrincipal);
            val newIndex = RedisPrincipalTicketIndexKeyGenerator.forPrincipal(
                RedisPrincipalIdentifierCodec.encode(newPrincipal));
            assertEquals(1, getCasRedisTemplates().getSessionsRedisTemplate()
                .boundZSetOps(oldIndex).zCard());
            assertFalse(getCasRedisTemplates().getSessionsRedisTemplate().hasKey(newIndex));
            assertEquals(oldPrincipal, registry.getTicket(ticketId, TicketGrantingTicket.class)
                .getAuthentication().getPrincipal().getId());
            assertTrue(principalMutationFence.release(oldPrincipal, token));
        }

        @RepeatedTest(1)
        void verifyExpiredAndMissingTicketsCleanIndex() throws Throwable {
            val principalId = UUID.randomUUID().toString();
            val registry = getNewTicketRegistry();
            val expiringId = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                .getNewTicketId(TicketGrantingTicket.PREFIX);
            registry.addTicket(new TicketGrantingTicketImpl(
                expiringId,
                CoreAuthenticationTestUtils.getAuthentication(principalId),
                new TimeoutExpirationPolicy(1)));
            val indexKey = RedisPrincipalTicketIndexKeyGenerator.forPrincipal(
                RedisPrincipalIdentifierCodec.encode(principalId));
            assertNotNull(rawIndexScore(indexKey, redisTicketKey(registry, expiringId)));
            await().atMost(3, TimeUnit.SECONDS).untilAsserted(() ->
                assertFalse(getCasRedisTemplates().getSessionsRedisTemplate().hasKey(indexKey)));

            val missingId = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                .getNewTicketId(TicketGrantingTicket.PREFIX);
            registry.addTicket(new TicketGrantingTicketImpl(
                missingId,
                CoreAuthenticationTestUtils.getAuthentication(principalId),
                NeverExpiresExpirationPolicy.INSTANCE));
            assertTrue(ticketRedisTemplate.delete(redisTicketKey(registry, missingId)));
            assertEquals(0, registry.deleteTicketsFor(principalId));
            assertFalse(getCasRedisTemplates().getSessionsRedisTemplate().hasKey(indexKey));
            await().atMost(3, TimeUnit.SECONDS).untilAsserted(() ->
                assertEquals(0, registry.countSessionsFor(principalId)));
        }

        @RepeatedTest(1)
        void verifyCorruptTicketFailsClosedWithoutConsumingIndex() throws Throwable {
            val principalId = UUID.randomUUID().toString();
            val registry = getNewTicketRegistry();
            val ticketId = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                .getNewTicketId(TicketGrantingTicket.PREFIX);
            registry.addTicket(new TicketGrantingTicketImpl(
                ticketId,
                CoreAuthenticationTestUtils.getAuthentication(principalId),
                NeverExpiresExpirationPolicy.INSTANCE));
            val ticketKey = redisTicketKey(registry, ticketId);
            assertTrue(ticketRedisTemplate.delete(ticketKey));
            getCasRedisTemplates().getSessionsRedisTemplate().opsForValue().set(ticketKey, "corrupt");
            val indexKey = RedisPrincipalTicketIndexKeyGenerator.forPrincipal(
                RedisPrincipalIdentifierCodec.encode(principalId));

            assertThrows(RuntimeException.class, () -> registry.deleteTicketsFor(principalId));
            assertEquals("corrupt", getCasRedisTemplates().getSessionsRedisTemplate()
                .opsForValue().get(ticketKey));
            assertEquals(1, getCasRedisTemplates().getSessionsRedisTemplate()
                .boundZSetOps(indexKey).zCard());
        }

        @RepeatedTest(1)
        void verifyMissingPrincipalFailsClosedWithoutOrphaningTicket() throws Throwable {
            val principalId = UUID.randomUUID().toString();
            val registry = getNewTicketRegistry();
            val ticketId = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                .getNewTicketId(TicketGrantingTicket.PREFIX);
            registry.addTicket(new TicketGrantingTicketImpl(
                ticketId,
                CoreAuthenticationTestUtils.getAuthentication(principalId),
                NeverExpiresExpirationPolicy.INSTANCE));
            val ticketKey = redisTicketKey(registry, ticketId);
            assertEquals(1, ticketRedisTemplate.boundHashOps(ticketKey)
                .delete(RedisTicketDocument.FIELD_NAME_PRINCIPAL));
            val indexKey = RedisPrincipalTicketIndexKeyGenerator.forPrincipal(
                RedisPrincipalIdentifierCodec.encode(principalId));

            assertThrows(RuntimeException.class, () -> registry.deleteTicketsFor(principalId));
            assertTrue(ticketRedisTemplate.hasKey(ticketKey));
            assertEquals(1, getCasRedisTemplates().getSessionsRedisTemplate()
                .boundZSetOps(indexKey).zCard());
        }

        @RepeatedTest(1)
        void verifyBoundedDeletionAndConcurrentCutover() throws Throwable {
            val principalId = UUID.randomUUID().toString();
            val registry = getNewTicketRegistry();
            val identifiers = Collections.synchronizedList(new ArrayList<String>());
            val started = new CountDownLatch(1);
            val writer = Thread.ofVirtual().start(() -> {
                for (var index = 0; index < 125; index++) {
                    val ticketId = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                        .getNewTicketId(TicketGrantingTicket.PREFIX);
                    FunctionUtils.doUnchecked(_ -> registry.addTicket(new TicketGrantingTicketImpl(
                        ticketId,
                        CoreAuthenticationTestUtils.getAuthentication(principalId),
                        NeverExpiresExpirationPolicy.INSTANCE)));
                    identifiers.add(ticketId);
                    started.countDown();
                }
            });
            assertTrue(started.await(5, TimeUnit.SECONDS));
            val firstPass = registry.deleteTicketsFor(principalId);
            writer.join();
            val secondPass = registry.deleteTicketsFor(principalId);

            assertEquals(125, firstPass + secondPass);
            assertEquals(0, registry.deleteTicketsFor(principalId));
            identifiers.forEach(identifier -> assertNull(registry.getTicket(identifier)));
        }

        @RepeatedTest(1)
        void verifyDeleteAllFencesConcurrentWriters() throws Throwable {
            val principalId = UUID.randomUUID().toString();
            val authentication = CoreAuthenticationTestUtils.getAuthentication(principalId);
            val registry = getNewTicketRegistry();
            val seedTickets = IntStream.range(0, 250)
                .mapToObj(_ -> new TicketGrantingTicketImpl(
                    new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                        .getNewTicketId(TicketGrantingTicket.PREFIX),
                    authentication,
                    NeverExpiresExpirationPolicy.INSTANCE))
                .toList();
            registry.addTicket(seedTickets.stream());

            val successfulWrites = Collections.synchronizedList(new ArrayList<String>());
            val start = new CountDownLatch(1);
            val writer = Thread.ofVirtual().start(() -> {
                FunctionUtils.doUnchecked(_ -> start.await());
                for (var index = 0; index < 500; index++) {
                    val ticketId = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                        .getNewTicketId(TicketGrantingTicket.PREFIX);
                    try {
                        FunctionUtils.doUnchecked(_ -> registry.addTicket(
                            new TicketGrantingTicketImpl(
                                ticketId,
                                authentication,
                                NeverExpiresExpirationPolicy.INSTANCE)));
                        successfulWrites.add(ticketId);
                    } catch (final Exception ignored) {
                        /*
                         * Registry-wide deletion intentionally rejects
                         * overlapping writes.
                         */
                    }
                }
            });
            start.countDown();
            registry.deleteAll();
            writer.join();

            val liveTickets = successfulWrites.stream()
                .filter(ticketId -> registry.getTicket(ticketId) != null)
                .count();
            assertEquals(liveTickets, registry.deleteTicketsFor(principalId));
            successfulWrites.forEach(ticketId -> assertNull(registry.getTicket(ticketId)));
        }

        @RepeatedTest(1)
        void verifyStaleRegistryAndRebuildLeasesCannotMutateRedis() throws Throwable {
            val principalId = UUID.randomUUID().toString();
            val registry = getNewTicketRegistry();
            val ticketId = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                .getNewTicketId(TicketGrantingTicket.PREFIX);
            registry.addTicket(new TicketGrantingTicketImpl(
                ticketId,
                CoreAuthenticationTestUtils.getAuthentication(principalId),
                NeverExpiresExpirationPolicy.INSTANCE));
            val concreteRegistry = (RedisTicketRegistry) AopTestUtils.getTargetObject(registry);
            val principalTicketIndex = concreteRegistry.getPrincipalTicketIndex();
            val indexTemplate = getCasRedisTemplates().getSessionsRedisTemplate();
            val ticketKey = redisTicketKey(registry, ticketId);
            val ticketGenerator = redisKeyGeneratorFactory
                .getRedisKeyGenerator(TicketGrantingTicket.PREFIX)
                .orElseThrow();
            val principalIndexKey = RedisPrincipalTicketIndexKeyGenerator.forPrincipal(
                RedisPrincipalIdentifierCodec.encode(principalId));

            val staleDeleteLease = principalTicketIndex.beginRegistryDelete();
            try {
                indexTemplate.opsForValue().set(
                    RedisPrincipalTicketIndexKeyGenerator.MUTATION_FENCE_KEY,
                    "replacement-owner", Duration.ofMinutes(5));
                assertThrows(RuntimeException.class, () -> principalTicketIndex.deleteKeysOnPrimary(
                    ticketRedisTemplate, ticketKey, staleDeleteLease));
                assertTrue(ticketRedisTemplate.hasKey(ticketKey));
                assertThrows(RuntimeException.class, () -> principalTicketIndex.deleteExactKeysOnPrimary(
                    ticketRedisTemplate, Set.of(ticketGenerator.getKeyspace()), staleDeleteLease));
                assertTrue(ticketRedisTemplate.hasKey(ticketGenerator.getKeyspace()));
            } finally {
                indexTemplate.delete(RedisPrincipalTicketIndexKeyGenerator.MUTATION_FENCE_KEY);
                indexTemplate.opsForValue().set(
                    RedisPrincipalTicketIndexKeyGenerator.READY_KEY,
                    RedisPrincipalTicketIndexKeyGenerator.SCHEMA_VERSION);
            }

            assertTrue(indexTemplate.delete(principalIndexKey));
            assertTrue(indexTemplate.delete(RedisPrincipalTicketIndexKeyGenerator.READY_KEY));
            indexTemplate.opsForValue().set(
                RedisPrincipalTicketIndexKeyGenerator.REBUILD_LOCK_KEY,
                "replacement-owner", Duration.ofMinutes(5));
            try {
                assertThrows(RuntimeException.class, () -> principalTicketIndex.rebuildPage(
                    "0", ticketKey, "stale-rebuild-owner"));
                assertFalse(indexTemplate.hasKey(principalIndexKey));
                assertTrue(ticketRedisTemplate.hasKey(ticketKey));
            } finally {
                indexTemplate.delete(RedisPrincipalTicketIndexKeyGenerator.REBUILD_LOCK_KEY);
                indexTemplate.opsForValue().set(
                    RedisPrincipalTicketIndexKeyGenerator.READY_KEY,
                    RedisPrincipalTicketIndexKeyGenerator.SCHEMA_VERSION);
            }
        }

        @RepeatedTest(1)
        void verifyPrincipalDeletePagesFailClosedWhenRegistryFenceInterleaves() throws Throwable {
            val principalId = UUID.randomUUID().toString();
            val registry = getNewTicketRegistry();
            val ticketId = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                .getNewTicketId(TicketGrantingTicket.PREFIX);
            registry.addTicket(new TicketGrantingTicketImpl(
                ticketId,
                CoreAuthenticationTestUtils.getAuthentication(principalId),
                NeverExpiresExpirationPolicy.INSTANCE));
            val concreteRegistry = (RedisTicketRegistry) AopTestUtils.getTargetObject(registry);
            val target = RedisPrincipalIdentifierCodec.encode(principalId);
            val principalIndexKey = RedisPrincipalTicketIndexKeyGenerator.forPrincipal(target);
            val principalGenerator = redisKeyGeneratorFactory
                .getRedisKeyGenerator(Principal.class.getName())
                .orElseThrow();
            val ticketGenerator = redisKeyGeneratorFactory
                .getRedisKeyGenerator(TicketGrantingTicket.PREFIX)
                .orElseThrow();
            val ticketKey = redisTicketKey(registry, ticketId);
            val documentId = RedisKeyGenerator.parse(ticketKey).getId();
            val ticketToDelete = new RedisTicketRegistry.RedisTicketToDelete(
                ticketKey, documentId, documentId, ticketGenerator.getKeyspace(), documentId, true);
            assertEquals(List.of(ticketKey),
                concreteRegistry.loadPrincipalTicketBatch(principalIndexKey));

            val principalTicketIndex = concreteRegistry.getPrincipalTicketIndex();
            val deleteLease = principalTicketIndex.beginRegistryDelete();
            var completed = false;
            try {
                assertThrows(RuntimeException.class,
                    () -> concreteRegistry.loadPrincipalTicketBatch(principalIndexKey));
                assertThrows(RuntimeException.class,
                    () -> concreteRegistry.loadPrincipalTicketBatch(
                        RedisPrincipalTicketIndexKeyGenerator.forPrincipal("absent-principal")),
                    "An empty terminal page must not bypass the READY/fence check");
                assertThrows(RuntimeException.class, () -> concreteRegistry.deletePrincipalTicketBatch(
                    target, principalIndexKey, principalGenerator.forId(target), List.of(ticketToDelete)));
                assertTrue(ticketRedisTemplate.hasKey(ticketKey));
                principalTicketIndex.completeRegistryDelete(deleteLease);
                completed = true;
            } finally {
                if (!completed) {
                    principalTicketIndex.abortRegistryDelete(deleteLease);
                }
            }
            assertNotNull(registry.getTicket(ticketId));
        }

        @RepeatedTest(1)
        void verifyLegacyRebuildCutoverAndReadinessFence() throws Throwable {
            val principalId = UUID.randomUUID().toString();
            val registry = getNewTicketRegistry();
            val ticketId = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                .getNewTicketId(TicketGrantingTicket.PREFIX);
            registry.addTicket(new TicketGrantingTicketImpl(
                ticketId,
                CoreAuthenticationTestUtils.getAuthentication(principalId),
                NeverExpiresExpirationPolicy.INSTANCE));
            val indexTemplate = getCasRedisTemplates().getSessionsRedisTemplate();
            val indexKey = RedisPrincipalTicketIndexKeyGenerator.forPrincipal(
                RedisPrincipalIdentifierCodec.encode(principalId));
            assertTrue(indexTemplate.delete(indexKey));
            addRawIndexMember(indexKey, redisTicketKey(registry, ticketId), 1);
            assertTrue(indexTemplate.delete(RedisPrincipalTicketIndexKeyGenerator.READY_KEY));

            val concreteRegistry = (RedisTicketRegistry) AopTestUtils.getTargetObject(registry);
            assertThrows(IllegalStateException.class,
                () -> registry.deleteTicketsFor(principalId));
            val allTickets = redisKeyGeneratorFactory
                .getRedisKeyGenerator(Ticket.class.getName())
                .orElseThrow()
                .forEverything();
            indexTemplate.opsForValue().set(
                RedisPrincipalTicketIndexKeyGenerator.REBUILD_LOCK_KEY,
                "crashed-owner",
                Duration.ofMillis(250));
            concreteRegistry.getPrincipalTicketIndex().rebuildIfNecessary(allTickets);
            assertThrows(IllegalStateException.class,
                () -> registry.deleteTicketsFor(principalId));
            await().atMost(10, TimeUnit.SECONDS).untilAsserted(() ->
                assertEquals(RedisPrincipalTicketIndexKeyGenerator.SCHEMA_VERSION,
                    rawString(RedisPrincipalTicketIndexKeyGenerator.READY_KEY)));
            assertTrue(Objects.requireNonNull(
                rawIndexScore(indexKey, redisTicketKey(registry, ticketId)))
                > Instant.now().toEpochMilli());
            assertEquals(1, registry.deleteTicketsFor(principalId));
            assertNull(registry.getTicket(ticketId));
        }

        @RepeatedTest(1)
        void verifyRebuildRejectsPrincipalTicketWithoutExpiration() {
            val principalId = UUID.randomUUID().toString();
            val registry = getNewTicketRegistry();
            val ticketId = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                .getNewTicketId(TicketGrantingTicket.PREFIX);
            val ticketKey = redisTicketKey(registry, ticketId);
            val indexTemplate = getCasRedisTemplates().getSessionsRedisTemplate();
            val principal = RedisPrincipalIdentifierCodec.encode(principalId);
            ticketRedisTemplate.execute((RedisCallback<Boolean>) connection ->
                connection.hashCommands().hSet(
                    ticketKey.getBytes(StandardCharsets.UTF_8),
                    RedisTicketDocument.FIELD_NAME_PRINCIPAL.getBytes(StandardCharsets.UTF_8),
                    principal.getBytes(StandardCharsets.UTF_8)));
            assertEquals(-1, ticketRedisTemplate.getExpire(ticketKey));
            assertTrue(indexTemplate.delete(RedisPrincipalTicketIndexKeyGenerator.READY_KEY));

            val concreteRegistry = (RedisTicketRegistry) AopTestUtils.getTargetObject(registry);
            val allTickets = redisKeyGeneratorFactory
                .getRedisKeyGenerator(Ticket.class.getName())
                .orElseThrow()
                .forEverything();
            assertThrows(RuntimeException.class,
                () -> concreteRegistry.getPrincipalTicketIndex().rebuildIfNecessary(allTickets));
            assertNull(rawString(RedisPrincipalTicketIndexKeyGenerator.READY_KEY));
            assertTrue(ticketRedisTemplate.hasKey(ticketKey));

            assertTrue(ticketRedisTemplate.delete(ticketKey));
            concreteRegistry.getPrincipalTicketIndex().rebuildIfNecessary(allTickets);
            assertEquals(RedisPrincipalTicketIndexKeyGenerator.SCHEMA_VERSION,
                rawString(RedisPrincipalTicketIndexKeyGenerator.READY_KEY));
        }

        private String redisTicketKey(final TicketRegistry registry,
                                      final String ticketId) {
            val prefix = StringUtils.substringBefore(ticketId, '-');
            val keyGenerator = redisKeyGeneratorFactory
                .getRedisKeyGenerator(prefix)
                .orElseThrow();
            return keyGenerator.forPrefixAndId(prefix, registry.digestIdentifier(ticketId));
        }

        private void addRawIndexMember(final String indexKey,
                                       final String member,
                                       final double score) {
            getCasRedisTemplates().getSessionsRedisTemplate().execute(
                (RedisCallback<Boolean>) connection -> connection.zSetCommands().zAdd(
                    indexKey.getBytes(StandardCharsets.UTF_8),
                    score,
                    member.getBytes(StandardCharsets.UTF_8)));
        }

        private Double rawIndexScore(final String indexKey,
                                     final String member) {
            return getCasRedisTemplates().getSessionsRedisTemplate().execute(
                (RedisCallback<Double>) connection -> connection.zSetCommands().zScore(
                    indexKey.getBytes(StandardCharsets.UTF_8),
                    member.getBytes(StandardCharsets.UTF_8)));
        }

        private String rawString(final String key) {
            val value = getCasRedisTemplates().getSessionsRedisTemplate().execute(
                (RedisCallback<byte[]>) connection -> connection.stringCommands().get(
                    key.getBytes(StandardCharsets.UTF_8)));
            return value == null ? null : new String(value, StandardCharsets.UTF_8);
        }
    }

    @Nested
    @TestPropertySource(properties = {
        "cas.ticket.registry.redis.protocol-version=RESP2",
        "cas.ticket.registry.redis.queue-identifier=cas-node-1",
        "cas.ticket.registry.redis.host=localhost",
        "cas.ticket.registry.redis.port=6379",
        "cas.ticket.registry.redis.pool.max-active=20",
        "cas.ticket.registry.redis.pool.enabled=true",
        "cas.ticket.registry.redis.crypto.enabled=true",
        "cas.ticket.registry.redis.crypto.encryption.key=AZ5y4I9qzKPYUVNL2Td4RMbpg6Z-ldui8VEFg8hsj1M",
        "cas.ticket.registry.redis.crypto.signing.key=cAPyoHMrOMWrwydOXzBA-ufZQM-TilnLjbRgMQWlUlwFmy07bOtAgCIdNBma3c5P4ae_JV6n1OpOAYqSh2NkmQ"
    })
    class DefaultTests extends BaseRedisSentinelTicketRegistryTests {

        private static final int COUNT = 50;

        @Autowired
        @Qualifier("redisTicketRegistryCache")
        private Cache<String, Ticket> redisTicketRegistryCache;

        @RepeatedTest(1)
        @Tag("TicketRegistryTestWithEncryption")
        void verifyDeleteTicketsForWithCacheAndListener() throws Throwable {
            val authentication = CoreAuthenticationTestUtils.getAuthentication(UUID.randomUUID().toString());
            val tgtId = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                .getNewTicketId(TicketGrantingTicket.PREFIX);
            val tgt = new TicketGrantingTicketImpl(tgtId, authentication, NeverExpiresExpirationPolicy.INSTANCE);
            getNewTicketRegistry().addTicket(tgt);
            assertNotNull(getNewTicketRegistry().getTicket(tgtId));

            val cacheKey = getNewTicketRegistry().digestIdentifier(tgt.getId());
            assertNotNull(redisTicketRegistryCache.getIfPresent(cacheKey));

            val deleted = getNewTicketRegistry().deleteTicketsFor(authentication.getPrincipal().getId());
            assertTrue(deleted > 0);
            assertNull(redisTicketRegistryCache.getIfPresent(cacheKey));
            assertNull(getNewTicketRegistry().getTicket(tgt.getId()));
        }

        @RepeatedTest(2)
        void verifyLargeDataset() {
            LOGGER.info("Current repetition: [{}]", useEncryption ? "Encrypted" : "Plain");
            val authentication = CoreAuthenticationTestUtils.getAuthentication(UUID.randomUUID().toString());
            val ticketGrantingTicketToAdd = Stream.generate(() -> {
                    val tgtId = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                        .getNewTicketId(TicketGrantingTicket.PREFIX);
                    return new TicketGrantingTicketImpl(tgtId, authentication, NeverExpiresExpirationPolicy.INSTANCE);
                })
                .limit(COUNT);
            executedTimedOperation("Adding tickets in bulk",
                Unchecked.consumer(_ -> getNewTicketRegistry().addTicket(ticketGrantingTicketToAdd)));
            executedTimedOperation("Getting tickets",
                Unchecked.consumer(_ -> {
                    val tickets = getNewTicketRegistry().getTickets();
                    assertFalse(tickets.isEmpty());
                }));
            val ticketStream = executedTimedOperation("Getting tickets in bulk",
                Unchecked.supplier(() -> getNewTicketRegistry().stream()));
            executedTimedOperation("Getting tickets individually",
                Unchecked.consumer(_ -> ticketStream.forEach(ticket -> assertNotNull(getNewTicketRegistry().getTicket(ticket.getId())))));

            executedTimedOperation("Counting all SSO sessions",
                Unchecked.consumer(_ -> getNewTicketRegistry().sessionCount()));
            executedTimedOperation("Counting all application sessions",
                Unchecked.consumer(_ -> getNewTicketRegistry().serviceTicketCount()));
            executedTimedOperation("Counting all user sessions",
                Unchecked.consumer(_ -> getNewTicketRegistry().countSessionsFor(authentication.getPrincipal().getId())));
        }

        @RepeatedTest(2)
        void verifyRegistryQuery() {
            LOGGER.info("Current repetition: [{}]", useEncryption ? "Encrypted" : "Plain");
            val authentication = CoreAuthenticationTestUtils.getAuthentication(UUID.randomUUID().toString());
            val ticketGrantingTicketToAdd = Stream.generate(() -> {
                    val tgtId = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                        .getNewTicketId(TicketGrantingTicket.PREFIX);
                    return new TicketGrantingTicketImpl(tgtId, authentication, NeverExpiresExpirationPolicy.INSTANCE);
                })
                .limit(5);
            getNewTicketRegistry().addTicket(ticketGrantingTicketToAdd);

            val criteria1 = new TicketRegistryQueryCriteria()
                .setCount(5L)
                .setDecode(Boolean.FALSE)
                .setType(TicketGrantingTicket.PREFIX);
            val queryResults1 = getNewTicketRegistry().query(criteria1);
            assertEquals(criteria1.getCount(), queryResults1.size());

            ((Cleanable) getNewTicketRegistry()).clean();
            val criteria2 = new TicketRegistryQueryCriteria()
                .setCount(5L)
                .setDecode(Boolean.TRUE)
                .setType(TicketGrantingTicket.PREFIX);
            val queryResults = getNewTicketRegistry().query(criteria2);
            assertEquals(criteria2.getCount(), queryResults.size());
        }

        @RepeatedTest(2)
        void verifyRegistryCount() {
            LOGGER.info("Current repetition: [{}]", useEncryption ? "Encrypted" : "Plain");
            val authentication = CoreAuthenticationTestUtils.getAuthentication(UUID.randomUUID().toString());
            val ticketGrantingTicketToAdd = Stream.generate(() -> {
                val tgtId = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                    .getNewTicketId(TicketGrantingTicket.PREFIX);
                return new TicketGrantingTicketImpl(tgtId, authentication, NeverExpiresExpirationPolicy.INSTANCE);
            }).limit(5);
            getNewTicketRegistry().addTicket(ticketGrantingTicketToAdd);
            val totalCount = getNewTicketRegistry().countTickets();
            assertTrue(totalCount > 0);
        }

        private static <T> T executedTimedOperation(final String name, final Supplier<T> operation) {
            val stopwatch = new StopWatch();
            stopwatch.start();
            val result = operation.get();
            stopwatch.stop();
            val time = stopwatch.getTime(TimeUnit.MILLISECONDS);
            LOGGER.info("[{}]: [{}]ms", name, time);
            assertTrue(time <= 8000);
            return result;
        }

        private static void executedTimedOperation(final String name, final Consumer operation) {
            val stopwatch = new StopWatch();
            stopwatch.start();
            operation.accept(null);
            stopwatch.stop();
            val time = stopwatch.getTime(TimeUnit.MILLISECONDS);
            LOGGER.info("[{}]: [{}]ms", name, time);
            assertTrue(time <= 6000);
        }

        @RepeatedTest(2)
        void verifyHealthOperation() {
            val health = redisHealthIndicator.health();
            val section = (Map) health.getDetails().get("redisTicketConnectionFactory");
            assertTrue(section.containsKey("server"));
            assertTrue(section.containsKey("memory"));
            assertTrue(section.containsKey("cpu"));
            assertTrue(section.containsKey("keyspace"));
            assertTrue(section.containsKey("stats"));
        }

        @RepeatedTest(1)
        void verifyFailure() throws Throwable {
            val ticketGrantingTicketId = TestTicketIdentifiers.generate().ticketGrantingTicketId();
            val originalAuthn = CoreAuthenticationTestUtils.getAuthentication();
            getNewTicketRegistry().addTicket(new TicketGrantingTicketImpl(ticketGrantingTicketId,
                originalAuthn, NeverExpiresExpirationPolicy.INSTANCE));
            assertNull(getNewTicketRegistry().getTicket(ticketGrantingTicketId, _ -> {
                throw new IllegalArgumentException();
            }));
            assertDoesNotThrow(() -> {
                getNewTicketRegistry().addTicket((Ticket) null);
                getNewTicketRegistry().updateTicket(null);
            });
        }
    }

    @Nested
    @TestPropertySource(properties = {
        "cas.ticket.registry.redis.protocol-version=RESP2",
        "cas.ticket.registry.redis.queue-identifier=cas-node-1",
        "cas.ticket.registry.redis.pool.max-active=20",
        "cas.ticket.registry.redis.pool.max-wait=PT10S",
        "cas.ticket.registry.redis.pool.enabled=true",
        "cas.ticket.registry.redis.host=localhost",
        "cas.ticket.registry.redis.port=6379",
        "cas.ticket.registry.redis.crypto.encryption.key=AZ5y4I9qzKPYUVNL2Td4RMbpg6Z-ldui8VEFg8hsj1M",
        "cas.ticket.registry.redis.crypto.signing.key=cAPyoHMrOMWrwydOXzBA-ufZQM-TilnLjbRgMQWlUlwFmy07bOtAgCIdNBma3c5P4ae_JV6n1OpOAYqSh2NkmQ",
        "CasFeatureModule.TicketRegistry.redis-messaging.enabled=false"
    })
    class NoMessagingTests extends BaseRedisSentinelTicketRegistryTests {

        @RepeatedTest(2)
        void verifyTicketWithIdleTimeout() throws Throwable {
            val originalAuthn = CoreAuthenticationTestUtils.getAuthentication();
            val ticketGrantingTicketId = TestTicketIdentifiers.generate().ticketGrantingTicketId();
            val addedTicket = getNewTicketRegistry().addTicket(new TicketGrantingTicketImpl(ticketGrantingTicketId,
                originalAuthn, new TimeoutExpirationPolicy(2)));
            val tgt = getNewTicketRegistry().getTicket(addedTicket.getId(), TicketGrantingTicket.class);
            assertNotNull(tgt);
            val authentication = tgt.getAuthentication();
            assertNotNull(authentication);
            await().atMost(3, TimeUnit.SECONDS).untilAsserted(() -> assertNull(getNewTicketRegistry().getTicket(ticketGrantingTicketId)));
        }

    }

    @Nested
    @SpringBootTest(
        classes = {
            CasRedisCoreAutoConfiguration.class,
            CasRedisTicketRegistryAutoConfiguration.class,
            BaseTicketRegistryTests.SharedTestConfiguration.class
        }, properties = {
        "cas.ticket.tgt.core.service-tracking-policy=MOST_RECENT",
        "cas.ticket.registry.redis.host=localhost",
        "cas.ticket.registry.redis.port=6379",
        "cas.ticket.registry.redis.pool.max-active=20",
        "cas.ticket.registry.redis.pool.enabled=true",
        "cas.ticket.registry.redis.enable-redis-search=false",
        "cas.ticket.registry.redis.crypto.enabled=true"
    })
    @ExtendWith(CasTestExtension.class)
    class RecentSessionsTests {
        @Autowired
        @Qualifier(TicketRegistry.BEAN_NAME)
        private TicketRegistry ticketRegistry;

        @RetryingTest(2)
        void verifyDifferentLoginSamePrincipal() throws Throwable {
            val principalId = UUID.randomUUID().toString();
            val authentication = CoreAuthenticationTestUtils.getAuthentication(principalId);
            for (var i = 0; i < 20; i++) {
                val tgtId = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                    .getNewTicketId(TicketGrantingTicket.PREFIX);
                val tgt1 = new TicketGrantingTicketImpl(tgtId, authentication, NeverExpiresExpirationPolicy.INSTANCE);
                ticketRegistry.addTicket(tgt1);
            }
            await().untilAsserted(() -> assertEquals(1, ticketRegistry.countSessionsFor(principalId)));
        }
    }

    @Nested
    @SpringBootTest(
        classes = {
            CasRedisCoreAutoConfiguration.class,
            CasRedisTicketRegistryAutoConfiguration.class,
            BaseTicketRegistryTests.SharedTestConfiguration.class
        }, properties = {
        "cas.ticket.tgt.core.service-tracking-policy=ALL",
        "cas.ticket.registry.redis.host=localhost",
        "cas.ticket.registry.redis.port=6379",
        "cas.ticket.registry.redis.enable-redis-search=false",
        "cas.ticket.registry.redis.crypto.enabled=false"
    })
    @ExtendWith(CasTestExtension.class)
    class TrackAllSessionsTests {
        @Autowired
        @Qualifier(TicketRegistry.BEAN_NAME)
        private TicketRegistry ticketRegistry;

        @Autowired
        @Qualifier("ticketRedisTemplate")
        private CasRedisTemplate<String, RedisTicketDocument> ticketRedisTemplate;

        @Autowired
        @Qualifier("sessionsRedisTemplate")
        private CasRedisTemplate<String, String> sessionsRedisTemplate;

        @Autowired
        @Qualifier(RedisKeyGeneratorFactory.BEAN_NAME)
        private RedisKeyGeneratorFactory redisKeyGeneratorFactory;

        @Autowired
        @Qualifier(RedisPrincipalTicketMutationFence.BEAN_NAME)
        private RedisPrincipalTicketMutationFence principalMutationFence;

        @Test
        void verifyDifferentLoginSamePrincipal() throws Throwable {
            val principalId = "Sensitive.User+" + UUID.randomUUID() + "@Example.ORG";
            for (var i = 0; i < 3; i++) {
                addTicketAndWait(principalId);
            }
            val mappedPrincipal = RedisPrincipalIdentifierCodec.encode(principalId);
            val keyGenerator = redisKeyGeneratorFactory.getRedisKeyGenerator(Principal.class.getName()).orElseThrow();
            val key = keyGenerator.forId(mappedPrincipal);
            await().atMost(3, TimeUnit.SECONDS).untilAsserted(() ->
                assertEquals(1, ticketRegistry.countSessionsFor(principalId)));
            assertEquals(0, ticketRegistry.countSessionsFor(
                principalId.toLowerCase(Locale.ROOT)));
            assertEquals(1, sessionsRedisTemplate.boundZSetOps(key).size());

            val principalIndexKey = RedisPrincipalTicketIndexKeyGenerator
                .forPrincipal(mappedPrincipal);
            val registry = (RedisTicketRegistry) AopTestUtils.getTargetObject(ticketRegistry);
            val indexedTickets = registry.loadPrincipalTicketBatch(principalIndexKey);
            assertFalse(indexedTickets.isEmpty());
            indexedTickets.forEach(indexedTicket -> {
                val storedPrincipal = ticketRedisTemplate.execute(
                    (RedisCallback<byte[]>) connection -> connection.hashCommands().hGet(
                        indexedTicket.getBytes(StandardCharsets.UTF_8),
                        RedisTicketDocument.FIELD_NAME_PRINCIPAL.getBytes(StandardCharsets.UTF_8)));
                assertNotNull(storedPrincipal);
                assertEquals(mappedPrincipal,
                    new String(storedPrincipal, StandardCharsets.UTF_8));
            });

            val fenceKey = principalMutationFence.keyForPrincipal(principalId);
            assertEquals(
                RedisPrincipalTicketMutationFenceKeyGenerator.forPrincipal(mappedPrincipal),
                fenceKey);
            assertNotEquals(fenceKey, principalMutationFence.keyForPrincipal(
                principalId.toLowerCase(Locale.ROOT)));
            assertFalse(principalIndexKey.toLowerCase(Locale.ROOT).contains("sensitive.user"));
            assertFalse(key.toLowerCase(Locale.ROOT).contains("sensitive.user"));
            assertFalse(fenceKey.toLowerCase(Locale.ROOT).contains("sensitive.user"));
        }

        private void addTicketAndWait(final String principalId) throws Throwable {
            val authentication = CoreAuthenticationTestUtils.getAuthentication(principalId);
            val tgtId = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY)
                .getNewTicketId(TicketGrantingTicket.PREFIX);
            val tgt = new TicketGrantingTicketImpl(tgtId, authentication, new HardTimeoutExpirationPolicy(2));
            ticketRegistry.addTicket(tgt);
            Thread.sleep(1000);
        }
    }

    @Nested
    @SpringBootTest(
        classes = {
            CasRedisCoreAutoConfiguration.class,
            CasRedisTicketRegistryAutoConfiguration.class,
            BaseTicketRegistryTests.SharedTestConfiguration.class
        }, properties = {
        "cas.ticket.tgt.core.service-tracking-policy=MOST_RECENT",
        "cas.ticket.registry.redis.host=localhost",
        "cas.ticket.registry.redis.port=6379"
    })
    @ExtendWith(CasTestExtension.class)
    class ConcurrentAddTicketGrantingTicketTests {
        @Autowired
        @Qualifier(TicketRegistry.BEAN_NAME)
        private TicketRegistry ticketRegistry;

        @Test
        void verifyConcurrentAddTicket() {
            val principalId = UUID.randomUUID().toString();
            val testHasFailed = new AtomicBoolean();
            val threads = new ArrayList<Thread>();
            for (var i = 1; i <= 100; i++) {
                val runnable = new RunnableAddTicketGrantingTicket(ticketRegistry, principalId, 100);
                val thread = Thread.ofVirtual();
                thread.name("Thread-" + i);
                thread.uncaughtExceptionHandler((t, e) -> {
                    LoggingUtils.error(LOGGER, e);
                    testHasFailed.set(true);
                });
                threads.add(thread.start(runnable));
            }
            for (val thread : threads) {
                try {
                    thread.join();
                } catch (final Throwable e) {
                    fail(e);
                }
            }
            if (testHasFailed.get()) {
                fail("Test failed");
            }
        }

        @RequiredArgsConstructor
        private static final class RunnableAddTicketGrantingTicket implements Runnable {
            private final TicketRegistry ticketRegistry;
            private final String principalId;
            private final int max;

            @Override
            public void run() {
                val authentication = CoreAuthenticationTestUtils.getAuthentication(principalId);
                val ticketGenerator = new TicketGrantingTicketIdGenerator(10, StringUtils.EMPTY);
                for (var i = 0; i < max; i++) {
                    val tgtId = ticketGenerator.getNewTicketId(TicketGrantingTicket.PREFIX);
                    val tgt = new TicketGrantingTicketImpl(tgtId, authentication, NeverExpiresExpirationPolicy.INSTANCE);
                    FunctionUtils.doUnchecked(_ -> ticketRegistry.addTicket(tgt));
                }
            }
        }
    }

    @Nested
    @SpringBootTest(
        classes = {
            CasRedisCoreAutoConfiguration.class,
            CasRedisTicketRegistryAutoConfiguration.class,
            BaseTicketRegistryTests.SharedTestConfiguration.class
        }, properties = {
        "cas.ticket.tgt.core.service-tracking-policy=ALL",
        "cas.ticket.registry.redis.host=localhost",
        "cas.ticket.registry.redis.port=6379"
    })
    @ExtendWith(CasTestExtension.class)
    class ConcurrentAddProxyTicketTests {
        @Autowired
        @Qualifier(TicketRegistry.BEAN_NAME)
        private TicketRegistry ticketRegistry;

        @Autowired
        @Qualifier(TicketTrackingPolicy.BEAN_NAME_SERVICE_TICKET_TRACKING)
        private TicketTrackingPolicy serviceTicketSessionTrackingPolicy;

        @Autowired
        @Qualifier(WebApplicationService.BEAN_NAME_FACTORY)
        private ServiceFactory<WebApplicationService> webApplicationServiceFactory;


        @Test
        void verifyConcurrentAddTicket() throws Throwable {
            val principalId = UUID.randomUUID().toString();
            val authentication = CoreAuthenticationTestUtils.getAuthentication(principalId);
            val tgtGenerator = new ProxyGrantingTicketIdGenerator(10, StringUtils.EMPTY);
            val pgt = new ProxyGrantingTicketImpl(tgtGenerator.getNewTicketId(TicketGrantingTicket.PREFIX),
                authentication, NeverExpiresExpirationPolicy.INSTANCE);
            ticketRegistry.addTicket(pgt);

            val request = new MockHttpServletRequest();
            request.setParameter(CasProtocolConstants.PARAMETER_SERVICE, "http://foo.com");
            val service = webApplicationServiceFactory.createService(request);

            val testHasFailed = new AtomicBoolean();
            val threads = new ArrayList<Thread>();
            for (var i = 1; i <= 3; i++) {
                val runnable = new RunnableAddProxyTicket(ticketRegistry, pgt, service, serviceTicketSessionTrackingPolicy, 100);
                val thread = new Thread(runnable);
                thread.setName("Thread-" + i);
                thread.setUncaughtExceptionHandler((t, e) -> {
                    LoggingUtils.error(LOGGER, e);
                    testHasFailed.set(true);
                });
                threads.add(thread);
                thread.start();
            }
            for (val thread : threads) {
                try {
                    thread.join();
                } catch (final Throwable e) {
                    fail(e);
                }
            }
            if (testHasFailed.get()) {
                fail("Test failed");
            }
        }

        @RequiredArgsConstructor
        private static final class RunnableAddProxyTicket implements Runnable {
            private final TicketRegistry ticketRegistry;
            private final ProxyGrantingTicket proxyGrantingTicket;
            private final Service service;
            private final TicketTrackingPolicy serviceTicketSessionTrackingPolicy;
            private final int max;

            @Override
            public void run() {
                val ptGenerator = new ProxyTicketIdGenerator(10, StringUtils.EMPTY);
                for (var i = 0; i < max; i++) {
                    val proxyTicket = proxyGrantingTicket.grantProxyTicket(ptGenerator.getNewTicketId(ProxyTicket.PREFIX),
                        service, new HardTimeoutExpirationPolicy(20), serviceTicketSessionTrackingPolicy);
                    FunctionUtils.doUnchecked(_ -> ticketRegistry.addTicket(proxyTicket));
                }
            }
        }
    }


    @Nested
    @SpringBootTest(
        classes = {
            CasRedisCoreAutoConfiguration.class,
            CasRedisTicketRegistryAutoConfiguration.class,
            BaseTicketRegistryTests.SharedTestConfiguration.class
        },
        properties = {
            "cas.ticket.tgt.core.service-tracking-policy=MOST_RECENT",
            "cas.ticket.registry.redis.host=localhost",
            "cas.ticket.registry.redis.port=6379",
            "cas.slo.disabled=true"
        })
    @ExtendWith(CasTestExtension.class)
    class DisabledSloTests {
        @Autowired
        @Qualifier(TicketRegistry.BEAN_NAME)
        private TicketRegistry ticketRegistry;

        @Autowired
        @Qualifier(TicketTrackingPolicy.BEAN_NAME_SERVICE_TICKET_TRACKING)
        private TicketTrackingPolicy serviceTicketSessionTrackingPolicy;
        
        @Test
        void verifyServicesUntrackedWithSloOff() throws Exception {
            val authn = CoreAuthenticationTestUtils.getAuthentication(
                Map.of("cn", List.of("cn1", "cn2"), "givenName", List.of("g1", "g2"),
                    "authn-context", List.of("mfa-example")));
            val ticketGrantingTicket = new TicketGrantingTicketImpl(
                BaseTicketRegistryTests.TestTicketIdentifiers.generate().ticketGrantingTicketId(),
                authn, NeverExpiresExpirationPolicy.INSTANCE);
            ticketRegistry.addTicket(ticketGrantingTicket);
            val st = ticketGrantingTicket.grantServiceTicket(
                BaseTicketRegistryTests.TestTicketIdentifiers.generate().serviceTicketId(),
                RegisteredServiceTestUtils.getService(),
                NeverExpiresExpirationPolicy.INSTANCE, false,
                serviceTicketSessionTrackingPolicy);
            ticketRegistry.addTicket(st);
            assertEquals(1, ticketGrantingTicket.getServices().size());
            ticketRegistry.updateTicket(ticketGrantingTicket);

            val ticket = ticketRegistry.getTicket(ticketGrantingTicket.getId(), TicketGrantingTicket.class);
            assertNotNull(ticket);
            assertTrue(ticket.getServices().isEmpty());
        }

    }
}
