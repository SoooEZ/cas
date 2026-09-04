package org.apereo.cas.ticket.registry;

import module java.base;
import org.apereo.cas.redis.core.CasRedisTemplate;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.ticket.registry.key.RedisPrincipalIdentifierCodec;
import org.apereo.cas.ticket.registry.key.RedisPrincipalTicketIndexKeyGenerator;
import org.apereo.cas.ticket.registry.key.RedisPrincipalTicketMutationFenceKeyGenerator;
import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisScriptingCommands;
import org.springframework.data.redis.connection.ReturnType;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.data.redis.core.convert.RedisData;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Non-Redis contract tests for {@link RedisTicketRegistryWriteExecutor}.
 *
 * @author SoooEZ
 * @since 8.0.1
 */
@Tag("Simple")
class RedisTicketRegistryWriteExecutorTests {

    @Test
    void verifySchemaAndBulkDeletionUsePrimaryRoutedLua() {
        val ticketsTemplate = mock(CasRedisTemplate.class);
        val indexTemplate = mock(CasRedisTemplate.class);
        val connection = mock(RedisConnection.class);
        val scriptingCommands = mock(RedisScriptingCommands.class);
        when(connection.scriptingCommands()).thenReturn(scriptingCommands);
        doAnswer(invocation -> {
            val returnType = invocation.getArgument(1, ReturnType.class);
            return switch (returnType) {
                case VALUE -> RedisPrincipalTicketIndexKeyGenerator.SCHEMA_VERSION
                    .getBytes(StandardCharsets.UTF_8);
                case MULTI -> List.of(
                    "0".getBytes(StandardCharsets.UTF_8),
                    "0".getBytes(StandardCharsets.UTF_8));
                case INTEGER -> 1L;
                default -> throw new AssertionError("Unexpected Redis script return type " + returnType);
            };
        }).when(scriptingCommands).eval(
            any(byte[].class), any(ReturnType.class), anyInt(), any(byte[][].class));
        doAnswer(invocation -> invocation
            .<RedisCallback<?>>getArgument(0)
            .doInRedis(connection))
            .when(indexTemplate).execute(any(RedisCallback.class));
        doAnswer(invocation -> invocation
            .<RedisCallback<?>>getArgument(0)
            .doInRedis(connection))
            .when(ticketsTemplate).execute(any(RedisCallback.class));

        try (val index = new RedisPrincipalTicketIndex(ticketsTemplate, indexTemplate)) {
            index.requireReady();
            assertEquals(0, index.deleteKeysOnPrimary(
                ticketsTemplate, "CAS_TICKET:*:*", "delete-lease"));
            assertEquals(1, index.deleteExactKeysOnPrimary(
                ticketsTemplate, Set.of("CAS_TICKET:TGT"), "delete-lease"));
        }
        val ticketRegistry = mock(TicketRegistry.class);
        val principalFence = new DefaultRedisPrincipalTicketMutationFence(
            indexTemplate, ticketRegistry);
        assertEquals(RedisPrincipalTicketMutationFenceKeyGenerator.forPrincipal(
                RedisPrincipalIdentifierCodec.encode("raw-principal")),
            principalFence.acquire(
                "raw-principal", "owner-token", Duration.ofSeconds(30)).redisKey());
        assertTrue(principalFence.release("raw-principal", "owner-token"));
        verify(ticketRegistry, never()).digestIdentifier(anyString());

        verify(scriptingCommands).eval(
            any(byte[].class), eq(ReturnType.VALUE), eq(1), any(byte[][].class));
        verify(scriptingCommands).eval(
            any(byte[].class), eq(ReturnType.MULTI), eq(1), any(byte[][].class));
        verify(connection, never()).stringCommands();
        verify(indexTemplate, never()).scan(any(ScanOptions.class));
        verify(ticketsTemplate, never()).scan(any(ScanOptions.class));
    }

    @Test
    void verifyPrincipalIndexKeyCodec() {
        val rawPrincipal = "Sensitive.User+PII@Example.ORG";
        val mappedPrincipal = RedisPrincipalIdentifierCodec.encode(rawPrincipal);
        assertEquals(128, mappedPrincipal.length());
        assertEquals(mappedPrincipal, RedisPrincipalIdentifierCodec.encode(rawPrincipal));
        assertNotEquals(mappedPrincipal,
            RedisPrincipalIdentifierCodec.encode("sensitive.user+pii@example.org"));
        assertNotEquals(mappedPrincipal,
            RedisPrincipalIdentifierCodec.encode(' ' + rawPrincipal));
        assertFalse(mappedPrincipal.toLowerCase(Locale.ROOT).contains("sensitive"));
        assertThrows(IllegalArgumentException.class,
            () -> RedisPrincipalIdentifierCodec.encode("  "));
        assertThrows(IllegalArgumentException.class,
            () -> RedisPrincipalIdentifierCodec.encode("x".repeat(1_025)));
        assertEquals("CAS_PRINCIPAL_TICKET:mapped-principal",
            RedisPrincipalTicketIndexKeyGenerator.forPrincipal("mapped-principal"));
        assertEquals("CAS_PRINCIPAL_TICKET:",
            RedisPrincipalTicketIndexKeyGenerator.prefix());
        assertEquals("CAS_PRINCIPAL_TICKET:*",
            RedisPrincipalTicketIndexKeyGenerator.forEverything());
        assertThrows(IllegalArgumentException.class,
            () -> RedisPrincipalTicketIndexKeyGenerator.forPrincipal(" "));
        assertEquals("CAS_PRINCIPAL_TICKET_MUTATION_FENCE:mapped-principal",
            RedisPrincipalTicketMutationFenceKeyGenerator.forPrincipal("mapped-principal"));
        assertThrows(IllegalArgumentException.class,
            () -> RedisPrincipalTicketMutationFenceKeyGenerator.forPrincipal(" "));
    }

    @Test
    void verifyWriteCommandBackwardsCompatibleDefaults() {
        val redisData = new RedisData();
        redisData.getBucket().put(RedisTicketDocument.FIELD_NAME_JSON, new byte[]{1});
        val command = new RedisTicketRegistryWriteExecutor.WriteCommand(
            mock(Ticket.class),
            TicketRegistryWriteInterceptor.Operation.ADD,
            "CAS_TICKET:TGT:id",
            "CAS_TICKET:TGT",
            "id",
            30,
            1_000,
            redisData);

        assertEquals(RedisPrincipalTicketIndexKeyGenerator.MUTATION_FENCE_KEY,
            command.mutationFenceKey());
        assertTrue(command.issuanceContext().isEmpty());
        assertTrue(command.principalMutationFenceKey().isEmpty());
        assertTrue(command.principalIndex().isEmpty());
        assertTrue(command.principalSessionIndex().isEmpty());
    }

    @Test
    void verifySessionIndexMemberIsImmutableAndRequiresTicketIndex() {
        val original = new byte[]{1, 2, 3};
        val sessionIndex = new RedisTicketRegistryWriteExecutor.PrincipalSessionIndexEntry(
            "CAS_PRINCIPAL:",
            "CAS_PRINCIPAL:mapped-principal",
            original,
            10,
            RedisTicketRegistryWriteExecutor.PrincipalSessionIndexMode.ALL);
        original[0] = 9;
        assertArrayEquals(new byte[]{1, 2, 3}, sessionIndex.serializedMember());
        val returned = sessionIndex.serializedMember();
        returned[1] = 9;
        assertArrayEquals(new byte[]{1, 2, 3}, sessionIndex.serializedMember());

        val redisData = new RedisData();
        redisData.getBucket().put(RedisTicketDocument.FIELD_NAME_JSON, new byte[]{1});
        assertThrows(IllegalArgumentException.class,
            () -> new RedisTicketRegistryWriteExecutor.WriteCommand(
                mock(Ticket.class),
                TicketRegistryWriteInterceptor.Operation.ADD,
                "CAS_TICKET:TGT:id",
                "CAS_TICKET:TGT",
                "id",
                30,
                1_000,
                redisData,
                Optional.empty(),
                RedisPrincipalTicketIndexKeyGenerator.MUTATION_FENCE_KEY,
                Optional.empty(),
                Optional.empty(),
                Optional.of(sessionIndex)));
    }
}
