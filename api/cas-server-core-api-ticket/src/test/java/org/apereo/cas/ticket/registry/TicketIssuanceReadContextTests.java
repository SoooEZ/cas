package org.apereo.cas.ticket.registry;

import module java.base;
import org.apereo.cas.ticket.PropertiesAwareTicket;
import org.apereo.cas.ticket.Ticket;
import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link TicketIssuanceReadContext}.
 *
 * @author SoooEZ
 * @since 8.0.0
 */
@Tag("Tickets")
class TicketIssuanceReadContextTests {

    private static final String INTENT_ID =
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

    private static final String LEASE_ID =
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

    private static final String OWNER_TOKEN =
        "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

    @Test
    void verifyUnawareRegistryAllowsOnlyStandardCompatibilityRead() {
        val registry = mock(TicketRegistry.class, CALLS_REAL_METHODS);
        val ticket = mock(Ticket.class);
        when(registry.getTicket("ticket-id")).thenReturn(ticket);

        assertSame(ticket, registry.getTicket(
            "ticket-id", TicketIssuanceReadContext.standard()));
        assertThrows(UnsupportedOperationException.class, () -> registry.getTicket(
            "ticket-id", TicketIssuanceReadContext.forIntent("intent-1")));
        assertThrows(UnsupportedOperationException.class, () -> registry.getTicket(
            "ticket-id", TicketIssuanceReadContext.forFinalResponse(
                INTENT_ID, LEASE_ID, OWNER_TOKEN, 1)));
        assertThrows(NullPointerException.class, () -> registry.getTicket(
            "ticket-id", (TicketIssuanceReadContext) null));
    }

    @Test
    void verifyUnawareRegistryAllowsOnlyStandardTypedCompatibilityRead() {
        val registry = mock(TicketRegistry.class, CALLS_REAL_METHODS);
        val ticket = mock(Ticket.class);
        when(registry.getTicket("ticket-id", Ticket.class)).thenReturn(ticket);

        assertSame(ticket, registry.getTicket(
            "ticket-id", Ticket.class, TicketIssuanceReadContext.standard()));
        assertThrows(UnsupportedOperationException.class, () -> registry.getTicket(
            "ticket-id", Ticket.class, TicketIssuanceReadContext.forIntent("intent-1")));
        assertThrows(UnsupportedOperationException.class, () -> registry.getTicket(
            "ticket-id", Ticket.class, TicketIssuanceReadContext.forFinalResponse(
                INTENT_ID, LEASE_ID, OWNER_TOKEN, 1)));
        assertThrows(NullPointerException.class, () -> registry.getTicket(
            "ticket-id", Ticket.class, null));
    }

    @Test
    void verifyIntentIdentifierIsCanonical() {
        assertNull(TicketIssuanceReadContext.standard().intentId());
        assertEquals(
            TicketIssuanceReadContext.ReadMode.STANDARD,
            TicketIssuanceReadContext.standard().mode());
        assertTrue(TicketIssuanceReadContext.standard().isStandard());
        assertEquals("intent-1", TicketIssuanceReadContext.forIntent("intent-1").intentId());
        assertEquals(
            TicketIssuanceReadContext.ReadMode.INTENT_INTERNAL,
            TicketIssuanceReadContext.forIntent("intent-1").mode());
        assertTrue(TicketIssuanceReadContext.forIntent("intent-1").isIntentInternal());
        assertEquals(
            TicketIssuanceReadContext.standard(),
            new TicketIssuanceReadContext(null));
        assertEquals("i".repeat(TicketIssuanceMetadata.MAX_INTENT_ID_UTF8_BYTES),
            TicketIssuanceReadContext.forIntent(
                "i".repeat(TicketIssuanceMetadata.MAX_INTENT_ID_UTF8_BYTES)).intentId());
        assertEquals("界".repeat(42),
            TicketIssuanceReadContext.forIntent("界".repeat(42)).intentId());
        assertThrows(IllegalArgumentException.class, () ->
            TicketIssuanceReadContext.forIntent(" "));
        assertThrows(IllegalArgumentException.class, () ->
            TicketIssuanceReadContext.forIntent(" intent-1"));
        assertThrows(IllegalArgumentException.class, () ->
            TicketIssuanceReadContext.forIntent("intent-1 "));
        assertThrows(IllegalArgumentException.class, () ->
            TicketIssuanceReadContext.forIntent("intent\n1"));
        assertThrows(IllegalArgumentException.class, () ->
            TicketIssuanceReadContext.forIntent(
                "i".repeat(TicketIssuanceMetadata.MAX_INTENT_ID_UTF8_BYTES + 1)));
        assertThrows(IllegalArgumentException.class, () ->
            TicketIssuanceReadContext.forIntent("界".repeat(43)));
        assertThrows(IllegalArgumentException.class, () ->
            TicketIssuanceReadContext.forIntent("\uD800"));
    }

    @Test
    void verifyFinalResponseCoordinatesAreCompleteCanonicalAndRedacted() {
        val context = TicketIssuanceReadContext.forFinalResponse(
            INTENT_ID, LEASE_ID, OWNER_TOKEN, 7);
        val metadata = new TicketIssuanceMetadata(
            "subject-1", 1, INTENT_ID);

        assertEquals(
            TicketIssuanceReadContext.ReadMode.FINAL_RESPONSE,
            context.mode());
        assertTrue(context.isFinalResponse());
        assertFalse(context.isStandard());
        assertFalse(context.isIntentInternal());
        assertEquals(INTENT_ID, context.intentId());
        assertEquals(LEASE_ID, context.leaseId());
        assertEquals(OWNER_TOKEN, context.ownerToken());
        assertEquals(7, context.ownerEpoch());
        assertTrue(context.references(metadata));
        assertFalse(context.toString().contains(INTENT_ID));
        assertFalse(context.toString().contains(LEASE_ID));
        assertFalse(context.toString().contains(OWNER_TOKEN));

        assertThrows(IllegalArgumentException.class, () ->
            new TicketIssuanceReadContext(
                TicketIssuanceReadContext.ReadMode.FINAL_RESPONSE,
                INTENT_ID, null, OWNER_TOKEN, 1L));
        assertThrows(IllegalArgumentException.class, () ->
            new TicketIssuanceReadContext(
                TicketIssuanceReadContext.ReadMode.FINAL_RESPONSE,
                INTENT_ID, LEASE_ID, null, 1L));
        assertThrows(IllegalArgumentException.class, () ->
            TicketIssuanceReadContext.forFinalResponse(
                INTENT_ID, LEASE_ID, OWNER_TOKEN, 0));
        assertThrows(IllegalArgumentException.class, () ->
            new TicketIssuanceReadContext(
                TicketIssuanceReadContext.ReadMode.STANDARD,
                "intent", null, null, null));
        assertThrows(IllegalArgumentException.class, () ->
            new TicketIssuanceReadContext(
                TicketIssuanceReadContext.ReadMode.INTENT_INTERNAL,
                "intent", "lease", null, null));
    }

    @Test
    void verifyFinalResponseCoordinatesRequireCanonicalLowercaseUuids() {
        val context = TicketIssuanceReadContext.forFinalResponse(
            INTENT_ID, LEASE_ID, OWNER_TOKEN, 1);

        assertEquals(LEASE_ID, context.leaseId());
        assertThrows(IllegalArgumentException.class, () ->
            TicketIssuanceReadContext.forFinalResponse(
                "not-a-uuid", LEASE_ID, OWNER_TOKEN, 1));
        assertThrows(IllegalArgumentException.class, () ->
            TicketIssuanceReadContext.forFinalResponse(
                "00000000-0000-0000-0000-000000000000",
                LEASE_ID,
                OWNER_TOKEN,
                1));
        assertThrows(IllegalArgumentException.class, () ->
            TicketIssuanceReadContext.forFinalResponse(
                INTENT_ID, "not-a-uuid", OWNER_TOKEN, 1));
        assertThrows(IllegalArgumentException.class, () ->
            TicketIssuanceReadContext.forFinalResponse(
                INTENT_ID, LEASE_ID, "not-a-uuid", 1));
        assertThrows(IllegalArgumentException.class, () ->
            TicketIssuanceReadContext.forFinalResponse(
                INTENT_ID.toUpperCase(Locale.ENGLISH),
                LEASE_ID,
                OWNER_TOKEN,
                1));
        assertThrows(IllegalArgumentException.class, () ->
            TicketIssuanceReadContext.forFinalResponse(
                INTENT_ID, LEASE_ID, "\uD800", 1));
    }

    @Test
    void verifyReadContextsRemainSerializable() throws Exception {
        val standard = serialize(TicketIssuanceReadContext.standard());
        val internal = serialize(TicketIssuanceReadContext.forIntent("intent-1"));
        val finalResponse = serialize(TicketIssuanceReadContext.forFinalResponse(
            INTENT_ID, LEASE_ID, OWNER_TOKEN, 3));

        assertEquals(TicketIssuanceReadContext.standard(), standard);
        assertEquals(TicketIssuanceReadContext.forIntent("intent-1"), internal);
        assertEquals(
            TicketIssuanceReadContext.forFinalResponse(
                INTENT_ID, LEASE_ID, OWNER_TOKEN, 3),
            finalResponse);
    }

    @Test
    void verifyDefaultPolicyAdmitsOnlyUnmanagedTicketReads() {
        val policy = new TicketIssuancePolicy() {
        };
        val unmanaged = mock(Ticket.class);
        val managed = mock(PropertiesAwareTicket.class);
        val incomplete = mock(PropertiesAwareTicket.class);
        when(managed.getId()).thenReturn("managed");
        when(managed.getProperties()).thenReturn(Map.of(
            TicketIssuanceMetadata.PROPERTY_SUBJECT_ID, "subject-1",
            TicketIssuanceMetadata.PROPERTY_GENERATION, 1L,
            TicketIssuanceMetadata.PROPERTY_INTENT_ID, "intent-1"));
        when(incomplete.getId()).thenReturn("incomplete");
        when(incomplete.getProperties()).thenReturn(Map.of(
            TicketIssuanceMetadata.PROPERTY_SUBJECT_ID, "subject-1"));

        assertTrue(policy.isTicketReadable(
            unmanaged, TicketIssuanceReadContext.standard()));
        assertFalse(policy.isTicketReadable(
            managed, TicketIssuanceReadContext.standard()));
        assertFalse(policy.isTicketReadable(
            managed, TicketIssuanceReadContext.forIntent("intent-1")));
        assertThrows(IllegalStateException.class, () -> policy.isTicketReadable(
            incomplete, TicketIssuanceReadContext.standard()));
        assertThrows(NullPointerException.class, () ->
            policy.isTicketReadable(unmanaged, null));
    }

    @SuppressWarnings("unchecked")
    private static <T extends Serializable> T serialize(final T value) throws Exception {
        val bytes = new ByteArrayOutputStream();
        try (val output = new ObjectOutputStream(bytes)) {
            output.writeObject(value);
        }
        try (val input = new ObjectInputStream(
            new ByteArrayInputStream(bytes.toByteArray()))) {
            return (T) input.readObject();
        }
    }
}
