package org.apereo.cas.ticket.registry;

import module java.base;
import org.apereo.cas.ticket.Ticket;
import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link TicketIssuanceWriteContext}.
 *
 * @author SoooEZ
 * @since 8.0.0
 */
@Tag("Tickets")
class TicketIssuanceWriteContextTests {

    @Test
    void verifyAccountCapabilityCoordinates() throws Throwable {
        val generation = new TicketIssuanceWriteContext.GenerationBinding(
            TicketIssuanceWriteContext.GenerationOwnerType.SUBJECT, "subject-1", 7);
        val relyingParty = new TicketIssuanceWriteContext.RelyingPartyBinding(
            "https://service.example.org", null);
        val context = TicketIssuanceWriteContext.managed(
            TicketIssuanceWriteContext.Classification.ACCOUNT_CAPABILITY,
            TicketIssuanceWriteContext.ProtocolFamily.CAS,
            "LOGIN",
            "CAS_ST",
            1,
            2,
            "intent-1",
            generation,
            relyingParty);

        assertTrue(context.isManaged());
        assertEquals(1, context.ordinal());
        assertEquals(2, context.expectedCount());
        assertSame(generation, context.generationBinding());
        assertSame(relyingParty, context.relyingPartyBinding());
        context.requireConsistentWith(new TicketIssuanceMetadata("subject-1", 7, "intent-1"));
        assertEquals(context, roundTrip(context));
    }

    @Test
    void verifyClientAndPreAuthenticationGenerationCoordinates() {
        val client = new TicketIssuanceWriteContext.RelyingPartyBinding(
            "https://resource.example.org", "client-1");
        val clientContext = TicketIssuanceWriteContext.managed(
            TicketIssuanceWriteContext.Classification.CLIENT_CAPABILITY,
            TicketIssuanceWriteContext.ProtocolFamily.OAUTH2,
            "CLIENT_CREDENTIALS",
            "ACCESS_TOKEN",
            0,
            1,
            "intent-client",
            new TicketIssuanceWriteContext.GenerationBinding(
                TicketIssuanceWriteContext.GenerationOwnerType.CLIENT, "client-1", 9),
            client);
        val preAuthenticationContext = TicketIssuanceWriteContext.managed(
            TicketIssuanceWriteContext.Classification.PREAUTH_STATE,
            TicketIssuanceWriteContext.ProtocolFamily.LOGIN,
            "LOGIN_EXECUTION",
            "TRANSIENT_STATE",
            0,
            1,
            "intent-state",
            new TicketIssuanceWriteContext.GenerationBinding(
                TicketIssuanceWriteContext.GenerationOwnerType.STATE, "login-policy", 3),
            null);

        assertTrue(clientContext.isManaged());
        assertEquals(TicketIssuanceWriteContext.GenerationOwnerType.STATE,
            preAuthenticationContext.generationBinding().ownerType());
    }

    @Test
    void verifyExplicitNonCapabilityCannotSmuggleLifecycleCoordinates() {
        val context = TicketIssuanceWriteContext.explicitNonCapability(
            TicketIssuanceWriteContext.ProtocolFamily.CUSTOM,
            "AUDIT_RECORD",
            "CUSTOM_STATE",
            null);

        assertFalse(context.isManaged());
        assertNull(context.intentId());
        assertNull(context.generationBinding());
        assertThrows(IllegalArgumentException.class, () -> new TicketIssuanceWriteContext(
            TicketIssuanceWriteContext.Classification.EXPLICIT_NON_CAPABILITY,
            TicketIssuanceWriteContext.ProtocolFamily.CUSTOM,
            "AUDIT_RECORD",
            "CUSTOM_STATE",
            0,
            1,
            "smuggled-intent",
            null,
            null));
    }

    @Test
    void verifyManifestAndCanonicalTokensFailClosed() {
        val generation = new TicketIssuanceWriteContext.GenerationBinding(
            TicketIssuanceWriteContext.GenerationOwnerType.SUBJECT, "subject-1", 1);

        assertThrows(IllegalArgumentException.class, () -> accountContext(
            "LOGIN", "CAS_TGT", -1, 1, generation));
        assertThrows(IllegalArgumentException.class, () -> accountContext(
            "LOGIN", "CAS_TGT", 1, 1, generation));
        assertThrows(IllegalArgumentException.class, () -> accountContext(
            "LOGIN", "CAS_TGT", 0,
            TicketIssuanceWriteContext.MAXIMUM_ARTIFACT_COUNT + 1, generation));
        assertThrows(IllegalArgumentException.class, () -> accountContext(
            "login", "CAS_TGT", 0, 1, generation));
        assertThrows(IllegalArgumentException.class, () -> accountContext(
            " LOGIN", "CAS_TGT", 0, 1, generation));
        assertThrows(IllegalArgumentException.class, () -> accountContext(
            "LOGIN", "\uD800", 0, 1, generation));
    }

    @Test
    void verifyProtocolAndGenerationBindingsFailClosed() {
        val subject = new TicketIssuanceWriteContext.GenerationBinding(
            TicketIssuanceWriteContext.GenerationOwnerType.SUBJECT, "subject-1", 1);
        val client = new TicketIssuanceWriteContext.GenerationBinding(
            TicketIssuanceWriteContext.GenerationOwnerType.CLIENT, "client-1", 1);

        assertThrows(IllegalArgumentException.class, () -> TicketIssuanceWriteContext.managed(
            TicketIssuanceWriteContext.Classification.ACCOUNT_CAPABILITY,
            TicketIssuanceWriteContext.ProtocolFamily.CAS,
            "LOGIN", "CAS_TGT", 0, 1, "intent", client, null));
        assertThrows(IllegalArgumentException.class, () -> TicketIssuanceWriteContext.managed(
            TicketIssuanceWriteContext.Classification.CLIENT_CAPABILITY,
            TicketIssuanceWriteContext.ProtocolFamily.OAUTH2,
            "CLIENT_CREDENTIALS", "ACCESS_TOKEN", 0, 1, "intent", client,
            new TicketIssuanceWriteContext.RelyingPartyBinding(null, "another-client")));
        assertThrows(IllegalArgumentException.class, () -> TicketIssuanceWriteContext.managed(
            TicketIssuanceWriteContext.Classification.ACCOUNT_CAPABILITY,
            TicketIssuanceWriteContext.ProtocolFamily.OPENID_CONNECT,
            "AUTHORIZATION", "ID_TOKEN", 0, 1, "intent", subject, null));
        assertThrows(IllegalArgumentException.class, () -> TicketIssuanceWriteContext.managed(
            TicketIssuanceWriteContext.Classification.ACCOUNT_CAPABILITY,
            TicketIssuanceWriteContext.ProtocolFamily.SAML,
            "SSO", "SAML_ASSERTION", 0, 1, "intent", subject,
            new TicketIssuanceWriteContext.RelyingPartyBinding(null, "client-1")));
        assertThrows(IllegalArgumentException.class, () ->
            new TicketIssuanceWriteContext.GenerationBinding(
                TicketIssuanceWriteContext.GenerationOwnerType.STATE, "policy", 0));
        assertThrows(IllegalArgumentException.class, () -> TicketIssuanceWriteContext.managed(
            TicketIssuanceWriteContext.Classification.PREAUTH_STATE,
            TicketIssuanceWriteContext.ProtocolFamily.LOGIN,
            "LOGIN_EXECUTION",
            "TRANSIENT_STATE",
            0,
            1,
            "intent",
            subject,
            null));
        assertThrows(IllegalArgumentException.class, () -> TicketIssuanceWriteContext.managed(
            TicketIssuanceWriteContext.Classification.PREAUTH_STATE,
            TicketIssuanceWriteContext.ProtocolFamily.OAUTH2,
            "DEVICE_AUTHORIZATION",
            "DEVICE_CODE",
            0,
            1,
            "intent",
            client,
            new TicketIssuanceWriteContext.RelyingPartyBinding(null, "client-1")));
    }

    @Test
    void verifyLegacyInterceptorCannotSilentlyIgnoreExplicitContext() {
        val ticket = mock(Ticket.class);
        val context = accountContext(
            "LOGIN",
            "CAS_TGT",
            0,
            1,
            new TicketIssuanceWriteContext.GenerationBinding(
                TicketIssuanceWriteContext.GenerationOwnerType.SUBJECT, "subject-1", 7));
        val legacy = (TicketRegistryWriteInterceptor) (value, operation) ->
            TicketRegistryWriteInterceptor.WriteContext.noOp();

        assertNotNull(legacy.beforeWrite(
            ticket, TicketRegistryWriteInterceptor.Operation.ADD));
        assertThrows(UnsupportedOperationException.class, () -> legacy.beforeWrite(
            ticket, TicketRegistryWriteInterceptor.Operation.ADD, context));
        assertNotNull(TicketRegistryWriteInterceptor.noOp().beforeWrite(
            ticket, TicketRegistryWriteInterceptor.Operation.ADD, context));
    }

    @Test
    void verifyPersistedMetadataMismatchFailsClosed() {
        val context = accountContext(
            "LOGIN",
            "CAS_TGT",
            0,
            1,
            new TicketIssuanceWriteContext.GenerationBinding(
                TicketIssuanceWriteContext.GenerationOwnerType.SUBJECT, "subject-1", 7));

        assertThrows(IllegalStateException.class, () ->
            context.requireConsistentWith(new TicketIssuanceMetadata("subject-2", 7, "intent-1")));
        assertThrows(IllegalStateException.class, () ->
            context.requireConsistentWith(new TicketIssuanceMetadata("subject-1", 8, "intent-1")));
        assertThrows(IllegalStateException.class, () ->
            context.requireConsistentWith(new TicketIssuanceMetadata("subject-1", 7, "intent-2")));

        val stateContext = TicketIssuanceWriteContext.managed(
            TicketIssuanceWriteContext.Classification.PREAUTH_STATE,
            TicketIssuanceWriteContext.ProtocolFamily.LOGIN,
            "LOGIN_EXECUTION",
            "TRANSIENT_STATE",
            0,
            1,
            "intent-state",
            new TicketIssuanceWriteContext.GenerationBinding(
                TicketIssuanceWriteContext.GenerationOwnerType.STATE, "login-policy", 3),
            null);
        assertThrows(IllegalStateException.class, () ->
            stateContext.requireConsistentWith(
                new TicketIssuanceMetadata("login-policy", 3, "intent-state")));
    }

    private static TicketIssuanceWriteContext accountContext(
        final String purpose,
        final String artifactType,
        final int ordinal,
        final int expectedCount,
        final TicketIssuanceWriteContext.GenerationBinding generation) {
        return TicketIssuanceWriteContext.managed(
            TicketIssuanceWriteContext.Classification.ACCOUNT_CAPABILITY,
            TicketIssuanceWriteContext.ProtocolFamily.CAS,
            purpose,
            artifactType,
            ordinal,
            expectedCount,
            "intent-1",
            generation,
            null);
    }

    private static TicketIssuanceWriteContext roundTrip(
        final TicketIssuanceWriteContext context) throws Throwable {
        val output = new ByteArrayOutputStream();
        try (val objectOutput = new ObjectOutputStream(output)) {
            objectOutput.writeObject(context);
        }
        try (val objectInput = new ObjectInputStream(
            new ByteArrayInputStream(output.toByteArray()))) {
            return (TicketIssuanceWriteContext) objectInput.readObject();
        }
    }
}
