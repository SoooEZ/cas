package org.apereo.cas.protocol;

import module java.base;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for fail-closed final protocol response policy contracts.
 *
 * @author SoooEZ
 * @since 8.0.0
 */
@Tag("CAS")
class ProtocolFinalResponsePolicyTests {

    private static final String CAPABILITY = "ST-secret-capability";

    @Test
    void verifyManagedCapabilityIsValidatedAndRedacted() {
        val capability = ProtocolFinalResponseCapability.managed(
            ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET,
            CAPABILITY, "subject-secret", 3, "intent-secret");

        assertTrue(capability.isLifecycleManaged());
        assertFalse(capability.toString().contains(CAPABILITY));
        assertFalse(capability.toString().contains("subject-secret"));
        assertThrows(IllegalArgumentException.class, () ->
            ProtocolFinalResponseCapability.managed(
                ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET,
                CAPABILITY, "subject-secret", 0, "intent-secret"));
        assertThrows(IllegalArgumentException.class, () ->
            ProtocolFinalResponseCapability.of(
                ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET, " "));
        assertThrows(IllegalArgumentException.class, () ->
            new ProtocolFinalResponseCapability(
                ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET,
                CAPABILITY, "subject-secret", null, null));
    }

    @Test
    void verifyContextIsImmutableAndRedacted() {
        val source = new ArrayList<ProtocolFinalResponseCapability>();
        source.add(ProtocolFinalResponseCapability.of(
            ProtocolFinalResponseCapability.Type.OAUTH_ACCESS_TOKEN, CAPABILITY));
        val context = new ProtocolFinalResponseContext(
            ProtocolFinalResponseContext.Protocol.OAUTH2,
            ProtocolFinalResponseContext.ResponseType.TOKEN_RESPONSE,
            "client-id", "subject-secret", source);
        source.clear();

        assertEquals(1, context.capabilities().size());
        assertThrows(UnsupportedOperationException.class, () -> context.capabilities().clear());
        assertFalse(context.toString().contains(CAPABILITY));
        assertFalse(context.toString().contains("subject-secret"));
        assertThrows(IllegalArgumentException.class, () -> new ProtocolFinalResponseContext(
            ProtocolFinalResponseContext.Protocol.OAUTH2,
            ProtocolFinalResponseContext.ResponseType.TOKEN_RESPONSE,
            null, null, List.of()));
        assertThrows(IllegalArgumentException.class, () -> ProtocolFinalResponseContext.of(
            ProtocolFinalResponseContext.Protocol.CAS,
            ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
            null, "different-subject",
            ProtocolFinalResponseCapability.managed(
                ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET,
                CAPABILITY, "subject-secret", 3, "intent-secret")));
        assertThrows(IllegalArgumentException.class, () -> ProtocolFinalResponseContext.of(
            ProtocolFinalResponseContext.Protocol.CAS,
            ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
            null, null,
            ProtocolFinalResponseCapability.managed(
                ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET,
                CAPABILITY, "subject-secret", 3, "intent-secret")));
    }

    @Test
    void verifyPolicyEnforcementFailsClosedWithoutLeakingCapabilities() {
        val context = context();

        assertDoesNotThrow(() -> ProtocolFinalResponsePolicy.noOp().enforce(context));
        val denied = assertThrows(ProtocolFinalResponseDeniedException.class,
            () -> ((ProtocolFinalResponsePolicy) _ ->
                ProtocolFinalResponseDecision.deny("generation_closed", true)).enforce(context));
        assertEquals("generation_closed", denied.getDecision().reasonCode());
        assertTrue(denied.getDecision().retryable());
        assertFalse(denied.getMessage().contains(CAPABILITY));

        val invalid = assertThrows(ProtocolFinalResponseDeniedException.class,
            () -> ((ProtocolFinalResponsePolicy) _ -> null).enforce(context));
        assertEquals("policy_invalid_decision", invalid.getDecision().reasonCode());

        val failure = assertThrows(ProtocolFinalResponseDeniedException.class,
            () -> ((ProtocolFinalResponsePolicy) _ -> {
                throw new IllegalStateException(CAPABILITY);
            }).enforce(context));
        assertEquals("policy_failure", failure.getDecision().reasonCode());
        assertFalse(failure.getMessage().contains(CAPABILITY));
        assertNull(failure.getCause());
    }

    @Test
    void verifyDecisionReasonCodesAreCanonical() {
        assertThrows(IllegalArgumentException.class, () ->
            ProtocolFinalResponseDecision.deny("NOT_CANONICAL"));
        assertThrows(IllegalArgumentException.class, () ->
            ProtocolFinalResponseDecision.deny(StringUtils.EMPTY));
    }

    private static ProtocolFinalResponseContext context() {
        return ProtocolFinalResponseContext.of(
            ProtocolFinalResponseContext.Protocol.CAS,
            ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
            "https://service.example.org", "subject-secret",
            ProtocolFinalResponseCapability.of(
                ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET, CAPABILITY));
    }
}
