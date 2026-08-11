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
        assertNull(context.delivery());
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

        val delivery = ProtocolFinalResponseDelivery.canonical(
            ProtocolFinalResponseDelivery.Mode.REDIRECT,
            "https://service.example.org?ticket=" + CAPABILITY,
            Map.of("ticket", CAPABILITY));
        val deliveredContext = ProtocolFinalResponseContext.of(
            ProtocolFinalResponseContext.Protocol.CAS,
            ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
            "https://service.example.org",
            "subject-secret",
            ProtocolFinalResponseCapability.managed(
                ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET,
                CAPABILITY, "subject-secret", 3, "intent-secret"),
            delivery);
        assertEquals(delivery, deliveredContext.delivery());
        assertFalse(deliveredContext.toString().contains(CAPABILITY));
        assertFalse(deliveredContext.toString().contains(
            delivery.canonicalRepresentationDigest()));
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

    @Test
    void verifyPreparedDeliverySupportsExactDurableReplayAndFailsClosed() {
        val delivery = ProtocolFinalResponseDelivery.canonical(
            ProtocolFinalResponseDelivery.Mode.HTTP_COOKIE,
            "semantic-tgt", Map.of("cookie_name", "TGC"));
        val payload = Base64.getUrlEncoder().withoutPadding().encodeToString(
            "exact-secret-cookie".getBytes(StandardCharsets.UTF_8));
        val logicalContext = ProtocolFinalResponseContext.of(
            ProtocolFinalResponseContext.Protocol.CAS,
            ProtocolFinalResponseContext.ResponseType.CAS_BROWSER_SSO_SESSION,
            null, "subject-secret",
            ProtocolFinalResponseCapability.of(
                ProtocolFinalResponseCapability.Type
                    .CAS_TICKET_GRANTING_TICKET,
                CAPABILITY));
        val binding = logicalContext.logicalResponseBinding();
        val prepared = new ProtocolFinalResponsePreparedDelivery(
            binding, delivery, "test-codec", 1, payload);
        val context = logicalContext.withPreparedDelivery(prepared);

        val replayDelivery = ProtocolFinalResponseDelivery.canonical(
            ProtocolFinalResponseDelivery.Mode.HTTP_COOKIE,
            "semantic-tgt", Map.of("cookie_name", "TGC", "version", "1"));
        val replayPayload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(
                "earlier-exact-secret-cookie".getBytes(StandardCharsets.UTF_8));
        val replay = new ProtocolFinalResponsePreparedDelivery(
            binding, replayDelivery, "test-codec", 1, replayPayload);
        val policy = new ProtocolFinalResponsePolicy() {
            @Override
            public ProtocolFinalResponseDecision decide(
                final ProtocolFinalResponseContext ignored) {
                return ProtocolFinalResponseDecision.permit();
            }

            @Override
            public ProtocolFinalResponseAuthorization authorize(
                final ProtocolFinalResponseContext ignored) {
                return ProtocolFinalResponseAuthorization
                    .durableReplay(replay);
            }
        };
        val authorized = policy.authorizeAndEnforce(context);

        assertEquals(
            ProtocolFinalResponseAuthorization.Source.DURABLE_REPLAY,
            authorized.source());
        assertEquals(replay, authorized.preparedDelivery());
        assertArrayEquals(
            "earlier-exact-secret-cookie".getBytes(StandardCharsets.UTF_8),
            replay.decodedPayload());
        assertEquals(ProtocolFinalResponseBundle.SHA_256_HEX_LENGTH,
            replay.payloadDigest().length());
        assertFalse(replay.toString().contains("earlier-exact-secret-cookie"));
        assertFalse(authorized.toString().contains(replayPayload));
        assertThrows(IllegalArgumentException.class, () ->
            new ProtocolFinalResponsePreparedDelivery(
                binding, delivery, "test-codec", 1,
                "not+url/base64"));
        assertThrows(IllegalArgumentException.class, () ->
            new ProtocolFinalResponsePreparedDelivery(
                binding, delivery, "test-codec", 1,
                payload + "="));
        assertThrows(IllegalArgumentException.class, () ->
            new ProtocolFinalResponsePreparedDelivery(
                binding, delivery, "test-codec", 1,
                "A".repeat(ProtocolFinalResponsePreparedDelivery
                    .MAXIMUM_PAYLOAD_BASE64_CHARACTERS + 1)));

        val changedCurrent = new ProtocolFinalResponsePolicy() {
            @Override
            public ProtocolFinalResponseDecision decide(
                final ProtocolFinalResponseContext ignored) {
                return ProtocolFinalResponseDecision.permit();
            }

            @Override
            public ProtocolFinalResponseAuthorization authorize(
                final ProtocolFinalResponseContext ignored) {
                return ProtocolFinalResponseAuthorization.current(
                    ProtocolFinalResponseDecision.permit(), replay);
            }
        };
        val denied = assertThrows(
            ProtocolFinalResponseDeniedException.class,
            () -> changedCurrent.authorizeAndEnforce(context));
        assertEquals(
            "policy_invalid_authorization",
            denied.getDecision().reasonCode());

        val crossSubjectReplay = new ProtocolFinalResponsePreparedDelivery(
            new ProtocolFinalResponseLogicalBinding("c".repeat(64)),
            replayDelivery,
            "test-codec",
            1,
            replayPayload);
        val crossSubjectPolicy = new ProtocolFinalResponsePolicy() {
            @Override
            public ProtocolFinalResponseDecision decide(
                final ProtocolFinalResponseContext ignored) {
                return ProtocolFinalResponseDecision.permit();
            }

            @Override
            public ProtocolFinalResponseAuthorization authorize(
                final ProtocolFinalResponseContext ignored) {
                return ProtocolFinalResponseAuthorization.durableReplay(
                    crossSubjectReplay);
            }
        };
        val crossSubjectDenied = assertThrows(
            ProtocolFinalResponseDeniedException.class,
            () -> crossSubjectPolicy.authorizeAndEnforce(context));
        assertEquals(
            "policy_invalid_replay",
            crossSubjectDenied.getDecision().reasonCode());
    }

    @Test
    void verifyLogicalBindingCoversEveryAuthorityCoordinateAndOrder() {
        val first = ProtocolFinalResponseCapability.managed(
            ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET,
            CAPABILITY, "subject-secret", 3, "intent-secret");
        val second = ProtocolFinalResponseCapability.of(
            ProtocolFinalResponseCapability.Type.CAS_PROXY_TICKET,
            "PT-secret-capability");
        val capabilities = List.of(first, second);
        val digests = new HashSet<String>();
        digests.add(binding(
            ProtocolFinalResponseContext.Protocol.CAS,
            ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
            "https://service.example.org", "subject-secret", capabilities));
        digests.add(binding(
            ProtocolFinalResponseContext.Protocol.OAUTH2,
            ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
            "https://service.example.org", "subject-secret", capabilities));
        digests.add(binding(
            ProtocolFinalResponseContext.Protocol.CAS,
            ProtocolFinalResponseContext.ResponseType.CAS_VALIDATION_RESPONSE,
            "https://service.example.org", "subject-secret", capabilities));
        digests.add(binding(
            ProtocolFinalResponseContext.Protocol.CAS,
            ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
            "https://other.example.org", "subject-secret", capabilities));
        digests.add(binding(
            ProtocolFinalResponseContext.Protocol.CAS,
            ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
            "https://service.example.org", "other-subject", capabilities));
        digests.add(binding(
            ProtocolFinalResponseContext.Protocol.CAS,
            ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
            "https://service.example.org", "subject-secret",
            List.of(
                ProtocolFinalResponseCapability.managed(
                    ProtocolFinalResponseCapability.Type.CAS_PROXY_TICKET,
                    CAPABILITY, "subject-secret", 3, "intent-secret"),
                second)));
        digests.add(binding(
            ProtocolFinalResponseContext.Protocol.CAS,
            ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
            "https://service.example.org", "subject-secret",
            List.of(
                ProtocolFinalResponseCapability.managed(
                    ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET,
                    "ST-other", "subject-secret", 3, "intent-secret"),
                second)));
        digests.add(binding(
            ProtocolFinalResponseContext.Protocol.CAS,
            ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
            "https://service.example.org", "subject-secret",
            List.of(
                ProtocolFinalResponseCapability.managed(
                    ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET,
                    CAPABILITY, "other-subject", 3, "intent-secret"),
                second)));
        digests.add(binding(
            ProtocolFinalResponseContext.Protocol.CAS,
            ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
            "https://service.example.org", "subject-secret",
            List.of(
                ProtocolFinalResponseCapability.managed(
                    ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET,
                    CAPABILITY, "subject-secret", 4, "intent-secret"),
                second)));
        digests.add(binding(
            ProtocolFinalResponseContext.Protocol.CAS,
            ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
            "https://service.example.org", "subject-secret",
            List.of(
                ProtocolFinalResponseCapability.managed(
                    ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET,
                    CAPABILITY, "subject-secret", 3, "other-intent"),
                second)));
        digests.add(binding(
            ProtocolFinalResponseContext.Protocol.CAS,
            ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
            "https://service.example.org", "subject-secret",
            List.of(second, first)));

        assertEquals(11, digests.size());
        val normalized = ProtocolFinalResponseLogicalBinding.of(
            ProtocolFinalResponseContext.Protocol.CAS,
            ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
            " https://service.example.org ", " subject-secret ", capabilities);
        assertTrue(digests.contains(normalized.digest()));
        assertFalse(normalized.toString().contains(normalized.digest()));
        assertThrows(IllegalArgumentException.class, () ->
            ProtocolFinalResponseLogicalBinding.of(
                ProtocolFinalResponseContext.Protocol.CAS,
                ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
                null, null, Arrays.asList(first, null)));
    }

    private static String binding(
        final ProtocolFinalResponseContext.Protocol protocol,
        final ProtocolFinalResponseContext.ResponseType responseType,
        final String relyingParty,
        final String subject,
        final List<ProtocolFinalResponseCapability> capabilities) {
        return ProtocolFinalResponseLogicalBinding.of(
            protocol, responseType, relyingParty, subject, capabilities).digest();
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
