package org.apereo.cas.protocol;

import module java.base;
import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for exact final-response bundles and typed commit failures.
 *
 * @author SoooEZ
 * @since 8.0.0
 */
@Tag("CAS")
class ProtocolFinalResponseBundleTests {

    private static final String BUNDLE_ID =
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

    private static final String SUBJECT_ID = "subject-secret";

    private static final String RELYING_PARTY = "https://client-secret.example.org";

    private static final String INTENT_ID =
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

    private static final String SECOND_INTENT_ID =
        "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";

    private static final long GENERATION = 7;

    @Test
    void verifyBundleIsExactImmutableDeterministicAndRedacted() {
        val source = new ArrayList<>(items());
        val bundle = bundle(source);
        val identical = bundle(items());
        source.clear();

        assertEquals(2, bundle.items().size());
        assertEquals(2, bundle.expectedCount());
        assertEquals(bundle.manifestIdentity(), identical.manifestIdentity());
        assertEquals(ProtocolFinalResponseBundle.SHA_256_HEX_LENGTH,
            bundle.manifestIdentity().length());
        assertTrue(bundle.items().getFirst().hasSource());
        assertThrows(UnsupportedOperationException.class, () ->
            bundle.items().clear());
        assertFalse(bundle.toString().contains(BUNDLE_ID));
        assertFalse(bundle.toString().contains(SUBJECT_ID));
        assertFalse(bundle.toString().contains(RELYING_PARTY));
        assertFalse(bundle.toString().contains(INTENT_ID));
        assertFalse(bundle.toString().contains("ST-capability-secret"));
        assertFalse(bundle.items().getFirst().toString().contains(INTENT_ID));
        assertFalse(bundle.items().getFirst().toString()
            .contains("ST-capability-secret"));

        val changedCapability = List.of(
            ProtocolFinalResponseBundle.Item.sourced(
                0,
                managed(
                    ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET,
                    "ST-different-secret"),
                INTENT_ID,
                0),
            items().get(1));
        assertNotEquals(
            bundle.manifestIdentity(),
            bundle(changedCapability).manifestIdentity());
    }

    @Test
    void verifyDeliveryRepresentationIsCanonicalBoundedAndRedacted() {
        val firstAttributes = new LinkedHashMap<String, String>();
        firstAttributes.put("ticket", "ST-capability-secret");
        firstAttributes.put("method", "redirect");
        val reversedAttributes = new LinkedHashMap<String, String>();
        reversedAttributes.put("method", "redirect");
        reversedAttributes.put("ticket", "ST-capability-secret");

        val first = ProtocolFinalResponseDelivery.canonical(
            ProtocolFinalResponseDelivery.Mode.REDIRECT,
            "https://service.example.org?ticket=ST-capability-secret",
            firstAttributes);
        val reordered = ProtocolFinalResponseDelivery.canonical(
            ProtocolFinalResponseDelivery.Mode.REDIRECT,
            "https://service.example.org?ticket=ST-capability-secret",
            reversedAttributes);
        val changedMode = ProtocolFinalResponseDelivery.canonical(
            ProtocolFinalResponseDelivery.Mode.POST,
            "https://service.example.org?ticket=ST-capability-secret",
            reversedAttributes);

        assertEquals(first, reordered);
        assertNotEquals(first, changedMode);
        assertEquals(
            ProtocolFinalResponseBundle.SHA_256_HEX_LENGTH,
            first.canonicalRepresentationDigest().length());
        assertFalse(first.toString().contains("ST-capability-secret"));
        assertFalse(first.toString().contains(
            first.canonicalRepresentationDigest()));
        assertThrows(IllegalArgumentException.class, () ->
            new ProtocolFinalResponseDelivery(
                ProtocolFinalResponseDelivery.Mode.REDIRECT,
                "A".repeat(ProtocolFinalResponseBundle.SHA_256_HEX_LENGTH)));
        assertThrows(IllegalArgumentException.class, () ->
            ProtocolFinalResponseDelivery.canonical(
                ProtocolFinalResponseDelivery.Mode.REDIRECT,
                " ",
                Map.of()));
        assertThrows(IllegalArgumentException.class, () ->
            ProtocolFinalResponseDelivery.canonical(
                ProtocolFinalResponseDelivery.Mode.REDIRECT,
                "https://service.example.org\n",
                Map.of()));
        assertThrows(IllegalArgumentException.class, () ->
            ProtocolFinalResponseDelivery.canonical(
                ProtocolFinalResponseDelivery.Mode.REDIRECT,
                "https://service.example.org",
                Map.of("ticket", "\uD800")));
        assertThrows(IllegalArgumentException.class, () ->
            ProtocolFinalResponseDelivery.canonical(
                ProtocolFinalResponseDelivery.Mode.REDIRECT,
                "x".repeat(
                    ProtocolFinalResponseDelivery
                        .MAXIMUM_PRIMARY_UTF8_BYTES + 1),
                Map.of()));
    }

    @Test
    void verifyV2ManifestBindsDeliveryAndRejectsBoundaryConfusion() {
        val delivery = serviceDelivery(
            ProtocolFinalResponseDelivery.Mode.REDIRECT);
        val delivered = ProtocolFinalResponseBundle.create(
            BUNDLE_ID,
            ProtocolFinalResponseContext.Protocol.CAS,
            ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
            "CAS_LOGIN",
            SUBJECT_ID,
            GENERATION,
            RELYING_PARTY,
            delivery,
            items().size(),
            items());
        val changedDelivery = serviceDelivery(
            ProtocolFinalResponseDelivery.Mode.POST);
        val changed = ProtocolFinalResponseBundle.create(
            BUNDLE_ID,
            delivered.protocol(),
            delivered.responseType(),
            delivered.purpose(),
            delivered.subjectId(),
            delivered.generation(),
            delivered.relyingPartyBinding(),
            changedDelivery,
            delivered.expectedCount(),
            delivered.items());

        assertEquals(delivery, delivered.delivery());
        assertNotEquals(
            bundle(items()).manifestIdentity(),
            delivered.manifestIdentity());
        assertNotEquals(
            delivered.manifestIdentity(),
            changed.manifestIdentity());
        assertThrows(IllegalArgumentException.class, () ->
            new ProtocolFinalResponseBundle(
                delivered.bundleId(),
                delivered.protocol(),
                delivered.responseType(),
                delivered.purpose(),
                delivered.subjectId(),
                delivered.generation(),
                delivered.relyingPartyBinding(),
                changedDelivery,
                delivered.expectedCount(),
                delivered.manifestIdentity(),
                delivered.items()));
        assertThrows(IllegalArgumentException.class, () ->
            ProtocolFinalResponseBundle.create(
                BUNDLE_ID,
                ProtocolFinalResponseContext.Protocol.CAS,
                ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
                "CAS_LOGIN",
                SUBJECT_ID,
                GENERATION,
                RELYING_PARTY,
                ProtocolFinalResponseDelivery.canonical(
                    ProtocolFinalResponseDelivery.Mode.HTTP_COOKIE,
                    "TGT-capability-secret",
                    Map.of("cookie_name", "TGC")),
                items().size(),
                items()));

        val browserItem = ProtocolFinalResponseBundle.Item.sourced(
            0,
            ProtocolFinalResponseCapability.managed(
                ProtocolFinalResponseCapability.Type
                    .CAS_TICKET_GRANTING_TICKET,
                "TGT-capability-secret",
                SUBJECT_ID,
                GENERATION,
                INTENT_ID),
            INTENT_ID,
            0);
        assertThrows(IllegalArgumentException.class, () ->
            ProtocolFinalResponseBundle.create(
                BUNDLE_ID,
                ProtocolFinalResponseContext.Protocol.CAS,
                ProtocolFinalResponseContext.ResponseType
                    .CAS_BROWSER_SSO_SESSION,
                "CAS_LOGIN",
                SUBJECT_ID,
                GENERATION,
                null,
                delivery,
                1,
                List.of(browserItem)));
    }

    @Test
    void verifyManifestIdentityBindsEverySecurityCoordinate() {
        val original = bundle(items());

        assertThrows(IllegalArgumentException.class, () ->
            new ProtocolFinalResponseBundle(
                original.bundleId(),
                original.protocol(),
                original.responseType(),
                original.purpose(),
                original.subjectId(),
                original.generation(),
                original.relyingPartyBinding(),
                original.expectedCount(),
                "0".repeat(ProtocolFinalResponseBundle.SHA_256_HEX_LENGTH),
                original.items()));
        assertThrows(IllegalArgumentException.class, () ->
            new ProtocolFinalResponseBundle(
                original.bundleId(),
                original.protocol(),
                original.responseType(),
                "DIFFERENT_PURPOSE",
                original.subjectId(),
                original.generation(),
                original.relyingPartyBinding(),
                original.expectedCount(),
                original.manifestIdentity(),
                original.items()));
        assertThrows(IllegalArgumentException.class, () ->
            new ProtocolFinalResponseBundle(
                original.bundleId(),
                original.protocol(),
                original.responseType(),
                original.purpose(),
                original.subjectId(),
                original.generation() + 1,
                original.relyingPartyBinding(),
                original.expectedCount(),
                original.manifestIdentity(),
                original.items()));
        assertThrows(IllegalArgumentException.class, () ->
            new ProtocolFinalResponseBundle(
                original.bundleId(),
                original.protocol(),
                original.responseType(),
                original.purpose(),
                original.subjectId(),
                original.generation(),
                "https://different.example.org",
                original.expectedCount(),
                original.manifestIdentity(),
                original.items()));
    }

    @Test
    void verifyItemOrdinalsAndIdentitiesAreExact() {
        val values = items();

        assertThrows(IllegalArgumentException.class, () ->
            bundle(List.of(values.get(1), values.get(0))));
        assertThrows(IllegalArgumentException.class, () ->
            bundle(List.of(
                values.get(0),
                ProtocolFinalResponseBundle.Item.sourced(
                    2,
                    managed(
                        ProtocolFinalResponseCapability.Type.CAS_PROXY_TICKET,
                        "PT-capability-secret",
                        SECOND_INTENT_ID),
                    SECOND_INTENT_ID,
                    0))));
        assertThrows(IllegalArgumentException.class, () ->
            ProtocolFinalResponseBundle.create(
                BUNDLE_ID,
                ProtocolFinalResponseContext.Protocol.CAS,
                ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
                "CAS_LOGIN",
                SUBJECT_ID,
                GENERATION,
                RELYING_PARTY,
                1,
                values));
        assertThrows(IllegalArgumentException.class, () ->
            bundle(List.of(
                values.get(0),
                ProtocolFinalResponseBundle.Item.sourced(
                    1, values.get(0).capability(), INTENT_ID, 1))));
        assertThrows(IllegalArgumentException.class, () ->
            bundle(List.of(
                values.get(0),
                ProtocolFinalResponseBundle.Item.sourced(
                    1,
                    managed(
                        ProtocolFinalResponseCapability.Type.CAS_PROXY_TICKET,
                        "PT-another-secret"),
                    INTENT_ID,
                    0))));
        assertThrows(IllegalArgumentException.class, () ->
            ProtocolFinalResponseBundle.Item.direct(
                -1, values.get(0).capability()));
        assertThrows(IllegalArgumentException.class, () ->
            new ProtocolFinalResponseBundle.Item(
                0, values.get(0).capability(), INTENT_ID, null));
        assertThrows(IllegalArgumentException.class, () ->
            ProtocolFinalResponseBundle.Item.sourced(
                0, values.get(0).capability(), INTENT_ID, -1));
    }

    @Test
    void verifyManagedCapabilityMustMatchBundleAndSourceAuthority() {
        val subjectMismatch = ProtocolFinalResponseCapability.managed(
            ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET,
            "ST-capability-secret",
            "different-subject",
            GENERATION,
            INTENT_ID);
        val generationMismatch = ProtocolFinalResponseCapability.managed(
            ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET,
            "ST-capability-secret",
            SUBJECT_ID,
            GENERATION + 1,
            INTENT_ID);

        assertThrows(IllegalArgumentException.class, () ->
            bundle(List.of(ProtocolFinalResponseBundle.Item.sourced(
                0, subjectMismatch, INTENT_ID, 0))));
        assertThrows(IllegalArgumentException.class, () ->
            bundle(List.of(ProtocolFinalResponseBundle.Item.sourced(
                0, generationMismatch, INTENT_ID, 0))));
        assertThrows(IllegalArgumentException.class, () ->
            bundle(List.of(ProtocolFinalResponseBundle.Item.sourced(
                0,
                managed(
                    ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET,
                    "ST-capability-secret"),
                "different-intent",
                0))));
    }

    @Test
    void verifyCanonicalTextUtf8AndTokenBoundaries() {
        val values = items();
        val browserSubject = "界".repeat(170);
        val browserSession = List.of(ProtocolFinalResponseBundle.Item.sourced(
            0,
            ProtocolFinalResponseCapability.managed(
                ProtocolFinalResponseCapability.Type.CAS_TICKET_GRANTING_TICKET,
                "TGT-capability-secret",
                browserSubject,
                GENERATION,
                INTENT_ID),
            INTENT_ID,
            0));
        val noRelyingParty = ProtocolFinalResponseBundle.create(
            BUNDLE_ID,
            ProtocolFinalResponseContext.Protocol.CAS,
            ProtocolFinalResponseContext.ResponseType.CAS_BROWSER_SSO_SESSION,
            "CAS_LOGIN",
            browserSubject,
            GENERATION,
            null,
            1,
            browserSession);

        assertEquals(
            browserSubject,
            noRelyingParty.subjectId());
        assertNull(noRelyingParty.relyingPartyBinding());
        assertEquals(
            "0190c7e8-7b2a-7cc7-9b1d-123456789abc",
            createWithBundleId(
                "0190c7e8-7b2a-7cc7-9b1d-123456789abc", values)
                .bundleId());
        assertThrows(IllegalArgumentException.class, () ->
            createWithBundleId("not-a-uuid", values));
        assertThrows(IllegalArgumentException.class, () ->
            createWithBundleId(
                "00000000-0000-0000-0000-000000000000", values));
        assertThrows(IllegalArgumentException.class, () ->
            createWithBundleId(
                BUNDLE_ID.toUpperCase(Locale.ENGLISH), values));
        assertThrows(IllegalArgumentException.class, () ->
            ProtocolFinalResponseBundle.create(
                BUNDLE_ID,
                ProtocolFinalResponseContext.Protocol.CAS,
                ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
                "CAS_LOGIN",
                "界".repeat(171),
                GENERATION,
                RELYING_PARTY,
                1,
                browserSession));
        assertThrows(IllegalArgumentException.class, () ->
            ProtocolFinalResponseBundle.create(
                BUNDLE_ID,
                ProtocolFinalResponseContext.Protocol.CAS,
                ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
                "cas_login",
                SUBJECT_ID,
                GENERATION,
                RELYING_PARTY,
                values.size(),
                values));
        assertThrows(IllegalArgumentException.class, () ->
            ProtocolFinalResponseBundle.create(
                BUNDLE_ID,
                ProtocolFinalResponseContext.Protocol.CAS,
                ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
                "CAS_LOGIN",
                SUBJECT_ID,
                GENERATION,
                " relying-party",
                values.size(),
                values));
        assertThrows(IllegalArgumentException.class, () ->
            ProtocolFinalResponseBundle.create(
                BUNDLE_ID,
                ProtocolFinalResponseContext.Protocol.CAS,
                ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
                "CAS_LOGIN",
                SUBJECT_ID,
                GENERATION,
                "界".repeat(683),
                values.size(),
                values));
        assertThrows(IllegalArgumentException.class, () ->
            bundle(List.of(ProtocolFinalResponseBundle.Item.sourced(
                0,
                ProtocolFinalResponseCapability.of(
                    ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET,
                    "\uD800"),
                INTENT_ID,
                0))));
        assertThrows(IllegalArgumentException.class, () ->
            ProtocolFinalResponseBundle.Item.sourced(
                0,
                values.getFirst().capability(),
                "not-a-uuid",
                0));
    }

    @Test
    void verifyProtocolResponseCapabilitySourceAndRelyingPartyClosedSet() {
        val supportedBoundaries = supportedBoundaries();
        for (val protocol : ProtocolFinalResponseContext.Protocol.values()) {
            for (val responseType : ProtocolFinalResponseContext.ResponseType.values()) {
                val boundary = new Boundary(protocol, responseType);
                val allowedCapabilities =
                    supportedBoundaries.getOrDefault(boundary, Set.of());
                for (val capabilityType : ProtocolFinalResponseCapability.Type.values()) {
                    val operation = (Executable) () ->
                        createBoundaryBundle(
                            protocol, responseType, capabilityType);
                    if (allowedCapabilities.contains(capabilityType)) {
                        assertDoesNotThrow(
                            operation,
                            () -> "Expected supported boundary " + boundary
                                + " for " + capabilityType);
                    } else {
                        assertThrows(
                            IllegalArgumentException.class,
                            operation,
                            () -> "Expected closed boundary " + boundary
                                + " for " + capabilityType);
                    }
                }
            }
        }

        val serviceTicket = ProtocolFinalResponseCapability.managed(
            ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET,
            "ST-capability-secret",
            SUBJECT_ID,
            GENERATION,
            INTENT_ID);
        val validationAssertion = ProtocolFinalResponseCapability.of(
            ProtocolFinalResponseCapability.Type.CAS_VALIDATION_ASSERTION,
            "validation-assertion-secret");
        assertThrows(IllegalArgumentException.class, () ->
            createBoundaryBundle(
                ProtocolFinalResponseContext.Protocol.CAS,
                ProtocolFinalResponseContext.ResponseType
                    .CAS_SERVICE_RESPONSE,
                null,
                ProtocolFinalResponseBundle.Item.sourced(
                    0, serviceTicket, INTENT_ID, 0)));
        assertThrows(IllegalArgumentException.class, () ->
            createBoundaryBundle(
                ProtocolFinalResponseContext.Protocol.CAS,
                ProtocolFinalResponseContext.ResponseType
                    .CAS_BROWSER_SSO_SESSION,
                RELYING_PARTY,
                boundaryItem(
                    ProtocolFinalResponseCapability.Type
                        .CAS_TICKET_GRANTING_TICKET)));
        assertThrows(IllegalArgumentException.class, () ->
            createBoundaryBundle(
                ProtocolFinalResponseContext.Protocol.CAS,
                ProtocolFinalResponseContext.ResponseType
                    .CAS_SERVICE_RESPONSE,
                RELYING_PARTY,
                ProtocolFinalResponseBundle.Item.direct(
                    0, serviceTicket)));
        assertThrows(IllegalArgumentException.class, () ->
            createBoundaryBundle(
                ProtocolFinalResponseContext.Protocol.CAS,
                ProtocolFinalResponseContext.ResponseType
                    .CAS_VALIDATION_RESPONSE,
                RELYING_PARTY,
                ProtocolFinalResponseBundle.Item.sourced(
                    0,
                    ProtocolFinalResponseCapability.managed(
                        validationAssertion.type(),
                        validationAssertion.reference(),
                        SUBJECT_ID,
                        GENERATION,
                        INTENT_ID),
                    INTENT_ID,
                    0)));
    }

    @Test
    void verifyCommitFailuresAreTypedFailClosedAndSecretFree() {
        val failure = new ProtocolFinalResponseCommitException(
            ProtocolFinalResponseCommitException.Code.GENERATION_CLOSED);

        assertEquals(
            ProtocolFinalResponseCommitException.Code.GENERATION_CLOSED,
            failure.getCode());
        assertFalse(failure.isRetryable());
        assertFalse(failure.getMessage().contains(BUNDLE_ID));
        assertFalse(failure.getMessage().contains(SUBJECT_ID));
        assertFalse(failure.getMessage().contains(RELYING_PARTY));
        assertTrue(new ProtocolFinalResponseCommitException(
            ProtocolFinalResponseCommitException.Code.AUTHORITY_UNAVAILABLE)
            .isRetryable());
        assertFalse(new ProtocolFinalResponseCommitException(
            ProtocolFinalResponseCommitException.Code.ALREADY_COMMITTED)
            .isRetryable());
        assertFalse(new ProtocolFinalResponseCommitException(
            ProtocolFinalResponseCommitException.Code.ALREADY_ABORTED)
            .isRetryable());
        assertFalse(new ProtocolFinalResponseCommitException(
            ProtocolFinalResponseCommitException.Code.OUTCOME_UNCERTAIN)
            .isRetryable());
        assertThrows(NullPointerException.class,
            () -> new ProtocolFinalResponseCommitException(null));
    }

    @Test
    void verifyBundlesAreSerializable() throws Exception {
        val bundle = bundle(items());
        val deliveredBundle = ProtocolFinalResponseBundle.create(
            bundle.bundleId(),
            bundle.protocol(),
            bundle.responseType(),
            bundle.purpose(),
            bundle.subjectId(),
            bundle.generation(),
            bundle.relyingPartyBinding(),
            serviceDelivery(ProtocolFinalResponseDelivery.Mode.REDIRECT),
            bundle.expectedCount(),
            bundle.items());
        assertEquals(bundle, serialize(bundle));
        assertEquals(deliveredBundle, serialize(deliveredBundle));
    }

    private static ProtocolFinalResponseBundle bundle(
        final List<ProtocolFinalResponseBundle.Item> values) {
        return ProtocolFinalResponseBundle.create(
            BUNDLE_ID,
            ProtocolFinalResponseContext.Protocol.CAS,
            ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
            "CAS_LOGIN",
            SUBJECT_ID,
            GENERATION,
            RELYING_PARTY,
            values.size(),
            values);
    }

    private static ProtocolFinalResponseDelivery serviceDelivery(
        final ProtocolFinalResponseDelivery.Mode mode) {
        return ProtocolFinalResponseDelivery.canonical(
            mode,
            "https://service.example.org?ticket=ST-capability-secret",
            Map.of("ticket", "ST-capability-secret"));
    }

    private static ProtocolFinalResponseBundle createWithBundleId(
        final String bundleId,
        final List<ProtocolFinalResponseBundle.Item> values) {
        return ProtocolFinalResponseBundle.create(
            bundleId,
            ProtocolFinalResponseContext.Protocol.CAS,
            ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
            "CAS_LOGIN",
            SUBJECT_ID,
            GENERATION,
            RELYING_PARTY,
            values.size(),
            values);
    }

    private static List<ProtocolFinalResponseBundle.Item> items() {
        return List.of(
            ProtocolFinalResponseBundle.Item.sourced(
                0,
                managed(
                    ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET,
                    "ST-capability-secret"),
                INTENT_ID,
                0),
            ProtocolFinalResponseBundle.Item.sourced(
                1,
                managed(
                    ProtocolFinalResponseCapability.Type.CAS_PROXY_TICKET,
                    "PT-capability-secret",
                    SECOND_INTENT_ID),
                SECOND_INTENT_ID,
                0));
    }

    private static ProtocolFinalResponseCapability managed(
        final ProtocolFinalResponseCapability.Type type,
        final String reference) {
        return managed(type, reference, INTENT_ID);
    }

    private static ProtocolFinalResponseCapability managed(
        final ProtocolFinalResponseCapability.Type type,
        final String reference,
        final String intentId) {
        return ProtocolFinalResponseCapability.managed(
            type, reference, SUBJECT_ID, GENERATION, intentId);
    }

    private static ProtocolFinalResponseBundle createBoundaryBundle(
        final ProtocolFinalResponseContext.Protocol protocol,
        final ProtocolFinalResponseContext.ResponseType responseType,
        final ProtocolFinalResponseCapability.Type capabilityType) {
        val relyingParty =
            responseType
                == ProtocolFinalResponseContext.ResponseType
                    .CAS_BROWSER_SSO_SESSION
            || responseType
                == ProtocolFinalResponseContext.ResponseType
                    .CAS_REST_TICKET_RESPONSE
                ? null
                : RELYING_PARTY;
        return createBoundaryBundle(
            protocol, responseType, relyingParty, boundaryItem(capabilityType));
    }

    private static ProtocolFinalResponseBundle createBoundaryBundle(
        final ProtocolFinalResponseContext.Protocol protocol,
        final ProtocolFinalResponseContext.ResponseType responseType,
        final String relyingParty,
        final ProtocolFinalResponseBundle.Item item) {
        return ProtocolFinalResponseBundle.create(
            BUNDLE_ID,
            protocol,
            responseType,
            "CAS_LOGIN",
            SUBJECT_ID,
            GENERATION,
            relyingParty,
            1,
            List.of(item));
    }

    private static ProtocolFinalResponseBundle.Item boundaryItem(
        final ProtocolFinalResponseCapability.Type capabilityType) {
        val reference = capabilityType + "-capability-secret";
        if (isSourceCapability(capabilityType)) {
            return ProtocolFinalResponseBundle.Item.sourced(
                0,
                managed(capabilityType, reference),
                INTENT_ID,
                0);
        }
        return ProtocolFinalResponseBundle.Item.direct(
            0, ProtocolFinalResponseCapability.of(capabilityType, reference));
    }

    private static boolean isSourceCapability(
        final ProtocolFinalResponseCapability.Type capabilityType) {
        return switch (capabilityType) {
            case CAS_SERVICE_TICKET, CAS_TICKET_GRANTING_TICKET,
                 CAS_PROXY_TICKET, CAS_PROXY_GRANTING_TICKET,
                 OAUTH_AUTHORIZATION_CODE, OAUTH_ACCESS_TOKEN,
                 OAUTH_REFRESH_TOKEN, OIDC_ID_TOKEN, SAML1_ARTIFACT,
                 SAML2_RESPONSE -> true;
            default -> false;
        };
    }

    private static Map<Boundary, Set<ProtocolFinalResponseCapability.Type>>
        supportedBoundaries() {
        return Map.ofEntries(
            boundary(
                ProtocolFinalResponseContext.Protocol.CAS,
                ProtocolFinalResponseContext.ResponseType
                    .CAS_BROWSER_SSO_SESSION,
                ProtocolFinalResponseCapability.Type
                    .CAS_TICKET_GRANTING_TICKET),
            boundary(
                ProtocolFinalResponseContext.Protocol.CAS,
                ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
                ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET,
                ProtocolFinalResponseCapability.Type.CAS_PROXY_TICKET),
            boundary(
                ProtocolFinalResponseContext.Protocol.CAS,
                ProtocolFinalResponseContext.ResponseType
                    .CAS_VALIDATION_RESPONSE,
                ProtocolFinalResponseCapability.Type
                    .CAS_VALIDATION_ASSERTION,
                ProtocolFinalResponseCapability.Type
                    .CAS_PROXY_GRANTING_TICKET_IOU),
            boundary(
                ProtocolFinalResponseContext.Protocol.CAS,
                ProtocolFinalResponseContext.ResponseType.CAS_PROXY_CALLBACK,
                ProtocolFinalResponseCapability.Type
                    .CAS_PROXY_GRANTING_TICKET,
                ProtocolFinalResponseCapability.Type
                    .CAS_PROXY_GRANTING_TICKET_IOU),
            boundary(
                ProtocolFinalResponseContext.Protocol.OAUTH2,
                ProtocolFinalResponseContext.ResponseType
                    .AUTHORIZATION_RESPONSE,
                ProtocolFinalResponseCapability.Type
                    .OAUTH_AUTHORIZATION_CODE),
            boundary(
                ProtocolFinalResponseContext.Protocol.OAUTH2,
                ProtocolFinalResponseContext.ResponseType.TOKEN_RESPONSE,
                ProtocolFinalResponseCapability.Type.OAUTH_ACCESS_TOKEN,
                ProtocolFinalResponseCapability.Type.OAUTH_REFRESH_TOKEN),
            boundary(
                ProtocolFinalResponseContext.Protocol.OPENID_CONNECT,
                ProtocolFinalResponseContext.ResponseType
                    .AUTHORIZATION_RESPONSE,
                ProtocolFinalResponseCapability.Type
                    .OAUTH_AUTHORIZATION_CODE),
            boundary(
                ProtocolFinalResponseContext.Protocol.OPENID_CONNECT,
                ProtocolFinalResponseContext.ResponseType.TOKEN_RESPONSE,
                ProtocolFinalResponseCapability.Type.OAUTH_ACCESS_TOKEN,
                ProtocolFinalResponseCapability.Type.OAUTH_REFRESH_TOKEN,
                ProtocolFinalResponseCapability.Type.OIDC_ID_TOKEN),
            boundary(
                ProtocolFinalResponseContext.Protocol.SAML1,
                ProtocolFinalResponseContext.ResponseType
                    .SAML_ARTIFACT_RESPONSE,
                ProtocolFinalResponseCapability.Type.SAML1_ARTIFACT),
            boundary(
                ProtocolFinalResponseContext.Protocol.SAML2,
                ProtocolFinalResponseContext.ResponseType
                    .SAML_ASSERTION_RESPONSE,
                ProtocolFinalResponseCapability.Type.SAML2_ASSERTION,
                ProtocolFinalResponseCapability.Type.SAML2_RESPONSE),
            boundary(
                ProtocolFinalResponseContext.Protocol.SAML2,
                ProtocolFinalResponseContext.ResponseType.SAML_SOAP_RESPONSE,
                ProtocolFinalResponseCapability.Type.SAML2_ASSERTION,
                ProtocolFinalResponseCapability.Type.SAML2_RESPONSE));
    }

    @SafeVarargs
    private static Map.Entry<
        Boundary, Set<ProtocolFinalResponseCapability.Type>> boundary(
            final ProtocolFinalResponseContext.Protocol protocol,
            final ProtocolFinalResponseContext.ResponseType responseType,
            final ProtocolFinalResponseCapability.Type... capabilityTypes) {
        return Map.entry(
            new Boundary(protocol, responseType),
            Set.of(capabilityTypes));
    }

    private record Boundary(
        ProtocolFinalResponseContext.Protocol protocol,
        ProtocolFinalResponseContext.ResponseType responseType) {
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
