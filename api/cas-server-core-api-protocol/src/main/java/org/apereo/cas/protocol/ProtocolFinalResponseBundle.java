package org.apereo.cas.protocol;

import module java.base;
import lombok.val;

/**
 * Immutable exact manifest of capabilities at one final protocol-response boundary.
 *
 * <p>The manifest identity is a SHA-256 digest over a versioned, length-prefixed
 * UTF-8 representation of every protocol security coordinate and every ordered
 * item. It identifies raw protocol output. It is deliberately distinct from a
 * database artifact-inventory digest or keyed lifecycle-evidence HMAC; an
 * implementation must persist an explicit binding between those different
 * evidence domains and must not assume that their bytes are recomputable from
 * one another.</p>
 *
 * <p>Capability references and lifecycle identifiers are deliberately excluded
 * from {@link #toString()}.</p>
 *
 * @author SoooEZ
 * @param bundleId canonical durable bundle identifier
 * @param protocol protocol family
 * @param responseType final response type
 * @param purpose canonical response purpose
 * @param subjectId stable subject identifier
 * @param generation positive subject-security generation
 * @param relyingPartyBinding exact relying-party, audience, or client binding;
 * required except for browser SSO and CAS REST responses, where it is forbidden
 * @param expectedCount exact number of manifest items
 * @param manifestIdentity SHA-256 identity of this exact manifest
 * @param items exact ordered response items
 * @since 8.0.0
 */
public record ProtocolFinalResponseBundle(
    String bundleId,
    ProtocolFinalResponseContext.Protocol protocol,
    ProtocolFinalResponseContext.ResponseType responseType,
    String purpose,
    String subjectId,
    long generation,
    String relyingPartyBinding,
    int expectedCount,
    String manifestIdentity,
    List<Item> items) implements Serializable {

    /** Maximum number of capabilities in one final response. */
    public static final int MAXIMUM_ITEM_COUNT = 64;

    /** Maximum UTF-8 size of a bundle, lease, or source-intent identifier. */
    public static final int MAXIMUM_IDENTIFIER_UTF8_BYTES = 128;

    /** Maximum UTF-8 size of a response purpose. */
    public static final int MAXIMUM_PURPOSE_UTF8_BYTES = 64;

    /** Maximum UTF-8 size of a subject identifier. */
    public static final int MAXIMUM_SUBJECT_UTF8_BYTES = 512;

    /** Maximum UTF-8 size of a relying-party binding. */
    public static final int MAXIMUM_RELYING_PARTY_UTF8_BYTES = 2_048;

    /** Maximum UTF-8 size of one opaque capability reference. */
    public static final int MAXIMUM_CAPABILITY_REFERENCE_UTF8_BYTES = 65_536;

    /** Length of a lowercase SHA-256 digest in hexadecimal form. */
    public static final int SHA_256_HEX_LENGTH = 64;

    @Serial
    private static final long serialVersionUID = -2651032979119036980L;

    private static final String MANIFEST_DOMAIN = "cas-protocol-final-response-manifest-v1";

    private static final Pattern CANONICAL_TOKEN_PATTERN =
        Pattern.compile("[A-Z][A-Z0-9_]{0,63}");

    private static final Pattern SHA_256_PATTERN = Pattern.compile("[0-9a-f]{64}");

    private static final Pattern UUID_PATTERN = Pattern.compile(
        "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

    private static final String NIL_UUID =
        "00000000-0000-0000-0000-000000000000";

    public ProtocolFinalResponseBundle {
        bundleId = requireUuid(bundleId, "bundleId");
        Objects.requireNonNull(protocol, "protocol");
        Objects.requireNonNull(responseType, "responseType");
        purpose = requireToken(purpose, "purpose");
        subjectId = requireText(
            subjectId, "subjectId", MAXIMUM_SUBJECT_UTF8_BYTES);
        if (generation <= 0) {
            throw new IllegalArgumentException("generation must be positive");
        }
        if (relyingPartyBinding != null) {
            relyingPartyBinding = requireText(
                relyingPartyBinding,
                "relyingPartyBinding",
                MAXIMUM_RELYING_PARTY_UTF8_BYTES);
        }
        validateResponseBoundary(
            protocol, responseType, relyingPartyBinding);
        if (expectedCount < 1 || expectedCount > MAXIMUM_ITEM_COUNT) {
            throw new IllegalArgumentException(
                "expectedCount is outside the supported range");
        }
        manifestIdentity = requireDigest(manifestIdentity, "manifestIdentity");
        items = List.copyOf(Objects.requireNonNull(items, "items"));
        if (items.size() != expectedCount) {
            throw new IllegalArgumentException(
                "items must match the exact expected count");
        }

        val capabilityReferences = new HashSet<String>();
        val sources = new HashSet<SourceIdentity>();
        for (var index = 0; index < items.size(); index++) {
            val item = Objects.requireNonNull(items.get(index), "item");
            if (item.ordinal() != index) {
                throw new IllegalArgumentException(
                    "item ordinals must be exact, ordered, and contiguous");
            }
            if (!capabilityReferences.add(item.capability().reference())) {
                throw new IllegalArgumentException(
                    "capability references cannot be duplicated within a response manifest");
            }
            validateCapability(item, subjectId, generation);
            validateCapabilityBoundary(protocol, responseType, item);
            if (item.hasSource()
                && !sources.add(new SourceIdentity(
                    item.sourceIntentId(), item.sourceArtifactOrdinal()))) {
                throw new IllegalArgumentException(
                    "source artifacts cannot be duplicated within a response manifest");
            }
        }

        val calculatedIdentity = calculateManifestIdentity(
            bundleId, protocol, responseType, purpose, subjectId, generation,
            relyingPartyBinding, expectedCount, items);
        if (!MessageDigest.isEqual(
            manifestIdentity.getBytes(StandardCharsets.US_ASCII),
            calculatedIdentity.getBytes(StandardCharsets.US_ASCII))) {
            throw new IllegalArgumentException(
                "manifestIdentity does not describe the exact response manifest");
        }
    }

    /**
     * Create a bundle and calculate its immutable manifest identity.
     *
     * @param bundleId durable bundle identifier
     * @param protocol protocol family
     * @param responseType final response type
     * @param purpose response purpose
     * @param subjectId subject identifier
     * @param generation subject-security generation
     * @param relyingPartyBinding exact relying-party, audience, or client binding;
     * required except for browser SSO and CAS REST responses, where it is forbidden
     * @param expectedCount exact expected item count
     * @param items exact ordered items
     * @return validated final response bundle
     */
    public static ProtocolFinalResponseBundle create(
        final String bundleId,
        final ProtocolFinalResponseContext.Protocol protocol,
        final ProtocolFinalResponseContext.ResponseType responseType,
        final String purpose,
        final String subjectId,
        final long generation,
        final String relyingPartyBinding,
        final int expectedCount,
        final List<Item> items) {
        val immutableItems = List.copyOf(Objects.requireNonNull(items, "items"));
        val identity = calculateManifestIdentity(
            bundleId, protocol, responseType, purpose, subjectId, generation,
            relyingPartyBinding, expectedCount, immutableItems);
        return new ProtocolFinalResponseBundle(
            bundleId, protocol, responseType, purpose, subjectId, generation,
            relyingPartyBinding, expectedCount, identity, immutableItems);
    }

    @Override
    public String toString() {
        return ("ProtocolFinalResponseBundle[bundleId=[REDACTED], protocol=%s, "
                + "responseType=%s, purpose=%s, subjectId=[REDACTED], generation=%d, "
                + "relyingPartyBinding=[REDACTED], expectedCount=%d, "
                + "manifestIdentity=[REDACTED], items=[REDACTED]]")
            .formatted(protocol, responseType, purpose, generation, expectedCount);
    }

    static String requireUuid(final String value, final String name) {
        val result = Objects.requireNonNull(value, name);
        if (!UUID_PATTERN.matcher(result).matches()
            || NIL_UUID.equals(result)) {
            throw new IllegalArgumentException(
                name + " must be a non-nil canonical lowercase UUID");
        }
        return result;
    }

    static String requireDigest(final String value, final String name) {
        val result = Objects.requireNonNull(value, name);
        if (!SHA_256_PATTERN.matcher(result).matches()) {
            throw new IllegalArgumentException(
                name + " must be a lowercase SHA-256 digest");
        }
        return result;
    }

    static String requireText(
        final String value,
        final String name,
        final int maximumUtf8Bytes) {
        val result = Objects.requireNonNull(value, name);
        if (result.isBlank() || !result.equals(result.strip())) {
            throw new IllegalArgumentException(
                name + " must be canonical non-blank text");
        }
        if (result.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(
                name + " cannot contain control characters");
        }
        try {
            val encoded = StandardCharsets.UTF_8.newEncoder()
                .encode(CharBuffer.wrap(result));
            if (encoded.remaining() > maximumUtf8Bytes) {
                throw new IllegalArgumentException(
                    name + " exceeds its UTF-8 size limit");
            }
        } catch (final CharacterCodingException e) {
            throw new IllegalArgumentException(
                name + " is not valid Unicode", e);
        }
        return result;
    }

    private static String requireToken(final String value, final String name) {
        val result = requireText(value, name, MAXIMUM_PURPOSE_UTF8_BYTES);
        if (!CANONICAL_TOKEN_PATTERN.matcher(result).matches()) {
            throw new IllegalArgumentException(
                name + " must be an uppercase canonical token");
        }
        return result;
    }

    private static void validateCapability(
        final Item item,
        final String subjectId,
        final long generation) {
        val capability = item.capability();
        requireText(
            capability.reference(),
            "capability reference",
            MAXIMUM_CAPABILITY_REFERENCE_UTF8_BYTES);
        if (capability.isLifecycleManaged()) {
            requireText(
                capability.subjectId(),
                "capability subjectId",
                MAXIMUM_SUBJECT_UTF8_BYTES);
            requireText(
                capability.intentId(),
                "capability intentId",
                MAXIMUM_IDENTIFIER_UTF8_BYTES);
            if (!subjectId.equals(capability.subjectId())
                || generation != capability.generation()) {
                throw new IllegalArgumentException(
                    "managed capability lifecycle coordinates must match the bundle");
            }
            if (item.hasSource()
                && !item.sourceIntentId().equals(capability.intentId())) {
                throw new IllegalArgumentException(
                    "managed capability intent must match its source intent");
            }
        }
    }

    private static void validateResponseBoundary(
        final ProtocolFinalResponseContext.Protocol protocol,
        final ProtocolFinalResponseContext.ResponseType responseType,
        final String relyingPartyBinding) {
        val responseAllowed = switch (protocol) {
            case CAS -> switch (responseType) {
                case CAS_SERVICE_RESPONSE, CAS_BROWSER_SSO_SESSION,
                     CAS_VALIDATION_RESPONSE, CAS_PROXY_CALLBACK,
                     CAS_REST_TICKET_RESPONSE -> true;
                default -> false;
            };
            case OAUTH2, OPENID_CONNECT -> switch (responseType) {
                case AUTHORIZATION_RESPONSE, TOKEN_RESPONSE,
                     DEVICE_AUTHORIZATION_RESPONSE,
                     CIBA_AUTHENTICATION_RESPONSE -> true;
                default -> false;
            };
            case SAML1, SAML2 -> switch (responseType) {
                case SAML_ASSERTION_RESPONSE, SAML_ARTIFACT_RESPONSE,
                     SAML_SOAP_RESPONSE -> true;
                default -> false;
            };
        };
        if (!responseAllowed) {
            throw new IllegalArgumentException(
                "responseType is not valid for the protocol family");
        }

        val relyingPartyForbidden =
            responseType
                == ProtocolFinalResponseContext.ResponseType
                    .CAS_BROWSER_SSO_SESSION
            || responseType
                == ProtocolFinalResponseContext.ResponseType
                    .CAS_REST_TICKET_RESPONSE;
        if (relyingPartyForbidden && relyingPartyBinding != null) {
            throw new IllegalArgumentException(
                "relyingPartyBinding is forbidden for this response type");
        }
        if (!relyingPartyForbidden && relyingPartyBinding == null) {
            throw new IllegalArgumentException(
                "relyingPartyBinding is required for this response type");
        }
    }

    private static void validateCapabilityBoundary(
        final ProtocolFinalResponseContext.Protocol protocol,
        final ProtocolFinalResponseContext.ResponseType responseType,
        final Item item) {
        val capabilityType = item.capability().type();
        val capabilityAllowed = switch (protocol) {
            case CAS -> switch (responseType) {
                case CAS_BROWSER_SSO_SESSION ->
                    capabilityType
                        == ProtocolFinalResponseCapability.Type
                            .CAS_TICKET_GRANTING_TICKET;
                case CAS_SERVICE_RESPONSE ->
                    capabilityType
                        == ProtocolFinalResponseCapability.Type
                            .CAS_SERVICE_TICKET
                        || capabilityType
                            == ProtocolFinalResponseCapability.Type
                                .CAS_PROXY_TICKET;
                case CAS_VALIDATION_RESPONSE ->
                    capabilityType
                        == ProtocolFinalResponseCapability.Type
                            .CAS_VALIDATION_ASSERTION
                        || capabilityType
                            == ProtocolFinalResponseCapability.Type
                                .CAS_PROXY_GRANTING_TICKET_IOU;
                case CAS_PROXY_CALLBACK ->
                    capabilityType
                        == ProtocolFinalResponseCapability.Type
                            .CAS_PROXY_GRANTING_TICKET
                        || capabilityType
                            == ProtocolFinalResponseCapability.Type
                                .CAS_PROXY_GRANTING_TICKET_IOU;
                default -> false;
            };
            case OAUTH2 -> switch (responseType) {
                case AUTHORIZATION_RESPONSE ->
                    capabilityType
                        == ProtocolFinalResponseCapability.Type
                            .OAUTH_AUTHORIZATION_CODE;
                case TOKEN_RESPONSE ->
                    capabilityType
                        == ProtocolFinalResponseCapability.Type
                            .OAUTH_ACCESS_TOKEN
                        || capabilityType
                            == ProtocolFinalResponseCapability.Type
                                .OAUTH_REFRESH_TOKEN;
                default -> false;
            };
            case OPENID_CONNECT -> switch (responseType) {
                case AUTHORIZATION_RESPONSE ->
                    capabilityType
                        == ProtocolFinalResponseCapability.Type
                            .OAUTH_AUTHORIZATION_CODE;
                case TOKEN_RESPONSE ->
                    capabilityType
                        == ProtocolFinalResponseCapability.Type
                            .OAUTH_ACCESS_TOKEN
                        || capabilityType
                            == ProtocolFinalResponseCapability.Type
                                .OAUTH_REFRESH_TOKEN
                        || capabilityType
                            == ProtocolFinalResponseCapability.Type
                                .OIDC_ID_TOKEN;
                default -> false;
            };
            case SAML1 -> responseType
                == ProtocolFinalResponseContext.ResponseType
                    .SAML_ARTIFACT_RESPONSE
                && capabilityType
                    == ProtocolFinalResponseCapability.Type.SAML1_ARTIFACT;
            case SAML2 -> switch (responseType) {
                case SAML_ASSERTION_RESPONSE, SAML_SOAP_RESPONSE ->
                    capabilityType
                        == ProtocolFinalResponseCapability.Type
                            .SAML2_ASSERTION
                        || capabilityType
                            == ProtocolFinalResponseCapability.Type
                                .SAML2_RESPONSE;
                default -> false;
            };
        };
        if (!capabilityAllowed) {
            throw new IllegalArgumentException(
                "capability type is not valid for the exact response boundary");
        }

        val sourceRequired = switch (capabilityType) {
            case CAS_SERVICE_TICKET, CAS_TICKET_GRANTING_TICKET,
                 CAS_PROXY_TICKET, CAS_PROXY_GRANTING_TICKET,
                 OAUTH_AUTHORIZATION_CODE, OAUTH_ACCESS_TOKEN,
                 OAUTH_REFRESH_TOKEN, OIDC_ID_TOKEN, SAML1_ARTIFACT,
                 SAML2_RESPONSE -> true;
            case CAS_PROXY_GRANTING_TICKET_IOU, CAS_VALIDATION_ASSERTION,
                 SAML2_ASSERTION -> false;
            default -> throw new IllegalArgumentException(
                "capability type has no supported durable source policy");
        };
        if (sourceRequired != item.hasSource()) {
            throw new IllegalArgumentException(
                sourceRequired
                    ? "capability type requires an exact durable source"
                    : "derived capability type cannot declare a durable source");
        }
    }

    private static String calculateManifestIdentity(
        final String bundleId,
        final ProtocolFinalResponseContext.Protocol protocol,
        final ProtocolFinalResponseContext.ResponseType responseType,
        final String purpose,
        final String subjectId,
        final long generation,
        final String relyingPartyBinding,
        final int expectedCount,
        final List<Item> items) {
        try {
            val digest = MessageDigest.getInstance("SHA-256");
            putText(digest, MANIFEST_DOMAIN);
            putText(digest, bundleId);
            putText(digest, protocol.name());
            putText(digest, responseType.name());
            putText(digest, purpose);
            putText(digest, subjectId);
            putLong(digest, generation);
            putNullableText(digest, relyingPartyBinding);
            putInt(digest, expectedCount);
            putInt(digest, items.size());
            for (val item : items) {
                putInt(digest, item.ordinal());
                putText(digest, item.capability().type().name());
                putText(digest, item.capability().reference());
                putNullableText(digest, item.capability().subjectId());
                putNullableLong(digest, item.capability().generation());
                putNullableText(digest, item.capability().intentId());
                putNullableText(digest, item.sourceIntentId());
                putNullableInt(digest, item.sourceArtifactOrdinal());
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                "SHA-256 is required by the Java platform", e);
        }
    }

    private static void putText(
        final MessageDigest digest,
        final String value) {
        val bytes = Objects.requireNonNull(value, "canonical manifest value")
            .getBytes(StandardCharsets.UTF_8);
        putInt(digest, bytes.length);
        digest.update(bytes);
    }

    private static void putNullableText(
        final MessageDigest digest,
        final String value) {
        digest.update((byte) (value == null ? 0 : 1));
        if (value != null) {
            putText(digest, value);
        }
    }

    private static void putNullableLong(
        final MessageDigest digest,
        final Long value) {
        digest.update((byte) (value == null ? 0 : 1));
        if (value != null) {
            putLong(digest, value);
        }
    }

    private static void putNullableInt(
        final MessageDigest digest,
        final Integer value) {
        digest.update((byte) (value == null ? 0 : 1));
        if (value != null) {
            putInt(digest, value);
        }
    }

    private static void putLong(
        final MessageDigest digest,
        final long value) {
        digest.update(ByteBuffer.allocate(Long.BYTES).putLong(value).array());
    }

    private static void putInt(
        final MessageDigest digest,
        final int value) {
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(value).array());
    }

    /**
     * One exact capability position in the response manifest.
     *
     * @param ordinal zero-based position in the final response
     * @param capability opaque capability to disclose
     * @param sourceIntentId optional durable source intent
     * @param sourceArtifactOrdinal optional source artifact ordinal
     */
    public record Item(
        int ordinal,
        ProtocolFinalResponseCapability capability,
        String sourceIntentId,
        Integer sourceArtifactOrdinal) implements Serializable {

        @Serial
        private static final long serialVersionUID = 7143992136919119197L;

        public Item {
            if (ordinal < 0 || ordinal >= MAXIMUM_ITEM_COUNT) {
                throw new IllegalArgumentException(
                    "ordinal is outside the supported range");
            }
            Objects.requireNonNull(capability, "capability");
            if ((sourceIntentId == null) != (sourceArtifactOrdinal == null)) {
                throw new IllegalArgumentException(
                    "source intent and artifact ordinal must be both present or both absent");
            }
            if (sourceIntentId != null) {
                sourceIntentId = requireUuid(
                    sourceIntentId, "sourceIntentId");
                if (sourceArtifactOrdinal < 0
                    || sourceArtifactOrdinal >= MAXIMUM_ITEM_COUNT) {
                    throw new IllegalArgumentException(
                        "sourceArtifactOrdinal is outside the supported range");
                }
            }
        }

        /**
         * Create an item without a durable source artifact.
         *
         * @param ordinal response ordinal
         * @param capability response capability
         * @return manifest item
         */
        public static Item direct(
            final int ordinal,
            final ProtocolFinalResponseCapability capability) {
            return new Item(ordinal, capability, null, null);
        }

        /**
         * Create an item bound to an exact durable source artifact.
         *
         * @param ordinal response ordinal
         * @param capability response capability
         * @param sourceIntentId durable source intent
         * @param sourceArtifactOrdinal source artifact ordinal
         * @return manifest item
         */
        public static Item sourced(
            final int ordinal,
            final ProtocolFinalResponseCapability capability,
            final String sourceIntentId,
            final int sourceArtifactOrdinal) {
            return new Item(
                ordinal, capability, sourceIntentId, sourceArtifactOrdinal);
        }

        /**
         * Whether this item is bound to a durable source artifact.
         *
         * @return true when both source coordinates are present
         */
        public boolean hasSource() {
            return sourceIntentId != null;
        }

        @Override
        public String toString() {
            return ("Item[ordinal=%d, capability=[REDACTED], "
                    + "sourceIntentId=%s, sourceArtifactOrdinal=%s]")
                .formatted(
                    ordinal,
                    sourceIntentId == null ? null : "[REDACTED]",
                    sourceArtifactOrdinal);
        }
    }

    private record SourceIdentity(
        String sourceIntentId,
        int sourceArtifactOrdinal) {
    }
}
