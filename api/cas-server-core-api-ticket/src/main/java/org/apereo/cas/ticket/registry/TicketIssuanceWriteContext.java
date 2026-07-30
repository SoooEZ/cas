package org.apereo.cas.ticket.registry;

import module java.base;
import lombok.val;
import org.jspecify.annotations.Nullable;

/**
 * Immutable, explicit authorization coordinates for one ticket-registry write.
 *
 * <p>This value is supplied by the protocol flow that knows what it is
 * issuing. Ticket registries and persistence extensions must pass it through
 * unchanged and must not reconstruct it from a ticket Java type, prefix, or a
 * thread-local value. A context describes exactly one artifact in an exact
 * response manifest.</p>
 *
 * <p>Managed account, client, and pre-authentication writes require a durable
 * intent and a positive subject, client, or anonymous-state policy generation.
 * An explicitly non-capability write is deliberately unable to carry those
 * lifecycle coordinates. This distinction prevents a partially populated
 * managed context from silently degrading to an unmanaged write.</p>
 *
 * @author SoooEZ
 * @param classification security classification
 * @param family protocol family
 * @param purpose canonical issuance purpose
 * @param artifactType canonical artifact type
 * @param ordinal zero-based artifact ordinal
 * @param expectedCount exact number of artifacts in the response manifest
 * @param intentId durable issuance intent for managed writes
 * @param generationBinding subject, client, or state generation for managed writes
 * @param relyingPartyBinding optional relying-party and client binding
 * @since 8.0.0
 */
public record TicketIssuanceWriteContext(
    Classification classification,
    ProtocolFamily family,
    String purpose,
    String artifactType,
    int ordinal,
    int expectedCount,
    @Nullable String intentId,
    @Nullable GenerationBinding generationBinding,
    @Nullable RelyingPartyBinding relyingPartyBinding) implements Serializable {

    /** Maximum artifacts supported by one exact response manifest. */
    public static final int MAXIMUM_ARTIFACT_COUNT = 64;

    /** Maximum UTF-8 size of a canonical purpose or artifact type. */
    public static final int MAXIMUM_TOKEN_UTF8_BYTES = 64;

    /** Maximum UTF-8 size of an issuance intent identifier. */
    public static final int MAXIMUM_INTENT_ID_UTF8_BYTES = 128;

    /** Maximum UTF-8 size of a subject or client generation owner. */
    public static final int MAXIMUM_OWNER_ID_UTF8_BYTES = 512;

    /** Maximum UTF-8 size of a relying-party identifier. */
    public static final int MAXIMUM_RELYING_PARTY_ID_UTF8_BYTES = 2_048;

    @Serial
    private static final long serialVersionUID = 4046441390981757197L;

    private static final Pattern CANONICAL_TOKEN_PATTERN = Pattern.compile("[A-Z][A-Z0-9_]{0,63}");

    public TicketIssuanceWriteContext {
        Objects.requireNonNull(classification, "classification");
        Objects.requireNonNull(family, "family");
        purpose = requireToken(purpose, "purpose");
        artifactType = requireToken(artifactType, "artifactType");
        if (expectedCount < 1 || expectedCount > MAXIMUM_ARTIFACT_COUNT) {
            throw new IllegalArgumentException("Expected artifact count is outside the supported range");
        }
        if (ordinal < 0 || ordinal >= expectedCount) {
            throw new IllegalArgumentException("Artifact ordinal is outside the exact response manifest");
        }
        intentId = normalizeNullableText(intentId, "intentId", MAXIMUM_INTENT_ID_UTF8_BYTES);

        if (classification == Classification.EXPLICIT_NON_CAPABILITY) {
            if (intentId != null || generationBinding != null) {
                throw new IllegalArgumentException(
                    "An explicitly non-capability write cannot carry lifecycle coordinates");
            }
        } else {
            if (intentId == null || generationBinding == null) {
                throw new IllegalArgumentException("A managed write requires an intent and generation binding");
            }
            val binding = generationBinding;
            if (classification == Classification.ACCOUNT_CAPABILITY
                && binding.ownerType() != GenerationOwnerType.SUBJECT) {
                throw new IllegalArgumentException("An account capability requires a subject generation");
            }
            if (classification == Classification.CLIENT_CAPABILITY
                && binding.ownerType() != GenerationOwnerType.CLIENT) {
                throw new IllegalArgumentException("A client capability requires a client generation");
            }
            if (classification == Classification.PREAUTH_STATE
                && binding.ownerType() != GenerationOwnerType.STATE) {
                throw new IllegalArgumentException(
                    "Pre-authentication state requires an anonymous-state policy generation");
            }
            if (binding.ownerType() == GenerationOwnerType.CLIENT) {
                if (relyingPartyBinding == null || relyingPartyBinding.clientId() == null) {
                    throw new IllegalArgumentException(
                        "A client generation requires an exact client binding");
                }
                val clientId = relyingPartyBinding.clientId();
                if (!binding.ownerId().equals(clientId)) {
                    throw new IllegalArgumentException(
                        "The client generation owner and client binding must match");
                }
            }
            if ((family == ProtocolFamily.OAUTH2 || family == ProtocolFamily.OPENID_CONNECT)
                && (relyingPartyBinding == null || relyingPartyBinding.clientId() == null)) {
                throw new IllegalArgumentException(
                    "OAuth and OpenID Connect writes require an exact client binding");
            }
            if (family == ProtocolFamily.SAML
                && (relyingPartyBinding == null || relyingPartyBinding.relyingPartyId() == null)) {
                throw new IllegalArgumentException(
                    "SAML writes require an exact relying-party binding");
            }
        }
    }

    /**
     * Create a managed account, client, or pre-authentication write context.
     *
     * @param classification managed classification
     * @param family protocol family
     * @param purpose canonical issuance purpose
     * @param artifactType canonical artifact type
     * @param ordinal artifact ordinal
     * @param expectedCount exact artifact count
     * @param intentId durable intent identifier
     * @param generationBinding subject or client generation
     * @param relyingPartyBinding optional relying-party and client binding
     * @return validated context
     */
    public static TicketIssuanceWriteContext managed(
        final Classification classification,
        final ProtocolFamily family,
        final String purpose,
        final String artifactType,
        final int ordinal,
        final int expectedCount,
        final String intentId,
        final GenerationBinding generationBinding,
        final @Nullable RelyingPartyBinding relyingPartyBinding) {
        if (classification == Classification.EXPLICIT_NON_CAPABILITY) {
            throw new IllegalArgumentException("Use explicitNonCapability for a non-capability write");
        }
        return new TicketIssuanceWriteContext(
            classification,
            family,
            purpose,
            artifactType,
            ordinal,
            expectedCount,
            intentId,
            generationBinding,
            relyingPartyBinding);
    }

    /**
     * Create an explicitly classified non-capability context.
     *
     * @param family protocol family
     * @param purpose canonical issuance purpose
     * @param artifactType canonical artifact type
     * @param relyingPartyBinding optional relying-party and client binding
     * @return validated context
     */
    public static TicketIssuanceWriteContext explicitNonCapability(
        final ProtocolFamily family,
        final String purpose,
        final String artifactType,
        final @Nullable RelyingPartyBinding relyingPartyBinding) {
        return new TicketIssuanceWriteContext(
            Classification.EXPLICIT_NON_CAPABILITY,
            family,
            purpose,
            artifactType,
            0,
            1,
            null,
            null,
            relyingPartyBinding);
    }

    /**
     * Whether this write participates in a durable lifecycle.
     *
     * @return true for a managed write
     */
    public boolean isManaged() {
        return classification != Classification.EXPLICIT_NON_CAPABILITY;
    }

    /**
     * Verify the durable ticket lifecycle metadata against this exact context.
     *
     * <p>The durable policy remains responsible for validating the complete
     * manifest, purpose, family, and relying-party binding. This check prevents
     * a registry update from changing the persisted intent, generation owner,
     * or generation before that policy is reached.</p>
     *
     * @param metadata persisted lifecycle metadata
     * @throws IllegalStateException when the metadata does not match
     */
    public void requireConsistentWith(final TicketIssuanceMetadata metadata) {
        Objects.requireNonNull(metadata, "metadata");
        if (!isManaged()) {
            throw new IllegalStateException(
                "An explicitly non-capability context cannot reference managed ticket metadata");
        }
        val owner = Objects.requireNonNull(generationBinding, "generationBinding");
        if (owner.ownerType() != GenerationOwnerType.SUBJECT) {
            throw new IllegalStateException(
                "Current ticket lifecycle metadata can only represent a subject generation");
        }
        if (!Objects.requireNonNull(intentId, "intentId").equals(metadata.intentId())
            || !owner.ownerId().equals(metadata.subjectId())
            || owner.generation() != metadata.generation()) {
            throw new IllegalStateException(
                "The issuance write context does not match persisted ticket lifecycle metadata");
        }
    }

    private static @Nullable String normalizeNullableText(
        final @Nullable String value,
        final String name,
        final int maximumUtf8Bytes) {
        return value != null ? requireText(value, name, maximumUtf8Bytes) : null;
    }

    private static String requireToken(final String value, final String name) {
        val result = requireText(value, name, MAXIMUM_TOKEN_UTF8_BYTES);
        if (!CANONICAL_TOKEN_PATTERN.matcher(result).matches()) {
            throw new IllegalArgumentException(
                name + " must be an uppercase canonical token");
        }
        return result;
    }

    private static String requireText(final String value, final String name, final int maximumUtf8Bytes) {
        val result = Objects.requireNonNull(value, name);
        if (result.isBlank() || !result.equals(result.strip())) {
            throw new IllegalArgumentException(name + " must be canonical non-blank text");
        }
        if (result.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(name + " cannot contain control characters");
        }
        try {
            val encoded = StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(result));
            if (encoded.remaining() > maximumUtf8Bytes) {
                throw new IllegalArgumentException(name + " exceeds its UTF-8 size limit");
            }
        } catch (final CharacterCodingException e) {
            throw new IllegalArgumentException(name + " is not valid Unicode", e);
        }
        return result;
    }

    /** Closed-world ticket security classification. */
    public enum Classification {
        /** Capability authorized by an account generation. */
        ACCOUNT_CAPABILITY,
        /** Capability authorized by a client generation. */
        CLIENT_CAPABILITY,
        /** Durable state used before final capability issuance. */
        PREAUTH_STATE,
        /** Reviewed ticket state that conveys no authorization capability. */
        EXPLICIT_NON_CAPABILITY
    }

    /** Protocol family that owns the issuance operation. */
    public enum ProtocolFamily {
        /** CAS protocol. */
        CAS,
        /** OAuth 2 protocol. */
        OAUTH2,
        /** OpenID Connect protocol. */
        OPENID_CONNECT,
        /** SAML protocol. */
        SAML,
        /** Login webflow state. */
        LOGIN,
        /** Multifactor authentication state. */
        MFA,
        /** Explicitly registered custom protocol. */
        CUSTOM
    }

    /** Generation owner kind. */
    public enum GenerationOwnerType {
        /** Account subject generation. */
        SUBJECT,
        /** OAuth, OIDC, SAML, or custom client generation. */
        CLIENT,
        /** Anonymous state or deployment policy epoch. */
        STATE
    }

    /**
     * Exact generation authorization for a managed write.
     *
     * @param ownerType subject, client, or anonymous-state owner type
     * @param ownerId stable owner identifier
     * @param generation positive security generation
     */
    public record GenerationBinding(
        GenerationOwnerType ownerType,
        String ownerId,
        long generation) implements Serializable {

        @Serial
        private static final long serialVersionUID = 7708620478767530244L;

        public GenerationBinding {
            Objects.requireNonNull(ownerType, "ownerType");
            ownerId = requireText(ownerId, "ownerId", MAXIMUM_OWNER_ID_UTF8_BYTES);
            if (generation <= 0) {
                throw new IllegalArgumentException("Security generation must be positive");
            }
        }
    }

    /**
     * Exact relying-party coordinates for the artifact.
     *
     * @param relyingPartyId relying-party or audience identifier
     * @param clientId protocol client identifier
     */
    public record RelyingPartyBinding(
        @Nullable String relyingPartyId,
        @Nullable String clientId) implements Serializable {

        @Serial
        private static final long serialVersionUID = 6627547131656225512L;

        public RelyingPartyBinding {
            relyingPartyId = normalizeNullableText(
                relyingPartyId, "relyingPartyId", MAXIMUM_RELYING_PARTY_ID_UTF8_BYTES);
            clientId = normalizeNullableText(clientId, "clientId", MAXIMUM_OWNER_ID_UTF8_BYTES);
            if (relyingPartyId == null && clientId == null) {
                throw new IllegalArgumentException(
                    "A relying-party binding requires a relying party or client");
            }
        }
    }
}
