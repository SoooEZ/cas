package org.apereo.cas.protocol;

import module java.base;
import lombok.val;

/**
 * Describes an opaque capability that is about to be disclosed by a protocol response.
 *
 * <p>The raw reference is deliberately excluded from {@link #toString()} so policy
 * diagnostics cannot accidentally write tickets or tokens to logs. Lifecycle
 * coordinates are optional and allow a deployment policy to correlate a capability
 * with an authoritative issuance intent without coupling this API to a persistence
 * implementation.</p>
 *
 * @author SoooEZ
 * @param type capability type
 * @param reference opaque value that will be disclosed
 * @param subjectId optional stable subject identifier
 * @param generation optional positive account-security generation
 * @param intentId optional durable issuance intent identifier
 * @since 8.0.0
 */
public record ProtocolFinalResponseCapability(
    Type type,
    String reference,
    String subjectId,
    Long generation,
    String intentId) implements Serializable {

    @Serial
    private static final long serialVersionUID = -6795883875684535012L;

    public ProtocolFinalResponseCapability {
        Objects.requireNonNull(type, "type");
        reference = requireText(reference, "reference");
        subjectId = requireOptionalText(subjectId, "subjectId");
        intentId = requireOptionalText(intentId, "intentId");
        if (generation != null && generation <= 0) {
            throw new IllegalArgumentException("generation must be positive");
        }
        val lifecycleCoordinates = Stream.of(subjectId, generation, intentId)
            .filter(Objects::nonNull)
            .count();
        if (lifecycleCoordinates != 0 && lifecycleCoordinates != 3) {
            throw new IllegalArgumentException(
                "Lifecycle coordinates must be either all present or all absent");
        }
    }

    /**
     * Create an unmanaged capability reference.
     *
     * @param type capability type
     * @param reference opaque reference
     * @return capability reference
     */
    public static ProtocolFinalResponseCapability of(final Type type, final String reference) {
        return new ProtocolFinalResponseCapability(type, reference, null, null, null);
    }

    /**
     * Create a capability reference carrying explicit lifecycle coordinates.
     *
     * @param type capability type
     * @param reference opaque reference
     * @param subjectId stable subject identifier
     * @param generation security generation
     * @param intentId durable issuance intent identifier
     * @return managed capability reference
     */
    public static ProtocolFinalResponseCapability managed(final Type type,
                                                          final String reference,
                                                          final String subjectId,
                                                          final long generation,
                                                          final String intentId) {
        return new ProtocolFinalResponseCapability(type, reference, subjectId, generation, intentId);
    }

    /**
     * Whether this reference carries complete lifecycle coordinates.
     *
     * @return true when lifecycle coordinates are complete
     */
    public boolean isLifecycleManaged() {
        return subjectId != null && generation != null && intentId != null;
    }

    @Override
    public String toString() {
        return "ProtocolFinalResponseCapability[type=%s, reference=[REDACTED], lifecycleManaged=%s]"
            .formatted(type, isLifecycleManaged());
    }

    private static String requireText(final String value, final String name) {
        val result = Objects.requireNonNull(value, name).trim();
        if (result.isEmpty()) {
            throw new IllegalArgumentException(name + " cannot be blank");
        }
        return result;
    }

    private static String requireOptionalText(final String value, final String name) {
        return value == null ? null : requireText(value, name);
    }

    /** Type of capability disclosed by the response. */
    public enum Type {
        /** CAS service ticket, including a tokenized service ticket. */
        CAS_SERVICE_TICKET,
        /** CAS ticket-granting ticket, including a tokenized ticket. */
        CAS_TICKET_GRANTING_TICKET,
        /** CAS proxy ticket. */
        CAS_PROXY_TICKET,
        /** CAS proxy-granting ticket. */
        CAS_PROXY_GRANTING_TICKET,
        /** CAS proxy-granting ticket IOU. */
        CAS_PROXY_GRANTING_TICKET_IOU,
        /** CAS validation assertion. */
        CAS_VALIDATION_ASSERTION,
        /** OAuth authorization code. */
        OAUTH_AUTHORIZATION_CODE,
        /** OAuth access token. */
        OAUTH_ACCESS_TOKEN,
        /** OAuth refresh token. */
        OAUTH_REFRESH_TOKEN,
        /** OAuth device code. */
        OAUTH_DEVICE_CODE,
        /** OAuth device user code. */
        OAUTH_DEVICE_USER_CODE,
        /** OpenID Connect ID token. */
        OIDC_ID_TOKEN,
        /** OpenID Connect device secret. */
        OIDC_DEVICE_SECRET,
        /** OpenID Connect CIBA authentication request identifier. */
        OIDC_CIBA_AUTHENTICATION_REQUEST_ID,
        /** OpenID Connect pushed authorization request URI. */
        OIDC_PUSHED_AUTHORIZATION_REQUEST_URI,
        /** SAML 1 artifact. */
        SAML1_ARTIFACT,
        /** SAML 2 assertion. */
        SAML2_ASSERTION,
        /** SAML 2 response. */
        SAML2_RESPONSE
    }
}
