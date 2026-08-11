package org.apereo.cas.protocol;

import module java.base;
import lombok.val;

/**
 * Explicit context supplied immediately before a protocol response discloses
 * one or more newly issued capabilities.
 *
 * <p>The context is immutable and request scoped by construction. It must be
 * passed through the call graph and must not be reconstructed from a thread-local
 * security authority.</p>
 *
 * @author SoooEZ
 * @param protocol protocol family
 * @param responseType final response type
 * @param relyingPartyId optional relying-party identifier
 * @param subjectId optional stable subject identifier
 * @param capabilities capabilities about to be disclosed
 * @param delivery optional exact final-response delivery identity; legacy
 * callers may omit it, while authoritative commit policies should fail closed
 * when it is absent
 * @param preparedDelivery optional exact replay envelope; authoritative native
 * CAS producers provide it so a durable policy can recover across processes
 * @since 8.0.0
 */
public record ProtocolFinalResponseContext(
    Protocol protocol,
    ResponseType responseType,
    String relyingPartyId,
    String subjectId,
    List<ProtocolFinalResponseCapability> capabilities,
    ProtocolFinalResponseDelivery delivery,
    ProtocolFinalResponsePreparedDelivery preparedDelivery)
    implements Serializable {

    @Serial
    private static final long serialVersionUID = 1655956071120769269L;

    public ProtocolFinalResponseContext {
        Objects.requireNonNull(protocol, "protocol");
        Objects.requireNonNull(responseType, "responseType");
        relyingPartyId = normalize(relyingPartyId);
        subjectId = normalize(subjectId);
        capabilities = List.copyOf(Objects.requireNonNull(capabilities, "capabilities"));
        if (capabilities.isEmpty()) {
            throw new IllegalArgumentException("capabilities cannot be empty");
        }
        if (capabilities.stream().anyMatch(Objects::isNull)) {
            throw new IllegalArgumentException("capabilities cannot contain null entries");
        }
        val responseSubjectId = subjectId;
        val managedCapabilities = capabilities.stream()
            .filter(ProtocolFinalResponseCapability::isLifecycleManaged)
            .toList();
        if (!managedCapabilities.isEmpty() && responseSubjectId == null) {
            throw new IllegalArgumentException(
                "A managed capability requires an explicit response subject");
        }
        if (managedCapabilities.stream()
            .anyMatch(capability -> !responseSubjectId.equals(capability.subjectId()))) {
            throw new IllegalArgumentException(
                "Managed capability subject must match the response subject");
        }
        if (preparedDelivery != null) {
            if (delivery == null
                || !preparedDelivery.delivery().equals(delivery)) {
                throw new IllegalArgumentException(
                    "Prepared delivery must match the exact delivery identity");
            }
            val binding = ProtocolFinalResponseLogicalBinding.of(
                protocol,
                responseType,
                relyingPartyId,
                subjectId,
                capabilities);
            if (!binding.equals(
                preparedDelivery.logicalResponseBinding())) {
                throw new IllegalArgumentException(
                    "Prepared delivery must match the logical response binding");
            }
        }
    }

    /**
     * Backwards-compatible constructor for callers that have not migrated to
     * exact delivery binding.
     *
     * @param protocol protocol family
     * @param responseType response type
     * @param relyingPartyId relying-party identifier
     * @param subjectId subject identifier
     * @param capabilities capabilities about to be disclosed
     */
    public ProtocolFinalResponseContext(
        final Protocol protocol,
        final ResponseType responseType,
        final String relyingPartyId,
        final String subjectId,
        final List<ProtocolFinalResponseCapability> capabilities) {
        this(protocol, responseType, relyingPartyId, subjectId,
            capabilities, null, null);
    }

    /**
     * Backwards-compatible constructor for callers that bind a delivery digest
     * but do not yet provide durable replay bytes.
     */
    public ProtocolFinalResponseContext(
        final Protocol protocol,
        final ResponseType responseType,
        final String relyingPartyId,
        final String subjectId,
        final List<ProtocolFinalResponseCapability> capabilities,
        final ProtocolFinalResponseDelivery delivery) {
        this(protocol, responseType, relyingPartyId, subjectId,
            capabilities, delivery, null);
    }

    /**
     * Create a context containing one capability.
     *
     * @param protocol protocol family
     * @param responseType response type
     * @param relyingPartyId relying-party identifier
     * @param subjectId subject identifier
     * @param capability capability about to be disclosed
     * @return immutable policy context
     */
    public static ProtocolFinalResponseContext of(final Protocol protocol,
                                                  final ResponseType responseType,
                                                  final String relyingPartyId,
                                                  final String subjectId,
                                                  final ProtocolFinalResponseCapability capability) {
        return new ProtocolFinalResponseContext(
            protocol, responseType, relyingPartyId, subjectId,
            List.of(capability), null, null);
    }

    /**
     * Create a context containing one capability and its exact delivery.
     *
     * @param protocol protocol family
     * @param responseType response type
     * @param relyingPartyId relying-party identifier
     * @param subjectId subject identifier
     * @param capability capability about to be disclosed
     * @param delivery exact final-response delivery identity
     * @return immutable policy context
     */
    public static ProtocolFinalResponseContext of(
        final Protocol protocol,
        final ResponseType responseType,
        final String relyingPartyId,
        final String subjectId,
        final ProtocolFinalResponseCapability capability,
        final ProtocolFinalResponseDelivery delivery) {
        return new ProtocolFinalResponseContext(
            protocol, responseType, relyingPartyId, subjectId,
            List.of(capability), Objects.requireNonNull(delivery, "delivery"),
            null);
    }

    /** Create a context containing one capability and replayable exact output. */
    public static ProtocolFinalResponseContext of(
        final Protocol protocol,
        final ResponseType responseType,
        final String relyingPartyId,
        final String subjectId,
        final ProtocolFinalResponseCapability capability,
        final ProtocolFinalResponsePreparedDelivery preparedDelivery) {
        val prepared = Objects.requireNonNull(
            preparedDelivery, "preparedDelivery");
        return new ProtocolFinalResponseContext(
            protocol, responseType, relyingPartyId, subjectId,
            List.of(capability), prepared.delivery(), prepared);
    }

    /** Stable binding shared by current output and any durable replay. */
    public ProtocolFinalResponseLogicalBinding logicalResponseBinding() {
        return ProtocolFinalResponseLogicalBinding.of(
            protocol,
            responseType,
            relyingPartyId,
            subjectId,
            capabilities);
    }

    /** Attach exact prepared output to this unchanged logical response. */
    public ProtocolFinalResponseContext withPreparedDelivery(
        final ProtocolFinalResponsePreparedDelivery preparedDelivery) {
        val prepared = Objects.requireNonNull(
            preparedDelivery, "preparedDelivery");
        return new ProtocolFinalResponseContext(
            protocol,
            responseType,
            relyingPartyId,
            subjectId,
            capabilities,
            prepared.delivery(),
            prepared);
    }

    @Override
    public String toString() {
        return ("ProtocolFinalResponseContext[protocol=%s, responseType=%s, relyingPartyId=%s, "
               + "subjectId=%s, capabilities=%s, delivery=%s, "
               + "preparedDelivery=[REDACTED]]")
            .formatted(protocol, responseType, relyingPartyId,
                subjectId == null ? null : "[REDACTED]", capabilities, delivery);
    }

    private static String normalize(final String value) {
        if (value == null) {
            return null;
        }
        val result = value.trim();
        return result.isEmpty() ? null : result;
    }

    /** Protocol family producing the response. */
    public enum Protocol {
        /** CAS protocol. */
        CAS,
        /** OAuth 2 protocol. */
        OAUTH2,
        /** OpenID Connect protocol. */
        OPENID_CONNECT,
        /** SAML 1 protocol. */
        SAML1,
        /** SAML 2 protocol. */
        SAML2
    }

    /** Final response boundary being guarded. */
    public enum ResponseType {
        /** Browser-facing CAS service response. */
        CAS_SERVICE_RESPONSE,
        /** Browser-facing CAS single sign-on session cookie or storage response. */
        CAS_BROWSER_SSO_SESSION,
        /** CAS validation assertion response. */
        CAS_VALIDATION_RESPONSE,
        /** CAS proxy callback. */
        CAS_PROXY_CALLBACK,
        /** CAS REST ticket response. */
        CAS_REST_TICKET_RESPONSE,
        /** OAuth/OIDC authorization endpoint response. */
        AUTHORIZATION_RESPONSE,
        /** OAuth/OIDC token endpoint response. */
        TOKEN_RESPONSE,
        /** OAuth device authorization response. */
        DEVICE_AUTHORIZATION_RESPONSE,
        /** OpenID Connect CIBA response. */
        CIBA_AUTHENTICATION_RESPONSE,
        /** SAML assertion or protocol response. */
        SAML_ASSERTION_RESPONSE,
        /** SAML artifact-binding response. */
        SAML_ARTIFACT_RESPONSE,
        /** SAML SOAP response. */
        SAML_SOAP_RESPONSE
    }
}
