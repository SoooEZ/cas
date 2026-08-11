package org.apereo.cas.web.flow.actions;

import module java.base;
import org.apereo.cas.authentication.principal.Response;
import org.apereo.cas.authentication.principal.ResponseBuilderLocator;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.protocol.ProtocolFinalResponseCapability;
import org.apereo.cas.protocol.ProtocolFinalResponseContext;
import org.apereo.cas.web.support.ProtocolFinalResponsePolicyEnforcer;
import org.apereo.cas.web.support.WebUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.jspecify.annotations.Nullable;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * This is {@link RedirectToServiceAction}.
 *
 * @author Misagh Moayyed
 * @since 5.1.0
 */
@Slf4j
@RequiredArgsConstructor
public class RedirectToServiceAction extends BaseCasWebflowAction {
    private final ResponseBuilderLocator<WebApplicationService> responseBuilderLocator;

    @Override
    protected @Nullable Event doExecuteInternal(final RequestContext requestContext) {
        val service = WebUtils.getService(requestContext);
        LOGGER.debug("Located service [{}] from the context", service);

        val auth = WebUtils.getAuthentication(requestContext);
        LOGGER.debug("Located authentication in the context: [{}]", auth != null);

        val serviceTicketId = WebUtils.getServiceTicketFromRequestScope(requestContext);
        LOGGER.debug("Located service ticket [{}] from the context",
            StringUtils.isBlank(serviceTicketId) ? null : "[REDACTED]");

        val builder = responseBuilderLocator.locate(service);
        LOGGER.debug("Located service response builder [{}] for [{}]", builder, service);

        val builtResponse = builder.build(service, serviceTicketId, auth);
        var response = builtResponse;

        if (StringUtils.isNotBlank(serviceTicketId)) {
            val applicationContext = requestContext.getActiveFlow()
                .getApplicationContext();
            if (!ProtocolFinalResponsePolicyEnforcer.isPolicyConfigured(
                applicationContext)) {
                LOGGER.debug("No authoritative final-response policy is configured; retaining the upstream service response path");
                return finalizeResponseEvent(
                    requestContext, service, response);
            }
            val issuanceMetadata = WebUtils.getServiceTicketIssuanceMetadata(requestContext);
            val subjectId = issuanceMetadata
                .map(metadata -> metadata.subjectId())
                .orElseGet(() -> Optional.ofNullable(auth)
                    .map(authentication -> authentication.getPrincipal().getId())
                    .orElse(null));
            val capability = issuanceMetadata
                .map(metadata -> ProtocolFinalResponseCapability.managed(
                    ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET,
                    serviceTicketId, metadata.subjectId(), metadata.generation(),
                    metadata.intentId()))
                .orElseGet(() -> ProtocolFinalResponseCapability.of(
                    ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET,
                    serviceTicketId));
            val logicalContext = ProtocolFinalResponseContext.of(
                ProtocolFinalResponseContext.Protocol.CAS,
                ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
                service != null ? service.getId() : null,
                subjectId,
                capability);
            val preparedResponse = CasProtocolFinalResponseDeliveryBuilder
                .prepareServiceResponse(
                    response,
                    logicalContext.logicalResponseBinding());
            val policyContext = logicalContext.withPreparedDelivery(
                preparedResponse);
            val authorization = ProtocolFinalResponsePolicyEnforcer.authorize(
                applicationContext, policyContext);
            response = CasProtocolFinalResponseDeliveryBuilder
                .decodeServiceResponse(authorization.preparedDelivery());
        }
        LOGGER.debug("Built response of type [{}] for [{}]",
            response != null ? response.responseType() : null, service);

        return finalizeResponseEvent(requestContext, service, response);
    }

    protected Event finalizeResponseEvent(final RequestContext requestContext, final WebApplicationService service, final Response response) {
        WebUtils.putServiceResponseIntoRequestScope(requestContext, response);
        WebUtils.putServiceOriginalUrlIntoRequestScope(requestContext, service);
        val eventId = getFinalResponseEventId(service, response, requestContext);
        return eventFactory.event(this, eventId);
    }

    protected String getFinalResponseEventId(final WebApplicationService service, final Response response, final RequestContext requestContext) {
        val eventId = response.responseType().name().toLowerCase(Locale.ENGLISH);
        LOGGER.debug("Signaling flow to redirect to service [{}] via event [{}]", service, eventId);
        return eventId;
    }

    /**
     * Immutable snapshot of the exact service response committed by policy.
     * Raw response fields remain available to the renderer but are redacted
     * from diagnostics.
     *
     * @author SoooEZ
     * @param responseType exact delivery type
     * @param url exact final target URL
     * @param attributes exact response attributes
     * @since 8.0.0
     */
    public record ImmutableFinalResponse(
        Response.ResponseType responseType,
        String url,
        Map<String, String> attributes) implements Response {

        @Serial
        private static final long serialVersionUID = 4670938835790091330L;

        public ImmutableFinalResponse {
            Objects.requireNonNull(responseType, "responseType");
            Objects.requireNonNull(url, "url");
            val source = Objects.requireNonNull(attributes, "attributes");
            val emittedAttributes = new LinkedHashMap<String, String>();
            source.forEach((name, value) -> {
                if (responseType == Response.ResponseType.REDIRECT
                    && value == null) {
                    return;
                }
                val attributeName = Objects.requireNonNull(
                    name, "response attribute name");
                emittedAttributes.put(attributeName, value);
            });
            attributes = emittedAttributes;
        }

        @Override
        public Map<String, String> attributes() {
            return new LinkedHashMap<>(attributes);
        }

        @Override
        public String toString() {
            return "ImmutableFinalResponse[responseType=%s, response=[REDACTED]]"
                .formatted(responseType);
        }
    }
}
