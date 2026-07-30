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

        val response = builder.build(service, serviceTicketId, auth);

        if (StringUtils.isNotBlank(serviceTicketId)) {
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
            val policyContext = ProtocolFinalResponseContext.of(
                ProtocolFinalResponseContext.Protocol.CAS,
                ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
                service != null ? service.getId() : null,
                subjectId,
                capability);
            ProtocolFinalResponsePolicyEnforcer.enforce(
                requestContext.getActiveFlow().getApplicationContext(), policyContext);
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
}
