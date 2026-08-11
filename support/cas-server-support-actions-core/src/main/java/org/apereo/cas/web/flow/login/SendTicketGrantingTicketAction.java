package org.apereo.cas.web.flow.login;

import module java.base;
import org.apereo.cas.configuration.support.TriStateBoolean;
import org.apereo.cas.monitor.Monitorable;
import org.apereo.cas.protocol.ProtocolFinalResponseCapability;
import org.apereo.cas.protocol.ProtocolFinalResponseContext;
import org.apereo.cas.protocol.ProtocolFinalResponsePreparedDelivery;
import org.apereo.cas.support.events.sso.CasSingleSignOnSessionCreatedEvent;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.ticket.registry.TicketIssuanceMetadata;
import org.apereo.cas.ticket.registry.TicketIssuanceReadContext;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.web.cookie.CasCookieBuilder;
import org.apereo.cas.web.cookie.CookieValueManager;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.flow.SingleSignOnParticipationRequest;
import org.apereo.cas.web.flow.SingleSignOnParticipationStrategy;
import org.apereo.cas.web.flow.actions.BaseCasWebflowAction;
import org.apereo.cas.web.flow.actions.CasProtocolFinalResponseDeliveryBuilder;
import org.apereo.cas.web.support.ProtocolFinalResponsePolicyEnforcer;
import org.apereo.cas.web.support.WebUtils;
import org.apereo.cas.web.support.gen.CookieRetrievingCookieGenerator;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apereo.inspektr.common.web.ClientInfoHolder;
import org.jspecify.annotations.Nullable;
import org.springframework.context.ApplicationContext;
import org.springframework.webflow.core.collection.LocalAttributeMap;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * Action that handles the TicketGrantingTicket creation and destruction. If the
 * action is given a TicketGrantingTicket and one also already exists, the old
 * one is destroyed and replaced with the new one. This action always returns
 * "success".
 *
 * @author Scott Battaglia
 * @since 3.0.0
 */
@Slf4j
@RequiredArgsConstructor
@Monitorable
@Getter
public class SendTicketGrantingTicketAction extends BaseCasWebflowAction {
    private final TicketRegistry ticketRegistry;

    private final CasCookieBuilder ticketGrantingCookieBuilder;

    private final SingleSignOnParticipationStrategy singleSignOnParticipationStrategy;

    @Override
    protected @Nullable Event doExecuteInternal(final RequestContext context) throws Throwable {
        val ticketGrantingTicketId = WebUtils.getTicketGrantingTicketId(context);
        val ticketGrantingTicketValueFromCookie = WebUtils.getTicketGrantingTicketIdFrom(context.getFlowScope());

        if (StringUtils.isBlank(ticketGrantingTicketId)) {
            LOGGER.debug("No ticket-granting ticket is found in the context.");
            return success();
        }

        var finalEvent = success();
        val ssoRequest = SingleSignOnParticipationRequest.builder()
            .requestContext(context)
            .build();
        if (WebUtils.isAuthenticatingAtPublicWorkstation(context)) {
            LOGGER.info("Authentication is at a public workstation. SSO cookie will not be generated");
        } else if (singleSignOnParticipationStrategy.supports(ssoRequest)) {
            val createCookie = shouldCreateSingleSignOnCookie(ssoRequest, ticketGrantingTicketId);
            if (createCookie) {
                LOGGER.debug("Setting ticket-granting cookie for current session linked to [REDACTED].");
                finalEvent = createSingleSignOnCookie(context, ticketGrantingTicketId);
            } else {
                LOGGER.info("Authentication session is renewed but CAS is not configured to create the SSO session. "
                    + "SSO cookie will not be generated. Subsequent requests will be challenged for credentials.");
            }
        }

        if (ticketGrantingTicketValueFromCookie != null && !ticketGrantingTicketId.equals(ticketGrantingTicketValueFromCookie)) {
            LOGGER.debug("Ticket-granting ticket from ticket-granting cookie does not match the ticket-granting ticket from context");
            ticketRegistry.deleteTicket(ticketGrantingTicketValueFromCookie);
        }
        return finalEvent;
    }

    protected boolean shouldCreateSingleSignOnCookie(final SingleSignOnParticipationRequest ssoRequest,
                                                     final String ticketGrantingTicketId) throws Throwable {
        return singleSignOnParticipationStrategy.isCreateCookieOnRenewedAuthentication(ssoRequest) == TriStateBoolean.TRUE
            || singleSignOnParticipationStrategy.isParticipating(ssoRequest);
    }

    protected Event createSingleSignOnCookie(final RequestContext requestContext, final String ticketGrantingTicketId) {
        val issuanceMetadata = WebUtils.getTicketGrantingTicketIssuanceMetadata(requestContext);
        val ticketGrantingTicket = issuanceMetadata
            .map(metadata -> ticketRegistry.getTicket(ticketGrantingTicketId,
                TicketGrantingTicket.class,
                TicketIssuanceReadContext.forIntent(metadata.intentId())))
            .orElseGet(() -> ticketRegistry.getTicket(
                ticketGrantingTicketId, TicketGrantingTicket.class));
        issuanceMetadata.ifPresent(expected -> {
            val actual = TicketIssuanceMetadata.from(ticketGrantingTicket).orElseThrow(() ->
                new IllegalStateException(
                    "Managed ticket-granting ticket lost its issuance metadata"));
            if (!expected.equals(actual)) {
                throw new IllegalStateException(
                    "Ticket-granting ticket issuance metadata changed before final response");
            }
        });
        val subjectId = issuanceMetadata
            .map(metadata -> metadata.subjectId())
            .orElseGet(() -> ticketGrantingTicket.getAuthentication().getPrincipal().getId());
        val capability = issuanceMetadata
            .map(metadata -> ProtocolFinalResponseCapability.managed(
                ProtocolFinalResponseCapability.Type.CAS_TICKET_GRANTING_TICKET,
                ticketGrantingTicketId, metadata.subjectId(), metadata.generation(),
                metadata.intentId()))
            .orElseGet(() -> ProtocolFinalResponseCapability.of(
                ProtocolFinalResponseCapability.Type.CAS_TICKET_GRANTING_TICKET,
                ticketGrantingTicketId));
        val stateless = ticketGrantingTicket.isStateless();
        val rememberMeAuthentication = stateless
            ? Boolean.FALSE
            : CookieRetrievingCookieGenerator.isRememberMeAuthentication(
                requestContext);
        val storageType = stateless
            ? CasProtocolFinalResponseDeliveryBuilder
                .browserStorageType(requestContext)
            : null;
        val request = WebUtils
            .getHttpServletRequestFromExternalWebflowContext(requestContext);
        val response = WebUtils
            .getHttpServletResponseFromExternalWebflowContext(requestContext);
        val applicationContext = requestContext.getActiveFlow()
            .getApplicationContext();
        if (!ProtocolFinalResponsePolicyEnforcer.isPolicyConfigured(
            applicationContext)) {
            if (stateless) {
                return result(
                    CasWebflowConstants.TRANSITION_ID_WRITE_BROWSER_STORAGE,
                    new LocalAttributeMap<>(
                        TicketGrantingTicket.class.getName(),
                        ticketGrantingTicketId));
            }
            ticketGrantingCookieBuilder.addCookie(
                request,
                response,
                rememberMeAuthentication,
                ticketGrantingTicketId);
            publishSingleSignOnSessionCreatedEvent(
                applicationContext, ticketGrantingTicket);
            return success();
        }
        if (!stateless
            && !ticketGrantingCookieBuilder
                .supportsPreparedFinalResponse()) {
            throw new IllegalStateException(
                "The configured ticket-granting cookie builder does not support authoritative prepared final responses");
        }
        final CookieValueManager.PreparedCookieValue preparedCookieValue;
        final CasCookieBuilder.PreparedCookie preparedCookie;
        if (stateless) {
            preparedCookieValue = ticketGrantingCookieBuilder
                .getCasCookieValueManager()
                .prepareCookieValue(ticketGrantingTicketId, request);
            preparedCookie = null;
        } else {
            preparedCookieValue = null;
            preparedCookie = ticketGrantingCookieBuilder.prepareCookie(
                request,
                response,
                rememberMeAuthentication,
                ticketGrantingTicketId);
        }
        val logicalContext = ProtocolFinalResponseContext.of(
            ProtocolFinalResponseContext.Protocol.CAS,
            ProtocolFinalResponseContext.ResponseType.CAS_BROWSER_SSO_SESSION,
            null, subjectId, capability);
        val logicalResponseBinding = logicalContext
            .logicalResponseBinding();
        val preparedDelivery = stateless
            ? CasProtocolFinalResponseDeliveryBuilder
                .prepareStatelessBrowserStorage(
                    ticketGrantingCookieBuilder,
                    preparedCookieValue,
                    storageType,
                    CasProtocolFinalResponseDeliveryBuilder
                        .DEFAULT_BROWSER_STORAGE_CONTEXT,
                    logicalResponseBinding)
            : CasProtocolFinalResponseDeliveryBuilder.prepareHttpCookie(
                preparedCookie, logicalResponseBinding);
        val policyContext = logicalContext.withPreparedDelivery(
            preparedDelivery);
        val authorization = ProtocolFinalResponsePolicyEnforcer.authorize(
            applicationContext, policyContext);
        val authorizedDelivery = authorization.preparedDelivery();
        if (stateless) {
            val eventAttributes = new LocalAttributeMap<>();
            eventAttributes.put(
                TicketGrantingTicket.class.getName(), ticketGrantingTicketId);
            eventAttributes.put(
                ProtocolFinalResponsePreparedDelivery.class.getName(),
                authorizedDelivery);
            return result(CasWebflowConstants.TRANSITION_ID_WRITE_BROWSER_STORAGE,
                eventAttributes);
        }
        ticketGrantingCookieBuilder.addCookie(
            response,
            CasProtocolFinalResponseDeliveryBuilder.decodeHttpCookie(
                authorizedDelivery));
        publishSingleSignOnSessionCreatedEvent(
            applicationContext, ticketGrantingTicket);
        return success();
    }

    private void publishSingleSignOnSessionCreatedEvent(
        final ApplicationContext applicationContext,
        final TicketGrantingTicket ticketGrantingTicket) {
        val clientInfo = ClientInfoHolder.getClientInfo();
        applicationContext.publishEvent(new CasSingleSignOnSessionCreatedEvent(this, ticketGrantingTicket, clientInfo));
    }
}
