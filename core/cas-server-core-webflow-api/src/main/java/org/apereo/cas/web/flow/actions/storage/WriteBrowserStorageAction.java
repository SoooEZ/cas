package org.apereo.cas.web.flow.actions.storage;

import module java.base;
import org.apereo.cas.protocol.ProtocolFinalResponsePreparedDelivery;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.web.BrowserStorage;
import org.apereo.cas.web.DefaultBrowserStorage;
import org.apereo.cas.web.cookie.CasCookieBuilder;
import org.apereo.cas.web.flow.actions.CasProtocolFinalResponseDeliveryBuilder;
import org.apereo.cas.web.support.ProtocolFinalResponsePolicyEnforcer;
import org.apereo.cas.web.support.WebUtils;
import lombok.Setter;
import lombok.val;
import org.jspecify.annotations.Nullable;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * This is {@link WriteBrowserStorageAction}.
 *
 * @author Misagh Moayyed
 * @since 7.0.0
 */
@Setter
public class WriteBrowserStorageAction extends BaseBrowserStorageAction {
    public WriteBrowserStorageAction(final CasCookieBuilder ticketGrantingCookieBuilder) {
        super(ticketGrantingCookieBuilder);
    }

    @Override
    protected @Nullable Event doExecuteInternal(final RequestContext requestContext) {
        val eventAttributes = requestContext.getCurrentEvent()
            .getAttributes();
        val storageType = determineStorageType(requestContext);
        val preparedDelivery = eventAttributes.get(
            ProtocolFinalResponsePreparedDelivery.class.getName(),
            ProtocolFinalResponsePreparedDelivery.class);
        val ticketGrantingTicket = eventAttributes.get(
            TicketGrantingTicket.class.getName(), String.class);
        if (preparedDelivery == null
            && ProtocolFinalResponsePolicyEnforcer.isPolicyConfigured(
                requestContext.getActiveFlow().getApplicationContext())) {
            throw new IllegalStateException(
                "Browser-storage response is missing its authorized delivery");
        }
        val outputValue = preparedDelivery == null
            ? buildLegacyOutput(requestContext, ticketGrantingTicket)
            : decodeAuthorizedOutput(preparedDelivery, storageType);
        val payload = CollectionUtils.wrap(
            ticketGrantingCookieBuilder.getCookieName(),
            outputValue);
        val sessionStorage = DefaultBrowserStorage.builder()
            .context(browserStorageContextKey)
            .storageType(storageType)
            .build()
            .setPayloadJson(payload);
        WebUtils.putBrowserStorage(requestContext, sessionStorage);
        return success(sessionStorage);
    }

    private String buildLegacyOutput(
        final RequestContext requestContext,
        final @Nullable String ticketGrantingTicket) {
        if (ticketGrantingTicket == null) {
            throw new IllegalStateException(
                "Browser-storage response is missing its ticket");
        }
        val request = WebUtils
            .getHttpServletRequestFromExternalWebflowContext(requestContext);
        return ticketGrantingCookieBuilder
            .getCasCookieValueManager()
            .buildCookieValue(ticketGrantingTicket, request);
    }

    private String decodeAuthorizedOutput(
        final ProtocolFinalResponsePreparedDelivery preparedDelivery,
        final BrowserStorage.BrowserStorageTypes storageType) {
        val decoded = CasProtocolFinalResponseDeliveryBuilder
            .decodeStatelessBrowserStorage(preparedDelivery);
        if (!Objects.equals(
            ticketGrantingCookieBuilder.getCookieName(),
            decoded.cookieName())
            || decoded.storageType() != storageType
            || !Objects.equals(
                browserStorageContextKey,
                decoded.storageContext())) {
            throw new IllegalStateException(
                "Browser-storage response changed after final authorization");
        }
        return decoded.preparedValue().outputValue();
    }
}
