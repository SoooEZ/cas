package org.apereo.cas.web.flow.actions.storage;

import module java.base;
import org.apereo.cas.util.serialization.JacksonObjectMapperFactory;
import org.apereo.cas.web.BrowserStorage;
import org.apereo.cas.web.cookie.CasCookieBuilder;
import org.apereo.cas.web.flow.actions.BaseCasWebflowAction;
import org.apereo.cas.web.flow.actions.CasProtocolFinalResponseDeliveryBuilder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.webflow.execution.RequestContext;
import tools.jackson.databind.ObjectMapper;

/**
 * This is {@link BaseBrowserStorageAction}.
 *
 * @author Misagh Moayyed
 * @since 7.0.0
 */
@RequiredArgsConstructor
@Getter
@Setter
public abstract class BaseBrowserStorageAction extends BaseCasWebflowAction {
    protected static final ObjectMapper MAPPER = JacksonObjectMapperFactory.builder()
        .defaultTypingEnabled(false).minimal(true).build().toObjectMapper();

    protected final CasCookieBuilder ticketGrantingCookieBuilder;

    protected String browserStorageContextKey =
        CasProtocolFinalResponseDeliveryBuilder
            .DEFAULT_BROWSER_STORAGE_CONTEXT;

    protected BrowserStorage.BrowserStorageTypes determineStorageType(final RequestContext requestContext) {
        return CasProtocolFinalResponseDeliveryBuilder
            .browserStorageType(requestContext);
    }
}
