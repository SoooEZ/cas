package org.apereo.cas.web.flow.actions;

import module java.base;
import org.apereo.cas.authentication.CoreAuthenticationTestUtils;
import org.apereo.cas.authentication.principal.Response;
import org.apereo.cas.authentication.principal.ResponseBuilderLocator;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.authentication.principal.WebApplicationServiceResponseBuilder;
import org.apereo.cas.protocol.ProtocolFinalResponseDecision;
import org.apereo.cas.protocol.ProtocolFinalResponseDeniedException;
import org.apereo.cas.protocol.ProtocolFinalResponsePolicy;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.ticket.PropertiesAwareTicket;
import org.apereo.cas.ticket.registry.TicketIssuanceMetadata;
import org.apereo.cas.util.MockRequestContext;
import org.apereo.cas.web.UrlValidator;
import org.apereo.cas.web.flow.BaseWebflowConfigurerTests;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.support.WebUtils;
import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.support.GenericApplicationContext;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * This is {@link RedirectToServiceActionTests}.
 *
 * @author Misagh Moayyed
 * @since 5.3.0
 */
@Tag("WebflowServiceActions")
class RedirectToServiceActionTests extends BaseWebflowConfigurerTests {
    @Autowired
    @Qualifier(ServicesManager.BEAN_NAME)
    private ServicesManager servicesManager;

    @Autowired
    @Qualifier(UrlValidator.BEAN_NAME)
    private UrlValidator urlValidator;

    @Test
    void verifyAction() throws Throwable {
        val context = MockRequestContext.create(applicationContext);

        WebUtils.putAuthentication(CoreAuthenticationTestUtils.getAuthentication(), context);
        WebUtils.putServiceIntoFlowScope(context, CoreAuthenticationTestUtils.getWebApplicationService());

        val locator = mock(ResponseBuilderLocator.class);
        when(locator.locate(any(WebApplicationService.class)))
            .thenReturn(new WebApplicationServiceResponseBuilder(this.servicesManager, this.urlValidator));

        val redirectToServiceAction = new RedirectToServiceAction(locator);
        val event = redirectToServiceAction.execute(context);
        assertEquals(CasWebflowConstants.TRANSITION_ID_REDIRECT, event.getId());
    }

    @Test
    void verifyFinalResponsePolicyDenialStopsServiceTicketDisclosure() throws Throwable {
        try (val policyApplicationContext = new GenericApplicationContext()) {
            policyApplicationContext.registerBean(ProtocolFinalResponsePolicy.BEAN_NAME,
                ProtocolFinalResponsePolicy.class,
                () -> policyContext -> {
                    val capability = policyContext.capabilities().getFirst();
                    assertTrue(capability.isLifecycleManaged());
                    assertEquals("subject-123", capability.subjectId());
                    assertEquals(3L, capability.generation());
                    assertEquals("intent-123", capability.intentId());
                    return ProtocolFinalResponseDecision.deny("generation_closed");
                });
            policyApplicationContext.refresh();
            val context = MockRequestContext.create(policyApplicationContext);
            WebUtils.putAuthentication(CoreAuthenticationTestUtils.getAuthentication(), context);
            val service = CoreAuthenticationTestUtils.getWebApplicationService();
            WebUtils.putServiceIntoFlowScope(context, service);
            val ticket = mock(PropertiesAwareTicket.class);
            when(ticket.getId()).thenReturn("ST-policy-denied");
            when(ticket.getProperties()).thenReturn(Map.of(
                TicketIssuanceMetadata.PROPERTY_SUBJECT_ID, "subject-123",
                TicketIssuanceMetadata.PROPERTY_GENERATION, 3L,
                TicketIssuanceMetadata.PROPERTY_INTENT_ID, "intent-123"));
            WebUtils.putServiceTicketInRequestScope(context, ticket);

            val locator = mock(ResponseBuilderLocator.class);
            val builder = mock(WebApplicationServiceResponseBuilder.class);
            when(locator.locate(any(WebApplicationService.class))).thenReturn(builder);
            when(builder.build(eq(service), eq("ST-policy-denied"), any()))
                .thenReturn(mock(Response.class));

            val action = new RedirectToServiceAction(locator);
            val denied = assertThrows(ProtocolFinalResponseDeniedException.class,
                () -> action.execute(context));
            assertEquals("generation_closed", denied.getDecision().reasonCode());
            assertFalse(context.getRequestScope().contains("serviceResponse"));
        }
    }
}
