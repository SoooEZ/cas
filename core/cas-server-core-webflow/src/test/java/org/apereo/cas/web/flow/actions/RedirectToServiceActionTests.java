package org.apereo.cas.web.flow.actions;

import module java.base;
import org.apereo.cas.authentication.CoreAuthenticationTestUtils;
import org.apereo.cas.authentication.principal.Response;
import org.apereo.cas.authentication.principal.ResponseBuilderLocator;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.authentication.principal.WebApplicationServiceResponseBuilder;
import org.apereo.cas.protocol.ProtocolFinalResponseAuthorization;
import org.apereo.cas.protocol.ProtocolFinalResponseCapability;
import org.apereo.cas.protocol.ProtocolFinalResponseContext;
import org.apereo.cas.protocol.ProtocolFinalResponseDecision;
import org.apereo.cas.protocol.ProtocolFinalResponseDelivery;
import org.apereo.cas.protocol.ProtocolFinalResponseDeniedException;
import org.apereo.cas.protocol.ProtocolFinalResponseLogicalBinding;
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
    private static final ProtocolFinalResponseLogicalBinding TEST_BINDING =
        new ProtocolFinalResponseLogicalBinding("a".repeat(64));

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
    void verifyRedirectSnapshotOmitsParametersNotEmittedInFinalUrl() {
        val attributes = new LinkedHashMap<String, String>();
        attributes.put("ticket", "ST-exact");
        attributes.put("optional", null);
        val response = new RedirectToServiceAction.ImmutableFinalResponse(
            Response.ResponseType.REDIRECT,
            "https://service.example/login?ticket=ST-exact",
            attributes);

        assertEquals(List.of("ticket"),
            new ArrayList<>(response.attributes().keySet()));
        assertEquals("ST-exact", response.attributes().get("ticket"));
        assertFalse(response.attributes().containsKey("optional"));
        assertEquals(
            ProtocolFinalResponseDelivery.canonicalOrdered(
                ProtocolFinalResponseDelivery.Mode.REDIRECT,
                response.url(),
                Map.of("ticket", "ST-exact")),
            CasProtocolFinalResponseDeliveryBuilder.serviceResponse(response));
        response.attributes().put("late", "change");
        assertFalse(response.attributes().containsKey("late"));
    }

    @Test
    void verifyPostAndHeaderSnapshotsPreserveRendererOrder() {
        for (val responseType : List.of(
            Response.ResponseType.POST,
            Response.ResponseType.HEADER)) {
            val attributes = new LinkedHashMap<String, String>();
            attributes.put("first", "one");
            attributes.put("second", null);
            attributes.put("third", "three");
            val response = new RedirectToServiceAction.ImmutableFinalResponse(
                responseType, "https://service.example/login", attributes);

            attributes.put("late", "change");
            assertEquals(List.of("first", "second", "third"),
                new ArrayList<>(response.attributes().keySet()));
            assertEquals(Arrays.asList("one", null, "three"),
                new ArrayList<>(response.attributes().values()));
            assertFalse(response.attributes().containsKey("late"));
            response.attributes().put("fourth", "four");
            assertFalse(response.attributes().containsKey("fourth"));
            assertDoesNotThrow(() ->
                CasProtocolFinalResponseDeliveryBuilder
                    .serviceResponse(response));
            val prepared = CasProtocolFinalResponseDeliveryBuilder
                .prepareServiceResponse(response, TEST_BINDING);
            val decoded = CasProtocolFinalResponseDeliveryBuilder
                .decodeServiceResponse(prepared);
            assertEquals(response.responseType(), decoded.responseType());
            assertEquals(response.url(), decoded.url());
            assertEquals(
                new ArrayList<>(response.attributes().entrySet()),
                new ArrayList<>(decoded.attributes().entrySet()));
        }
    }

    @Test
    void verifyDurableReplaySelectsPreviouslyCommittedExactResponse()
        throws Throwable {
        val service = CoreAuthenticationTestUtils.getWebApplicationService();
        val serviceId = service.getId();
        val replayAttributes = new LinkedHashMap<String, String>();
        replayAttributes.put("ticket", "ST-durable-replay");
        replayAttributes.put("opaque", "first-process-output");
        val replay = CasProtocolFinalResponseDeliveryBuilder
            .prepareServiceResponse(
                new RedirectToServiceAction.ImmutableFinalResponse(
                    Response.ResponseType.POST,
                    serviceId,
                    replayAttributes),
                ProtocolFinalResponseLogicalBinding.of(
                    ProtocolFinalResponseContext.Protocol.CAS,
                    ProtocolFinalResponseContext.ResponseType
                        .CAS_SERVICE_RESPONSE,
                    serviceId,
                    "subject-123",
                    List.of(ProtocolFinalResponseCapability.managed(
                        ProtocolFinalResponseCapability.Type
                            .CAS_SERVICE_TICKET,
                        "ST-durable-replay",
                        "subject-123",
                        3,
                        "intent-123"))));
        try (val policyApplicationContext = new GenericApplicationContext()) {
            policyApplicationContext.registerBean(
                ProtocolFinalResponsePolicy.BEAN_NAME,
                ProtocolFinalResponsePolicy.class,
                () -> new ProtocolFinalResponsePolicy() {
                    @Override
                    public ProtocolFinalResponseDecision decide(
                        final ProtocolFinalResponseContext policyContext) {
                        return ProtocolFinalResponseDecision.permit();
                    }

                    @Override
                    public ProtocolFinalResponseAuthorization authorize(
                        final ProtocolFinalResponseContext policyContext) {
                        assertNotNull(policyContext.preparedDelivery());
                        assertNotEquals(
                            replay.payloadDigest(),
                            policyContext.preparedDelivery().payloadDigest());
                        return ProtocolFinalResponseAuthorization
                            .durableReplay(replay);
                    }
                });
            policyApplicationContext.refresh();
            val context = MockRequestContext.create(
                policyApplicationContext);
            WebUtils.putAuthentication(
                CoreAuthenticationTestUtils.getAuthentication(), context);
            WebUtils.putServiceIntoFlowScope(context, service);
            val ticket = mock(PropertiesAwareTicket.class);
            when(ticket.getId()).thenReturn("ST-durable-replay");
            when(ticket.getProperties()).thenReturn(Map.of(
                TicketIssuanceMetadata.PROPERTY_SUBJECT_ID, "subject-123",
                TicketIssuanceMetadata.PROPERTY_GENERATION, 3L,
                TicketIssuanceMetadata.PROPERTY_INTENT_ID, "intent-123"));
            WebUtils.putServiceTicketInRequestScope(context, ticket);

            val locator = mock(ResponseBuilderLocator.class);
            val responseBuilder = mock(
                WebApplicationServiceResponseBuilder.class);
            when(locator.locate(any(WebApplicationService.class)))
                .thenReturn(responseBuilder);
            val currentAttributes = new LinkedHashMap<String, String>();
            currentAttributes.put("ticket", "ST-durable-replay");
            currentAttributes.put("opaque", "second-process-output");
            when(responseBuilder.build(
                eq(service), eq("ST-durable-replay"), any()))
                .thenReturn(new RedirectToServiceAction.ImmutableFinalResponse(
                    Response.ResponseType.POST,
                    serviceId,
                    currentAttributes));

            val event = new RedirectToServiceAction(locator)
                .execute(context);
            assertEquals(CasWebflowConstants.TRANSITION_ID_POST, event.getId());
            assertEquals(serviceId,
                context.getRequestScope().get("url"));
            assertEquals(replayAttributes,
                context.getRequestScope().get("parameters"));
        }
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
                    assertEquals(
                        ProtocolFinalResponseDelivery.Mode.REDIRECT,
                        policyContext.delivery().mode());
                    assertEquals(
                        ProtocolFinalResponseDelivery.canonicalOrdered(
                            ProtocolFinalResponseDelivery.Mode.REDIRECT,
                            policyContext.relyingPartyId()
                                + "?ticket=ST-policy-denied",
                            Map.of("ticket", "ST-policy-denied")),
                        policyContext.delivery());
                    return ProtocolFinalResponseDecision.deny("generation_closed");
                });
            policyApplicationContext.refresh();
            val context = MockRequestContext.create(policyApplicationContext);
            WebUtils.putAuthentication(CoreAuthenticationTestUtils.getAuthentication(), context);
            val service = CoreAuthenticationTestUtils.getWebApplicationService();
            val serviceId = service.getId();
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
            val response = mock(Response.class);
            when(response.responseType()).thenReturn(
                Response.ResponseType.REDIRECT);
            when(response.url()).thenReturn(
                serviceId + "?ticket=ST-policy-denied");
            when(response.attributes()).thenReturn(
                Map.of("ticket", "ST-policy-denied"));
            when(builder.build(eq(service), eq("ST-policy-denied"), any()))
                .thenReturn(response);

            val action = new RedirectToServiceAction(locator);
            val denied = assertThrows(ProtocolFinalResponseDeniedException.class,
                () -> action.execute(context));
            assertEquals("generation_closed", denied.getDecision().reasonCode());
            assertFalse(context.getRequestScope().contains("serviceResponse"));
        }
    }
}
