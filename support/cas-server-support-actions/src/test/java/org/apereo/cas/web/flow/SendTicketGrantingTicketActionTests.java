package org.apereo.cas.web.flow;

import module java.base;
import org.apereo.cas.CasProtocolConstants;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.mock.MockTicketGrantingTicket;
import org.apereo.cas.protocol.ProtocolFinalResponseAuthorization;
import org.apereo.cas.protocol.ProtocolFinalResponseCapability;
import org.apereo.cas.protocol.ProtocolFinalResponseContext;
import org.apereo.cas.protocol.ProtocolFinalResponseDecision;
import org.apereo.cas.protocol.ProtocolFinalResponseDelivery;
import org.apereo.cas.protocol.ProtocolFinalResponseDeniedException;
import org.apereo.cas.protocol.ProtocolFinalResponseLogicalBinding;
import org.apereo.cas.protocol.ProtocolFinalResponsePolicy;
import org.apereo.cas.ticket.PropertiesAwareTicket;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.ticket.registry.TicketIssuanceMetadata;
import org.apereo.cas.ticket.registry.TicketIssuanceReadContext;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.util.MockRequestContext;
import org.apereo.cas.web.BrowserStorage;
import org.apereo.cas.web.cookie.CasCookieBuilder;
import org.apereo.cas.web.cookie.CookieValueManager;
import org.apereo.cas.web.flow.actions.CasProtocolFinalResponseDeliveryBuilder;
import org.apereo.cas.web.flow.login.SendTicketGrantingTicketAction;
import org.apereo.cas.web.support.WebUtils;
import lombok.val;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.webflow.execution.Action;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import jakarta.servlet.http.Cookie;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * @author Marvin S. Addison
 * @since 3.4.0
 */
@Tag("WebflowActions")
class SendTicketGrantingTicketActionTests {
    private static final String LOCALHOST_IP = "127.0.0.1";

    @Test
    void verifyManagedTicketDenialStopsCookieDisclosure() throws Throwable {
        val canonicalAttributes = Map.of(
            "cookie_name", "TGC",
            "domain_present", "false",
            "http_only", "true",
            "max_age", "-1",
            "path", "/",
            "same_site_present", "false",
            "secure", "false");
        val preparedCookie = new CasCookieBuilder.PreparedCookie(
            "TGC",
            "random-ciphertext",
            "TGT-managed@127.0.0.1@Firefox",
            "TGC=random-ciphertext; Path=/; HttpOnly",
            "/",
            null,
            -1,
            false,
            true,
            canonicalAttributes);
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
                        ProtocolFinalResponseDelivery.canonical(
                            ProtocolFinalResponseDelivery.Mode.HTTP_COOKIE,
                            preparedCookie.replayValue(),
                            preparedCookie.canonicalAttributes()),
                        policyContext.delivery());
                    return ProtocolFinalResponseDecision.deny("generation_closed");
                });
            policyApplicationContext.refresh();
            val context = MockRequestContext.create(policyApplicationContext);
            val ticket = mock(TicketGrantingTicket.class,
                withSettings().extraInterfaces(PropertiesAwareTicket.class));
            when(ticket.getId()).thenReturn("TGT-managed");
            when(((PropertiesAwareTicket) ticket).getProperties()).thenReturn(Map.of(
                TicketIssuanceMetadata.PROPERTY_SUBJECT_ID, "subject-123",
                TicketIssuanceMetadata.PROPERTY_GENERATION, 3L,
                TicketIssuanceMetadata.PROPERTY_INTENT_ID, "intent-123"));
            WebUtils.putTicketGrantingTicketInScopes(context, ticket);

            val ticketRegistry = mock(TicketRegistry.class);
            when(ticketRegistry.getTicket(
                eq("TGT-managed"), eq(TicketGrantingTicket.class),
                eq(TicketIssuanceReadContext.forIntent("intent-123"))))
                .thenReturn(ticket);
            val cookieBuilder = mock(CasCookieBuilder.class);
            when(cookieBuilder.getCookieName()).thenReturn("TGC");
            when(cookieBuilder.getCookiePath()).thenReturn("/");
            when(cookieBuilder.supportsPreparedFinalResponse())
                .thenReturn(true);
            when(cookieBuilder.prepareCookie(
                any(), any(), eq(false), eq("TGT-managed")))
                .thenReturn(preparedCookie);
            val action = new TestableSendTicketGrantingTicketAction(
                ticketRegistry, cookieBuilder, mock(SingleSignOnParticipationStrategy.class));

            val initialFlowScopeSize = context.getFlowScope().size();
            val denied = assertThrows(ProtocolFinalResponseDeniedException.class,
                () -> action.createCookie(context, ticket.getId()));
            assertEquals("generation_closed", denied.getDecision().reasonCode());
            assertEquals(initialFlowScopeSize, context.getFlowScope().size());
            assertTrue(context.getHttpServletResponse()
                .getHeaders("Set-Cookie").isEmpty());
            verify(cookieBuilder).prepareCookie(
                any(), any(), eq(false), eq("TGT-managed"));
            verify(cookieBuilder, never()).addCookie(
                any(), same(preparedCookie));
            verify(cookieBuilder, never()).addCookie(any(), any(), anyBoolean(), anyString());
        }
    }

    @Test
    void verifyManagedStatelessTicketDenialStopsBrowserStorageDisclosure()
        throws Throwable {
        val preparedValue = new CookieValueManager.PreparedCookieValue(
            "random-ciphertext",
            "TGT-managed-stateless@127.0.0.1@Firefox");
        try (val policyApplicationContext = new GenericApplicationContext()) {
            policyApplicationContext.registerBean(
                ProtocolFinalResponsePolicy.BEAN_NAME,
                ProtocolFinalResponsePolicy.class,
                () -> policyContext -> {
                    assertEquals(
                        ProtocolFinalResponseDelivery.canonical(
                            ProtocolFinalResponseDelivery.Mode
                                .STATELESS_BROWSER_STORAGE,
                            preparedValue.replayValue(),
                            Map.of(
                                "cookie_name", "TGC",
                                "output_value_sha256",
                                preparedValue.outputValueDigest(),
                                "storage_context",
                                "CasBrowserStorageContext",
                                "storage_type", "LOCAL")),
                        policyContext.delivery());
                    return ProtocolFinalResponseDecision.deny(
                        "generation_closed");
                });
            policyApplicationContext.refresh();
            val context = MockRequestContext.create(policyApplicationContext);
            val ticket = mock(
                TicketGrantingTicket.class,
                withSettings().extraInterfaces(PropertiesAwareTicket.class));
            when(ticket.getId()).thenReturn("TGT-managed-stateless");
            when(ticket.isStateless()).thenReturn(true);
            when(((PropertiesAwareTicket) ticket).getProperties()).thenReturn(
                Map.of(
                    TicketIssuanceMetadata.PROPERTY_SUBJECT_ID, "subject-123",
                    TicketIssuanceMetadata.PROPERTY_GENERATION, 3L,
                    TicketIssuanceMetadata.PROPERTY_INTENT_ID, "intent-123"));
            WebUtils.putTicketGrantingTicketInScopes(context, ticket);

            val ticketRegistry = mock(TicketRegistry.class);
            when(ticketRegistry.getTicket(
                eq("TGT-managed-stateless"),
                eq(TicketGrantingTicket.class),
                eq(TicketIssuanceReadContext.forIntent("intent-123"))))
                .thenReturn(ticket);
            val cookieBuilder = mock(CasCookieBuilder.class);
            when(cookieBuilder.getCookieName()).thenReturn("TGC");
            val cookieValueManager = mock(CookieValueManager.class);
            when(cookieBuilder.getCasCookieValueManager())
                .thenReturn(cookieValueManager);
            when(cookieValueManager.prepareCookieValue(
                eq("TGT-managed-stateless"), any()))
                .thenReturn(preparedValue);
            val action = new TestableSendTicketGrantingTicketAction(
                ticketRegistry,
                cookieBuilder,
                mock(SingleSignOnParticipationStrategy.class));

            val initialFlowScopeSize = context.getFlowScope().size();
            val denied = assertThrows(
                ProtocolFinalResponseDeniedException.class,
                () -> action.createCookie(context, ticket.getId()));

            assertEquals("generation_closed", denied.getDecision().reasonCode());
            assertEquals(initialFlowScopeSize, context.getFlowScope().size());
            assertTrue(context.getHttpServletResponse()
                .getHeaders("Set-Cookie").isEmpty());
            assertFalse(context.getFlowScope().contains(
                BrowserStorage.PARAMETER_BROWSER_STORAGE));
            verify(cookieValueManager).prepareCookieValue(
                eq("TGT-managed-stateless"), any());
            verify(cookieValueManager, never()).buildCookieValue(any(), any());
            verify(cookieBuilder, never()).addCookie(
                any(), any(CasCookieBuilder.PreparedCookie.class));
            verify(cookieBuilder, never()).addCookie(
                any(), any(), anyBoolean(), anyString());
        }
    }

    @Test
    void verifyDurableReplayAppliesPreviouslyCommittedCookie()
        throws Throwable {
        val canonicalAttributes = Map.of(
            "cookie_name", "TGC",
            "domain_present", "false",
            "http_only", "true",
            "max_age", "-1",
            "path", "/",
            "same_site_present", "false",
            "secure", "false");
        val currentCookie = new CasCookieBuilder.PreparedCookie(
            "TGC", "second-process-ciphertext", "stable-replay-value",
            "TGC=second-process-ciphertext; Path=/; HttpOnly",
            "/", null, -1, false, true, canonicalAttributes);
        val replayCookie = new CasCookieBuilder.PreparedCookie(
            "TGC", "first-process-ciphertext", "stable-replay-value",
            "TGC=first-process-ciphertext; Path=/; HttpOnly",
            "/", null, -1, false, true, canonicalAttributes);
        val replay = CasProtocolFinalResponseDeliveryBuilder
            .prepareHttpCookie(
                replayCookie,
                ProtocolFinalResponseLogicalBinding.of(
                    ProtocolFinalResponseContext.Protocol.CAS,
                    ProtocolFinalResponseContext.ResponseType
                        .CAS_BROWSER_SSO_SESSION,
                    null,
                    "subject-123",
                    List.of(ProtocolFinalResponseCapability.managed(
                            ProtocolFinalResponseCapability.Type
                                .CAS_TICKET_GRANTING_TICKET,
                            "TGT-durable-replay",
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
            val ticket = managedTicket("TGT-durable-replay");
            WebUtils.putTicketGrantingTicketInScopes(context, ticket);
            val ticketRegistry = managedTicketRegistry(ticket);
            val cookieBuilder = mock(CasCookieBuilder.class);
            when(cookieBuilder.supportsPreparedFinalResponse())
                .thenReturn(true);
            when(cookieBuilder.prepareCookie(
                any(), any(), eq(false), eq("TGT-durable-replay")))
                .thenReturn(currentCookie);

            val action = new TestableSendTicketGrantingTicketAction(
                ticketRegistry,
                cookieBuilder,
                mock(SingleSignOnParticipationStrategy.class));
            assertEquals(
                CasWebflowConstants.TRANSITION_ID_SUCCESS,
                action.createCookie(
                    context, "TGT-durable-replay").getId());
            verify(cookieBuilder).addCookie(
                any(), eq(replayCookie));
            verify(cookieBuilder, never()).addCookie(
                any(), same(currentCookie));
        }
    }

    @Test
    void verifyLegacyCookieBuilderRetainsUpstreamPathWithoutPolicy()
        throws Throwable {
        try (val policyApplicationContext = new GenericApplicationContext()) {
            policyApplicationContext.refresh();
            val context = MockRequestContext.create(
                policyApplicationContext);
            val ticket = managedTicket("TGT-legacy-builder");
            WebUtils.putTicketGrantingTicketInScopes(context, ticket);
            val cookieBuilder = mock(CasCookieBuilder.class);
            val action = new TestableSendTicketGrantingTicketAction(
                managedTicketRegistry(ticket),
                cookieBuilder,
                mock(SingleSignOnParticipationStrategy.class));

            assertEquals(
                CasWebflowConstants.TRANSITION_ID_SUCCESS,
                action.createCookie(
                    context, "TGT-legacy-builder").getId());
            verify(cookieBuilder).addCookie(
                any(), any(), eq(false), eq("TGT-legacy-builder"));
            verify(cookieBuilder, never()).prepareCookie(
                any(), any(), anyBoolean(), anyString());
            verify(cookieBuilder, never())
                .supportsPreparedFinalResponse();
        }
    }

    private static TicketGrantingTicket managedTicket(
        final String ticketId) {
        val ticket = mock(
            TicketGrantingTicket.class,
            withSettings().extraInterfaces(PropertiesAwareTicket.class));
        when(ticket.getId()).thenReturn(ticketId);
        when(((PropertiesAwareTicket) ticket).getProperties()).thenReturn(
            Map.of(
                TicketIssuanceMetadata.PROPERTY_SUBJECT_ID, "subject-123",
                TicketIssuanceMetadata.PROPERTY_GENERATION, 3L,
                TicketIssuanceMetadata.PROPERTY_INTENT_ID, "intent-123"));
        return ticket;
    }

    private static TicketRegistry managedTicketRegistry(
        final TicketGrantingTicket ticket) {
        val ticketRegistry = mock(TicketRegistry.class);
        when(ticketRegistry.getTicket(
            eq(ticket.getId()),
            eq(TicketGrantingTicket.class),
            eq(TicketIssuanceReadContext.forIntent("intent-123"))))
            .thenReturn(ticket);
        return ticketRegistry;
    }

    private static final class TestableSendTicketGrantingTicketAction
        extends SendTicketGrantingTicketAction {

        TestableSendTicketGrantingTicketAction(
            final TicketRegistry ticketRegistry,
            final CasCookieBuilder cookieBuilder,
            final SingleSignOnParticipationStrategy participationStrategy) {
            super(ticketRegistry, cookieBuilder, participationStrategy);
        }

        Event createCookie(final RequestContext context, final String ticketId) {
            return createSingleSignOnCookie(context, ticketId);
        }
    }

    @Nested
    class PublicWorkstationCookie extends AbstractWebflowActionsTests {
        @Autowired
        @Qualifier(CasWebflowConstants.ACTION_ID_SEND_TICKET_GRANTING_TICKET)
        private Action action;
        @Test
        void verifyTgtMismatch() throws Throwable {
            val context = MockRequestContext.create(applicationContext);
            context.setRemoteAddr(LOCALHOST_IP);
            context.setLocalAddr(LOCALHOST_IP);
            context.getHttpServletRequest().addParameter(CasWebflowConstants.ATTRIBUTE_PUBLIC_WORKSTATION, "true");
            context.setClientInfo();
            context.withUserAgent();

            val tgt1 = new MockTicketGrantingTicket(UUID.randomUUID().toString());
            getTicketRegistry().addTicket(tgt1);
            WebUtils.putPublicWorkstationToFlowIfRequestParameterPresent(context);
            WebUtils.putTicketGrantingTicketIntoMap(context.getRequestScope(), tgt1.getId());

            val tgt2 = new MockTicketGrantingTicket(UUID.randomUUID().toString());
            getTicketRegistry().addTicket(tgt2);
            WebUtils.putTicketGrantingTicketIntoMap(context.getFlowScope(), tgt2.getId());
            assertEquals(CasWebflowConstants.TRANSITION_ID_SUCCESS, action.execute(context).getId());
        }

    }

    @Nested
    class CreateSsoCookieOnRenew extends AbstractWebflowActionsTests {
        @Autowired
        @Qualifier(CasWebflowConstants.ACTION_ID_SEND_TICKET_GRANTING_TICKET)
        private Action action;

        
        @Test
        void verifyNoTgtToSet() throws Throwable {
            val context = MockRequestContext.create(applicationContext);
            assertEquals(CasWebflowConstants.TRANSITION_ID_SUCCESS, action.execute(context).getId());
        }

        @Test
        void verifyTgtToSet() throws Throwable {
            val context = MockRequestContext.create(applicationContext);
            context.setRemoteAddr(LOCALHOST_IP);
            context.setLocalAddr(LOCALHOST_IP);
            context.setClientInfo();

            context.withUserAgent();
            val tgt = new MockTicketGrantingTicket(UUID.randomUUID().toString());
            getTicketRegistry().addTicket(tgt);
            WebUtils.putTicketGrantingTicketInScopes(context, tgt);
            assertEquals(CasWebflowConstants.TRANSITION_ID_SUCCESS, action.execute(context).getId());
            context.setRequestCookiesFromResponse();
            assertEquals(tgt.getId(), getTicketGrantingTicketCookieGenerator().retrieveCookieValue(context.getHttpServletRequest()));
        }

        @Test
        void verifyTgtToSetRemovingOldTgt() throws Throwable {
            val context = MockRequestContext.create(applicationContext);
            context.setRemoteAddr(LOCALHOST_IP);
            context.setLocalAddr(LOCALHOST_IP);
            context.setClientInfo();
            context.withUserAgent();

            val tgt = new MockTicketGrantingTicket(UUID.randomUUID().toString());
            getTicketRegistry().addTicket(tgt);
            context.setHttpRequestCookies(new Cookie("TGT", "test5"));
            WebUtils.putTicketGrantingTicketInScopes(context, tgt);

            assertEquals(CasWebflowConstants.TRANSITION_ID_SUCCESS, action.execute(context).getId());
            context.setRequestCookiesFromResponse();
            assertEquals(tgt.getId(), getTicketGrantingTicketCookieGenerator().retrieveCookieValue(context.getHttpServletRequest()));
        }
    }

    @Nested
    @TestPropertySource(properties = "cas.sso.create-sso-cookie-on-renew-authn=false")
    class IgnoreSsoCookieOnRenew extends AbstractWebflowActionsTests {
        @Autowired
        @Qualifier(CasWebflowConstants.ACTION_ID_SEND_TICKET_GRANTING_TICKET)
        private Action action;

        @Test
        void verifySsoSessionCookieOnRenewAsParameter() throws Throwable {
            val context = MockRequestContext.create(applicationContext);
            
            context.setParameter(CasProtocolConstants.PARAMETER_RENEW, "true");
            context.setRemoteAddr(LOCALHOST_IP);
            context.setLocalAddr(LOCALHOST_IP);
            context.withUserAgent();
            context.setClientInfo();

            val tgt = new MockTicketGrantingTicket(UUID.randomUUID().toString());
            context.setHttpRequestCookies(new Cookie("TGT", "test5"));
            WebUtils.putTicketGrantingTicketInScopes(context, tgt);
            assertEquals(CasWebflowConstants.TRANSITION_ID_SUCCESS, action.execute(context).getId());
            assertEquals(0, context.getHttpServletResponse().getCookies().length);
        }

        @Test
        void verifySsoSessionCookieOnServiceSsoDisallowed() throws Throwable {
            val context = MockRequestContext.create(applicationContext);

            context.setRemoteAddr(LOCALHOST_IP);
            context.setLocalAddr(LOCALHOST_IP);
            context.withUserAgent();
            context.setClientInfo();

            val svc = mock(WebApplicationService.class);
            when(svc.getId()).thenReturn("TestSsoFalse");

            val tgt = new MockTicketGrantingTicket(UUID.randomUUID().toString());
            context.setHttpRequestCookies(new Cookie("TGT", "test5"));
            WebUtils.putTicketGrantingTicketInScopes(context, tgt);
            context.getFlowScope().put(CasProtocolConstants.PARAMETER_SERVICE, svc);

            assertEquals(CasWebflowConstants.TRANSITION_ID_SUCCESS, action.execute(context).getId());
            assertEquals(0, context.getHttpServletResponse().getCookies().length);
        }
    }
}
