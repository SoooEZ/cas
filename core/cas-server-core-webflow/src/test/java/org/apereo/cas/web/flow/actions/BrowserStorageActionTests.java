package org.apereo.cas.web.flow.actions;

import module java.base;
import org.apereo.cas.mock.MockTicketGrantingTicket;
import org.apereo.cas.protocol.ProtocolFinalResponseDelivery;
import org.apereo.cas.protocol.ProtocolFinalResponseLogicalBinding;
import org.apereo.cas.protocol.ProtocolFinalResponsePreparedDelivery;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.ticket.registry.TicketRegistry;
import org.apereo.cas.util.MockRequestContext;
import org.apereo.cas.util.serialization.JacksonObjectMapperFactory;
import org.apereo.cas.web.BrowserStorage;
import org.apereo.cas.web.DefaultBrowserStorage;
import org.apereo.cas.web.cookie.CasCookieBuilder;
import org.apereo.cas.web.cookie.CookieValueManager;
import org.apereo.cas.web.flow.BaseWebflowConfigurerTests;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.flow.actions.storage.ReadBrowserStorageAction;
import org.apereo.cas.web.support.WebUtils;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apereo.inspektr.common.web.ClientInfo;
import org.apereo.inspektr.common.web.ClientInfoHolder;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.test.context.TestPropertySource;
import org.springframework.webflow.core.collection.LocalAttributeMap;
import org.springframework.webflow.execution.Action;
import org.springframework.webflow.execution.Event;
import tools.jackson.databind.ObjectMapper;
import static org.junit.jupiter.api.Assertions.*;

/**
 * This is {@link BrowserStorageActionTests}.
 *
 * @author Misagh Moayyed
 * @since 7.0.0
 */
@Tag("WebflowAuthenticationActions")
@TestPropertySource(properties = {
    "cas.tgc.pin-to-session=false",
    "cas.tgc.crypto.enabled=false"
})
class BrowserStorageActionTests extends BaseWebflowConfigurerTests {
    private static final ObjectMapper MAPPER = JacksonObjectMapperFactory.builder()
        .defaultTypingEnabled(false).minimal(false).build().toObjectMapper();

    private static final ProtocolFinalResponseLogicalBinding TEST_BINDING =
        new ProtocolFinalResponseLogicalBinding("b".repeat(64));

    @Autowired
    @Qualifier(CasCookieBuilder.BEAN_NAME_TICKET_GRANTING_COOKIE_BUILDER)
    private CasCookieBuilder ticketGrantingTicketCookieGenerator;

    @Autowired
    @Qualifier(CasWebflowConstants.ACTION_ID_WRITE_BROWSER_STORAGE)
    private Action writeSessionStorageAction;

    @Autowired
    @Qualifier(CasWebflowConstants.ACTION_ID_READ_BROWSER_STORAGE)
    private Action readSessionStorageAction;

    @Autowired
    @Qualifier(CasWebflowConstants.ACTION_ID_PUT_BROWSER_STORAGE)
    private Action putSessionStorageAction;

    @Autowired
    @Qualifier(TicketRegistry.BEAN_NAME)
    private TicketRegistry ticketRegistry;

    @Test
    void verifyPutStorage() throws Exception {
        val context = MockRequestContext.create(applicationContext).withUserAgent("Firefox");
        val request = context.getHttpServletRequest();
        context.setRemoteAddr("185.86.151.11").setLocalAddr("185.88.151.11").setClientInfo();
        val result = putSessionStorageAction.execute(context);
        assertNull(result);
        assertNotNull(WebUtils.getBrowserStoragePayload(request));
    }

    @Test
    void verifyReadFromLocalStorage() throws Exception {
        val ticketGrantingTicket = new MockTicketGrantingTicket("casuser");
        ticketRegistry.addTicket(ticketGrantingTicket);
        
        val context = MockRequestContext.create(applicationContext).withUserAgent("Firefox");
        val request = context.getHttpServletRequest();
        context.setRemoteAddr("185.86.151.11").setLocalAddr("185.88.151.11").setClientInfo();

        var storage = DefaultBrowserStorage.builder()
            .build()
            .setPayloadJson(Map.of(ticketGrantingTicketCookieGenerator.getCookieName(), ticketGrantingTicket.getId()));

        context.setParameter(BrowserStorage.PARAMETER_BROWSER_STORAGE, MAPPER.writeValueAsString(Map.of(storage.getContext(), storage.getPayload())));
        ClientInfoHolder.setClientInfo(ClientInfo.from(request));

        context.setCurrentEvent(new Event(this, CasWebflowConstants.TRANSITION_ID_SUCCESS,
            new LocalAttributeMap<>(TicketGrantingTicket.class.getName(), ticketGrantingTicket.getId())));

        context.getRequestScope().put(BrowserStorage.BrowserStorageTypes.class.getSimpleName(), BrowserStorage.BrowserStorageTypes.LOCAL.name());
        val readResult = readSessionStorageAction.execute(context);
        storage = WebUtils.getBrowserStorage(context);
        assertNotNull(storage);
        assertEquals(BrowserStorage.BrowserStorageTypes.LOCAL, storage.getStorageType());
        assertEquals(CasWebflowConstants.TRANSITION_ID_SUCCESS, readResult.getId());
        assertNotNull(WebUtils.getTicketGrantingTicketId(context));
        storage = readResult.getAttributes().get(BrowserStorage.PARAMETER_BROWSER_STORAGE, BrowserStorage.class);
        assertNotNull(storage);
    }

    @Test
    void verifyOperation() throws Exception {
        val context = MockRequestContext.create(applicationContext).withUserAgent("Firefox");
        context.setRemoteAddr("185.86.151.11").setLocalAddr("185.88.151.11").setClientInfo();

        val ticketGrantingTicket = new MockTicketGrantingTicket("casuser");
        val preparedValue = new CookieValueManager.PreparedCookieValue(
            ticketGrantingTicket.getId(), ticketGrantingTicket.getId());
        val eventAttributes = new LocalAttributeMap<>();
        eventAttributes.put(
            TicketGrantingTicket.class.getName(),
            ticketGrantingTicket.getId());
        eventAttributes.put(
            CookieValueManager.PreparedCookieValue.class.getName(),
            preparedValue);
        eventAttributes.put(
            ProtocolFinalResponseDelivery.class.getName(),
            CasProtocolFinalResponseDeliveryBuilder
                .statelessBrowserStorage(
                    ticketGrantingTicketCookieGenerator,
                    preparedValue,
                    BrowserStorage.BrowserStorageTypes.LOCAL,
                    CasProtocolFinalResponseDeliveryBuilder
                        .DEFAULT_BROWSER_STORAGE_CONTEXT));
        context.setCurrentEvent(new Event(
            this,
            CasWebflowConstants.TRANSITION_ID_SUCCESS,
            eventAttributes));

        var readResult = readSessionStorageAction.execute(context);
        val storage = WebUtils.getBrowserStorage(context);
        assertNotNull(storage);
        assertEquals(BrowserStorage.BrowserStorageTypes.LOCAL, storage.getStorageType());
        assertEquals(CasWebflowConstants.TRANSITION_ID_READ_BROWSER_STORAGE, readResult.getId());
        assertTrue(context.getFlowScope().contains(ReadBrowserStorageAction.BROWSER_STORAGE_REQUEST_IN_PROGRESS));

        val writeResult = writeSessionStorageAction.execute(context);
        assertEquals(CasWebflowConstants.TRANSITION_ID_SUCCESS, writeResult.getId());
        assertTrue(context.getFlowScope().contains(BrowserStorage.PARAMETER_BROWSER_STORAGE));

        context.setCurrentEvent(new Event(this, CasWebflowConstants.TRANSITION_ID_CONTINUE));
        val sessionStorage = writeResult.getAttributes().getRequired("result", BrowserStorage.class);
        context.setParameter(BrowserStorage.PARAMETER_BROWSER_STORAGE,
            MAPPER.writeValueAsString(Map.of(sessionStorage.getContext(), sessionStorage.getPayload())));
        readResult = readSessionStorageAction.execute(context);
        assertFalse(context.getFlowScope().contains(ReadBrowserStorageAction.BROWSER_STORAGE_REQUEST_IN_PROGRESS));
        assertEquals(CasWebflowConstants.TRANSITION_ID_SUCCESS, readResult.getId());
        assertEquals(CasWebflowConstants.STATE_ID_TICKET_GRANTING_TICKET_CHECK, WebUtils.getTargetState(context));
        assertNotNull(WebUtils.getTicketGrantingTicketId(context));

        context.getFlowScope().clear();
        context.getRequestScope().clear();
        context.setParameter(BrowserStorage.PARAMETER_BROWSER_STORAGE, StringUtils.EMPTY);
        readResult = readSessionStorageAction.execute(context);
        assertEquals(CasWebflowConstants.TRANSITION_ID_READ_BROWSER_STORAGE, readResult.getId());
        assertNull(WebUtils.getTicketGrantingTicketId(context));
        
        context.getFlowScope().put(ReadBrowserStorageAction.BROWSER_STORAGE_REQUEST_IN_PROGRESS, Boolean.TRUE);
        readResult = readSessionStorageAction.execute(context);
        assertEquals(CasWebflowConstants.TRANSITION_ID_SKIP, readResult.getId());
        assertFalse(context.getFlowScope().contains(ReadBrowserStorageAction.BROWSER_STORAGE_REQUEST_IN_PROGRESS));
    }

    @Test
    void verifyAuthorizedPreparedBrowserStorageUsesExactOutput()
        throws Exception {
        val context = MockRequestContext.create(applicationContext)
            .withUserAgent("Firefox");
        context.setRemoteAddr("185.86.151.11")
            .setLocalAddr("185.88.151.11")
            .setClientInfo();
        val preparedValue = new CookieValueManager.PreparedCookieValue(
            "first-process-ciphertext", "stable-replay-value");
        val prepared = CasProtocolFinalResponseDeliveryBuilder
            .prepareStatelessBrowserStorage(
                ticketGrantingTicketCookieGenerator,
                    preparedValue,
                    BrowserStorage.BrowserStorageTypes.LOCAL,
                    CasProtocolFinalResponseDeliveryBuilder
                        .DEFAULT_BROWSER_STORAGE_CONTEXT,
                    TEST_BINDING);
        val attributes = new LocalAttributeMap<>();
        attributes.put(
            ProtocolFinalResponsePreparedDelivery.class.getName(),
            prepared);
        context.setCurrentEvent(new Event(
            this, CasWebflowConstants.TRANSITION_ID_SUCCESS, attributes));

        val result = writeSessionStorageAction.execute(context);
        val storage = result.getAttributes()
            .getRequired("result", BrowserStorage.class);
        assertEquals(
            Map.of(
                ticketGrantingTicketCookieGenerator.getCookieName(),
                preparedValue.outputValue()),
            MAPPER.readValue(
                Base64.getDecoder().decode(storage.getPayload()),
                Map.class));
        assertFalse(prepared.toString()
            .contains(preparedValue.outputValue()));
        assertFalse(prepared.toString()
            .contains(preparedValue.replayValue()));
    }

    @Test
    void verifyCommittedDeliveryMismatchStopsBrowserStorageDisclosure()
        throws Exception {
        val context = MockRequestContext.create(applicationContext)
            .withUserAgent("Firefox");
        context.setRemoteAddr("185.86.151.11")
            .setLocalAddr("185.88.151.11")
            .setClientInfo();
        val preparedValue = new CookieValueManager.PreparedCookieValue(
            "ciphertext-once", "TGT-committed-secret");
        val attributes = new LocalAttributeMap<>();
        attributes.put(
            ProtocolFinalResponsePreparedDelivery.class.getName(),
            CasProtocolFinalResponseDeliveryBuilder
                .prepareStatelessBrowserStorage(
                    ticketGrantingTicketCookieGenerator,
                    preparedValue,
                    BrowserStorage.BrowserStorageTypes.LOCAL,
                    "different-storage-context",
                    TEST_BINDING));
        context.setCurrentEvent(new Event(
            this, CasWebflowConstants.TRANSITION_ID_SUCCESS, attributes));

        assertThrows(
            IllegalStateException.class,
            () -> writeSessionStorageAction.execute(context));
        assertFalse(context.getFlowScope().contains(
            BrowserStorage.PARAMETER_BROWSER_STORAGE));
    }

    @Test
    void verifyMissingCommittedDeliveryStopsBrowserStorageDisclosure()
        throws Exception {
        val context = MockRequestContext.create(applicationContext)
            .withUserAgent("Firefox");
        val preparedValue = new CookieValueManager.PreparedCookieValue(
            "ciphertext-once", "TGT-committed-secret");
        val attributes = new LocalAttributeMap<>();
        attributes.put(
            CookieValueManager.PreparedCookieValue.class.getName(),
            preparedValue);
        context.setCurrentEvent(new Event(
            this, CasWebflowConstants.TRANSITION_ID_SUCCESS, attributes));

        assertThrows(
            IllegalStateException.class,
            () -> writeSessionStorageAction.execute(context));
        assertFalse(context.getFlowScope().contains(
            BrowserStorage.PARAMETER_BROWSER_STORAGE));
    }

    @Test
    void verifyWrongPreparedEnvelopeTypeStopsBrowserStorageDisclosure()
        throws Exception {
        val context = MockRequestContext.create(applicationContext)
            .withUserAgent("Firefox");
        val cookie = new CasCookieBuilder.PreparedCookie(
            "TGC", "ciphertext", "replay-value",
            "TGC=ciphertext; Path=/; HttpOnly", "/", null,
            -1, false, true, Map.of(
                "cookie_name", "TGC",
                "domain_present", "false",
                "http_only", "true",
                "max_age", "-1",
                "path", "/",
                "same_site_present", "false",
                "secure", "false"));
        val attributes = new LocalAttributeMap<>();
        attributes.put(
            ProtocolFinalResponsePreparedDelivery.class.getName(),
            CasProtocolFinalResponseDeliveryBuilder
                .prepareHttpCookie(cookie, TEST_BINDING));
        context.setCurrentEvent(new Event(
            this, CasWebflowConstants.TRANSITION_ID_SUCCESS, attributes));

        assertThrows(
            IllegalArgumentException.class,
            () -> writeSessionStorageAction.execute(context));
        assertFalse(context.getFlowScope().contains(
            BrowserStorage.PARAMETER_BROWSER_STORAGE));
    }

    @Test
    void verifyTamperedPreparedOutputStopsBrowserStorageDisclosure()
        throws Exception {
        val context = MockRequestContext.create(applicationContext)
            .withUserAgent("Firefox");
        val committedValue = new CookieValueManager.PreparedCookieValue(
            "committed-ciphertext", "TGT-committed-secret");
        val committed = CasProtocolFinalResponseDeliveryBuilder
            .prepareStatelessBrowserStorage(
                ticketGrantingTicketCookieGenerator,
                committedValue,
                BrowserStorage.BrowserStorageTypes.LOCAL,
                CasProtocolFinalResponseDeliveryBuilder
                    .DEFAULT_BROWSER_STORAGE_CONTEXT,
                TEST_BINDING);
        val tamperedBytes = committed.decodedPayload();
        tamperedBytes[tamperedBytes.length - 1] ^= 1;
        val tampered = new ProtocolFinalResponsePreparedDelivery(
            committed.logicalResponseBinding(),
            committed.delivery(),
            committed.producerCodecId(),
            committed.producerCodecVersion(),
            Base64.getUrlEncoder().withoutPadding()
                .encodeToString(tamperedBytes));
        val attributes = new LocalAttributeMap<>();
        attributes.put(
            ProtocolFinalResponsePreparedDelivery.class.getName(),
            tampered);
        context.setCurrentEvent(new Event(
            this, CasWebflowConstants.TRANSITION_ID_SUCCESS, attributes));

        assertThrows(
            IllegalArgumentException.class,
            () -> writeSessionStorageAction.execute(context));
        assertFalse(context.getFlowScope().contains(
            BrowserStorage.PARAMETER_BROWSER_STORAGE));
    }

    @Test
    void verifyDeliveryDigestBindsReplayConfigurationAndStorage() {
        val canonicalAttributes = Map.of(
            "cookie_name", "TGC",
            "domain_present", "false",
            "http_only", "true",
            "max_age", "3600",
            "path", "/cas/tenants/alpha",
            "same_site_present", "true",
            "same_site", "SameSite=Lax;",
            "secure", "true");
        val first = new CasCookieBuilder.PreparedCookie(
            "TGC",
            "random-ciphertext-one",
            "TGT-secret@192.0.2.1@Firefox",
            "TGC=random-ciphertext-one; Max-Age=3600; "
                + "Path=/cas/tenants/alpha; SameSite=Lax; Secure; HttpOnly",
            "/cas/tenants/alpha",
            null,
            3600,
            true,
            true,
            canonicalAttributes);
        val secondCipher = new CasCookieBuilder.PreparedCookie(
            "TGC",
            "random-ciphertext-two",
            first.replayValue(),
            "TGC=random-ciphertext-two; Max-Age=3600; "
                + "Path=/cas/tenants/alpha; SameSite=Lax; Secure; HttpOnly",
            first.path(),
            null,
            first.maxAge(),
            first.secure(),
            first.httpOnly(),
            canonicalAttributes);
        val changedUserAgent = new CasCookieBuilder.PreparedCookie(
            first.cookieName(),
            first.outputValue(),
            "TGT-secret@192.0.2.1@Safari",
            first.headerValue(),
            first.path(),
            first.domain(),
            first.maxAge(),
            first.secure(),
            first.httpOnly(),
            canonicalAttributes);
        val changedHeader = new CasCookieBuilder.PreparedCookie(
            first.cookieName(),
            first.outputValue(),
            first.replayValue(),
            "TGC=random-ciphertext-one; Path=/tampered",
            first.path(),
            first.domain(),
            first.maxAge(),
            first.secure(),
            first.httpOnly(),
            canonicalAttributes);
        val changedPathAttributes = new HashMap<>(canonicalAttributes);
        changedPathAttributes.put("path", "/cas/tenants/beta");
        val changedTenantPath = new CasCookieBuilder.PreparedCookie(
            first.cookieName(),
            first.outputValue(),
            first.replayValue(),
            "TGC=random-ciphertext-one; Max-Age=3600; "
                + "Path=/cas/tenants/beta; SameSite=Lax; Secure; HttpOnly",
            "/cas/tenants/beta",
            first.domain(),
            first.maxAge(),
            first.secure(),
            first.httpOnly(),
            changedPathAttributes);

        val committed = CasProtocolFinalResponseDeliveryBuilder
            .httpCookie(first);
        assertNotEquals(committed,
            CasProtocolFinalResponseDeliveryBuilder
                .httpCookie(secondCipher));
        assertNotEquals(committed,
            CasProtocolFinalResponseDeliveryBuilder
                .httpCookie(changedHeader));
        assertNotEquals(committed,
            CasProtocolFinalResponseDeliveryBuilder
                .httpCookie(changedUserAgent));
        assertNotEquals(committed,
            CasProtocolFinalResponseDeliveryBuilder
                .httpCookie(changedTenantPath));
        assertFalse(first.toString().contains("random-ciphertext-one"));
        assertFalse(first.toString().contains(first.replayValue()));

        val firstStorageValue = new CookieValueManager.PreparedCookieValue(
            "random-ciphertext-one", first.replayValue());
        val secondStorageCipher = new CookieValueManager.PreparedCookieValue(
            "random-ciphertext-two", first.replayValue());
        val localDelivery = CasProtocolFinalResponseDeliveryBuilder
            .statelessBrowserStorage(
                ticketGrantingTicketCookieGenerator,
                firstStorageValue,
                BrowserStorage.BrowserStorageTypes.LOCAL,
                CasProtocolFinalResponseDeliveryBuilder
                    .DEFAULT_BROWSER_STORAGE_CONTEXT);
        assertNotEquals(localDelivery,
            CasProtocolFinalResponseDeliveryBuilder
                .statelessBrowserStorage(
                    ticketGrantingTicketCookieGenerator,
                    secondStorageCipher,
                    BrowserStorage.BrowserStorageTypes.LOCAL,
                    CasProtocolFinalResponseDeliveryBuilder
                        .DEFAULT_BROWSER_STORAGE_CONTEXT));
        assertNotEquals(localDelivery,
            CasProtocolFinalResponseDeliveryBuilder
                .statelessBrowserStorage(
                    ticketGrantingTicketCookieGenerator,
                    firstStorageValue,
                    BrowserStorage.BrowserStorageTypes.SESSION,
                    CasProtocolFinalResponseDeliveryBuilder
                        .DEFAULT_BROWSER_STORAGE_CONTEXT));
        assertFalse(firstStorageValue.toString()
            .contains("random-ciphertext-one"));
        assertFalse(firstStorageValue.toString()
            .contains(first.replayValue()));
    }

}
