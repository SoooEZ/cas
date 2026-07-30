package org.apereo.cas.support.oauth.web.endpoints;

import module java.base;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.ticket.accesstoken.OAuth20AccessToken;
import org.apereo.cas.ticket.registry.TicketRegistry;
import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests access-token and parent-session usage persistence in
 * {@link OAuth20UserProfileEndpointController}.
 *
 * @author SoooEZ
 * @since 8.0.0
 */
@Tag("OAuthWeb")
class OAuth20UserProfileEndpointControllerUsageTests {
    @Test
    void verifyParentTicketGrantingTicketIsReadAndUpdated() throws Exception {
        val ticketRegistry = mock(TicketRegistry.class);
        val accessToken = accessToken(ticketRegistry);
        val referencedTicketGrantingTicket = mock(TicketGrantingTicket.class);
        val storedTicketGrantingTicket = mock(TicketGrantingTicket.class);
        when(referencedTicketGrantingTicket.getId()).thenReturn("TGT-referenced");
        when(accessToken.getTicketGrantingTicket()).thenReturn(referencedTicketGrantingTicket);
        when(ticketRegistry.getTicket("TGT-referenced", TicketGrantingTicket.class))
            .thenReturn(storedTicketGrantingTicket);
        when(storedTicketGrantingTicket.update()).thenReturn(storedTicketGrantingTicket);
        when(ticketRegistry.updateTicket(storedTicketGrantingTicket)).thenReturn(storedTicketGrantingTicket);

        controller(ticketRegistry).updateAccessTokenUsage(accessToken);

        verify(ticketRegistry).getTicket("TGT-referenced", TicketGrantingTicket.class);
        verify(storedTicketGrantingTicket).update();
        verify(ticketRegistry).updateTicket(storedTicketGrantingTicket);
    }

    @Test
    void verifyMissingParentReferenceIsANoOp() throws Exception {
        val ticketRegistry = mock(TicketRegistry.class);
        val accessToken = accessToken(ticketRegistry);

        assertDoesNotThrow(() -> controller(ticketRegistry).updateAccessTokenUsage(accessToken));

        verify(ticketRegistry, never()).getTicket(anyString(), eq(TicketGrantingTicket.class));
        verify(ticketRegistry).updateTicket(accessToken);
    }

    @Test
    void verifyReferencedParentMustExistInRegistry() throws Exception {
        val ticketRegistry = mock(TicketRegistry.class);
        val accessToken = accessToken(ticketRegistry);
        val referencedTicketGrantingTicket = mock(TicketGrantingTicket.class);
        when(referencedTicketGrantingTicket.getId()).thenReturn("TGT-missing");
        when(accessToken.getTicketGrantingTicket()).thenReturn(referencedTicketGrantingTicket);

        val failure = assertThrowsExactly(IllegalStateException.class,
            () -> controller(ticketRegistry).updateAccessTokenUsage(accessToken));

        assertEquals("Unable to locate the ticket-granting ticket referenced by the access token",
            failure.getMessage());
    }

    @Test
    void verifyParentUpdateFailureIsPropagated() throws Exception {
        val ticketRegistry = mock(TicketRegistry.class);
        val accessToken = accessToken(ticketRegistry);
        val referencedTicketGrantingTicket = mock(TicketGrantingTicket.class);
        val storedTicketGrantingTicket = mock(TicketGrantingTicket.class);
        when(referencedTicketGrantingTicket.getId()).thenReturn("TGT-referenced");
        when(accessToken.getTicketGrantingTicket()).thenReturn(referencedTicketGrantingTicket);
        when(ticketRegistry.getTicket("TGT-referenced", TicketGrantingTicket.class))
            .thenReturn(storedTicketGrantingTicket);
        when(storedTicketGrantingTicket.update()).thenReturn(storedTicketGrantingTicket);
        val expected = new IllegalStateException("Registry update failed");
        when(ticketRegistry.updateTicket(storedTicketGrantingTicket)).thenThrow(expected);

        val failure = assertThrowsExactly(IllegalStateException.class,
            () -> controller(ticketRegistry).updateAccessTokenUsage(accessToken));

        assertSame(expected, failure);
    }

    @Test
    void verifyNullParentUpdateResultFailsClosed() throws Exception {
        val ticketRegistry = mock(TicketRegistry.class);
        val accessToken = accessToken(ticketRegistry);
        val referencedTicketGrantingTicket = mock(TicketGrantingTicket.class);
        val storedTicketGrantingTicket = mock(TicketGrantingTicket.class);
        when(referencedTicketGrantingTicket.getId()).thenReturn("TGT-referenced");
        when(accessToken.getTicketGrantingTicket()).thenReturn(referencedTicketGrantingTicket);
        when(ticketRegistry.getTicket("TGT-referenced", TicketGrantingTicket.class))
            .thenReturn(storedTicketGrantingTicket);
        when(storedTicketGrantingTicket.update()).thenReturn(storedTicketGrantingTicket);

        val failure = assertThrowsExactly(IllegalStateException.class,
            () -> controller(ticketRegistry).updateAccessTokenUsage(accessToken));

        assertEquals("Unable to persist the ticket-granting ticket referenced by the access token",
            failure.getMessage());
    }

    private static OAuth20AccessToken accessToken(final TicketRegistry ticketRegistry) throws Exception {
        val accessToken = mock(OAuth20AccessToken.class);
        when(accessToken.update()).thenReturn(accessToken);
        when(ticketRegistry.updateTicket(accessToken)).thenReturn(accessToken);
        return accessToken;
    }

    private static OAuth20UserProfileEndpointController<OAuth20ConfigurationContext> controller(
        final TicketRegistry ticketRegistry) {
        val configurationContext = mock(OAuth20ConfigurationContext.class);
        when(configurationContext.getTicketRegistry()).thenReturn(ticketRegistry);
        return new OAuth20UserProfileEndpointController<>(configurationContext);
    }
}
