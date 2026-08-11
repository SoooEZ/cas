package org.apereo.cas.web.support.mgmr;

import module java.base;
import org.apereo.cas.multitenancy.TenantExtractor;
import org.apereo.cas.util.crypto.CipherExecutor;
import org.apereo.cas.util.crypto.CipherExecutorResolver;
import org.apereo.cas.web.cookie.CookieGenerationContext;
import org.apereo.cas.web.cookie.CookieSameSitePolicy;
import org.apereo.cas.web.support.gen.CookieRetrievingCookieGenerator;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * This is {@link EncryptedCookieValueManagerTests}.
 *
 * @author Misagh Moayyed
 * @since 6.2.0
 */
@Tag("Cookie")
class EncryptedCookieValueManagerTests {

    @Test
    void verifyNoValue() {
        val mgr = new EncryptedCookieValueManager(CipherExecutorResolver.with(mock(CipherExecutor.class)),
            mock(TenantExtractor.class), DefaultCookieSameSitePolicy.INSTANCE);
        assertNull(mgr.obtainCookieValue("something", new MockHttpServletRequest()));
    }

    @Test
    void verifyEmptyValue() {
        val cipher = mock(CipherExecutor.class);
        when(cipher.decode(anyString(), any())).thenReturn(StringUtils.EMPTY);
        val mgr = new EncryptedCookieValueManager(CipherExecutorResolver.with(cipher),
            mock(TenantExtractor.class), DefaultCookieSameSitePolicy.INSTANCE);
        assertNull(mgr.obtainCookieValue("something", new MockHttpServletRequest()));
    }

    @Test
    void verifyPreparedValueRetainsReplayFormAndRedactsSecrets() {
        val cipher = mock(CipherExecutor.class);
        when(cipher.encode(eq("ticket@address@agent"), any()))
            .thenReturn("random-ciphertext-one", "random-ciphertext-two");
        val mgr = new EncryptedCookieValueManager(
            CipherExecutorResolver.with(cipher),
            mock(TenantExtractor.class),
            DefaultCookieSameSitePolicy.INSTANCE);

        val prepared = mgr.prepareCookieValue(
            "ticket@address@agent", new MockHttpServletRequest());

        assertEquals("random-ciphertext-one", prepared.outputValue());
        assertEquals("ticket@address@agent", prepared.replayValue());
        assertFalse(prepared.toString().contains("random-ciphertext-one"));
        assertFalse(prepared.toString().contains("ticket@address@agent"));
        verify(cipher).encode(eq("ticket@address@agent"), any());
    }

    @Test
    void verifyPreparedCookieIsAppliedOnceWithoutPolicySideEffects() {
        val generationContext = CookieGenerationContext.builder()
            .name("cas")
            .path("/prepared")
            .maxAge(1000)
            .domain("example.org")
            .secure(true)
            .httpOnly(true)
            .build();
        val cipher = mock(CipherExecutor.class);
        when(cipher.encode(eq("TGT-prepared-secret"), any()))
            .thenReturn("random-ciphertext-one", "random-ciphertext-two");
        val sameSitePolicy = (CookieSameSitePolicy) (request, response, snapshot) -> {
            response.addHeader("X-SameSite-Leak", "must-not-escape");
            response.setStatus(299);
            snapshot.setPath("/mutated-by-policy");
            return Optional.of("SameSite=Lax;");
        };
        val tenantExtractor = mock(TenantExtractor.class);
        when(tenantExtractor.extract(any(HttpServletRequest.class)))
            .thenReturn(Optional.empty());
        val valueManager = new EncryptedCookieValueManager(
            CipherExecutorResolver.with(cipher),
            tenantExtractor,
            sameSitePolicy);
        val generator = new CookieRetrievingCookieGenerator(
            generationContext, valueManager);
        val request = new MockHttpServletRequest();
        val response = new MockHttpServletResponse();

        val prepared = generator.prepareCookie(
            request, response, false, "TGT-prepared-secret");

        assertNull(response.getHeader("X-SameSite-Leak"));
        assertEquals(200, response.getStatus());
        assertTrue(response.getHeaders("Set-Cookie").isEmpty());
        assertEquals("/prepared", generationContext.getPath());
        assertEquals("random-ciphertext-one", prepared.outputValue());
        assertEquals("TGT-prepared-secret", prepared.replayValue());
        assertEquals("1000", prepared.canonicalAttributes().get("max_age"));
        assertEquals("example.org", prepared.canonicalAttributes().get("domain"));
        assertEquals("/prepared", prepared.canonicalAttributes().get("path"));
        assertEquals("SameSite=Lax;",
            prepared.canonicalAttributes().get("same_site"));
        assertEquals("true", prepared.canonicalAttributes().get("secure"));
        assertEquals("true", prepared.canonicalAttributes().get("http_only"));
        assertFalse(prepared.toString().contains("random-ciphertext-one"));
        assertFalse(prepared.toString().contains("TGT-prepared-secret"));

        val cookie = generator.addCookie(response, prepared);

        assertEquals("random-ciphertext-one", cookie.getValue());
        assertTrue(response.getHeader("Set-Cookie")
            .contains("cas=random-ciphertext-one"));
        assertNull(response.getHeader("X-SameSite-Leak"));
        assertEquals(200, response.getStatus());
        verify(cipher).encode(eq("TGT-prepared-secret"), any());
    }

    @Test
    void verifySameSiteNoneForcesSecureAndRejectsAmbiguity() {
        val tenantExtractor = mock(TenantExtractor.class);
        when(tenantExtractor.extract(any(HttpServletRequest.class)))
            .thenReturn(Optional.empty());
        val generationContext = CookieGenerationContext.builder()
            .name("cas")
            .path("/")
            .secure(false)
            .httpOnly(true)
            .build();
        val valueManager = new EncryptedCookieValueManager(
            CipherExecutorResolver.with(CipherExecutor.noOp()),
            tenantExtractor,
            CookieSameSitePolicy.none());
        val generator = new CookieRetrievingCookieGenerator(
            generationContext, valueManager);

        val prepared = generator.prepareCookie(
            new MockHttpServletRequest(),
            new MockHttpServletResponse(),
            false,
            "TGT-same-site-none");

        assertTrue(prepared.headerValue().contains("SameSite=None; Secure"));
        assertEquals("true", prepared.canonicalAttributes().get("secure"));

        val ambiguousPolicy = (CookieSameSitePolicy) (request, response, snapshot) ->
            Optional.of("SameSite=Lax; SameSite=None;");
        val ambiguousManager = new EncryptedCookieValueManager(
            CipherExecutorResolver.with(CipherExecutor.noOp()),
            tenantExtractor,
            ambiguousPolicy);
        val ambiguousGenerator = new CookieRetrievingCookieGenerator(
            generationContext, ambiguousManager);
        assertThrows(IllegalArgumentException.class,
            () -> ambiguousGenerator.prepareCookie(
                new MockHttpServletRequest(),
                new MockHttpServletResponse(),
                false,
                "TGT-ambiguous-same-site"));

        val injectionPolicy = (CookieSameSitePolicy) (request, response, snapshot) ->
            Optional.of("SameSite=None;\r\nX-Injected: value");
        val injectionManager = new EncryptedCookieValueManager(
            CipherExecutorResolver.with(CipherExecutor.noOp()),
            tenantExtractor,
            injectionPolicy);
        val injectionGenerator = new TestCookieGenerator(
            generationContext, injectionManager);
        val injectionResponse = new MockHttpServletResponse();
        val cookie = new Cookie("cas", "safe-output");
        cookie.setPath("/");
        assertThrows(IllegalArgumentException.class,
            () -> injectionGenerator.applyLegacy(
                cookie,
                new MockHttpServletRequest(),
                injectionResponse));
        assertTrue(injectionResponse.getHeaders("Set-Cookie").isEmpty());
    }

    private static final class TestCookieGenerator
        extends CookieRetrievingCookieGenerator {

        TestCookieGenerator(
            final CookieGenerationContext generationContext,
            final EncryptedCookieValueManager valueManager) {
            super(generationContext, valueManager);
        }

        Cookie applyLegacy(
            final Cookie cookie,
            final HttpServletRequest request,
            final HttpServletResponse response) {
            return addCookieHeaderToResponse(cookie, request, response);
        }
    }
}
