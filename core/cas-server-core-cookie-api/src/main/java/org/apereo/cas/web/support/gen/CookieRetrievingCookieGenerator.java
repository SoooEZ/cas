package org.apereo.cas.web.support.gen;

import module java.base;
import org.apereo.cas.authentication.CoreAuthenticationUtils;
import org.apereo.cas.authentication.RememberMeCredential;
import org.apereo.cas.util.LoggingUtils;
import org.apereo.cas.util.function.FunctionUtils;
import org.apereo.cas.web.cookie.CasCookieBuilder;
import org.apereo.cas.web.cookie.CookieGenerationContext;
import org.apereo.cas.web.cookie.CookieValueManager;
import org.apereo.cas.web.support.CookieUtils;
import org.apereo.cas.web.support.InvalidCookieException;
import org.apereo.cas.web.support.WebUtils;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.webflow.execution.RequestContext;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Extends CookieGenerator to allow you to retrieve a value from a request.
 * The cookie is automatically marked as httpOnly, if the servlet container has support for it.
 * Also has support for remember-me.
 *
 * @author Scott Battaglia
 * @author Misagh Moayyed
 * @since 3.1
 */
@Slf4j
@Getter
@RequiredArgsConstructor
public class CookieRetrievingCookieGenerator implements Serializable, CasCookieBuilder {
    @Serial
    private static final long serialVersionUID = -4926982428809856313L;

    /**
     * Default path that cookies will be visible to: "/", i.e. the entire server.
     */
    private static final String DEFAULT_COOKIE_PATH = "/";

    private static final String SAME_SITE_ATTRIBUTE = "SameSite=";

    private final CookieGenerationContext cookieGenerationContext;

    private final CookieValueManager casCookieValueManager;
    
    /**
     * Is remember me authentication ?
     *
     * @param requestContext the request context
     * @return true/false
     */
    public static Boolean isRememberMeAuthentication(final RequestContext requestContext) {
        if (isRememberMeProvidedInRequest(requestContext)) {
            LOGGER.debug("This request is from a remember-me authentication event");
            return Boolean.TRUE;
        }
        val authn = WebUtils.getAuthentication(requestContext);
        if (CoreAuthenticationUtils.isRememberMeAuthentication(authn)) {
            LOGGER.debug("The recorded authentication is from a remember-me request");
            return Boolean.TRUE;
        }
        return Boolean.FALSE;
    }

    private static boolean isRememberMeProvidedInRequest(final RequestContext requestContext) {
        val request = WebUtils.getHttpServletRequestFromExternalWebflowContext(requestContext);
        val value = request.getParameter(RememberMeCredential.REQUEST_PARAMETER_REMEMBER_ME);
        LOGGER.trace("Locating request parameter [{}] with value [{}]", RememberMeCredential.REQUEST_PARAMETER_REMEMBER_ME, value);
        return StringUtils.isNotBlank(value) && BooleanUtils.toBoolean(value) && WebUtils.isRememberMeAuthenticationEnabled(requestContext);
    }


    @Override
    public Cookie addCookie(final HttpServletRequest request, final HttpServletResponse response,
                            final boolean rememberMe, final String cookieValue) {
        return addCookie(response,
            prepareCookie(request, response, rememberMe, cookieValue));
    }

    @Override
    public Cookie addCookie(
        final HttpServletResponse response,
        final PreparedCookie preparedCookie) {
        val prepared = Objects.requireNonNull(
            preparedCookie, "preparedCookie");
        applyCookieHeaderToResponse(
            prepared.cookieName(), prepared.headerValue(), response);
        return prepared.toCookie();
    }

    @Override
    public Cookie addCookie(final HttpServletRequest request, final HttpServletResponse response, final String cookieValue) {
        return addCookie(request, response, false, cookieValue);
    }

    @Override
    public boolean supportsPreparedFinalResponse() {
        return true;
    }

    @Override
    public PreparedCookie prepareCookie(
        final HttpServletRequest request,
        final HttpServletResponse response,
        final boolean rememberMe,
        final String cookieValue) {
        val preparedValue = casCookieValueManager.prepareCookieValue(
            cookieValue, request);
        val cookie = createTenantCookie(
            createCookie(preparedValue.outputValue()), request);

        if (rememberMe) {
            LOGGER.trace("Creating CAS cookie [{}] for remember-me authentication", getCookieName());
            cookie.setMaxAge(cookieGenerationContext.getRememberMeMaxAge());
        } else {
            LOGGER.trace("Creating CAS cookie [{}]", getCookieName());
            cookie.setMaxAge(cookieGenerationContext.getMaxAge());
        }
        cookie.setSecure(cookieGenerationContext.isSecure());
        cookie.setHttpOnly(cookieGenerationContext.isHttpOnly());
        cookie.setPath(cleanCookiePath(cookie.getPath()));

        val sameSiteResult = determineSameSiteResult(request, response);
        val headerSecure = cookie.getSecure()
            || requiresSecureCookie(sameSiteResult);
        val headerValue = buildCookieHeader(
            cookie, preparedValue.outputValue(), sameSiteResult, headerSecure);
        val canonicalAttributes = buildCanonicalHeaderAttributes(
            cookie, sameSiteResult, headerSecure);
        return new PreparedCookie(
            cookie.getName(),
            preparedValue.outputValue(),
            preparedValue.replayValue(),
            headerValue,
            cookie.getPath(),
            cookie.getDomain(),
            cookie.getMaxAge(),
            cookie.getSecure(),
            cookie.isHttpOnly(),
            canonicalAttributes);
    }

    @Override
    public @Nullable String retrieveCookieValue(final HttpServletRequest request) {
        try {
            if (StringUtils.isBlank(getCookieName())) {
                throw new InvalidCookieException("Cookie name is undefined");
            }
            var cookie = org.springframework.web.util.WebUtils.getCookie(request, Objects.requireNonNull(getCookieName()));
            if (cookie == null) {
                val cookieValue = request.getHeader(getCookieName());
                if (StringUtils.isNotBlank(cookieValue)) {
                    LOGGER.trace("Found cookie [REDACTED] under header name [{}]", getCookieName());
                    cookie = createCookie(cookieValue);
                }
            }
            if (cookie == null) {
                val cookieValue = request.getParameter(getCookieName());
                if (StringUtils.isNotBlank(cookieValue)) {
                    LOGGER.trace("Found cookie [REDACTED] under request parameter name [{}]", getCookieName());
                    cookie = createCookie(cookieValue);
                }
            }
            return Optional.ofNullable(cookie)
                .map(ck -> casCookieValueManager.obtainCookieValue(ck, request))
                .orElse(null);
        } catch (final Exception e) {
            LoggingUtils.warn(LOGGER, e);
        }
        return null;
    }

    @Override
    public void removeCookie(final HttpServletResponse response) {
        val cookie = CookieUtils.createSetCookieHeader(null, cookieGenerationContext.withMaxAge(0));
        response.addHeader(HttpHeaders.SET_COOKIE, cookie);
        LOGGER.trace("Removed cookie [{}]", getCookieName());
    }

    @Override
    public String getCookiePath() {
        return cookieGenerationContext.getPath();
    }

    @Override
    public void setCookiePath(final String path) {
        cookieGenerationContext.setPath(path);
    }

    @Override
    public String getCookieDomain() {
        return StringUtils.trimToNull(cookieGenerationContext.getDomain());
    }

    @Override
    public String getCookieName() {
        return cookieGenerationContext.getName();
    }

    @Override
    public void removeAll(final HttpServletRequest request, final HttpServletResponse response) {
        Optional.ofNullable(request.getCookies()).ifPresent(cookies -> Arrays.stream(cookies)
            .filter(cookie -> Strings.CI.equals(cookie.getName(), getCookieName()))
            .forEach(cookie ->
                Stream
                    .of("/", getCookiePath(),
                        Strings.CI.removeEnd(getCookiePath(), "/"),
                        Strings.CI.appendIfMissing(getCookiePath(), "/"))
                    .distinct()
                    .filter(StringUtils::isNotBlank)
                    .forEach(path -> {
                        val crm = new Cookie(cookie.getName(), cookie.getValue());
                        crm.setMaxAge(0);
                        crm.setPath(path);
                        crm.setSecure(cookie.getSecure());
                        crm.setHttpOnly(cookie.isHttpOnly());
                        LOGGER.debug("Removing cookie [{}] with path [{}] and value [REDACTED]", crm.getName(), crm.getPath());
                        response.addCookie(crm);
                    })));
    }

    @Override
    public boolean containsCookie(final HttpServletRequest request) {
        return request.getCookies() != null
            && Arrays.stream(request.getCookies()).anyMatch(cookie -> Strings.CI.equals(cookie.getName(), getCookieName()));
    }

    protected Cookie addCookieHeaderToResponse(final Cookie cookie,
                                               final HttpServletRequest request,
                                               final HttpServletResponse response) {
        cookie.setPath(cleanCookiePath(cookie.getPath()));
        val sameSiteResult = determineSameSiteResult(request, response);
        val headerSecure = cookie.getSecure()
            || requiresSecureCookie(sameSiteResult);
        val value = buildCookieHeader(
            cookie, cookie.getValue(), sameSiteResult, headerSecure);
        applyCookieHeaderToResponse(cookie.getName(), value, response);
        return cookie;
    }

    private String buildCookieHeader(
        final Cookie cookie,
        final String outputValue,
        final Optional<String> sameSiteResult,
        final boolean headerSecure) {
        val builder = new StringBuilder();
        builder.append(cookie.getName()).append('=').append(outputValue)
            .append(';');

        if (cookie.getMaxAge() > -1) {
            builder.append(" Max-Age=").append(cookie.getMaxAge()).append(';');
        }
        if (StringUtils.isNotBlank(cookie.getDomain())) {
            builder.append(" Domain=").append(cookie.getDomain()).append(';');
        }
        builder.append(" Path=").append(cookie.getPath()).append(';');
        sameSiteResult.ifPresent(result -> builder.append(' ').append(result));
        if (headerSecure) {
            builder.append(" Secure;");
            LOGGER.trace("Marked cookie [{}] as secure as indicated by cookie configuration or the configured same-site policy", cookie.getName());
        }
        if (cookie.isHttpOnly()) {
            builder.append(" HttpOnly;");
        }
        return Strings.CI.removeEnd(builder.toString(), ";");
    }

    private Map<String, String> buildCanonicalHeaderAttributes(
        final Cookie cookie,
        final Optional<String> sameSiteResult,
        final boolean headerSecure) {
        val attributes = new HashMap<String, String>();
        attributes.put("cookie_name", cookie.getName());
        attributes.put("max_age", Integer.toString(cookie.getMaxAge()));
        attributes.put("path", cookie.getPath());
        attributes.put("domain_present", Boolean.toString(
            StringUtils.isNotBlank(cookie.getDomain())));
        if (StringUtils.isNotBlank(cookie.getDomain())) {
            attributes.put("domain", cookie.getDomain());
        }
        attributes.put("same_site_present", Boolean.toString(
            sameSiteResult.isPresent()));
        sameSiteResult.ifPresent(result ->
            attributes.put("same_site", result));
        attributes.put("secure", Boolean.toString(headerSecure));
        attributes.put("http_only", Boolean.toString(cookie.isHttpOnly()));
        return attributes;
    }

    private Optional<String> determineSameSiteResult(
        final HttpServletRequest request,
        final HttpServletResponse response) {
        val sameSitePolicy = casCookieValueManager.getCookieSameSitePolicy();
        val result = Objects.requireNonNull(sameSitePolicy.build(
            request,
            isolateResponse(response),
            snapshotCookieGenerationContext()), "sameSiteResult");
        result.ifPresent(value -> {
            if (value.codePoints().anyMatch(Character::isISOControl)) {
                throw new IllegalArgumentException(
                    "Same-site policy cannot return control characters");
            }
        });
        return result;
    }

    private static boolean requiresSecureCookie(
        final Optional<String> sameSiteResult) {
        val values = sameSiteResult.stream()
            .flatMap(result -> Arrays.stream(result.split(";", -1)))
            .map(String::strip)
            .filter(token -> token.regionMatches(
                true,
                0,
                SAME_SITE_ATTRIBUTE,
                0,
                SAME_SITE_ATTRIBUTE.length()))
            .map(token -> token.substring(SAME_SITE_ATTRIBUTE.length()).strip())
            .toList();
        if (values.size() > 1) {
            throw new IllegalArgumentException(
                "Same-site policy returned multiple SameSite attributes");
        }
        return values.size() == 1
            && Strings.CI.equals(values.getFirst(), "None");
    }

    private CookieGenerationContext snapshotCookieGenerationContext() {
        return CookieGenerationContext.builder()
            .name(cookieGenerationContext.getName())
            .path(cookieGenerationContext.getPath())
            .maxAge(cookieGenerationContext.getMaxAge())
            .secure(cookieGenerationContext.isSecure())
            .domain(cookieGenerationContext.getDomain())
            .rememberMeMaxAge(cookieGenerationContext.getRememberMeMaxAge())
            .httpOnly(cookieGenerationContext.isHttpOnly())
            .sameSitePolicy(cookieGenerationContext.getSameSitePolicy())
            .build();
    }

    private static HttpServletResponse isolateResponse(
        final HttpServletResponse response) {
        val target = Objects.requireNonNull(response, "response");
        return (HttpServletResponse) java.lang.reflect.Proxy.newProxyInstance(
            HttpServletResponse.class.getClassLoader(),
            new Class[] {HttpServletResponse.class},
            (proxy, method, arguments) -> {
                if (method.getDeclaringClass() == Object.class) {
                    return switch (method.getName()) {
                        case "toString" -> "IsolatedHttpServletResponse[REDACTED]";
                        case "hashCode" -> System.identityHashCode(proxy);
                        case "equals" -> isSameProxyInstance(proxy, arguments[0]);
                        default -> throw new UnsupportedOperationException(
                            method.getName());
                    };
                }
                if (method.getName().equals("getWriter")) {
                    return new PrintWriter(Writer.nullWriter());
                }
                if (method.getName().equals("getOutputStream")) {
                    return new ServletOutputStream() {
                        @Override
                        public boolean isReady() {
                            return true;
                        }

                        @Override
                        public void setWriteListener(
                            final WriteListener writeListener) {
                        }

                        @Override
                        public void write(final int value) {
                        }
                    };
                }
                if (method.getReturnType() == Void.TYPE) {
                    return null;
                }
                try {
                    val result = method.invoke(target, arguments);
                    if (result instanceof Collection<?> collection) {
                        return List.copyOf(collection);
                    }
                    if (method.getName().equals("getTrailerFields")
                        && result instanceof Supplier<?> supplier
                        && supplier.get() instanceof Map<?, ?> trailers) {
                        val snapshot = Map.copyOf(trailers);
                        return (Supplier<Map<?, ?>>) () -> snapshot;
                    }
                    return result;
                } catch (final InvocationTargetException e) {
                    throw e.getCause();
                }
            });
    }

    @SuppressWarnings("ReferenceEquality")
    private static boolean isSameProxyInstance(
        final Object proxy,
        final Object candidate) {
        return proxy == candidate;
    }

    private static void applyCookieHeaderToResponse(
        final String cookieName,
        final String headerValue,
        final HttpServletResponse response) {
        LOGGER.trace("Adding cookie header for [{}] with value [REDACTED]", cookieName);
        val setCookieHeaders = new ArrayList<>(
            response.getHeaders(HttpHeaders.SET_COOKIE));
        response.setHeader(HttpHeaders.SET_COOKIE, headerValue);
        setCookieHeaders.stream()
            .filter(header -> !header.startsWith(cookieName + '='))
            .forEach(header ->
                response.addHeader(HttpHeaders.SET_COOKIE, header));
    }

    private String cleanCookiePath(final String givenPath) {
        return FunctionUtils.doIf(StringUtils.isBlank(cookieGenerationContext.getPath()),
            () -> {
                val path = Strings.CI.removeEnd(StringUtils.defaultIfBlank(givenPath, DEFAULT_COOKIE_PATH), "/");
                return StringUtils.defaultIfBlank(path, "/");
            },
            () -> StringUtils.defaultIfBlank(givenPath, DEFAULT_COOKIE_PATH)).get();
    }

    private Cookie createTenantCookie(final Cookie cookie, final HttpServletRequest request) {
        val tenantDefinition = casCookieValueManager.getTenantExtractor().extract(request);
        tenantDefinition.ifPresent(tenant -> cookie.setPath(
            Strings.CI.appendIfMissing(cookie.getPath(), "/") + "tenants/" + tenant.getId()));
        return cookie;
    }

    protected Cookie createCookie(final String cookieValue) {
        val cookie = new Cookie(getCookieName(), cookieValue);
        if (StringUtils.isNotBlank(getCookieDomain())) {
            cookie.setDomain(getCookieDomain());
        }
        cookie.setPath(cleanCookiePath(getCookiePath()));
        return cookie;
    }
}
