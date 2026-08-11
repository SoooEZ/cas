package org.apereo.cas.web.cookie;

import module java.base;
import org.apereo.cas.authentication.RememberMeCredential;
import lombok.val;
import org.jspecify.annotations.Nullable;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * This is {@link CasCookieBuilder}.
 *
 * @author Misagh Moayyed
 * @since 6.1.0
 */
public interface CasCookieBuilder {

    /**
     * Immutable stateful cookie disclosure prepared before the final-response
     * policy is committed.
     *
     * <p>The header and output value are the exact bytes/characters that may
     * be applied after a permit decision. The replay value and canonical
     * attributes form the stable semantic representation bound by the
     * response manifest. Sensitive fields are never rendered by
     * {@link #toString()}.</p>
     *
     * @param cookieName exact cookie name
     * @param outputValue exact prepared cookie value
     * @param replayValue deterministic pre-encryption value
     * @param headerValue exact Set-Cookie header value
     * @param path exact effective path
     * @param domain exact effective domain, or {@code null}
     * @param maxAge exact effective max age
     * @param secure whether the cookie itself is configured secure
     * @param httpOnly whether the cookie is HTTP-only
     * @param canonicalAttributes complete canonical header semantics
     */
    record PreparedCookie(
        String cookieName,
        String outputValue,
        String replayValue,
        String headerValue,
        String path,
        @Nullable String domain,
        int maxAge,
        boolean secure,
        boolean httpOnly,
        Map<String, String> canonicalAttributes) implements Serializable {

        @Serial
        private static final long serialVersionUID = -1660335025029152293L;

        public PreparedCookie {
            cookieName = requirePreparedText(cookieName, "cookieName");
            outputValue = requirePreparedText(outputValue, "outputValue");
            replayValue = requirePreparedText(replayValue, "replayValue");
            headerValue = requirePreparedText(headerValue, "headerValue");
            path = requirePreparedText(path, "path");
            if (domain != null) {
                domain = requirePreparedText(domain, "domain");
            }
            val source = Objects.requireNonNull(
                canonicalAttributes, "canonicalAttributes");
            val copy = new TreeMap<String, String>();
            source.forEach((name, value) -> copy.put(
                requirePreparedText(name, "canonical attribute name"),
                requirePreparedText(value, "canonical attribute value")));
            copy.put("output_value_sha256", digestPreparedText(
                "cas-prepared-cookie-output-v1", outputValue));
            copy.put("set_cookie_header_sha256", digestPreparedText(
                "cas-prepared-set-cookie-header-v1", headerValue));
            canonicalAttributes = Map.copyOf(copy);
        }

        /**
         * Materialize a new servlet cookie carrying only prepared state.
         *
         * @return prepared servlet cookie
         */
        public Cookie toCookie() {
            val cookie = new Cookie(cookieName, outputValue);
            if (domain != null) {
                cookie.setDomain(domain);
            }
            cookie.setPath(path);
            cookie.setMaxAge(maxAge);
            cookie.setSecure(secure);
            cookie.setHttpOnly(httpOnly);
            return cookie;
        }

        @Override
        public String toString() {
            return "PreparedCookie[REDACTED]";
        }

        private static String requirePreparedText(
            final String value,
            final String name) {
            val result = Objects.requireNonNull(value, name);
            if (result.isBlank()
                || result.codePoints().anyMatch(Character::isISOControl)) {
                throw new IllegalArgumentException(
                    name + " must be non-blank text without control characters");
            }
            return result;
        }

        private static String digestPreparedText(
            final String domain,
            final String value) {
            try {
                val digest = MessageDigest.getInstance("SHA-256");
                val domainBytes = domain.getBytes(StandardCharsets.UTF_8);
                val valueBytes = value.getBytes(StandardCharsets.UTF_8);
                digest.update(ByteBuffer.allocate(Integer.BYTES)
                    .putInt(domainBytes.length).array());
                digest.update(domainBytes);
                digest.update(ByteBuffer.allocate(Integer.BYTES)
                    .putInt(valueBytes.length).array());
                digest.update(valueBytes);
                return HexFormat.of().formatHex(digest.digest());
            } catch (final NoSuchAlgorithmException e) {
                throw new IllegalStateException(
                    "SHA-256 is required by the Java platform", e);
            }
        }
    }

    /**
     * Bean name that generates the cookie for the ticket-granting cookie.
     */
    String BEAN_NAME_TICKET_GRANTING_COOKIE_BUILDER = "ticketGrantingTicketCookieGenerator";
    /**
     * Bean name that generates the warning cookie.
     */
    String BEAN_NAME_WARN_COOKIE_BUILDER = "warnCookieGenerator";

    /**
     * Adds the cookie, taking into account {@link RememberMeCredential#REQUEST_PARAMETER_REMEMBER_ME}
     * in the request.
     *
     * @param request     the request
     * @param response    the response
     * @param rememberMe  the remember me
     * @param cookieValue the cookie value
     * @return the cookie
     */
    Cookie addCookie(HttpServletRequest request, HttpServletResponse response,
                     boolean rememberMe, String cookieValue);

    /**
     * Add cookie.
     *
     * @param request     the request
     * @param response    the response
     * @param cookieValue the cookie value
     * @return the cookie
     */
    Cookie addCookie(HttpServletRequest request, HttpServletResponse response, String cookieValue);

    /**
     * Apply an already-prepared cookie after a permit decision.
     *
     * <p>The default fails closed because rebuilding from live configuration
     * would invalidate the committed response manifest.</p>
     *
     * @param response the response
     * @param preparedCookie exact prepared cookie
     * @return a servlet cookie containing the prepared state
     */
    default Cookie addCookie(
        final HttpServletResponse response,
        final PreparedCookie preparedCookie) {
        throw new UnsupportedOperationException(
            "Cookie builder does not support prepared final responses");
    }

    /**
     * Whether this implementation can prepare and later apply the exact same
     * stateful cookie without consulting mutable configuration again.
     *
     * <p>The default is {@code false} so third-party builders retain their
     * legacy behavior unless an authoritative final-response policy is
     * installed. Production authority wiring must reject a builder that does
     * not opt in.</p>
     *
     * @return whether prepared final responses are supported
     */
    default boolean supportsPreparedFinalResponse() {
        return false;
    }

    /**
     * Prepare the exact stateful cookie disclosure without mutating the real
     * HTTP response.
     *
     * <p>The default fails closed so an implementation cannot accidentally
     * rebuild a response after the final-response policy has committed.</p>
     *
     * @param request the request
     * @param response the response used only for isolated policy reads
     * @param rememberMe whether remember-me lifetime is selected
     * @param cookieValue the source cookie value
     * @return immutable prepared cookie
     */
    default PreparedCookie prepareCookie(
        final HttpServletRequest request,
        final HttpServletResponse response,
        final boolean rememberMe,
        final String cookieValue) {
        throw new UnsupportedOperationException(
            "Cookie builder does not support prepared final responses");
    }

    /**
     * Retrieve cookie value.
     *
     * @param request the request
     * @return the cookie value
     */
    @Nullable String retrieveCookieValue(HttpServletRequest request);

    /**
     * Remove cookie.
     *
     * @param response the response
     */
    void removeCookie(HttpServletResponse response);

    /**
     * Gets cookie path.
     *
     * @return the cookie path
     */
    String getCookiePath();

    /**
     * Sets cookie path.
     *
     * @param path the path
     */
    void setCookiePath(String path);

    /**
     * Gets cookie domain.
     *
     * @return the cookie domain
     */
    String getCookieDomain();

    /**
     * Get cookie name.
     *
     * @return the string
     */
    String getCookieName();

    /**
     * Remove all cookies by the same name.
     * Attempts to ensure all variations of the same cookie
     * that may have been issued under root, or those with a lingering {@code /}
     * are removed from the response.
     *
     * @param request  the request
     * @param response the response
     */
    void removeAll(HttpServletRequest request, HttpServletResponse response);

    /**
     * Gets cas cookie value manager.
     *
     * @return the cas cookie value manager
     */
    CookieValueManager getCasCookieValueManager();

    /**
     * Contains cookie.
     *
     * @param request the request
     * @return true/false
     */
    boolean containsCookie(HttpServletRequest request);
}
