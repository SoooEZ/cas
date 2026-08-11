package org.apereo.cas.web.cookie;

import module java.base;
import org.apereo.cas.multitenancy.TenantExtractor;
import lombok.val;
import org.jspecify.annotations.Nullable;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

/**
 * The {@link CookieValueManager} is responsible for
 * managing all cookies and their value structure for CAS. Implementations
 * may choose to encode and sign the cookie value and optionally perform
 * additional checks to ensure the integrity of the cookie.
 *
 * @author Misagh Moayyed
 * @since 4.1
 */
public interface CookieValueManager extends Serializable {

    /**
     * Immutable cookie value prepared before the final-response policy is
     * committed.
     *
     * <p>The output value is the exact value that may be disclosed after a
     * permit decision. The replay value is the deterministic, pre-encryption
     * representation used to bind that disclosure to a response manifest.
     * Neither value is rendered by {@link #toString()}.</p>
     *
     * @param outputValue exact value to disclose
     * @param replayValue deterministic representation before encryption
     */
    record PreparedCookieValue(String outputValue, String replayValue)
        implements Serializable {

        @Serial
        private static final long serialVersionUID = 4317727198770912884L;

        public PreparedCookieValue {
            outputValue = requirePreparedText(outputValue, "outputValue");
            replayValue = requirePreparedText(replayValue, "replayValue");
        }

        @Override
        public String toString() {
            return "PreparedCookieValue[REDACTED]";
        }

        /**
         * Digest of the exact value that may be disclosed.
         *
         * @return domain-separated lowercase SHA-256 digest
         */
        public String outputValueDigest() {
            return digestPreparedText(
                "cas-prepared-cookie-output-v1", outputValue);
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
     * Default bean name.
     */
    String BEAN_NAME = "cookieValueManager";
    
    /**
     * Build cookie value.
     *
     * @param givenCookieValue the given cookie value
     * @param request          the request
     * @return the original cookie value
     */
    String buildCookieValue(String givenCookieValue, HttpServletRequest request);

    /**
     * Prepare a cookie value exactly once before the final-response policy is
     * committed.
     *
     * <p>The default preserves compatibility with value managers whose output
     * is already its own replayable representation. Managers that apply
     * randomized encryption should override this method and return the
     * plaintext representation after all request/session pinning has been
     * applied as {@link PreparedCookieValue#replayValue()}.</p>
     *
     * @param givenCookieValue the given cookie value
     * @param request the request
     * @return immutable prepared value
     */
    default PreparedCookieValue prepareCookieValue(
        final String givenCookieValue,
        final HttpServletRequest request) {
        val outputValue = buildCookieValue(givenCookieValue, request);
        return new PreparedCookieValue(outputValue, outputValue);
    }

    /**
     * Obtain cookie value.
     *
     * @param cookie  the cookie
     * @param request the request
     * @return the string
     */
    default @Nullable String obtainCookieValue(final Cookie cookie, final HttpServletRequest request) {
        return obtainCookieValue(cookie.getValue(), request);
    }

    /**
     * Obtain cookie value.
     *
     * @param cookie  the cookie
     * @param request the request
     * @return the string
     */
    @Nullable String obtainCookieValue(String cookie, HttpServletRequest request);

    /**
     * Gets cookie same site policy.
     *
     * @return the cookie same site policy
     */
    CookieSameSitePolicy getCookieSameSitePolicy();

    /**
     * Gets tenant extractor.
     *
     * @return the tenant extractor
     */
    TenantExtractor getTenantExtractor();
}
