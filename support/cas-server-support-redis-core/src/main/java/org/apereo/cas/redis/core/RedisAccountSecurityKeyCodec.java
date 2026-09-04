package org.apereo.cas.redis.core;

import module java.base;

import lombok.val;

/**
 * Stable, raw-principal-free Redis keys for account security state.
 *
 * <p>The principal digest is also the Redis Cluster hash tag. A terminal
 * deletion fence and every security record owned by that principal therefore
 * share one slot and can be checked and mutated by one Redis script.</p>
 *
 * @author Apereo CAS
 * @since 8.0.1
 */
public final class RedisAccountSecurityKeyCodec {
    /** Namespace of permanent account-deletion fences. */
    public static final String DELETION_FENCE_NAMESPACE = "CAS_ACCOUNT_SECURITY_DELETION_FENCE";

    private static final Pattern SAFE_SEGMENT = Pattern.compile("[A-Za-z][A-Za-z0-9._-]{0,127}");

    private static final Pattern PRINCIPAL_DIGEST = Pattern.compile("[0-9a-f]{64}");

    private static final int MAXIMUM_PRINCIPAL_LENGTH = 1_024;

    private static final byte[] PRINCIPAL_DIGEST_DOMAIN =
        "org.apereo.cas.redis.account-security-principal:v1"
            .getBytes(StandardCharsets.UTF_8);

    /**
     * Build the permanent terminal-fence key for a principal.
     *
     * @param rawPrincipal principal supplied by the owning security repository
     * @return stable Redis key
     */
    public String deletionFenceKey(final String rawPrincipal) {
        return deletionFenceKeyForPrincipalDigest(principalDigest(rawPrincipal));
    }

    /**
     * Build a permanent terminal-fence key from a validated principal digest.
     *
     * @param principalDigest SHA-256 principal digest
     * @return stable Redis key
     */
    public String deletionFenceKeyForPrincipalDigest(final String principalDigest) {
        return DELETION_FENCE_NAMESPACE + ":{" + requirePrincipalDigest(principalDigest) + "}:terminal";
    }

    /**
     * Build a security-data key in the same Redis Cluster slot as its fence.
     *
     * @param namespace repository namespace
     * @param rawPrincipal record owner
     * @param suffix stable record suffix
     * @return stable Redis key
     */
    public String dataKey(final String namespace, final String rawPrincipal, final String suffix) {
        return dataKeyForPrincipalDigest(namespace, principalDigest(rawPrincipal), suffix);
    }

    /**
     * Build a security-data key from a validated principal digest.
     *
     * @param namespace repository namespace
     * @param principalDigest SHA-256 principal digest
     * @param suffix stable record suffix
     * @return stable slot-local Redis key
     */
    public String dataKeyForPrincipalDigest(
        final String namespace,
        final String principalDigest,
        final String suffix) {
        return requireSegment(namespace, "namespace") + ":{" + requirePrincipalDigest(principalDigest) + "}:"
            + requireSegment(suffix, "suffix");
    }

    /**
     * Build the glob that selects every current-format record for a principal.
     *
     * @param namespace repository namespace
     * @param rawPrincipal record owner
     * @return slot-local Redis glob
     */
    public String dataPattern(final String namespace, final String rawPrincipal) {
        return requireSegment(namespace, "namespace") + ":{" + principalDigest(rawPrincipal) + "}:*";
    }

    /**
     * Derive the stable domain-separated SHA-256 digest used by
     * raw-principal-free Redis keys.
     *
     * @param rawPrincipal principal
     * @return lowercase hexadecimal digest
     */
    public String principalDigest(final String rawPrincipal) {
        try {
            val digest = MessageDigest.getInstance("SHA-256");
            digest.update(PRINCIPAL_DIGEST_DOMAIN);
            digest.update((byte) 0);
            return HexFormat.of().formatHex(digest.digest(
                normalizePrincipal(rawPrincipal).getBytes(StandardCharsets.UTF_8)));
        } catch (final NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    /**
     * Normalize a principal exactly once before key derivation.
     *
     * @param rawPrincipal principal
     * @return normalized principal
     */
    public String normalizePrincipal(final String rawPrincipal) {
        if (rawPrincipal == null || rawPrincipal.length() > MAXIMUM_PRINCIPAL_LENGTH) {
            throw new IllegalArgumentException("Account security principal is outside supported bounds");
        }
        val normalized = rawPrincipal.strip().toLowerCase(Locale.ROOT);
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("Account security principal is outside supported bounds");
        }
        return normalized;
    }

    /**
     * Escape a literal value for use inside a Redis SCAN glob.
     *
     * @param value literal value
     * @return escaped glob fragment
     */
    public String escapeGlobLiteral(final String value) {
        val result = new StringBuilder(Objects.requireNonNull(value, "value").length());
        for (var index = 0; index < value.length(); index++) {
            val character = value.charAt(index);
            if (character == '\\' || character == '*' || character == '?'
                || character == '[' || character == ']') {
                result.append('\\');
            }
            result.append(character);
        }
        return result.toString();
    }

    private static String requirePrincipalDigest(final String principalDigest) {
        if (principalDigest == null || !PRINCIPAL_DIGEST.matcher(principalDigest).matches()) {
            throw new IllegalArgumentException("Account security principal digest is invalid");
        }
        return principalDigest;
    }

    private static String requireSegment(final String value, final String name) {
        if (value == null || !SAFE_SEGMENT.matcher(value).matches()) {
            throw new IllegalArgumentException("Account security " + name + " is invalid");
        }
        return value;
    }
}
