package org.apereo.cas.ticket.registry.key;

import module java.base;

import lombok.experimental.UtilityClass;
import lombok.val;

/**
 * Stable, raw-principal-free identifier codec for Redis ticket authority
 * state.
 *
 * <p>The domain separator and exact principal-identity semantics are part of
 * the persisted Redis schema. Case and surrounding whitespace are not folded,
 * because generic CAS principal identifiers may distinguish them. These rules
 * must not change without a coordinated schema migration.
 * Principal identifiers are always encoded independently of ticket-registry
 * payload encryption so disabling that optional feature cannot expose a raw
 * username in principal indexes, session indexes, or mutation-fence keys.</p>
 *
 * @author Apereo CAS
 * @since 8.0.1
 */
@UtilityClass
public class RedisPrincipalIdentifierCodec {

    private static final int MAXIMUM_PRINCIPAL_LENGTH = 1_024;

    private static final byte[] DOMAIN_SEPARATOR =
        "org.apereo.cas.redis.principal-authority:v1"
            .getBytes(StandardCharsets.UTF_8);

    /**
     * Encode an exact principal identifier with domain-separated SHA-512.
     *
     * @param rawPrincipal raw principal identifier
     * @return stable lowercase hexadecimal digest
     */
    public String encode(final String rawPrincipal) {
        if (rawPrincipal == null) {
            throw new IllegalArgumentException("Redis ticket principal is required");
        }
        if (rawPrincipal.isBlank() || rawPrincipal.length() > MAXIMUM_PRINCIPAL_LENGTH) {
            throw new IllegalArgumentException("Redis ticket principal is outside supported bounds");
        }
        try {
            val digest = MessageDigest.getInstance("SHA-512");
            digest.update(DOMAIN_SEPARATOR);
            digest.update((byte) 0);
            return HexFormat.of().formatHex(
                digest.digest(rawPrincipal.getBytes(StandardCharsets.UTF_8)));
        } catch (final NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-512 is unavailable", exception);
        }
    }
}
