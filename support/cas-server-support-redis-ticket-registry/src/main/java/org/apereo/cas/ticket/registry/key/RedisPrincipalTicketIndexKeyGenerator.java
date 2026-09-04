package org.apereo.cas.ticket.registry.key;

import lombok.experimental.UtilityClass;
import org.apache.commons.lang3.StringUtils;

/**
 * Builds keys used by the Redis principal-to-ticket authority index.
 *
 * <p>Principal identifiers supplied to this codec must already have passed
 * through {@link RedisPrincipalIdentifierCodec}. Index keys intentionally
 * do not use Redis hash tags: the existing ticket key schema and Spring Data
 * keyspace sets do not share a cluster slot. Consequently, atomic ticket and
 * index scripts support Redis single-primary and Sentinel deployments, but not
 * Redis Cluster.</p>
 *
 * @author SoooEZ
 * @since 8.0.1
 */
@UtilityClass
public class RedisPrincipalTicketIndexKeyGenerator {

    /**
     * Namespace for per-principal sorted sets.
     */
    public static final String NAMESPACE = "CAS_PRINCIPAL_TICKET";

    /**
     * Persistent index schema readiness marker.
     */
    public static final String READY_KEY = "CAS_PRINCIPAL_TICKET_INDEX:SCHEMA";

    /**
     * Lease used to serialize an upgrade rebuild.
     */
    public static final String REBUILD_LOCK_KEY = "CAS_PRINCIPAL_TICKET_INDEX:REBUILD_LOCK";

    /**
     * Lease fencing every ticket write while registry-wide deletion runs.
     */
    public static final String MUTATION_FENCE_KEY = "CAS_PRINCIPAL_TICKET_INDEX:MUTATION_FENCE";

    /**
     * Current on-disk index schema marker.
     */
    public static final String SCHEMA_VERSION = "1";

    /**
     * Build a principal index key.
     *
     * @param digestedPrincipal stably encoded exact principal identifier
     * @return Redis ZSET key
     */
    public static String forPrincipal(final String digestedPrincipal) {
        if (StringUtils.isBlank(digestedPrincipal)) {
            throw new IllegalArgumentException("Digested principal must not be blank");
        }
        return NAMESPACE + ':' + digestedPrincipal;
    }

    /**
     * Pattern covering only per-principal index keys.
     *
     * @return namespace scan pattern
     */
    public static String forEverything() {
        return NAMESPACE + ":*";
    }

    /**
     * Prefix used by Lua when the authoritative principal is read from a
     * ticket hash at the mutation linearization point.
     *
     * @return namespace prefix
     */
    public static String prefix() {
        return NAMESPACE + ':';
    }
}
