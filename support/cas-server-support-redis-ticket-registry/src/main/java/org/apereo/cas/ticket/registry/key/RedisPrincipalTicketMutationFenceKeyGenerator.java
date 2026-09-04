package org.apereo.cas.ticket.registry.key;

import lombok.experimental.UtilityClass;
import org.apache.commons.lang3.StringUtils;

/**
 * Generates Redis keys for principal-scoped ticket mutation fences.
 *
 * <p>This namespace is deliberately separate from principal ticket indexes
 * and their rebuild/global-delete leases. The input is the stable principal
 * identifier produced by {@link RedisPrincipalIdentifierCodec}, never the raw
 * account id.</p>
 *
 * @author SoooEZ
 * @since 8.0.1
 */
@UtilityClass
public class RedisPrincipalTicketMutationFenceKeyGenerator {

    private static final String PREFIX = "CAS_PRINCIPAL_TICKET_MUTATION_FENCE:";

    /**
     * Build a fence key for one mapped principal.
     *
     * @param mappedPrincipal stably encoded exact principal identifier
     * @return Redis mutation-fence key
     */
    public String forPrincipal(final String mappedPrincipal) {
        if (StringUtils.isBlank(mappedPrincipal)) {
            throw new IllegalArgumentException("Mapped principal must not be blank");
        }
        return PREFIX + mappedPrincipal;
    }

    /**
     * Get the stable fence-key prefix.
     *
     * @return fence-key prefix
     */
    public String prefix() {
        return PREFIX;
    }
}
