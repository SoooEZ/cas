package org.apereo.cas.protocol;

import module java.base;
import lombok.val;

/**
 * Authoritative admission policy evaluated immediately before a final protocol
 * response discloses a newly issued capability.
 *
 * <p>Implementations must be thread-safe and should be idempotent because a
 * composed protocol response can encounter more than one final serialization
 * boundary. A thread-local value must never be the sole security authority.
 * Returning {@code null}, throwing a runtime exception, or returning a denial
 * fails closed.</p>
 *
 * @author SoooEZ
 * @since 8.0.0
 */
@FunctionalInterface
public interface ProtocolFinalResponsePolicy extends Serializable {

    /** Default Spring bean name for the final response policy. */
    String BEAN_NAME = "protocolFinalResponsePolicy";

    /**
     * Decide whether the response may disclose its capabilities.
     *
     * @param context explicit final-response context
     * @return typed decision; never {@code null}
     */
    ProtocolFinalResponseDecision decide(ProtocolFinalResponseContext context);

    /**
     * Enforce this policy using fail-closed semantics.
     *
     * @param context explicit final-response context
     * @throws ProtocolFinalResponseDeniedException when disclosure is not permitted
     */
    default void enforce(final ProtocolFinalResponseContext context) {
        val finalContext = Objects.requireNonNull(context, "context");
        val decision = evaluate(finalContext);
        if (decision == null) {
            throw new ProtocolFinalResponseDeniedException(finalContext,
                ProtocolFinalResponseDecision.deny("policy_invalid_decision"));
        }
        if (!decision.isPermitted()) {
            throw new ProtocolFinalResponseDeniedException(finalContext, decision);
        }
    }

    private ProtocolFinalResponseDecision evaluate(final ProtocolFinalResponseContext context) {
        try {
            return decide(context);
        } catch (final ProtocolFinalResponseDeniedException e) {
            throw e;
        } catch (final Exception e) {
            throw new ProtocolFinalResponseDeniedException(context,
                ProtocolFinalResponseDecision.deny("policy_failure", true));
        }
    }

    /**
     * Create the explicit backwards-compatible policy that permits every response.
     *
     * @return no-op policy
     */
    static ProtocolFinalResponsePolicy noOp() {
        return NoOpProtocolFinalResponsePolicy.INSTANCE;
    }

    /** Backwards-compatible no-op policy singleton. */
    enum NoOpProtocolFinalResponsePolicy implements ProtocolFinalResponsePolicy {
        /** Singleton instance. */
        INSTANCE;

        @Override
        public ProtocolFinalResponseDecision decide(final ProtocolFinalResponseContext context) {
            return ProtocolFinalResponseDecision.permit();
        }
    }
}
