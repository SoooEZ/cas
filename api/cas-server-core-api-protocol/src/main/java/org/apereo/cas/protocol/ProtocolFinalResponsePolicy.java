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
     * Authorize exact output for disclosure. Implementations with durable
     * replay storage override this method and may return previously committed
     * bytes for the same stable logical response. Legacy policies retain the
     * current request's prepared output.
     *
     * @param context explicit final-response context
     * @return non-null authorization
     */
    default ProtocolFinalResponseAuthorization authorize(
        final ProtocolFinalResponseContext context) {
        val decision = decide(context);
        return decision == null ? null
            : ProtocolFinalResponseAuthorization.current(
                decision, context.preparedDelivery());
    }

    /**
     * Enforce this policy using fail-closed semantics.
     *
     * @param context explicit final-response context
     * @throws ProtocolFinalResponseDeniedException when disclosure is not permitted
     */
    default void enforce(final ProtocolFinalResponseContext context) {
        authorizeAndEnforce(context);
    }

    /**
     * Enforce policy and return the exact output selected for disclosure.
     *
     * @param context explicit final-response context
     * @return exact permitted authorization
     */
    default ProtocolFinalResponseAuthorization authorizeAndEnforce(
        final ProtocolFinalResponseContext context) {
        val finalContext = Objects.requireNonNull(context, "context");
        val authorization = evaluate(finalContext);
        if (authorization == null) {
            throw new ProtocolFinalResponseDeniedException(finalContext,
                ProtocolFinalResponseDecision.deny("policy_invalid_decision"));
        }
        val decision = authorization.decision();
        if (!decision.isPermitted()) {
            throw new ProtocolFinalResponseDeniedException(finalContext, decision);
        }
        if (authorization.source()
            == ProtocolFinalResponseAuthorization.Source.CURRENT_REQUEST) {
            if (!Objects.equals(
                finalContext.preparedDelivery(),
                authorization.preparedDelivery())) {
                throw new ProtocolFinalResponseDeniedException(finalContext,
                    ProtocolFinalResponseDecision.deny(
                        "policy_invalid_authorization"));
            }
        } else if (authorization.source()
            == ProtocolFinalResponseAuthorization.Source.DURABLE_REPLAY) {
            if (finalContext.preparedDelivery() == null
                || authorization.preparedDelivery() == null
                || !authorization.preparedDelivery()
                    .logicalResponseBinding()
                    .equals(finalContext.logicalResponseBinding())
                || authorization.preparedDelivery().delivery().mode()
                    != finalContext.preparedDelivery().delivery().mode()) {
                throw new ProtocolFinalResponseDeniedException(finalContext,
                    ProtocolFinalResponseDecision.deny(
                        "policy_invalid_replay"));
            }
        }
        return authorization;
    }

    private ProtocolFinalResponseAuthorization evaluate(
        final ProtocolFinalResponseContext context) {
        try {
            return authorize(context);
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
