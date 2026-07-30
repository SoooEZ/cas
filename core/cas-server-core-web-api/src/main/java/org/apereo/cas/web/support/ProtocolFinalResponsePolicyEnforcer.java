package org.apereo.cas.web.support;

import module java.base;
import org.apereo.cas.protocol.ProtocolFinalResponseContext;
import org.apereo.cas.protocol.ProtocolFinalResponsePolicy;
import lombok.val;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.context.ApplicationContext;

/**
 * Resolves and invokes the application final-response policy without relying on
 * implicit request or thread-local state.
 *
 * @author SoooEZ
 * @since 8.0.0
 */
public final class ProtocolFinalResponsePolicyEnforcer {

    private ProtocolFinalResponsePolicyEnforcer() {
    }

    /**
     * Resolve the application policy and enforce it for the explicit context.
     * An application context without a policy retains upstream behavior.
     *
     * @param applicationContext application context
     * @param context final-response context
     */
    public static void enforce(final ApplicationContext applicationContext,
                               final ProtocolFinalResponseContext context) {
        val policies = BeanFactoryUtils.beansOfTypeIncludingAncestors(
            Objects.requireNonNull(applicationContext, "applicationContext"),
            ProtocolFinalResponsePolicy.class);
        if (policies.size() > 1) {
            throw new IllegalStateException("Exactly one protocol final response policy is required");
        }
        policies.values().stream().findFirst()
            .orElseGet(ProtocolFinalResponsePolicy::noOp)
            .enforce(context);
    }
}
