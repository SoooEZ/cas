package org.apereo.cas.protocol;

import module java.base;

/**
 * Raised when final protocol response disclosure is not permitted.
 *
 * <p>The exception intentionally retains only non-secret decision metadata;
 * opaque capability values never appear in its message.</p>
 *
 * @author SoooEZ
 * @since 8.0.0
 */
public class ProtocolFinalResponseDeniedException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = -1261807909523805514L;

    private final ProtocolFinalResponseContext.Protocol protocol;

    private final ProtocolFinalResponseContext.ResponseType responseType;

    private final ProtocolFinalResponseDecision decision;

    public ProtocolFinalResponseDeniedException(final ProtocolFinalResponseContext context,
                                                final ProtocolFinalResponseDecision decision) {
        super("Protocol final response denied [protocol=%s, responseType=%s, reason=%s]"
            .formatted(context.protocol(), context.responseType(), decision.reasonCode()));
        this.protocol = context.protocol();
        this.responseType = context.responseType();
        this.decision = decision;
    }

    public ProtocolFinalResponseContext.Protocol getProtocol() {
        return protocol;
    }

    public ProtocolFinalResponseContext.ResponseType getResponseType() {
        return responseType;
    }

    public ProtocolFinalResponseDecision getDecision() {
        return decision;
    }
}
