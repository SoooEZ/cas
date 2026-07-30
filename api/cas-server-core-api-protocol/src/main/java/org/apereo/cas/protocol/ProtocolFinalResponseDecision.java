package org.apereo.cas.protocol;

import module java.base;

/**
 * Typed policy decision for a final protocol response.
 *
 * @author SoooEZ
 * @param outcome policy outcome
 * @param reasonCode stable machine-readable reason code
 * @param retryable whether a caller may safely retry after state reconciliation
 * @since 8.0.0
 */
public record ProtocolFinalResponseDecision(Outcome outcome, String reasonCode, boolean retryable) implements Serializable {

    @Serial
    private static final long serialVersionUID = 8217700276789720088L;

    private static final Pattern REASON_CODE_PATTERN = Pattern.compile("[a-z0-9][a-z0-9._-]{0,127}");

    public ProtocolFinalResponseDecision {
        Objects.requireNonNull(outcome, "outcome");
        reasonCode = Objects.requireNonNull(reasonCode, "reasonCode").trim();
        if (!REASON_CODE_PATTERN.matcher(reasonCode).matches()) {
            throw new IllegalArgumentException("reasonCode must be a canonical lowercase identifier");
        }
    }

    /**
     * Create a permit decision.
     *
     * @return permit decision
     */
    public static ProtocolFinalResponseDecision permit() {
        return new ProtocolFinalResponseDecision(Outcome.PERMIT, "permitted", false);
    }

    /**
     * Create a non-retryable denial.
     *
     * @param reasonCode stable reason code
     * @return deny decision
     */
    public static ProtocolFinalResponseDecision deny(final String reasonCode) {
        return deny(reasonCode, false);
    }

    /**
     * Create a denial.
     *
     * @param reasonCode stable reason code
     * @param retryable whether reconciliation may make a retry safe
     * @return deny decision
     */
    public static ProtocolFinalResponseDecision deny(final String reasonCode, final boolean retryable) {
        return new ProtocolFinalResponseDecision(Outcome.DENY, reasonCode, retryable);
    }

    /**
     * Whether this decision permits disclosure.
     *
     * @return true when disclosure is permitted
     */
    public boolean isPermitted() {
        return outcome == Outcome.PERMIT;
    }

    /** Policy outcome. */
    public enum Outcome {
        /** Permit capability disclosure. */
        PERMIT,
        /** Deny capability disclosure. */
        DENY
    }
}
