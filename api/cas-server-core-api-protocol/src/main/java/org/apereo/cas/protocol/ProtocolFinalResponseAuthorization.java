package org.apereo.cas.protocol;

import module java.base;
import lombok.val;

/**
 * Fail-closed authorization result for one prepared final response.
 *
 * <p>A durable replay may replace the current request's randomized candidate
 * with the exact response bytes committed by an earlier process. A denial
 * never carries prepared output.</p>
 *
 * @author SoooEZ
 * @param decision policy decision
 * @param preparedDelivery exact authorized delivery, or {@code null} for a
 * legacy context without prepared output
 * @param source source of the authorized delivery
 * @since 8.0.0
 */
public record ProtocolFinalResponseAuthorization(
    ProtocolFinalResponseDecision decision,
    ProtocolFinalResponsePreparedDelivery preparedDelivery,
    Source source) implements Serializable {

    @Serial
    private static final long serialVersionUID = 3534242185876475331L;

    public ProtocolFinalResponseAuthorization {
        Objects.requireNonNull(decision, "decision");
        Objects.requireNonNull(source, "source");
        if (!decision.isPermitted()) {
            if (preparedDelivery != null || source != Source.NONE) {
                throw new IllegalArgumentException(
                    "A denied response cannot carry authorized output");
            }
        } else if (source == Source.NONE) {
            throw new IllegalArgumentException(
                "A permitted response must identify its output source");
        } else if (source == Source.DURABLE_REPLAY
            && preparedDelivery == null) {
            throw new IllegalArgumentException(
                "A durable replay requires exact prepared output");
        }
    }

    /** Build the default authorization for the current request. */
    public static ProtocolFinalResponseAuthorization current(
        final ProtocolFinalResponseDecision decision,
        final ProtocolFinalResponsePreparedDelivery preparedDelivery) {
        val value = Objects.requireNonNull(decision, "decision");
        return value.isPermitted()
            ? new ProtocolFinalResponseAuthorization(
                value, preparedDelivery, Source.CURRENT_REQUEST)
            : denied(value);
    }

    /** Build an authorization that replays previously committed exact bytes. */
    public static ProtocolFinalResponseAuthorization durableReplay(
        final ProtocolFinalResponsePreparedDelivery preparedDelivery) {
        return new ProtocolFinalResponseAuthorization(
            ProtocolFinalResponseDecision.permit(),
            Objects.requireNonNull(preparedDelivery, "preparedDelivery"),
            Source.DURABLE_REPLAY);
    }

    /** Build a denied authorization. */
    public static ProtocolFinalResponseAuthorization denied(
        final ProtocolFinalResponseDecision decision) {
        val value = Objects.requireNonNull(decision, "decision");
        if (value.isPermitted()) {
            throw new IllegalArgumentException(
                "A denied authorization requires a denial decision");
        }
        return new ProtocolFinalResponseAuthorization(
            value, null, Source.NONE);
    }

    @Override
    public String toString() {
        return ("ProtocolFinalResponseAuthorization[decision=%s, "
                + "preparedDelivery=[REDACTED], source=%s]")
            .formatted(decision, source);
    }

    /** Origin of the exact response bytes selected for disclosure. */
    public enum Source {
        /** No output is authorized because the decision denied disclosure. */
        NONE,
        /** Output prepared in the current request. */
        CURRENT_REQUEST,
        /** Exact output loaded from an earlier durable commit. */
        DURABLE_REPLAY
    }
}
