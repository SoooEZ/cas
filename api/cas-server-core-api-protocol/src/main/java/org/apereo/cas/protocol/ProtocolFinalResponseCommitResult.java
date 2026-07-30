package org.apereo.cas.protocol;

import module java.base;

/**
 * Typed durable outcome of committing or aborting one exact response bundle.
 *
 * <p>{@link Outcome#REPLAY} is a successful idempotent replay of the same
 * operation and exact manifest. Conflicting terminal state must fail closed
 * with {@link ProtocolFinalResponseCommitException}, not be reported as replay.</p>
 *
 * @author SoooEZ
 * @param bundleId exact bundle identifier
 * @param manifestDigest exact manifest digest
 * @param operation terminal operation
 * @param outcome durable operation outcome
 * @param abortReason exact durable abort reason, present only for abort
 * @since 8.0.0
 */
public record ProtocolFinalResponseCommitResult(
    String bundleId,
    String manifestDigest,
    Operation operation,
    Outcome outcome,
    ProtocolFinalResponseCommitPolicy.AbortReason abortReason) implements Serializable {

    @Serial
    private static final long serialVersionUID = 2190468062490185228L;

    public ProtocolFinalResponseCommitResult {
        bundleId = ProtocolFinalResponseBundle.requireUuid(
            bundleId, "bundleId");
        manifestDigest = ProtocolFinalResponseBundle.requireDigest(
            manifestDigest, "manifestDigest");
        Objects.requireNonNull(operation, "operation");
        Objects.requireNonNull(outcome, "outcome");
        if ((operation == Operation.ABORT) != (abortReason != null)) {
            throw new IllegalArgumentException(
                "abortReason must be present only for an abort result");
        }
    }

    /**
     * Verify that this result describes the supplied exact bundle and operation.
     *
     * @param bundle response bundle
     * @param expectedOperation expected terminal operation
     * @param expectedAbortReason expected abort reason, or {@code null} for commit
     * @throws IllegalArgumentException when the result is not exact
     */
    public void requireMatches(
        final ProtocolFinalResponseBundle bundle,
        final Operation expectedOperation,
        final ProtocolFinalResponseCommitPolicy.AbortReason expectedAbortReason) {
        Objects.requireNonNull(bundle, "bundle");
        Objects.requireNonNull(expectedOperation, "expectedOperation");
        if (operation != expectedOperation
            || abortReason != expectedAbortReason) {
            throw new IllegalArgumentException(
                "Commit result operation or abort reason does not match the request");
        }
        if (!bundleId.equals(bundle.bundleId())
            || !MessageDigest.isEqual(
                manifestDigest.getBytes(StandardCharsets.US_ASCII),
                bundle.manifestIdentity().getBytes(StandardCharsets.US_ASCII))) {
            throw new IllegalArgumentException(
                "Commit result does not match the exact response bundle");
        }
    }

    @Override
    public String toString() {
        return ("ProtocolFinalResponseCommitResult[bundleId=[REDACTED], "
                + "manifestDigest=[REDACTED], operation=%s, outcome=%s, "
                + "abortReason=%s]")
            .formatted(operation, outcome, abortReason);
    }

    /** Terminal response operation. */
    public enum Operation {
        /** Commit exact capability disclosure. */
        COMMIT,
        /** Abort capability disclosure. */
        ABORT
    }

    /** Durable operation result. */
    public enum Outcome {
        /** This invocation applied the operation. */
        APPLIED,
        /** The identical operation and manifest had already been applied. */
        REPLAY
    }
}
