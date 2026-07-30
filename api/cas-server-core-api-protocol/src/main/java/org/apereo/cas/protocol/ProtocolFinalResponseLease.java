package org.apereo.cas.protocol;

import module java.base;
import lombok.val;

/**
 * Immutable fencing lease for one exact final-response bundle.
 *
 * <p>A lease is short-lived ownership evidence, not a lock on the subject's
 * security generation. Account disablement, deletion, logout, password change,
 * or any other security closure may invalidate the generation while this value
 * remains unexpired. Final commit must therefore revalidate the generation.</p>
 *
 * <p>The expiration is a positive persisted epoch-millisecond instant. It is
 * not required to remain in the future when an existing durable lease is
 * deserialized for timeout recovery. Newly acquired and renewed leases must be
 * created with {@link #active(String, String, String, long, long, String)}.</p>
 *
 * <p>Lease identifiers, owner tokens, and manifest digests are redacted from
 * {@link #toString()}.</p>
 *
 * @author SoooEZ
 * @param bundleId exact response bundle identifier
 * @param leaseId unique lease identifier
 * @param ownerToken unguessable lease-owner token
 * @param ownerEpoch positive fencing epoch
 * @param expiresAtEpochMilli positive expiration time
 * @param manifestDigest exact bundle manifest digest
 * @since 8.0.0
 */
public record ProtocolFinalResponseLease(
    String bundleId,
    String leaseId,
    String ownerToken,
    long ownerEpoch,
    long expiresAtEpochMilli,
    String manifestDigest) implements Serializable {

    @Serial
    private static final long serialVersionUID = 7423870503301769845L;

    public ProtocolFinalResponseLease {
        bundleId = ProtocolFinalResponseBundle.requireUuid(
            bundleId, "bundleId");
        leaseId = ProtocolFinalResponseBundle.requireUuid(
            leaseId, "leaseId");
        ownerToken = ProtocolFinalResponseBundle.requireUuid(
            ownerToken, "ownerToken");
        if (ownerEpoch <= 0) {
            throw new IllegalArgumentException("ownerEpoch must be positive");
        }
        if (expiresAtEpochMilli <= 0) {
            throw new IllegalArgumentException(
                "expiresAtEpochMilli must be positive");
        }
        manifestDigest = ProtocolFinalResponseBundle.requireDigest(
            manifestDigest, "manifestDigest");
    }

    /**
     * Create a newly acquired or renewed lease with a future expiration.
     *
     * <p>The canonical constructor accepts a positive past expiration so a
     * durable expired lease can be deserialized and recovered. Implementations
     * of acquire and renew should use this factory for active results.</p>
     *
     * @param bundleId exact response bundle identifier
     * @param leaseId unique lease identifier
     * @param ownerToken unguessable owner token
     * @param ownerEpoch positive fencing epoch
     * @param expiresAtEpochMilli future expiration time
     * @param manifestDigest exact bundle manifest digest
     * @return active lease
     */
    public static ProtocolFinalResponseLease active(
        final String bundleId,
        final String leaseId,
        final String ownerToken,
        final long ownerEpoch,
        final long expiresAtEpochMilli,
        final String manifestDigest) {
        if (expiresAtEpochMilli <= System.currentTimeMillis()) {
            throw new IllegalArgumentException(
                "An active lease requires a future expiration");
        }
        return new ProtocolFinalResponseLease(
            bundleId,
            leaseId,
            ownerToken,
            ownerEpoch,
            expiresAtEpochMilli,
            manifestDigest);
    }

    /**
     * Verify that this lease belongs to the exact immutable bundle.
     *
     * @param bundle response bundle
     * @throws IllegalArgumentException when identity or manifest differs
     */
    public void requireMatches(final ProtocolFinalResponseBundle bundle) {
        val value = Objects.requireNonNull(bundle, "bundle");
        if (!bundleId.equals(value.bundleId())
            || !MessageDigest.isEqual(
                manifestDigest.getBytes(StandardCharsets.US_ASCII),
                value.manifestIdentity().getBytes(StandardCharsets.US_ASCII))) {
            throw new IllegalArgumentException(
                "Lease does not match the exact response bundle");
        }
    }

    /**
     * Determine whether the lease is expired at a supplied wall-clock instant.
     *
     * @param epochMilli wall-clock instant
     * @return true when the instant is at or after expiration
     */
    public boolean isExpiredAt(final long epochMilli) {
        if (epochMilli <= 0) {
            throw new IllegalArgumentException("epochMilli must be positive");
        }
        return epochMilli >= expiresAtEpochMilli;
    }

    @Override
    public String toString() {
        return ("ProtocolFinalResponseLease[bundleId=[REDACTED], leaseId=[REDACTED], "
                + "ownerToken=[REDACTED], ownerEpoch=%d, expiresAtEpochMilli=%d, "
                + "manifestDigest=[REDACTED]]")
            .formatted(ownerEpoch, expiresAtEpochMilli);
    }
}
