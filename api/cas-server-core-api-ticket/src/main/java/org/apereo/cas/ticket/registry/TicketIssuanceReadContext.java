package org.apereo.cas.ticket.registry;

import module java.base;
import org.jspecify.annotations.Nullable;

/**
 * Explicit security context supplied when reading a ticket participating in issuance.
 *
 * <p>An intent identifier is a claim about the caller's operation, not proof of
 * authorization. A {@link TicketIssuancePolicy} must still verify that the
 * intent is active, belongs to the same subject and generation, and is allowed
 * to observe the ticket. This context deliberately has no thread-local fallback.</p>
 *
 * <p>A final-response read additionally presents fenced response-lease
 * coordinates. Those coordinates do not reserve generation authority. The
 * final-response commit authority must still revalidate the exact current
 * generation after all reads and immediately before disclosure.</p>
 *
 * @author SoooEZ
 * @param mode explicit read mode
 * @param intentId issuance intent identifier
 * @param leaseId final-response lease identifier
 * @param ownerToken final-response lease-owner token
 * @param ownerEpoch final-response fencing epoch
 * @since 8.0.0
 */
public record TicketIssuanceReadContext(
    ReadMode mode,
    @Nullable String intentId,
    @Nullable String leaseId,
    @Nullable String ownerToken,
    @Nullable Long ownerEpoch) implements Serializable {

    /** Maximum UTF-8 size of a response lease identifier or owner token. */
    public static final int MAXIMUM_LEASE_COORDINATE_UTF8_BYTES = 128;

    @Serial
    private static final long serialVersionUID = 5099913589017056424L;

    private static final TicketIssuanceReadContext STANDARD =
        new TicketIssuanceReadContext(
            ReadMode.STANDARD, null, null, null, null);

    private static final Pattern UUID_PATTERN = Pattern.compile(
        "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

    private static final String NIL_UUID =
        "00000000-0000-0000-0000-000000000000";

    public TicketIssuanceReadContext {
        Objects.requireNonNull(mode, "mode");
        if (intentId != null) {
            intentId = requireText(
                intentId,
                "Issuance intent identifier",
                TicketIssuanceMetadata.MAX_INTENT_ID_UTF8_BYTES);
        }
        if (leaseId != null) {
            leaseId = requireText(
                leaseId,
                "Final-response lease identifier",
                MAXIMUM_LEASE_COORDINATE_UTF8_BYTES);
        }
        if (ownerToken != null) {
            ownerToken = requireText(
                ownerToken,
                "Final-response owner token",
                MAXIMUM_LEASE_COORDINATE_UTF8_BYTES);
        }

        if (mode == ReadMode.STANDARD
            && (intentId != null || leaseId != null
                || ownerToken != null || ownerEpoch != null)) {
            throw new IllegalArgumentException(
                "A standard read cannot carry issuance or response-lease coordinates");
        }
        if (mode == ReadMode.INTENT_INTERNAL
            && (intentId == null || leaseId != null
                || ownerToken != null || ownerEpoch != null)) {
            throw new IllegalArgumentException(
                "An internal intent read requires only an intent identifier");
        }
        if (mode == ReadMode.FINAL_RESPONSE
            && (intentId == null || leaseId == null || ownerToken == null
                || ownerEpoch == null || ownerEpoch <= 0)) {
            throw new IllegalArgumentException(
                "A final-response read requires complete positive lease coordinates");
        }
        if (mode == ReadMode.FINAL_RESPONSE) {
            intentId = requireUuid(intentId, "Final-response intent identifier");
            leaseId = requireUuid(leaseId, "Final-response lease identifier");
            ownerToken = requireUuid(ownerToken, "Final-response owner token");
        }
    }

    /**
     * Backwards-compatible constructor for a standard or internal-intent read.
     *
     * @param intentId issuance intent identifier, or {@code null} for a standard read
     */
    public TicketIssuanceReadContext(final @Nullable String intentId) {
        this(
            intentId == null ? ReadMode.STANDARD : ReadMode.INTENT_INTERNAL,
            intentId,
            null,
            null,
            null);
    }

    /**
     * Create a context for a normal read outside an issuance intent.
     *
     * @return standard read context
     */
    public static TicketIssuanceReadContext standard() {
        return STANDARD;
    }

    /**
     * Create a context for an internal read performed by an issuance intent.
     *
     * @param intentId issuance intent identifier
     * @return intent-aware read context
     */
    public static TicketIssuanceReadContext forIntent(final String intentId) {
        return new TicketIssuanceReadContext(intentId);
    }

    /**
     * Create a read performed while assembling one fenced final response.
     *
     * <p>The caller must present these exact coordinates to the durable commit
     * policy after reading. This read context alone never authorizes disclosure.</p>
     *
     * @param intentId source issuance intent identifier
     * @param leaseId final-response lease identifier
     * @param ownerToken final-response owner token
     * @param ownerEpoch positive fencing epoch
     * @return final-response read context
     */
    public static TicketIssuanceReadContext forFinalResponse(
        final String intentId,
        final String leaseId,
        final String ownerToken,
        final long ownerEpoch) {
        return new TicketIssuanceReadContext(
            ReadMode.FINAL_RESPONSE,
            intentId,
            leaseId,
            ownerToken,
            ownerEpoch);
    }

    /**
     * Whether this is a standard compatibility read.
     *
     * @return true for a standard read
     */
    public boolean isStandard() {
        return mode == ReadMode.STANDARD;
    }

    /**
     * Whether this is an issuance-internal read.
     *
     * @return true for an internal intent read
     */
    public boolean isIntentInternal() {
        return mode == ReadMode.INTENT_INTERNAL;
    }

    /**
     * Whether this read participates in a fenced final response.
     *
     * @return true for a final-response read
     */
    public boolean isFinalResponse() {
        return mode == ReadMode.FINAL_RESPONSE;
    }

    /**
     * Determine whether this context references the metadata's intent.
     * Equality alone does not authorize the read.
     *
     * @param metadata ticket lifecycle metadata
     * @return true when intent identifiers match
     */
    public boolean references(final TicketIssuanceMetadata metadata) {
        return intentId != null && intentId.equals(metadata.intentId());
    }

    @Override
    public String toString() {
        return ("TicketIssuanceReadContext[mode=%s, intentId=%s, leaseId=%s, "
                + "ownerToken=%s, ownerEpoch=%s]")
            .formatted(
                mode,
                intentId == null ? null : "[REDACTED]",
                leaseId == null ? null : "[REDACTED]",
                ownerToken == null ? null : "[REDACTED]",
                ownerEpoch);
    }

    private static String requireText(
        final String value,
        final String name,
        final int maximumUtf8Bytes) {
        if (value.isBlank() || !value.equals(value.strip())) {
            throw new IllegalArgumentException(
                name + " must be canonical non-blank text");
        }
        if (value.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(
                name + " cannot contain control characters");
        }
        try {
            var encoded = StandardCharsets.UTF_8.newEncoder()
                .encode(CharBuffer.wrap(value));
            if (encoded.remaining() > maximumUtf8Bytes) {
                throw new IllegalArgumentException(
                    name + " exceeds its UTF-8 size limit");
            }
        } catch (final CharacterCodingException e) {
            throw new IllegalArgumentException(
                name + " is not valid Unicode", e);
        }
        return value;
    }

    private static String requireUuid(
        final String value,
        final String name) {
        if (!UUID_PATTERN.matcher(value).matches()
            || NIL_UUID.equals(value)) {
            throw new IllegalArgumentException(
                name + " must be a non-nil canonical lowercase UUID");
        }
        return value;
    }

    /** Explicit ticket-read authority mode. */
    public enum ReadMode {
        /** Compatibility read outside issuance. */
        STANDARD,
        /** Internal read owned by an active issuance intent. */
        INTENT_INTERNAL,
        /** Read performed under a fenced final-response lease. */
        FINAL_RESPONSE
    }
}
