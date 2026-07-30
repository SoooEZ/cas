package org.apereo.cas.ticket.registry;

import module java.base;
import org.apereo.cas.ticket.PropertiesAwareTicket;
import org.apereo.cas.ticket.Ticket;

/**
 * Immutable lifecycle metadata attached to a ticket issued for an account.
 *
 * <p>The property names are stable persistence contracts. The value object is
 * intentionally stored as three scalar ticket properties so ticket payloads
 * remain portable across serializers and rolling upgrades. A subject identifier
 * may be pseudonymous when exposing the account identifier in ticket storage is
 * undesirable.</p>
 *
 * @author SoooEZ
 * @param subjectId stable subject identifier
 * @param generation account security generation admitted for issuance
 * @param intentId durable issuance intent identifier
 * @since 8.0.0
 */
public record TicketIssuanceMetadata(String subjectId, long generation, String intentId) implements Serializable {

    /** Ticket property containing the subject identifier. */
    public static final String PROPERTY_SUBJECT_ID = "org.apereo.cas.ticket.issuance.subject-id";

    /** Ticket property containing the security generation. */
    public static final String PROPERTY_GENERATION = "org.apereo.cas.ticket.issuance.generation";

    /** Ticket property containing the durable issuance intent identifier. */
    public static final String PROPERTY_INTENT_ID = "org.apereo.cas.ticket.issuance.intent-id";

    /** Maximum UTF-8 size of a persisted subject identifier. */
    public static final int MAX_SUBJECT_ID_UTF8_BYTES = 512;

    /** Maximum UTF-8 size of a persisted issuance intent identifier. */
    public static final int MAX_INTENT_ID_UTF8_BYTES = 128;

    @Serial
    private static final long serialVersionUID = -4043430498617980406L;

    public TicketIssuanceMetadata {
        subjectId = requireText(subjectId, "subjectId", MAX_SUBJECT_ID_UTF8_BYTES);
        intentId = requireText(intentId, "intentId", MAX_INTENT_ID_UTF8_BYTES);
        if (generation <= 0) {
            throw new IllegalArgumentException("Ticket issuance generation must be positive");
        }
    }

    /**
     * Attach this metadata to a properties-aware ticket.
     *
     * @param ticket ticket that will be persisted
     * @throws IllegalArgumentException when the ticket cannot carry properties
     */
    public void writeTo(final Ticket ticket) {
        Objects.requireNonNull(ticket, "ticket");
        if (!(ticket instanceof final PropertiesAwareTicket propertiesAwareTicket)) {
            throw new IllegalArgumentException("Ticket [%s] cannot carry issuance metadata".formatted(ticket.getId()));
        }
        var existing = from(ticket);
        if (existing.isPresent()) {
            if (!equals(existing.get())) {
                throw new IllegalStateException("Ticket [%s] issuance metadata is immutable".formatted(ticket.getId()));
            }
            return;
        }
        propertiesAwareTicket.putProperty(PROPERTY_SUBJECT_ID, subjectId);
        propertiesAwareTicket.putProperty(PROPERTY_GENERATION, generation);
        propertiesAwareTicket.putProperty(PROPERTY_INTENT_ID, intentId);
    }

    /**
     * Read issuance metadata from a ticket.
     *
     * <p>A ticket with none of the lifecycle properties is unmanaged and returns
     * an empty result. Partially present or malformed lifecycle properties fail
     * closed with an exception rather than being treated as an unmanaged ticket.</p>
     *
     * @param ticket ticket to inspect
     * @return lifecycle metadata, when present
     */
    public static Optional<TicketIssuanceMetadata> from(final Ticket ticket) {
        Objects.requireNonNull(ticket, "ticket");
        if (!(ticket instanceof final PropertiesAwareTicket propertiesAwareTicket)) {
            return Optional.empty();
        }
        var properties = propertiesAwareTicket.getProperties();
        var subjectId = properties.get(PROPERTY_SUBJECT_ID);
        var generation = properties.get(PROPERTY_GENERATION);
        var intentId = properties.get(PROPERTY_INTENT_ID);
        if (subjectId == null && generation == null && intentId == null) {
            return Optional.empty();
        }
        if (!(subjectId instanceof final String subjectValue)
            || !(intentId instanceof final String intentValue)
            || generation == null) {
            throw new IllegalStateException("Ticket [%s] contains incomplete issuance metadata".formatted(ticket.getId()));
        }
        return Optional.of(new TicketIssuanceMetadata(subjectValue, parseGeneration(ticket, generation), intentValue));
    }

    private static long parseGeneration(final Ticket ticket, final Object value) {
        try {
            if (value instanceof final Byte number) {
                return number.longValue();
            }
            if (value instanceof final Short number) {
                return number.longValue();
            }
            if (value instanceof final Integer number) {
                return number.longValue();
            }
            if (value instanceof final Long number) {
                return number;
            }
            if (value instanceof final BigInteger number) {
                return number.longValueExact();
            }
            if (value instanceof final BigDecimal number) {
                return number.longValueExact();
            }
            if (value instanceof final String number) {
                return Long.parseLong(number);
            }
        } catch (final ArithmeticException | NumberFormatException e) {
            throw new IllegalStateException("Ticket [%s] contains an invalid issuance generation".formatted(ticket.getId()), e);
        }
        throw new IllegalStateException("Ticket [%s] contains a non-integral issuance generation".formatted(ticket.getId()));
    }

    private static String requireText(final String value, final String name, final int maximumUtf8Bytes) {
        var result = Objects.requireNonNull(value, name).trim();
        if (result.isEmpty()) {
            throw new IllegalArgumentException(name + " cannot be blank");
        }
        if (result.length() > maximumUtf8Bytes) {
            throw new IllegalArgumentException(name + " exceeds its UTF-8 size limit");
        }
        try {
            var encoded = StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(result));
            if (encoded.remaining() > maximumUtf8Bytes) {
                throw new IllegalArgumentException(name + " exceeds its UTF-8 size limit");
            }
        } catch (final CharacterCodingException e) {
            throw new IllegalArgumentException(name + " is not valid Unicode", e);
        }
        return result;
    }
}
