package org.apereo.cas.protocol;

import module java.base;
import lombok.val;

/**
 * Secret-free identity of the exact delivery representation at a final
 * protocol-response boundary.
 *
 * <p>The digest is calculated over a versioned, length-prefixed canonical
 * representation. Map-like semantic attributes use sorted canonical order;
 * renderer-observable attributes use their exact insertion order. The raw
 * target, ticket, cookie value, and response attributes are deliberately not
 * retained by this object or exposed by {@link #toString()}.</p>
 *
 * @author SoooEZ
 * @param mode exact response delivery mode
 * @param canonicalRepresentationDigest lowercase SHA-256 identity of the
 * canonical representation
 * @since 8.0.0
 */
public record ProtocolFinalResponseDelivery(
    Mode mode,
    String canonicalRepresentationDigest) implements Serializable {

    /** Maximum number of named canonical response attributes. */
    public static final int MAXIMUM_ATTRIBUTE_COUNT = 256;

    /** Maximum UTF-8 size of a primary response component. */
    public static final int MAXIMUM_PRIMARY_UTF8_BYTES = 262_144;

    /** Maximum UTF-8 size of a canonical attribute name. */
    public static final int MAXIMUM_ATTRIBUTE_NAME_UTF8_BYTES = 256;

    /** Maximum UTF-8 size of one canonical attribute value. */
    public static final int MAXIMUM_ATTRIBUTE_VALUE_UTF8_BYTES = 262_144;

    /** Maximum aggregate UTF-8 size of the canonical representation. */
    public static final int MAXIMUM_REPRESENTATION_UTF8_BYTES = 1_048_576;

    @Serial
    private static final long serialVersionUID = -1354112563220275881L;

    private static final String REPRESENTATION_DOMAIN =
        "cas-protocol-final-response-delivery-v1";

    private static final String ORDERED_REPRESENTATION_DOMAIN =
        "cas-protocol-final-response-delivery-ordered-v1";

    private static final Pattern SHA_256_PATTERN =
        Pattern.compile("[0-9a-f]{64}");

    public ProtocolFinalResponseDelivery {
        Objects.requireNonNull(mode, "mode");
        val digest = Objects.requireNonNull(
            canonicalRepresentationDigest,
            "canonicalRepresentationDigest");
        if (!SHA_256_PATTERN.matcher(digest).matches()) {
            throw new IllegalArgumentException(
                "canonicalRepresentationDigest must be a lowercase SHA-256 digest");
        }
    }

    /**
     * Create an exact canonical delivery identity.
     *
     * <p>The primary component is the final response target for native CAS
     * service responses and the deterministic prepared, pre-encryption value
     * for browser SSO delivery. Named attributes are sorted by key before
     * hashing. Every component is independently length-prefixed; callers must
     * not concatenate fields with delimiters.</p>
     *
     * @param mode exact delivery mode
     * @param primaryComponent final target or replayable primary component
     * @param attributes exact named response or delivery coordinates
     * @return validated secret-free delivery identity
     */
    public static ProtocolFinalResponseDelivery canonical(
        final Mode mode,
        final String primaryComponent,
        final Map<String, String> attributes) {
        val deliveryMode = Objects.requireNonNull(mode, "mode");
        val primary = requireText(
            primaryComponent,
            "primaryComponent",
            MAXIMUM_PRIMARY_UTF8_BYTES);
        val source = Objects.requireNonNull(attributes, "attributes");
        if (source.size() > MAXIMUM_ATTRIBUTE_COUNT) {
            throw new IllegalArgumentException(
                "attributes exceed the supported count");
        }

        val canonicalAttributes = new TreeMap<String, String>();
        var aggregateSize = utf8Length(primary);
        for (val entry : source.entrySet()) {
            val name = requireText(
                entry.getKey(),
                "attribute name",
                MAXIMUM_ATTRIBUTE_NAME_UTF8_BYTES);
            val value = requireText(
                entry.getValue(),
                "attribute value",
                MAXIMUM_ATTRIBUTE_VALUE_UTF8_BYTES);
            canonicalAttributes.put(name, value);
            aggregateSize = Math.addExact(
                aggregateSize,
                Math.addExact(utf8Length(name), utf8Length(value)));
        }
        if (aggregateSize > MAXIMUM_REPRESENTATION_UTF8_BYTES) {
            throw new IllegalArgumentException(
                "canonical representation exceeds its UTF-8 size limit");
        }

        try {
            val digest = MessageDigest.getInstance("SHA-256");
            putText(digest, REPRESENTATION_DOMAIN);
            putText(digest, deliveryMode.name());
            putText(digest, primary);
            putInt(digest, canonicalAttributes.size());
            canonicalAttributes.forEach((name, value) -> {
                putText(digest, name);
                putText(digest, value);
            });
            return new ProtocolFinalResponseDelivery(
                deliveryMode,
                HexFormat.of().formatHex(digest.digest()));
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                "SHA-256 is required by the Java platform", e);
        }
    }

    /**
     * Create an exact ordered delivery identity whose attribute values may be
     * {@code null}. This form is used where renderer iteration order and the
     * distinction between a missing, null, and empty value are observable.
     *
     * <p>Unlike {@link #canonical(Mode, String, Map)}, entries are hashed in
     * iteration order. Every nullable value carries an explicit presence tag,
     * so a null value cannot collide with an empty string or a text sentinel.</p>
     *
     * @param mode exact delivery mode
     * @param primaryComponent final response target
     * @param attributes exact ordered response attributes
     * @return validated secret-free delivery identity
     */
    public static ProtocolFinalResponseDelivery canonicalOrdered(
        final Mode mode,
        final String primaryComponent,
        final Map<String, String> attributes) {
        val deliveryMode = Objects.requireNonNull(mode, "mode");
        val primary = requireText(
            primaryComponent,
            "primaryComponent",
            MAXIMUM_PRIMARY_UTF8_BYTES);
        val source = Objects.requireNonNull(attributes, "attributes");
        if (source.size() > MAXIMUM_ATTRIBUTE_COUNT) {
            throw new IllegalArgumentException(
                "attributes exceed the supported count");
        }

        val canonicalAttributes = new LinkedHashMap<String, String>();
        var aggregateSize = utf8Length(primary);
        for (val entry : source.entrySet()) {
            val name = requireText(
                entry.getKey(),
                "attribute name",
                MAXIMUM_ATTRIBUTE_NAME_UTF8_BYTES);
            aggregateSize = Math.addExact(aggregateSize, utf8Length(name));
            if (entry.getValue() != null) {
                val value = requireNullableValue(entry.getValue());
                aggregateSize = Math.addExact(
                    aggregateSize, utf8Length(value));
            }
            canonicalAttributes.put(name, entry.getValue());
        }
        if (aggregateSize > MAXIMUM_REPRESENTATION_UTF8_BYTES) {
            throw new IllegalArgumentException(
                "canonical representation exceeds its UTF-8 size limit");
        }

        try {
            val digest = MessageDigest.getInstance("SHA-256");
            putText(digest, ORDERED_REPRESENTATION_DOMAIN);
            putText(digest, deliveryMode.name());
            putText(digest, primary);
            putInt(digest, canonicalAttributes.size());
            canonicalAttributes.forEach((name, value) -> {
                putText(digest, name);
                digest.update((byte) (value == null ? 0 : 1));
                if (value != null) {
                    putText(digest, value);
                }
            });
            return new ProtocolFinalResponseDelivery(
                deliveryMode,
                HexFormat.of().formatHex(digest.digest()));
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                "SHA-256 is required by the Java platform", e);
        }
    }

    @Override
    public String toString() {
        return ("ProtocolFinalResponseDelivery[mode=%s, "
                + "canonicalRepresentationDigest=[REDACTED]]")
            .formatted(mode);
    }

    private static String requireText(
        final String value,
        final String name,
        final int maximumUtf8Bytes) {
        val result = Objects.requireNonNull(value, name);
        if (result.isBlank() || !result.equals(result.strip())) {
            throw new IllegalArgumentException(
                name + " must be canonical non-blank text");
        }
        if (result.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(
                name + " cannot contain control characters");
        }
        try {
            val encoded = StandardCharsets.UTF_8.newEncoder()
                .encode(CharBuffer.wrap(result));
            if (encoded.remaining() > maximumUtf8Bytes) {
                throw new IllegalArgumentException(
                    name + " exceeds its UTF-8 size limit");
            }
        } catch (final CharacterCodingException e) {
            throw new IllegalArgumentException(
                name + " is not valid Unicode", e);
        }
        return result;
    }

    private static int utf8Length(final String value) {
        return value.getBytes(StandardCharsets.UTF_8).length;
    }

    private static String requireNullableValue(final String value) {
        try {
            val encoded = StandardCharsets.UTF_8.newEncoder()
                .encode(CharBuffer.wrap(value));
            if (encoded.remaining() > MAXIMUM_ATTRIBUTE_VALUE_UTF8_BYTES) {
                throw new IllegalArgumentException(
                    "attribute value exceeds its UTF-8 size limit");
            }
        } catch (final CharacterCodingException e) {
            throw new IllegalArgumentException(
                "attribute value is not valid Unicode", e);
        }
        if (value.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(
                "attribute value cannot contain control characters");
        }
        return value;
    }

    private static void putText(
        final MessageDigest digest,
        final String value) {
        val bytes = value.getBytes(StandardCharsets.UTF_8);
        putInt(digest, bytes.length);
        digest.update(bytes);
    }

    private static void putInt(
        final MessageDigest digest,
        final int value) {
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(value).array());
    }

    /** Exact mode used to deliver the reviewed native CAS response. */
    public enum Mode {
        /** Browser redirect to a CAS relying party. */
        REDIRECT,
        /** Browser form POST to a CAS relying party. */
        POST,
        /** Response values delivered as HTTP headers. */
        HEADER,
        /** Stateful TGT delivered as an HTTP cookie. */
        HTTP_COOKIE,
        /** Stateless TGT delivered through browser storage. */
        STATELESS_BROWSER_STORAGE
    }
}
