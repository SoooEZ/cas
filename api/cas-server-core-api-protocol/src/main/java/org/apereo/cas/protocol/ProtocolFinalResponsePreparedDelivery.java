package org.apereo.cas.protocol;

import module java.base;
import lombok.val;

/**
 * Opaque, exact final-response bytes prepared before durable authorization.
 *
 * <p>The payload is canonical URL-safe Base64 without padding. Its decoded
 * bytes are deliberately opaque to the protocol authority: a producer owns
 * the versioned codec and must decode and revalidate the resulting delivery
 * identity before disclosure. This object may cross a durable authority
 * boundary, so diagnostics never expose the payload or either digest.</p>
 *
 * @author SoooEZ
 * @param logicalResponseBinding stable identity of the logical response
 * @param delivery secret-free identity of the represented response
 * @param producerCodecId stable producer-owned codec identifier
 * @param producerCodecVersion positive producer-owned codec version
 * @param payload canonical URL-safe Base64 encoded response envelope
 * @since 8.0.0
 */
public record ProtocolFinalResponsePreparedDelivery(
    ProtocolFinalResponseLogicalBinding logicalResponseBinding,
    ProtocolFinalResponseDelivery delivery,
    String producerCodecId,
    int producerCodecVersion,
    String payload) implements Serializable {

    /** Maximum decoded size of one exact replay envelope. */
    public static final int MAXIMUM_PAYLOAD_BYTES = 1_048_576;

    /** Maximum URL-safe Base64 characters for the decoded payload bound. */
    public static final int MAXIMUM_PAYLOAD_BASE64_CHARACTERS =
        Math.multiplyExact(
            Math.floorDiv(MAXIMUM_PAYLOAD_BYTES + 2, 3), 4);

    @Serial
    private static final long serialVersionUID = -2826090207104854908L;

    private static final String PAYLOAD_DOMAIN =
        "cas-protocol-final-response-prepared-payload-v1";

    private static final Pattern CODEC_ID_PATTERN =
        Pattern.compile("[a-z][a-z0-9.-]{0,127}");

    public ProtocolFinalResponsePreparedDelivery {
        Objects.requireNonNull(
            logicalResponseBinding, "logicalResponseBinding");
        Objects.requireNonNull(delivery, "delivery");
        Objects.requireNonNull(producerCodecId, "producerCodecId");
        Objects.requireNonNull(payload, "payload");
        if (!CODEC_ID_PATTERN.matcher(producerCodecId).matches()) {
            throw new IllegalArgumentException(
                "producerCodecId must be a canonical lowercase identifier");
        }
        if (producerCodecVersion <= 0) {
            throw new IllegalArgumentException(
                "producerCodecVersion must be positive");
        }
        if (payload.isEmpty() || !payload.equals(payload.strip())
            || payload.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(
                "payload must be canonical non-blank text");
        }
        if (payload.length() > MAXIMUM_PAYLOAD_BASE64_CHARACTERS) {
            throw new IllegalArgumentException(
                "payload is outside the supported size range");
        }
        val decoded = decodeCanonical(payload);
        if (decoded.length == 0
            || decoded.length > MAXIMUM_PAYLOAD_BYTES) {
            throw new IllegalArgumentException(
                "payload is outside the supported size range");
        }
    }

    /**
     * Domain-separated SHA-256 binding of the exact payload and delivery.
     *
     * @return lowercase exact payload digest
     */
    public String payloadDigest() {
        try {
            val digest = MessageDigest.getInstance("SHA-256");
            putText(digest, PAYLOAD_DOMAIN);
            putText(digest, logicalResponseBinding.digest());
            putText(digest, delivery.mode().name());
            putText(digest, delivery.canonicalRepresentationDigest());
            putText(digest, producerCodecId);
            digest.update(ByteBuffer.allocate(Integer.BYTES)
                .putInt(producerCodecVersion).array());
            val decoded = decodeCanonical(payload);
            digest.update(ByteBuffer.allocate(Integer.BYTES)
                .putInt(decoded.length).array());
            digest.update(decoded);
            return HexFormat.of().formatHex(digest.digest());
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                "SHA-256 is required by the Java platform", e);
        }
    }

    /** Decode the canonical opaque envelope for its owning producer. */
    public byte[] decodedPayload() {
        return decodeCanonical(payload);
    }

    @Override
    public String toString() {
        return ("ProtocolFinalResponsePreparedDelivery[mode=%s, "
                + "logicalResponseBinding=[REDACTED], codec=%s:%d, "
                + "delivery=[REDACTED], payload=[REDACTED]]")
            .formatted(delivery.mode(), producerCodecId,
                producerCodecVersion);
    }

    private static byte[] decodeCanonical(final String value) {
        final byte[] decoded;
        try {
            decoded = Base64.getUrlDecoder().decode(value);
        } catch (final IllegalArgumentException e) {
            throw new IllegalArgumentException(
                "payload must be URL-safe Base64", e);
        }
        if (!Base64.getUrlEncoder().withoutPadding()
            .encodeToString(decoded).equals(value)) {
            throw new IllegalArgumentException(
                "payload must use canonical URL-safe Base64 without padding");
        }
        return decoded;
    }

    private static void putText(
        final MessageDigest digest,
        final String value) {
        val bytes = value.getBytes(StandardCharsets.UTF_8);
        digest.update(ByteBuffer.allocate(Integer.BYTES)
            .putInt(bytes.length).array());
        digest.update(bytes);
    }
}
