package org.apereo.cas.protocol;

import module java.base;
import lombok.val;

/**
 * Stable, secret-free identity of one logical protocol response.
 *
 * <p>The binding excludes randomized delivery bytes but includes every
 * security coordinate that determines which capability may be disclosed to
 * which subject and relying party. It therefore remains stable across a retry
 * while preventing a same-mode response from another user or relying party
 * from being substituted during durable replay.</p>
 *
 * @author SoooEZ
 * @param digest lowercase SHA-256 digest of the logical response coordinates
 * @since 8.0.0
 */
public record ProtocolFinalResponseLogicalBinding(String digest)
    implements Serializable {

    @Serial
    private static final long serialVersionUID = -8122691759228986161L;

    private static final String BINDING_DOMAIN =
        "cas-protocol-final-response-logical-binding-v1";

    private static final Pattern SHA_256_PATTERN =
        Pattern.compile("[0-9a-f]{64}");

    public ProtocolFinalResponseLogicalBinding {
        val value = Objects.requireNonNull(digest, "digest");
        if (!SHA_256_PATTERN.matcher(value).matches()) {
            throw new IllegalArgumentException(
                "digest must be a lowercase SHA-256 digest");
        }
    }

    /**
     * Derive a stable binding from the complete logical response authority.
     *
     * @param protocol protocol family
     * @param responseType response boundary
     * @param relyingPartyId optional relying-party identifier
     * @param subjectId optional subject identifier
     * @param capabilities exact capabilities being disclosed
     * @return stable logical response binding
     */
    public static ProtocolFinalResponseLogicalBinding of(
        final ProtocolFinalResponseContext.Protocol protocol,
        final ProtocolFinalResponseContext.ResponseType responseType,
        final String relyingPartyId,
        final String subjectId,
        final List<ProtocolFinalResponseCapability> capabilities) {
        val source = Objects.requireNonNull(capabilities, "capabilities");
        if (source.isEmpty() || source.stream().anyMatch(Objects::isNull)) {
            throw new IllegalArgumentException(
                "capabilities must contain at least one non-null entry");
        }
        val values = List.copyOf(source);
        try {
            val digest = MessageDigest.getInstance("SHA-256");
            putText(digest, BINDING_DOMAIN);
            putText(digest, Objects.requireNonNull(
                protocol, "protocol").name());
            putText(digest, Objects.requireNonNull(
                responseType, "responseType").name());
            putNullableText(digest, normalize(relyingPartyId));
            putNullableText(digest, normalize(subjectId));
            putInt(digest, values.size());
            values.forEach(capability -> {
                putText(digest, capability.type().name());
                putText(digest, capability.reference());
                putNullableText(digest, capability.subjectId());
                putNullableLong(digest, capability.generation());
                putNullableText(digest, capability.intentId());
            });
            return new ProtocolFinalResponseLogicalBinding(
                HexFormat.of().formatHex(digest.digest()));
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                "SHA-256 is required by the Java platform", e);
        }
    }

    @Override
    public String toString() {
        return "ProtocolFinalResponseLogicalBinding[digest=[REDACTED]]";
    }

    private static String normalize(final String value) {
        if (value == null) {
            return null;
        }
        val normalized = value.trim();
        return normalized.isEmpty() ? null : normalized;
    }

    private static void putNullableText(
        final MessageDigest digest,
        final String value) {
        digest.update((byte) (value == null ? 0 : 1));
        if (value != null) {
            putText(digest, value);
        }
    }

    private static void putNullableLong(
        final MessageDigest digest,
        final Long value) {
        digest.update((byte) (value == null ? 0 : 1));
        if (value != null) {
            digest.update(ByteBuffer.allocate(Long.BYTES)
                .putLong(value).array());
        }
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
        digest.update(ByteBuffer.allocate(Integer.BYTES)
            .putInt(value).array());
    }
}
