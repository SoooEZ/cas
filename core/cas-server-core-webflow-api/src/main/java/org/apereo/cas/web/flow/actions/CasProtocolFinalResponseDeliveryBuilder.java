package org.apereo.cas.web.flow.actions;

import module java.base;
import org.apereo.cas.authentication.principal.Response;
import org.apereo.cas.protocol.ProtocolFinalResponseDelivery;
import org.apereo.cas.protocol.ProtocolFinalResponseLogicalBinding;
import org.apereo.cas.protocol.ProtocolFinalResponsePreparedDelivery;
import org.apereo.cas.web.BrowserStorage;
import org.apereo.cas.web.cookie.CasCookieBuilder;
import org.apereo.cas.web.cookie.CookieValueManager;
import lombok.val;
import org.springframework.webflow.execution.RequestContext;

/**
 * Builds canonical native CAS delivery identities at the final webflow
 * disclosure boundary.
 *
 * <p>Raw tickets and response fields exist only long enough to calculate the
 * canonical digest. Returned values retain no response secret.</p>
 *
 * @author SoooEZ
 * @since 8.0.0
 */
public final class CasProtocolFinalResponseDeliveryBuilder {

    /** Stable browser-storage namespace used by the native TGT writer. */
    public static final String DEFAULT_BROWSER_STORAGE_CONTEXT =
        "CasBrowserStorageContext";

    /** Stable ID of the producer-owned native CAS exact-response codec. */
    public static final String PRODUCER_CODEC_ID =
        "apereo-cas-native-final-response";

    /** Version written by this release. */
    public static final int CURRENT_WRITE_CODEC_VERSION = 1;

    /** Versions accepted during replay; old readers remain until rows expire. */
    public static final Set<Integer> READABLE_CODEC_VERSIONS = Set.of(1);

    private static final int ENVELOPE_MAGIC = 0x43415346;

    private static final int ENVELOPE_TYPE_SERVICE_RESPONSE = 1;

    private static final int ENVELOPE_TYPE_HTTP_COOKIE = 2;

    private static final int ENVELOPE_TYPE_BROWSER_STORAGE = 3;

    private static final int MAXIMUM_ENUM_TEXT_BYTES = 64;

    private static final int MAXIMUM_COOKIE_NAME_BYTES = 256;

    private static final int MAXIMUM_CONFIGURATION_TEXT_BYTES = 16_384;

    private static final int INITIAL_ENVELOPE_BUFFER_BYTES = 8_192;

    private CasProtocolFinalResponseDeliveryBuilder() {
    }

    /**
     * Bind the exact immutable native service response.
     *
     * @param response final service response
     * @return canonical delivery identity
     */
    public static ProtocolFinalResponseDelivery serviceResponse(
        final Response response) {
        val value = Objects.requireNonNull(response, "response");
        val responseType = Objects.requireNonNull(
            value.responseType(), "responseType");
        val mode = switch (responseType) {
            case REDIRECT -> ProtocolFinalResponseDelivery.Mode.REDIRECT;
            case POST -> ProtocolFinalResponseDelivery.Mode.POST;
            case HEADER -> ProtocolFinalResponseDelivery.Mode.HEADER;
        };
        val sourceAttributes = Objects.requireNonNull(
            value.attributes(), "attributes");
        val canonicalAttributes = responseType == Response.ResponseType.REDIRECT
            ? sourceAttributes.entrySet()
                .stream()
                .filter(entry -> entry.getValue() != null)
                .collect(Collectors.toMap(
                    Map.Entry::getKey,
                    Map.Entry::getValue,
                    (first, second) -> first,
                    LinkedHashMap::new))
            : sourceAttributes;
        return ProtocolFinalResponseDelivery.canonicalOrdered(
            mode,
            value.url(),
            canonicalAttributes);
    }

    /**
     * Prepare the exact native CAS service response for durable replay.
     *
     * @param response final service response
     * @return canonical response identity and versioned exact envelope
     */
    public static ProtocolFinalResponsePreparedDelivery prepareServiceResponse(
        final Response response,
        final ProtocolFinalResponseLogicalBinding logicalResponseBinding) {
        val snapshot = immutableServiceResponse(response);
        val delivery = serviceResponse(snapshot);
        return prepared(
            logicalResponseBinding,
            delivery,
            ENVELOPE_TYPE_SERVICE_RESPONSE,
            output -> {
                writeText(output, snapshot.responseType().name());
                writeText(output, snapshot.url());
                writeAttributes(output, snapshot.attributes(), true);
            });
    }

    /**
     * Decode and verify an exact service response selected by the authority.
     *
     * @param preparedDelivery authorized prepared delivery
     * @return immutable exact response
     */
    public static Response decodeServiceResponse(
        final ProtocolFinalResponsePreparedDelivery preparedDelivery) {
        val prepared = requireMode(
            preparedDelivery,
            ProtocolFinalResponseDelivery.Mode.REDIRECT,
            ProtocolFinalResponseDelivery.Mode.POST,
            ProtocolFinalResponseDelivery.Mode.HEADER);
        try (val input = open(
            prepared, ENVELOPE_TYPE_SERVICE_RESPONSE)) {
            val responseType = enumValue(
                Response.ResponseType.class,
                readText(input, MAXIMUM_ENUM_TEXT_BYTES),
                "service response type");
            val url = readText(
                input,
                ProtocolFinalResponseDelivery.MAXIMUM_PRIMARY_UTF8_BYTES);
            val attributes = readAttributes(input, true);
            requireEnd(input);
            val response = new RedirectToServiceAction.ImmutableFinalResponse(
                responseType, url, attributes);
            requireExactDelivery(prepared, serviceResponse(response));
            requireCanonicalEnvelope(
                prepared,
                prepareServiceResponse(
                    response, prepared.logicalResponseBinding()));
            return response;
        } catch (final IOException e) {
            throw invalidEnvelope(e);
        }
    }

    /**
     * Bind the replayable semantic representation of a stateful TGT cookie.
     *
     * @param preparedCookie exact immutable cookie snapshot
     * @return canonical cookie delivery identity
     */
    public static ProtocolFinalResponseDelivery httpCookie(
        final CasCookieBuilder.PreparedCookie preparedCookie) {
        val prepared = Objects.requireNonNull(
            preparedCookie, "preparedCookie");
        return ProtocolFinalResponseDelivery.canonical(
            ProtocolFinalResponseDelivery.Mode.HTTP_COOKIE,
            prepared.replayValue(),
            prepared.canonicalAttributes());
    }

    /** Prepare an exact stateful TGT cookie for durable replay. */
    public static ProtocolFinalResponsePreparedDelivery prepareHttpCookie(
        final CasCookieBuilder.PreparedCookie preparedCookie,
        final ProtocolFinalResponseLogicalBinding logicalResponseBinding) {
        val cookie = Objects.requireNonNull(
            preparedCookie, "preparedCookie");
        val delivery = httpCookie(cookie);
        return prepared(
            logicalResponseBinding,
            delivery,
            ENVELOPE_TYPE_HTTP_COOKIE,
            output -> {
                writeText(output, cookie.cookieName());
                writeText(output, cookie.outputValue());
                writeText(output, cookie.replayValue());
                writeText(output, cookie.headerValue());
                writeText(output, cookie.path());
                writeNullableText(output, cookie.domain());
                output.writeInt(cookie.maxAge());
                output.writeBoolean(cookie.secure());
                output.writeBoolean(cookie.httpOnly());
                writeAttributes(
                    output, cookie.canonicalAttributes(), false);
            });
    }

    /** Decode and verify an exact stateful TGT cookie. */
    public static CasCookieBuilder.PreparedCookie decodeHttpCookie(
        final ProtocolFinalResponsePreparedDelivery preparedDelivery) {
        val prepared = requireMode(
            preparedDelivery,
            ProtocolFinalResponseDelivery.Mode.HTTP_COOKIE);
        try (val input = open(prepared, ENVELOPE_TYPE_HTTP_COOKIE)) {
            val cookie = new CasCookieBuilder.PreparedCookie(
                readText(input, MAXIMUM_COOKIE_NAME_BYTES),
                readText(input,
                    ProtocolFinalResponsePreparedDelivery
                        .MAXIMUM_PAYLOAD_BYTES),
                readText(input,
                    ProtocolFinalResponseDelivery.MAXIMUM_PRIMARY_UTF8_BYTES),
                readText(input,
                    ProtocolFinalResponsePreparedDelivery
                        .MAXIMUM_PAYLOAD_BYTES),
                readText(input, MAXIMUM_CONFIGURATION_TEXT_BYTES),
                readNullableText(
                    input, MAXIMUM_CONFIGURATION_TEXT_BYTES),
                input.readInt(),
                readCanonicalBoolean(input),
                readCanonicalBoolean(input),
                readAttributes(input, false));
            requireEnd(input);
            requireExactDelivery(prepared, httpCookie(cookie));
            requireCanonicalEnvelope(
                prepared,
                prepareHttpCookie(
                    cookie, prepared.logicalResponseBinding()));
            return cookie;
        } catch (final IOException e) {
            throw invalidEnvelope(e);
        }
    }

    /**
     * Bind the replayable semantic representation of a stateless TGT browser
     * storage response.
     *
     * @param cookieBuilder cookie-value configuration
     * @param preparedValue exact immutable cookie-value snapshot
     * @param storageType exact local/session storage selection
     * @param storageContext exact browser-storage namespace
     * @return canonical browser-storage delivery identity
     */
    public static ProtocolFinalResponseDelivery statelessBrowserStorage(
        final CasCookieBuilder cookieBuilder,
        final CookieValueManager.PreparedCookieValue preparedValue,
        final BrowserStorage.BrowserStorageTypes storageType,
        final String storageContext) {
        val builder = Objects.requireNonNull(cookieBuilder, "cookieBuilder");
        return statelessBrowserStorage(
            builder.getCookieName(),
            preparedValue,
            storageType,
            storageContext);
    }

    private static ProtocolFinalResponseDelivery statelessBrowserStorage(
        final String cookieName,
        final CookieValueManager.PreparedCookieValue preparedValue,
        final BrowserStorage.BrowserStorageTypes storageType,
        final String storageContext) {
        val prepared = Objects.requireNonNull(
            preparedValue, "preparedValue");
        return ProtocolFinalResponseDelivery.canonical(
            ProtocolFinalResponseDelivery.Mode.STATELESS_BROWSER_STORAGE,
            prepared.replayValue(),
            Map.of(
                "cookie_name", Objects.requireNonNull(
                    cookieName, "cookieName"),
                "output_value_sha256", prepared.outputValueDigest(),
                "storage_context", Objects.requireNonNull(
                    storageContext, "storageContext"),
                "storage_type", Objects.requireNonNull(
                    storageType, "storageType").name()));
    }

    /** Prepare exact stateless TGT browser-storage output for durable replay. */
    public static ProtocolFinalResponsePreparedDelivery
        prepareStatelessBrowserStorage(
            final CasCookieBuilder cookieBuilder,
            final CookieValueManager.PreparedCookieValue preparedValue,
            final BrowserStorage.BrowserStorageTypes storageType,
            final String storageContext,
            final ProtocolFinalResponseLogicalBinding
                logicalResponseBinding) {
        val builder = Objects.requireNonNull(cookieBuilder, "cookieBuilder");
        val value = Objects.requireNonNull(preparedValue, "preparedValue");
        val type = Objects.requireNonNull(storageType, "storageType");
        val context = Objects.requireNonNull(storageContext, "storageContext");
        val cookieName = Objects.requireNonNull(
            builder.getCookieName(), "cookieName");
        return prepareStatelessBrowserStorage(
            cookieName,
            value,
            type,
            context,
            logicalResponseBinding);
    }

    private static ProtocolFinalResponsePreparedDelivery
        prepareStatelessBrowserStorage(
            final String cookieName,
            final CookieValueManager.PreparedCookieValue preparedValue,
            final BrowserStorage.BrowserStorageTypes storageType,
            final String storageContext,
            final ProtocolFinalResponseLogicalBinding
                logicalResponseBinding) {
        val delivery = statelessBrowserStorage(
            cookieName, preparedValue, storageType, storageContext);
        return prepared(
            logicalResponseBinding,
            delivery,
            ENVELOPE_TYPE_BROWSER_STORAGE,
            output -> {
                writeText(output, cookieName);
                writeText(output, preparedValue.outputValue());
                writeText(output, preparedValue.replayValue());
                writeText(output, storageType.name());
                writeText(output, storageContext);
            });
    }

    /** Decode and verify exact stateless TGT browser-storage output. */
    public static PreparedBrowserStorage decodeStatelessBrowserStorage(
        final ProtocolFinalResponsePreparedDelivery preparedDelivery) {
        val prepared = requireMode(
            preparedDelivery,
            ProtocolFinalResponseDelivery.Mode.STATELESS_BROWSER_STORAGE);
        try (val input = open(
            prepared, ENVELOPE_TYPE_BROWSER_STORAGE)) {
            val cookieName = readText(input, MAXIMUM_COOKIE_NAME_BYTES);
            val value = new CookieValueManager.PreparedCookieValue(
                readText(input,
                    ProtocolFinalResponsePreparedDelivery
                        .MAXIMUM_PAYLOAD_BYTES),
                readText(input,
                    ProtocolFinalResponseDelivery.MAXIMUM_PRIMARY_UTF8_BYTES));
            val storageType = enumValue(
                BrowserStorage.BrowserStorageTypes.class,
                readText(input, MAXIMUM_ENUM_TEXT_BYTES),
                "browser storage type");
            val storageContext = readText(
                input, MAXIMUM_CONFIGURATION_TEXT_BYTES);
            requireEnd(input);
            val decoded = new PreparedBrowserStorage(
                cookieName, value, storageType, storageContext);
            requireExactDelivery(
                prepared,
                statelessBrowserStorage(
                    decoded.cookieName(),
                    decoded.preparedValue(),
                    decoded.storageType(),
                    decoded.storageContext()));
            requireCanonicalEnvelope(
                prepared,
                prepareStatelessBrowserStorage(
                    decoded.cookieName(),
                    decoded.preparedValue(),
                    decoded.storageType(),
                    decoded.storageContext(),
                    prepared.logicalResponseBinding()));
            return decoded;
        } catch (final IOException e) {
            throw invalidEnvelope(e);
        }
    }

    /**
     * Resolve the exact storage type used by native browser-storage actions.
     *
     * @param requestContext current request context
     * @return exact storage type
     */
    public static BrowserStorage.BrowserStorageTypes browserStorageType(
        final RequestContext requestContext) {
        val requestScope = Objects.requireNonNull(
            requestContext, "requestContext").getRequestScope();
        if (requestScope.contains(
            BrowserStorage.BrowserStorageTypes.class.getSimpleName())) {
            val requiredType = requestScope.getRequiredString(
                BrowserStorage.BrowserStorageTypes.class.getSimpleName());
            return BrowserStorage.BrowserStorageTypes.valueOf(
                requiredType.toUpperCase(Locale.ENGLISH));
        }
        return BrowserStorage.BrowserStorageTypes.LOCAL;
    }

    private static Response immutableServiceResponse(final Response response) {
        val value = Objects.requireNonNull(response, "response");
        return new RedirectToServiceAction.ImmutableFinalResponse(
            Objects.requireNonNull(value.responseType(), "responseType"),
            Objects.requireNonNull(value.url(), "response url"),
            value.attributes());
    }

    private static ProtocolFinalResponsePreparedDelivery prepared(
        final ProtocolFinalResponseLogicalBinding logicalResponseBinding,
        final ProtocolFinalResponseDelivery delivery,
        final int type,
        final EnvelopeWriter writer) {
        try {
            val bytes = new BoundedByteArrayOutputStream(
                ProtocolFinalResponsePreparedDelivery.MAXIMUM_PAYLOAD_BYTES);
            try (val output = new DataOutputStream(bytes)) {
                output.writeInt(ENVELOPE_MAGIC);
                output.writeInt(CURRENT_WRITE_CODEC_VERSION);
                output.writeInt(type);
                writer.write(output);
            }
            return new ProtocolFinalResponsePreparedDelivery(
                Objects.requireNonNull(
                    logicalResponseBinding, "logicalResponseBinding"),
                delivery,
                PRODUCER_CODEC_ID,
                CURRENT_WRITE_CODEC_VERSION,
                Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(bytes.toByteArray()));
        } catch (final IOException e) {
            throw new IllegalStateException(
                "Unable to encode the exact final response", e);
        }
    }

    private static DataInputStream open(
        final ProtocolFinalResponsePreparedDelivery preparedDelivery,
        final int expectedType) throws IOException {
        if (!PRODUCER_CODEC_ID.equals(
            preparedDelivery.producerCodecId())
            || !READABLE_CODEC_VERSIONS.contains(
                preparedDelivery.producerCodecVersion())) {
            throw new IOException(
                "Unsupported exact final-response producer codec");
        }
        val input = new DataInputStream(new ByteArrayInputStream(
            preparedDelivery.decodedPayload()));
        if (input.readInt() != ENVELOPE_MAGIC
            || input.readInt()
                != preparedDelivery.producerCodecVersion()
            || input.readInt() != expectedType) {
            throw new IOException("Unsupported exact final-response envelope");
        }
        return input;
    }

    private static void writeAttributes(
        final DataOutputStream output,
        final Map<String, String> attributes,
        final boolean preserveOrder) throws IOException {
        val source = Objects.requireNonNull(attributes, "attributes");
        if (source.size()
            > ProtocolFinalResponseDelivery.MAXIMUM_ATTRIBUTE_COUNT) {
            throw new IllegalArgumentException(
                "attributes exceed the supported count");
        }
        val entries = preserveOrder
            ? source.entrySet()
            : new TreeMap<>(source).entrySet();
        output.writeInt(entries.size());
        for (val entry : entries) {
            writeText(output, Objects.requireNonNull(
                entry.getKey(), "attribute name"));
            writeNullableText(output, entry.getValue());
        }
    }

    private static Map<String, String> readAttributes(
        final DataInputStream input,
        final boolean preserveOrder) throws IOException {
        val count = input.readInt();
        if (count < 0
            || count > ProtocolFinalResponseDelivery.MAXIMUM_ATTRIBUTE_COUNT) {
            throw new IOException("Invalid exact response attribute count");
        }
        val attributes = preserveOrder
            ? new LinkedHashMap<String, String>()
            : new TreeMap<String, String>();
        for (var index = 0; index < count; index++) {
            val name = readText(
                input,
                ProtocolFinalResponseDelivery
                    .MAXIMUM_ATTRIBUTE_NAME_UTF8_BYTES);
            val previous = attributes.put(
                name,
                readNullableText(
                    input,
                    ProtocolFinalResponseDelivery
                        .MAXIMUM_ATTRIBUTE_VALUE_UTF8_BYTES));
            if (previous != null || attributes.size() != index + 1) {
                throw new IOException(
                    "Duplicate exact response attribute name");
            }
        }
        return attributes;
    }

    private static void writeText(
        final DataOutputStream output,
        final String value) throws IOException {
        val text = Objects.requireNonNull(value, "value");
        if (text.length()
            > ProtocolFinalResponsePreparedDelivery.MAXIMUM_PAYLOAD_BYTES) {
            throw new IllegalArgumentException(
                "Exact response text exceeds its size limit");
        }
        val bytes = encodeUtf8(text);
        if (bytes.length
            > ProtocolFinalResponsePreparedDelivery.MAXIMUM_PAYLOAD_BYTES) {
            throw new IllegalArgumentException(
                "Exact response text exceeds its UTF-8 size limit");
        }
        output.writeInt(bytes.length);
        output.write(bytes);
    }

    private static void writeNullableText(
        final DataOutputStream output,
        final String value) throws IOException {
        output.writeBoolean(value != null);
        if (value != null) {
            writeText(output, value);
        }
    }

    private static String readText(
        final DataInputStream input,
        final int maximumBytes) throws IOException {
        val length = input.readInt();
        if (length < 0 || length > maximumBytes
            || length > input.available()) {
            throw new IOException("Invalid exact response text length");
        }
        val bytes = input.readNBytes(length);
        if (bytes.length != length) {
            throw new EOFException("Truncated exact response text");
        }
        try {
            return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString();
        } catch (final CharacterCodingException e) {
            throw new IOException("Invalid UTF-8 in exact response", e);
        }
    }

    private static String readNullableText(
        final DataInputStream input,
        final int maximumBytes) throws IOException {
        return readCanonicalBoolean(input)
            ? readText(input, maximumBytes)
            : null;
    }

    private static boolean readCanonicalBoolean(
        final DataInputStream input) throws IOException {
        val value = input.readUnsignedByte();
        if (value != 0 && value != 1) {
            throw new IOException("Invalid exact response boolean");
        }
        return value == 1;
    }

    private static byte[] encodeUtf8(final String value) {
        try {
            val encoded = StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .encode(CharBuffer.wrap(value));
            val bytes = new byte[encoded.remaining()];
            encoded.get(bytes);
            return bytes;
        } catch (final CharacterCodingException e) {
            throw new IllegalArgumentException(
                "Exact response contains invalid Unicode", e);
        }
    }

    private static <T extends Enum<T>> T enumValue(
        final Class<T> type,
        final String value,
        final String name) throws IOException {
        try {
            return Enum.valueOf(type, value);
        } catch (final IllegalArgumentException e) {
            throw new IOException("Invalid " + name, e);
        }
    }

    private static void requireEnd(
        final DataInputStream input) throws IOException {
        if (input.available() != 0) {
            throw new IOException(
                "Trailing bytes in exact final-response envelope");
        }
    }

    private static ProtocolFinalResponsePreparedDelivery requireMode(
        final ProtocolFinalResponsePreparedDelivery preparedDelivery,
        final ProtocolFinalResponseDelivery.Mode... allowedModes) {
        val prepared = Objects.requireNonNull(
            preparedDelivery, "preparedDelivery");
        if (Arrays.stream(allowedModes)
            .noneMatch(prepared.delivery().mode()::equals)) {
            throw new IllegalArgumentException(
                "Prepared delivery has an incompatible response mode");
        }
        return prepared;
    }

    private static void requireExactDelivery(
        final ProtocolFinalResponsePreparedDelivery preparedDelivery,
        final ProtocolFinalResponseDelivery decodedDelivery) {
        if (!preparedDelivery.delivery().equals(decodedDelivery)) {
            throw new IllegalArgumentException(
                "Prepared delivery payload does not match its identity");
        }
    }

    private static void requireCanonicalEnvelope(
        final ProtocolFinalResponsePreparedDelivery preparedDelivery,
        final ProtocolFinalResponsePreparedDelivery canonicalDelivery) {
        if (!preparedDelivery.logicalResponseBinding().equals(
            canonicalDelivery.logicalResponseBinding())
            || !preparedDelivery.delivery().equals(
                canonicalDelivery.delivery())
            || !preparedDelivery.producerCodecId().equals(
                canonicalDelivery.producerCodecId())
            || preparedDelivery.producerCodecVersion()
                != canonicalDelivery.producerCodecVersion()
            || !MessageDigest.isEqual(
                preparedDelivery.decodedPayload(),
                canonicalDelivery.decodedPayload())) {
            throw new IllegalArgumentException(
                "Exact final-response envelope is not canonical");
        }
    }

    private static IllegalArgumentException invalidEnvelope(
        final IOException cause) {
        return new IllegalArgumentException(
            "Invalid exact final-response envelope", cause);
    }

    private static final class BoundedByteArrayOutputStream
        extends ByteArrayOutputStream {

        private final int maximumBytes;

        BoundedByteArrayOutputStream(final int maximumBytes) {
            super(Math.min(maximumBytes, INITIAL_ENVELOPE_BUFFER_BYTES));
            if (maximumBytes <= 0) {
                throw new IllegalArgumentException(
                    "maximumBytes must be positive");
            }
            this.maximumBytes = maximumBytes;
        }

        @Override
        public synchronized void write(final int value) {
            requireCapacity(1);
            super.write(value);
        }

        @Override
        public synchronized void write(
            final byte[] values,
            final int offset,
            final int length) {
            Objects.checkFromIndexSize(offset, length, values.length);
            requireCapacity(length);
            super.write(values, offset, length);
        }

        private void requireCapacity(final int additionalBytes) {
            if (additionalBytes > maximumBytes - count) {
                throw new IllegalArgumentException(
                    "Exact final-response envelope exceeds its size limit");
            }
        }
    }

    /** Exact decoded stateless browser-storage response. */
    public record PreparedBrowserStorage(
        String cookieName,
        CookieValueManager.PreparedCookieValue preparedValue,
        BrowserStorage.BrowserStorageTypes storageType,
        String storageContext) implements Serializable {

        @Serial
        private static final long serialVersionUID = -7563818257664085184L;

        public PreparedBrowserStorage {
            Objects.requireNonNull(cookieName, "cookieName");
            Objects.requireNonNull(preparedValue, "preparedValue");
            Objects.requireNonNull(storageType, "storageType");
            Objects.requireNonNull(storageContext, "storageContext");
        }

        @Override
        public String toString() {
            return ("PreparedBrowserStorage[storageType=%s, "
                    + "response=[REDACTED]]")
                .formatted(storageType);
        }
    }

    @FunctionalInterface
    private interface EnvelopeWriter {
        void write(DataOutputStream output) throws IOException;
    }
}
