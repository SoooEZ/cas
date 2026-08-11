package org.apereo.cas.web.flow.actions;

import module java.base;
import org.apereo.cas.authentication.principal.Response;
import org.apereo.cas.protocol.ProtocolFinalResponseCapability;
import org.apereo.cas.protocol.ProtocolFinalResponseContext;
import org.apereo.cas.protocol.ProtocolFinalResponseDelivery;
import org.apereo.cas.protocol.ProtocolFinalResponseLogicalBinding;
import org.apereo.cas.protocol.ProtocolFinalResponsePreparedDelivery;
import org.apereo.cas.web.BrowserStorage;
import org.apereo.cas.web.cookie.CasCookieBuilder;
import org.apereo.cas.web.cookie.CookieValueManager;
import lombok.val;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Direct compatibility and adversarial tests for the native final-response
 * envelope codec.
 *
 * @author SoooEZ
 * @since 8.0.0
 */
@Tag("WebflowActions")
class CasProtocolFinalResponseDeliveryBuilderTests {

    private static final int ENVELOPE_MAGIC = 0x43415346;

    private static final int SERVICE_RESPONSE_TYPE = 1;

    private static final int HTTP_COOKIE_TYPE = 2;

    private static final int HEADER_BYTES = Integer.BYTES * 3;

    private static final ProtocolFinalResponseLogicalBinding TEST_BINDING =
        new ProtocolFinalResponseLogicalBinding("a".repeat(64));

    @Test
    void verifyServiceResponseRoundTripPreservesNullAndOrder()
        throws Exception {
        val attributes = new LinkedHashMap<String, String>();
        attributes.put("first", "one");
        attributes.put("nullable", null);
        attributes.put("third", "three");
        val response = new RedirectToServiceAction.ImmutableFinalResponse(
            Response.ResponseType.POST,
            "https://service.example/login",
            attributes);

        val prepared = CasProtocolFinalResponseDeliveryBuilder
            .prepareServiceResponse(response, TEST_BINDING);
        val decoded = CasProtocolFinalResponseDeliveryBuilder
            .decodeServiceResponse(prepared);

        assertEquals(response.responseType(), decoded.responseType());
        assertEquals(response.url(), decoded.url());
        assertEquals(
            new ArrayList<>(response.attributes().entrySet()),
            new ArrayList<>(decoded.attributes().entrySet()));
        assertEquals(TEST_BINDING, prepared.logicalResponseBinding());
        assertEquals(
            CasProtocolFinalResponseDeliveryBuilder.PRODUCER_CODEC_ID,
            prepared.producerCodecId());
        assertEquals(
            CasProtocolFinalResponseDeliveryBuilder
                .CURRENT_WRITE_CODEC_VERSION,
            prepared.producerCodecVersion());
    }

    @Test
    void verifyHttpCookieRoundTripPreservesExactOutput() {
        val cookie = preparedCookie();
        val prepared = CasProtocolFinalResponseDeliveryBuilder
            .prepareHttpCookie(cookie, TEST_BINDING);

        assertEquals(cookie,
            CasProtocolFinalResponseDeliveryBuilder
                .decodeHttpCookie(prepared));
    }

    @Test
    void verifyBrowserStorageRoundTripPreservesExactOutput() {
        val value = new CookieValueManager.PreparedCookieValue(
            "ciphertext-v1", "stable-replay-v1");
        val prepared = CasProtocolFinalResponseDeliveryBuilder
            .prepareStatelessBrowserStorage(
                cookieBuilder("TGC"),
                value,
                BrowserStorage.BrowserStorageTypes.SESSION,
                "tenant-storage-context",
                TEST_BINDING);

        val decoded = CasProtocolFinalResponseDeliveryBuilder
            .decodeStatelessBrowserStorage(prepared);
        assertEquals("TGC", decoded.cookieName());
        assertEquals(value, decoded.preparedValue());
        assertEquals(BrowserStorage.BrowserStorageTypes.SESSION,
            decoded.storageType());
        assertEquals("tenant-storage-context", decoded.storageContext());
    }

    @Test
    void verifyRedirectNullAttributeAliasIsRejected() throws Exception {
        val attributes = new LinkedHashMap<String, String>();
        attributes.put("ticket", "ST-1");
        val response = new RedirectToServiceAction.ImmutableFinalResponse(
            Response.ResponseType.REDIRECT,
            "https://service.example/login?ticket=ST-1",
            attributes);
        val prepared = CasProtocolFinalResponseDeliveryBuilder
            .prepareServiceResponse(response, TEST_BINDING);
        val alias = serviceEnvelope(
            response.responseType(),
            response.url(),
            List.of(
                entry("ticket", "ST-1"),
                entry("ignored", null)));

        assertThrows(IllegalArgumentException.class, () ->
            CasProtocolFinalResponseDeliveryBuilder.decodeServiceResponse(
                withPayload(prepared, alias)));
    }

    @Test
    void verifyCookieAttributeOrderAliasIsRejected() throws Exception {
        val cookie = preparedCookie();
        val prepared = CasProtocolFinalResponseDeliveryBuilder
            .prepareHttpCookie(cookie, TEST_BINDING);
        val reverseOrderedAttributes = cookie.canonicalAttributes()
            .entrySet()
            .stream()
            .sorted(Map.Entry.<String, String>comparingByKey().reversed())
            .map(current -> entry(current.getKey(), current.getValue()))
            .toList();
        val alias = cookieEnvelope(
            cookie,
            reverseOrderedAttributes,
            1,
            cookie.secure() ? 1 : 0,
            cookie.httpOnly() ? 1 : 0);

        assertThrows(IllegalArgumentException.class, () ->
            CasProtocolFinalResponseDeliveryBuilder.decodeHttpCookie(
                withPayload(prepared, alias)));
    }

    @Test
    void verifyWrongMagicIsRejected() {
        val prepared = preparedServiceResponse();
        val corrupted = replaceInt(
            prepared.decodedPayload(), 0, ENVELOPE_MAGIC ^ 1);

        assertThrows(IllegalArgumentException.class, () ->
            CasProtocolFinalResponseDeliveryBuilder.decodeServiceResponse(
                withPayload(prepared, corrupted)));
    }

    @Test
    void verifyWrongEnvelopeVersionIsRejected() {
        val prepared = preparedServiceResponse();
        val corrupted = replaceInt(
            prepared.decodedPayload(),
            Integer.BYTES,
            CasProtocolFinalResponseDeliveryBuilder
                .CURRENT_WRITE_CODEC_VERSION + 1);

        assertThrows(IllegalArgumentException.class, () ->
            CasProtocolFinalResponseDeliveryBuilder.decodeServiceResponse(
                withPayload(prepared, corrupted)));
    }

    @Test
    void verifyWrongEnvelopeTypeIsRejected() {
        val prepared = preparedServiceResponse();
        val corrupted = replaceInt(
            prepared.decodedPayload(), Integer.BYTES * 2, HTTP_COOKIE_TYPE);

        assertThrows(IllegalArgumentException.class, () ->
            CasProtocolFinalResponseDeliveryBuilder.decodeServiceResponse(
                withPayload(prepared, corrupted)));
    }

    @Test
    void verifyTruncatedEnvelopeIsRejected() {
        val prepared = preparedServiceResponse();
        val payload = prepared.decodedPayload();
        val truncated = Arrays.copyOf(payload, payload.length - 1);

        assertThrows(IllegalArgumentException.class, () ->
            CasProtocolFinalResponseDeliveryBuilder.decodeServiceResponse(
                withPayload(prepared, truncated)));
    }

    @Test
    void verifyNegativeTextLengthIsRejectedBeforeAllocation() {
        val prepared = preparedServiceResponse();
        val corrupted = replaceInt(
            prepared.decodedPayload(), HEADER_BYTES, -1);

        assertThrows(IllegalArgumentException.class, () ->
            CasProtocolFinalResponseDeliveryBuilder.decodeServiceResponse(
                withPayload(prepared, corrupted)));
    }

    @Test
    void verifyInvalidUtf8IsRejected() {
        val prepared = preparedServiceResponse();
        val corrupted = prepared.decodedPayload();
        corrupted[HEADER_BYTES + Integer.BYTES] = (byte) 0xC3;
        corrupted[HEADER_BYTES + Integer.BYTES + 1] = 0x28;

        assertThrows(IllegalArgumentException.class, () ->
            CasProtocolFinalResponseDeliveryBuilder.decodeServiceResponse(
                withPayload(prepared, corrupted)));
    }

    @Test
    void verifyNonCanonicalBooleanIsRejected() throws Exception {
        val cookie = preparedCookie();
        val prepared = CasProtocolFinalResponseDeliveryBuilder
            .prepareHttpCookie(cookie, TEST_BINDING);
        val attributes = cookie.canonicalAttributes()
            .entrySet()
            .stream()
            .sorted(Map.Entry.comparingByKey())
            .map(current -> entry(current.getKey(), current.getValue()))
            .toList();
        val corrupted = cookieEnvelope(
            cookie,
            attributes,
            2,
            cookie.secure() ? 1 : 0,
            cookie.httpOnly() ? 1 : 0);

        assertThrows(IllegalArgumentException.class, () ->
            CasProtocolFinalResponseDeliveryBuilder.decodeHttpCookie(
                withPayload(prepared, corrupted)));
    }

    @Test
    void verifyTrailingBytesAreRejected() {
        val prepared = preparedServiceResponse();
        val payload = prepared.decodedPayload();
        val withTrailingByte = Arrays.copyOf(payload, payload.length + 1);
        withTrailingByte[withTrailingByte.length - 1] = 1;

        assertThrows(IllegalArgumentException.class, () ->
            CasProtocolFinalResponseDeliveryBuilder.decodeServiceResponse(
                withPayload(prepared, withTrailingByte)));
    }

    @Test
    void verifyDeliveryMismatchIsRejected() {
        val prepared = preparedServiceResponse();
        val changedDelivery = new ProtocolFinalResponseDelivery(
            prepared.delivery().mode(), "f".repeat(64));
        val mismatched = withMetadata(
            prepared,
            prepared.logicalResponseBinding(),
            changedDelivery,
            prepared.producerCodecId(),
            prepared.producerCodecVersion(),
            prepared.decodedPayload());

        assertThrows(IllegalArgumentException.class, () ->
            CasProtocolFinalResponseDeliveryBuilder
                .decodeServiceResponse(mismatched));
    }

    @Test
    void verifyIncompatibleDeliveryModeIsRejected() {
        val prepared = preparedServiceResponse();
        val wrongMode = new ProtocolFinalResponseDelivery(
            ProtocolFinalResponseDelivery.Mode.HTTP_COOKIE,
            prepared.delivery().canonicalRepresentationDigest());
        val mismatched = withMetadata(
            prepared,
            prepared.logicalResponseBinding(),
            wrongMode,
            prepared.producerCodecId(),
            prepared.producerCodecVersion(),
            prepared.decodedPayload());

        assertThrows(IllegalArgumentException.class, () ->
            CasProtocolFinalResponseDeliveryBuilder
                .decodeServiceResponse(mismatched));
    }

    @Test
    void verifyWrongProducerCodecIsRejected() {
        val prepared = preparedServiceResponse();
        val wrongCodec = withMetadata(
            prepared,
            prepared.logicalResponseBinding(),
            prepared.delivery(),
            "other-final-response-codec",
            prepared.producerCodecVersion(),
            prepared.decodedPayload());

        assertThrows(IllegalArgumentException.class, () ->
            CasProtocolFinalResponseDeliveryBuilder
                .decodeServiceResponse(wrongCodec));
    }

    @Test
    void verifyUnsupportedProducerCodecVersionIsRejected() {
        val prepared = preparedServiceResponse();
        val unsupportedVersion = CasProtocolFinalResponseDeliveryBuilder
            .CURRENT_WRITE_CODEC_VERSION + 1;
        val wrongVersion = withMetadata(
            prepared,
            prepared.logicalResponseBinding(),
            prepared.delivery(),
            prepared.producerCodecId(),
            unsupportedVersion,
            replaceInt(
                prepared.decodedPayload(),
                Integer.BYTES,
                unsupportedVersion));

        assertThrows(IllegalArgumentException.class, () ->
            CasProtocolFinalResponseDeliveryBuilder
                .decodeServiceResponse(wrongVersion));
    }

    @Test
    void verifyWrongLogicalBindingIsRejectedByAuthorityContext() {
        val capability = ProtocolFinalResponseCapability.managed(
            ProtocolFinalResponseCapability.Type.CAS_SERVICE_TICKET,
            "ST-binding",
            "subject-1",
            7,
            "intent-1");
        val serviceUrl = "https://service.example/login";
        val expectedBinding = ProtocolFinalResponseLogicalBinding.of(
            ProtocolFinalResponseContext.Protocol.CAS,
            ProtocolFinalResponseContext.ResponseType.CAS_SERVICE_RESPONSE,
            serviceUrl,
            "subject-1",
            List.of(capability));
        val response = new RedirectToServiceAction.ImmutableFinalResponse(
            Response.ResponseType.POST,
            serviceUrl,
            Map.of("ticket", "ST-binding"));
        val prepared = CasProtocolFinalResponseDeliveryBuilder
            .prepareServiceResponse(response, expectedBinding);
        val wrongBinding = withMetadata(
            prepared,
            new ProtocolFinalResponseLogicalBinding("f".repeat(64)),
            prepared.delivery(),
            prepared.producerCodecId(),
            prepared.producerCodecVersion(),
            prepared.decodedPayload());

        assertNotEquals(prepared.payloadDigest(), wrongBinding.payloadDigest());
        assertThrows(IllegalArgumentException.class, () ->
            ProtocolFinalResponseContext.of(
                ProtocolFinalResponseContext.Protocol.CAS,
                ProtocolFinalResponseContext.ResponseType
                    .CAS_SERVICE_RESPONSE,
                serviceUrl,
                "subject-1",
                capability,
                wrongBinding));
    }

    @Test
    void verifyMaximumSizedEnvelopeRoundTrips() {
        val outputLength = ProtocolFinalResponsePreparedDelivery
            .MAXIMUM_PAYLOAD_BYTES
            - browserStorageEnvelopeOverhead("TGC", "r", "LOCAL", "c");
        val value = new CookieValueManager.PreparedCookieValue(
            "x".repeat(outputLength), "r");
        val prepared = CasProtocolFinalResponseDeliveryBuilder
            .prepareStatelessBrowserStorage(
                cookieBuilder("TGC"),
                value,
                BrowserStorage.BrowserStorageTypes.LOCAL,
                "c",
                TEST_BINDING);

        assertEquals(
            ProtocolFinalResponsePreparedDelivery.MAXIMUM_PAYLOAD_BYTES,
            prepared.decodedPayload().length);
        assertEquals(value,
            CasProtocolFinalResponseDeliveryBuilder
                .decodeStatelessBrowserStorage(prepared)
                .preparedValue());
    }

    @Test
    void verifyEnvelopeOneByteOverMaximumIsRejected() {
        val outputLength = ProtocolFinalResponsePreparedDelivery
            .MAXIMUM_PAYLOAD_BYTES
            - browserStorageEnvelopeOverhead("TGC", "r", "LOCAL", "c")
            + 1;
        val value = new CookieValueManager.PreparedCookieValue(
            "x".repeat(outputLength), "r");

        assertThrows(IllegalArgumentException.class, () ->
            CasProtocolFinalResponseDeliveryBuilder
                .prepareStatelessBrowserStorage(
                    cookieBuilder("TGC"),
                    value,
                    BrowserStorage.BrowserStorageTypes.LOCAL,
                    "c",
                    TEST_BINDING));
    }

    private static ProtocolFinalResponsePreparedDelivery
        preparedServiceResponse() {
        val attributes = new LinkedHashMap<String, String>();
        attributes.put("ticket", "ST-1");
        attributes.put("state", "opaque-state");
        return CasProtocolFinalResponseDeliveryBuilder
            .prepareServiceResponse(
                new RedirectToServiceAction.ImmutableFinalResponse(
                    Response.ResponseType.POST,
                    "https://service.example/login",
                    attributes),
                TEST_BINDING);
    }

    private static CasCookieBuilder.PreparedCookie preparedCookie() {
        return new CasCookieBuilder.PreparedCookie(
            "TGC",
            "ciphertext-v1",
            "stable-replay-v1",
            "TGC=ciphertext-v1; Path=/cas; Secure; HttpOnly",
            "/cas",
            "example.org",
            3_600,
            true,
            true,
            Map.of(
                "cookie_name", "TGC",
                "domain", "example.org",
                "path", "/cas",
                "secure", "true"));
    }

    private static CasCookieBuilder cookieBuilder(final String cookieName) {
        val builder = mock(CasCookieBuilder.class);
        when(builder.getCookieName()).thenReturn(cookieName);
        return builder;
    }

    private static byte[] serviceEnvelope(
        final Response.ResponseType responseType,
        final String url,
        final List<Map.Entry<String, String>> attributes) throws IOException {
        return envelope(SERVICE_RESPONSE_TYPE, output -> {
            writeText(output, responseType.name());
            writeText(output, url);
            writeAttributes(output, attributes);
        });
    }

    private static byte[] cookieEnvelope(
        final CasCookieBuilder.PreparedCookie cookie,
        final List<Map.Entry<String, String>> attributes,
        final int domainPresence,
        final int secure,
        final int httpOnly) throws IOException {
        return envelope(HTTP_COOKIE_TYPE, output -> {
            writeText(output, cookie.cookieName());
            writeText(output, cookie.outputValue());
            writeText(output, cookie.replayValue());
            writeText(output, cookie.headerValue());
            writeText(output, cookie.path());
            output.writeByte(domainPresence);
            if (domainPresence == 1) {
                writeText(output, cookie.domain());
            }
            output.writeInt(cookie.maxAge());
            output.writeByte(secure);
            output.writeByte(httpOnly);
            writeAttributes(output, attributes);
        });
    }

    private static byte[] envelope(
        final int type,
        final EnvelopeWriter writer) throws IOException {
        val bytes = new ByteArrayOutputStream();
        try (val output = new DataOutputStream(bytes)) {
            output.writeInt(ENVELOPE_MAGIC);
            output.writeInt(CasProtocolFinalResponseDeliveryBuilder
                .CURRENT_WRITE_CODEC_VERSION);
            output.writeInt(type);
            writer.write(output);
        }
        return bytes.toByteArray();
    }

    private static void writeAttributes(
        final DataOutputStream output,
        final List<Map.Entry<String, String>> attributes) throws IOException {
        output.writeInt(attributes.size());
        for (val attribute : attributes) {
            writeText(output, attribute.getKey());
            output.writeBoolean(attribute.getValue() != null);
            if (attribute.getValue() != null) {
                writeText(output, attribute.getValue());
            }
        }
    }

    private static void writeText(
        final DataOutputStream output,
        final String value) throws IOException {
        val bytes = value.getBytes(StandardCharsets.UTF_8);
        output.writeInt(bytes.length);
        output.write(bytes);
    }

    private static ProtocolFinalResponsePreparedDelivery withPayload(
        final ProtocolFinalResponsePreparedDelivery prepared,
        final byte[] payload) {
        return withMetadata(
            prepared,
            prepared.logicalResponseBinding(),
            prepared.delivery(),
            prepared.producerCodecId(),
            prepared.producerCodecVersion(),
            payload);
    }

    private static ProtocolFinalResponsePreparedDelivery withMetadata(
        final ProtocolFinalResponsePreparedDelivery prepared,
        final ProtocolFinalResponseLogicalBinding logicalResponseBinding,
        final ProtocolFinalResponseDelivery delivery,
        final String producerCodecId,
        final int producerCodecVersion,
        final byte[] payload) {
        Objects.requireNonNull(prepared, "prepared");
        return new ProtocolFinalResponsePreparedDelivery(
            logicalResponseBinding,
            delivery,
            producerCodecId,
            producerCodecVersion,
            Base64.getUrlEncoder().withoutPadding().encodeToString(payload));
    }

    private static byte[] replaceInt(
        final byte[] payload,
        final int offset,
        final int value) {
        val copy = payload.clone();
        ByteBuffer.wrap(copy).putInt(offset, value);
        return copy;
    }

    private static int browserStorageEnvelopeOverhead(
        final String cookieName,
        final String replayValue,
        final String storageType,
        final String storageContext) {
        return HEADER_BYTES
            + Integer.BYTES * 5
            + utf8Length(cookieName)
            + utf8Length(replayValue)
            + utf8Length(storageType)
            + utf8Length(storageContext);
    }

    private static int utf8Length(final String value) {
        return value.getBytes(StandardCharsets.UTF_8).length;
    }

    private static Map.Entry<String, String> entry(
        final String name,
        final String value) {
        return new AbstractMap.SimpleImmutableEntry<>(name, value);
    }

    @FunctionalInterface
    private interface EnvelopeWriter {
        void write(DataOutputStream output) throws IOException;
    }
}
