package com.acme.mule.signer.internal.core;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class S3RequestsTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-11-10T09:30:00Z"), ZoneOffset.UTC);
    private static final String HOST = "my-bucket.s3.ap-southeast-2.amazonaws.com";

    private static S3Requests.Signed put(byte[] body, boolean signPayload, Map<String, String> meta) {
        return S3Requests.sign("put", HOST, "ap-southeast-2", "data/order 55.json", "", new ByteArrayInputStream(body),
                signPayload, "ASIATESTKEY", "tempSecret", "SESSION-TOKEN", meta, CLOCK);
    }

    @Test
    void putHashesTheBodyAndSignsTokenAndMetadata() {
        byte[] body = "{\"orderId\":55}".getBytes(StandardCharsets.UTF_8);
        Map<String, String> meta = new LinkedHashMap<>();
        meta.put("Source-System", "salesforce");
        S3Requests.Signed s = put(body, true, meta);

        assertEquals("/data/order%2055.json", s.path);
        assertEquals(64, s.payloadHash.length());
        assertEquals(S3Requests.sha256Hex(new ByteArrayInputStream(body)), s.payloadHash);
        assertEquals(s.payloadHash, s.headers.get("x-amz-content-sha256"));
        assertEquals("SESSION-TOKEN", s.headers.get("x-amz-security-token"));
        assertEquals("salesforce", s.headers.get("x-amz-meta-source-system"));
        assertEquals("20261110T093000Z", s.headers.get("x-amz-date"));
        assertTrue(s.headers.get("Authorization").startsWith(
                "AWS4-HMAC-SHA256 Credential=ASIATESTKEY/20261110/ap-southeast-2/s3/aws4_request, "
                        + "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-meta-source-system;x-amz-security-token, Signature="));
        assertTrue(s.canonicalRequest.contains("x-amz-security-token:<masked>"));
        assertTrue(!s.canonicalRequest.contains("SESSION-TOKEN"));
    }

    @Test
    void unsignedPayloadDoesNotReadTheBody() {
        ByteArrayInputStream body = new ByteArrayInputStream(new byte[]{1, 2, 3});
        S3Requests.Signed s = S3Requests.sign("PUT", HOST, "ap-southeast-2", "a.bin", null, body, false,
                "AK", "SK", null, null, CLOCK);
        assertEquals("UNSIGNED-PAYLOAD", s.payloadHash);
        assertEquals(3, body.available());
    }

    @Test
    void getHeadDeleteUseTheEmptyBodyHashWhateverBodyIsPassed() {
        for (String m : new String[]{"GET", "HEAD", "DELETE"}) {
            S3Requests.Signed s = S3Requests.sign(m, HOST, "ap-southeast-2", "a.txt", "", new ByteArrayInputStream(new byte[]{9}),
                    true, "AK", "SK", "T", null, CLOCK);
            assertEquals(S3Requests.EMPTY_SHA256, s.payloadHash, m);
        }
    }

    @Test
    void pathStyleAndEncoding() {
        assertEquals("/my-bucket/reports/Q3%20summary%2Bfinal%20%C3%A9.pdf",
                S3Requests.objectPath("my-bucket/", "/reports/Q3 summary+final é.pdf"));
    }

    @Test
    void invalidInputsAreRejected() {
        for (String key : new String[]{"", " ", "a//b", "a/../b", "./a", "a/"}) {
            SignerException e = assertThrows(SignerException.class, () -> S3Requests.objectPath("", key), key);
            assertEquals(SignerException.Kind.INVALID_INPUT, e.getKind(), key);
        }
        assertThrows(SignerException.class, () -> S3Requests.sign("GET", "https://" + HOST, "r", "a", "", null, true, "AK", "SK", null, null, CLOCK));
        assertThrows(SignerException.class, () -> S3Requests.sign("GET", HOST, "r", "a", "", null, true, "", "SK", null, null, CLOCK));
        assertThrows(SignerException.class, () -> put(new byte[0], true, Map.of("bad name", "x")));
        assertThrows(SignerException.class, () -> put(new byte[0], true, Map.of("ok", "café")));
    }

    @Test
    void clientAssertionVerifiesWithTheCertificate() throws Exception {
        ClientCertificate cert = ClientCertificate.cached("test-client.p12", "changeit".toCharArray(), null, "PKCS12");
        String endpoint = "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token";
        String jwt = cert.createAssertion(endpoint, "client-1", CLOCK.instant());
        String[] parts = jwt.split("\\.");
        String claims = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        assertEquals(endpoint, MiniJson.stringField(claims, "aud"));
        assertEquals("client-1", MiniJson.stringField(claims, "iss"));
        assertTrue(claims.contains("\"exp\":" + (CLOCK.instant().getEpochSecond() + 600)));
        Signature v = Signature.getInstance("SHA256withRSA");
        v.initVerify(cert.getCertificate().getPublicKey());
        v.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        assertTrue(v.verify(Base64.getUrlDecoder().decode(parts[2])));

        SignerException bad = assertThrows(SignerException.class,
                () -> ClientCertificate.load("test-client.p12", "wrong".toCharArray(), null, "PKCS12"));
        assertEquals(SignerException.Kind.CERTIFICATE, bad.getKind());
    }
}
