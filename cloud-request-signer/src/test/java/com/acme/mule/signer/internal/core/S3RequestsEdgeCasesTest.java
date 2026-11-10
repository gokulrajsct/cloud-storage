package com.acme.mule.signer.internal.core;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Behaviour of {@link S3Requests} beyond {@link S3RequestsTest}. */
class S3RequestsEdgeCasesTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-11-10T09:30:00Z"), ZoneOffset.UTC);
    private static final String HOST = "my-bucket.s3.ap-southeast-2.amazonaws.com";

    @Test
    void sha256OfKnownBodies() {
        assertEquals(S3Requests.EMPTY_SHA256, S3Requests.sha256Hex(null));
        assertEquals(S3Requests.EMPTY_SHA256, S3Requests.sha256Hex(new ByteArrayInputStream(new byte[0])));
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                S3Requests.sha256Hex(new ByteArrayInputStream("abc".getBytes(StandardCharsets.US_ASCII))));
    }

    @Test
    void sha256OfBodyLargerThanTheReadBuffer() {
        byte[] big = new byte[200 * 1024 + 7];
        for (int i = 0; i < big.length; i++) {
            big[i] = (byte) i;
        }
        String expected;
        try {
            byte[] d = java.security.MessageDigest.getInstance("SHA-256").digest(big);
            StringBuilder sb = new StringBuilder();
            for (byte b : d) {
                sb.append(String.format("%02x", b));
            }
            expected = sb.toString();
        } catch (Exception e) {
            throw new AssertionError(e);
        }
        assertEquals(expected, S3Requests.sha256Hex(new ByteArrayInputStream(big)));
    }

    @Test
    void sha256ClosesTheStream() {
        boolean[] closed = {false};
        InputStream in = new ByteArrayInputStream(new byte[]{1}) {
            @Override
            public void close() {
                closed[0] = true;
            }
        };
        S3Requests.sha256Hex(in);
        assertTrue(closed[0]);
    }

    @Test
    void unreadableBodyIsReportedAsBodyUnreadable() {
        InputStream broken = new InputStream() {
            @Override
            public int read() throws IOException {
                throw new IOException("boom");
            }
        };
        SignerException e = assertThrows(SignerException.class, () -> S3Requests.sign("PUT", HOST, "ap-southeast-2", "a",
                "", broken, true, "AK", "SK", null, null, CLOCK));
        assertEquals(SignerException.Kind.BODY_UNREADABLE, e.getKind());
    }

    @Test
    void putWithoutBodySignsTheEmptyHash() {
        S3Requests.Signed s = S3Requests.sign("PUT", HOST, "ap-southeast-2", "a", "", null, true, "AK", "SK", null, null, CLOCK);
        assertEquals(S3Requests.EMPTY_SHA256, s.payloadHash);
    }

    @Test
    void postBodyIsHashedLikePut() {
        S3Requests.Signed s = S3Requests.sign("post", HOST, "ap-southeast-2", "a", "",
                new ByteArrayInputStream("abc".getBytes(StandardCharsets.US_ASCII)), true, "AK", "SK", null, null, CLOCK);
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", s.payloadHash);
        assertTrue(s.canonicalRequest.startsWith("POST\n/a\n"));
    }

    @Test
    void noSessionTokenMeansNoTokenHeader() {
        S3Requests.Signed s = S3Requests.sign("GET", HOST, "ap-southeast-2", "a", "", null, true, "AK", "SK", "", null, CLOCK);
        assertFalse(s.headers.containsKey("x-amz-security-token"));
        assertFalse(s.canonicalRequest.contains("x-amz-security-token"));
    }

    @Test
    void inputsAreTrimmed() {
        S3Requests.Signed a = S3Requests.sign("GET", HOST, "ap-southeast-2", "a", "", null, true, "AK", "SK", null, null, CLOCK);
        S3Requests.Signed b = S3Requests.sign(" GET ", " " + HOST + " ", " ap-southeast-2 ", "a", "", null, true,
                " AK ", " SK ", null, null, CLOCK);
        assertEquals(a.headers, b.headers);
    }

    @Test
    void signingHostWithPortOrPathIsRejected() {
        for (String host : new String[]{HOST + ":443", HOST + "/x", "", "  ", null}) {
            SignerException e = assertThrows(SignerException.class, () -> S3Requests.sign("GET", host, "r", "a", "", null,
                    true, "AK", "SK", null, null, CLOCK), String.valueOf(host));
            assertEquals(SignerException.Kind.INVALID_INPUT, e.getKind());
        }
    }

    @Test
    void everyRequiredArgumentIsChecked() {
        assertThrows(SignerException.class, () -> S3Requests.sign(null, HOST, "r", "a", "", null, true, "AK", "SK", null, null, CLOCK));
        assertThrows(SignerException.class, () -> S3Requests.sign("GET", HOST, "", "a", "", null, true, "AK", "SK", null, null, CLOCK));
        assertThrows(SignerException.class, () -> S3Requests.sign("GET", HOST, "r", null, "", null, true, "AK", "SK", null, null, CLOCK));
        assertThrows(SignerException.class, () -> S3Requests.sign("GET", HOST, "r", "a", "", null, true, null, "SK", null, null, CLOCK));
        assertThrows(SignerException.class, () -> S3Requests.sign("GET", HOST, "r", "a", "", null, true, "AK", " ", null, null, CLOCK));
    }

    @Test
    void objectPathPrefixVariants() {
        assertEquals("/a/b.txt", S3Requests.objectPath(null, "a/b.txt"));
        assertEquals("/a/b.txt", S3Requests.objectPath("", "///a/b.txt"));
        assertEquals("/bucket/a", S3Requests.objectPath("/bucket", "a"));
        assertEquals("/bucket/a", S3Requests.objectPath(" bucket// ", "a"));
        assertEquals("/a/..b/c.", S3Requests.objectPath("", "a/..b/c."));
    }

    @Test
    void metadataNamesAreNormalisedAndPrefixed() {
        Map<String, String> in = new LinkedHashMap<>();
        in.put(" Source-System ", " salesforce ");
        in.put("X-Amz-Meta-Batch", "42");
        in.put("empty", null);
        Map<String, String> out = S3Requests.metadataHeaders(in);
        assertEquals("salesforce", out.get("x-amz-meta-source-system"));
        assertEquals("42", out.get("x-amz-meta-batch"));
        assertEquals("", out.get("x-amz-meta-empty"));
        assertEquals(3, out.size());
        assertTrue(S3Requests.metadataHeaders(null).isEmpty());
    }

    @Test
    void invalidMetadataIsRejected() {
        for (String name : new String[]{"", "-lead", "under_score", "x-amz-meta-", "dot.name"}) {
            Map<String, String> m = new LinkedHashMap<>();
            m.put(name, "v");
            SignerException e = assertThrows(SignerException.class, () -> S3Requests.metadataHeaders(m), name);
            assertEquals(SignerException.Kind.INVALID_INPUT, e.getKind());
        }
        Map<String, String> nullName = new LinkedHashMap<>();
        nullName.put(null, "v");
        assertThrows(SignerException.class, () -> S3Requests.metadataHeaders(nullName));
        assertThrows(SignerException.class, () -> S3Requests.metadataHeaders(Map.of("ok", "line\nbreak")));
    }

    @Test
    void metadataHeadersAreSignedAndReturnedTogether() {
        S3Requests.Signed s = S3Requests.sign("PUT", HOST, "ap-southeast-2", "a", "", null, true, "AK", "SK", null,
                Map.of("b", "2"), CLOCK);
        assertEquals("2", s.headers.get("x-amz-meta-b"));
        assertTrue(s.canonicalRequest.contains("\nx-amz-meta-b:2\n"));
        assertTrue(s.headers.get("Authorization").contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-meta-b,"));
    }
}
