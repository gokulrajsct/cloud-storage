package com.acme.mule.signer.internal.core;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Behaviour of the SigV4 signer beyond the AWS worked examples in {@link S3SigV4SignerTest}. */
class S3SigV4SignerEdgeCasesTest {

    private static final Clock FIXED = Clock.fixed(Instant.parse("2013-05-24T00:00:00Z"), ZoneOffset.UTC);

    private static Map<String, Object> base() {
        Map<String, Object> req = new HashMap<>();
        req.put("method", "GET");
        req.put("host", "examplebucket.s3.amazonaws.com");
        req.put("uri", "/test.txt");
        req.put("region", "us-east-1");
        req.put("payloadHash", S3Requests.EMPTY_SHA256);
        req.put("accessKeyId", "AKIAIOSFODNN7EXAMPLE");
        req.put("secretAccessKey", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        return req;
    }

    @Test
    void canonicalQueryStringSortsAndEncodes() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("prefix", "a b/c");
        params.put("list-type", "2");
        params.put("empty", null);
        assertEquals("empty=&list-type=2&prefix=a%20b%2Fc", S3SigV4Signer.canonicalQueryString(params));
        assertEquals("", S3SigV4Signer.canonicalQueryString(null));
        assertEquals("", S3SigV4Signer.canonicalQueryString(Map.of()));
    }

    @Test
    void uriEncodeKeepsOnlyUnreservedCharacters() {
        assertEquals("AZaz09-_.~", S3SigV4Signer.uriEncode("AZaz09-_.~"));
        assertEquals("%20%2B%2F%3D%26%2A%25", S3SigV4Signer.uriEncode(" +/=&*%"));
        assertEquals("%E2%82%AC", S3SigV4Signer.uriEncode("€"));
    }

    @Test
    void missingQueryAndLowerCaseMethodAreAccepted() {
        Map<String, Object> a = base();
        Map<String, Object> b = base();
        b.put("method", "get");
        b.put("query", "");
        assertEquals(S3SigV4Signer.signAt(a, FIXED), S3SigV4Signer.signAt(b, FIXED));
    }

    @Test
    void extraHeadersAreLowerCasedTrimmedAndCollapsed() {
        Map<String, Object> req = base();
        Map<String, Object> extra = new HashMap<>();
        extra.put("  Content-Type ", "  text/plain;   charset=utf-8 ");
        extra.put("Authorization", "must be ignored");
        extra.put("Host", "evil.example.com");
        extra.put("x-null", null);
        req.put("headers", extra);

        String described = S3SigV4Signer.describeAt(req, FIXED);

        assertTrue(described.contains("\ncontent-type:text/plain; charset=utf-8\n"), described);
        assertTrue(described.contains("\nhost:examplebucket.s3.amazonaws.com\n"), described);
        assertFalse(described.contains("evil"), described);
        assertFalse(described.contains("authorization"), described);
        assertFalse(described.contains("x-null"), described);
        assertTrue(S3SigV4Signer.signAt(req, FIXED).get("Authorization")
                .contains("SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date,"));
    }

    @Test
    void signatureChangesWithEverySignedInput() {
        String reference = S3SigV4Signer.signAt(base(), FIXED).get("Authorization");
        String[][] changes = {
                {"method", "HEAD"}, {"host", "other.s3.amazonaws.com"}, {"uri", "/other.txt"}, {"query", "a=b"},
                {"region", "eu-west-1"}, {"payloadHash", S3SigV4Signer.UNSIGNED_PAYLOAD}, {"secretAccessKey", "x"},
                {"sessionToken", "t"}};
        for (String[] c : changes) {
            Map<String, Object> req = base();
            req.put(c[0], c[1]);
            assertNotEquals(reference, S3SigV4Signer.signAt(req, FIXED).get("Authorization"), c[0]);
        }
        Clock later = Clock.fixed(Instant.parse("2013-05-24T00:00:01Z"), ZoneOffset.UTC);
        assertNotEquals(reference, S3SigV4Signer.signAt(base(), later).get("Authorization"));
    }

    @Test
    void returnsExactlyTheHeadersToSend() {
        Map<String, Object> req = base();
        req.put("sessionToken", "TOKEN");
        Map<String, String> out = S3SigV4Signer.signAt(req, FIXED);
        assertEquals(java.util.List.of("Authorization", "x-amz-date", "x-amz-content-sha256", "x-amz-security-token"),
                new java.util.ArrayList<>(out.keySet()));
        assertEquals("20130524T000000Z", out.get("x-amz-date"));
        assertFalse(out.containsKey("host"));
    }

    @Test
    void everyRequiredParameterIsChecked() {
        for (String key : new String[]{"method", "host", "uri", "region", "payloadHash", "accessKeyId", "secretAccessKey"}) {
            Map<String, Object> missing = base();
            missing.remove(key);
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> S3SigV4Signer.signAt(missing, FIXED));
            assertTrue(e.getMessage().endsWith(key), e.getMessage());

            Map<String, Object> empty = base();
            empty.put(key, "");
            assertThrows(IllegalArgumentException.class, () -> S3SigV4Signer.signAt(empty, FIXED), key);
        }
    }

    @Test
    void publicSignUsesTheSystemClock() {
        Map<String, String> out = S3SigV4Signer.sign(base());
        assertTrue(out.get("x-amz-date").matches("\\d{8}T\\d{6}Z"));
        assertTrue(S3SigV4Signer.describe(base()).contains("--- credential scope: "));
    }
}
