package com.acme.mule.signer.internal.core;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClientCertificateTest {

    private static final char[] PASSWORD = "changeit".toCharArray();

    @Test
    void loadsFromClasspathWithOrWithoutLeadingSlashAndByAlias() {
        assertNotNull(ClientCertificate.load("test-client.p12", PASSWORD, null, null).getCertificate());
        assertNotNull(ClientCertificate.load("/test-client.p12", PASSWORD, "", "").getCertificate());
        assertNotNull(ClientCertificate.load(" test-client.p12 ", PASSWORD, " mule-test ", " PKCS12 ").getCertificate());
    }

    @Test
    void loadsFromAFilePath() throws Exception {
        URL url = getClass().getClassLoader().getResource("test-client.p12");
        String path = new File(url.toURI()).getAbsolutePath();
        assertNotNull(ClientCertificate.load(path, PASSWORD, null, "PKCS12").getCertificate());
    }

    @Test
    void cachedReturnsTheSameInstanceAndRetriesAfterAFailure() {
        ClientCertificate a = ClientCertificate.cached("test-client.p12", PASSWORD, null, "PKCS12");
        assertSame(a, ClientCertificate.cached("test-client.p12", PASSWORD, null, "PKCS12"));
        assertThrows(SignerException.class, () -> ClientCertificate.cached("test-client.p12", "bad".toCharArray(), null, "PKCS12"));
        // a failed load is not cached, so the right password still works afterwards
        assertSame(a, ClientCertificate.cached("test-client.p12", PASSWORD, null, "PKCS12"));
    }

    @Test
    void loadFailuresMapToTheRightKind() {
        assertEquals(SignerException.Kind.INVALID_INPUT,
                assertThrows(SignerException.class, () -> ClientCertificate.load(" ", PASSWORD, null, null)).getKind());
        assertEquals(SignerException.Kind.INVALID_INPUT,
                assertThrows(SignerException.class, () -> ClientCertificate.load(null, PASSWORD, null, null)).getKind());
        assertEquals(SignerException.Kind.CERTIFICATE,
                assertThrows(SignerException.class, () -> ClientCertificate.load("no-such.p12", PASSWORD, null, null)).getKind());
        assertEquals(SignerException.Kind.CERTIFICATE,
                assertThrows(SignerException.class, () -> ClientCertificate.load("test-client.p12", PASSWORD, "missing", null)).getKind());
        assertEquals(SignerException.Kind.CERTIFICATE,
                assertThrows(SignerException.class, () -> ClientCertificate.load("test-client.p12", PASSWORD, null, "JKS-NOPE")).getKind());
    }

    @Test
    void assertionHeaderCarriesCertificateThumbprints() throws Exception {
        ClientCertificate cert = ClientCertificate.load("test-client.p12", PASSWORD, null, null);
        Instant now = Instant.parse("2026-11-10T09:30:00Z");
        String jwt = cert.createAssertion("https://login.example/t/oauth2/v2.0/token", "client-1", now);
        String[] parts = jwt.split("\\.");
        assertEquals(3, parts.length);
        String header = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        String claims = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);

        byte[] der = cert.getCertificate().getEncoded();
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        assertEquals("RS256", MiniJson.stringField(header, "alg"));
        assertEquals(b64.encodeToString(java.security.MessageDigest.getInstance("SHA-1").digest(der)),
                MiniJson.stringField(header, "x5t"));
        assertEquals(b64.encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(der)),
                MiniJson.stringField(header, "x5t#S256"));
        assertEquals("client-1", MiniJson.stringField(claims, "sub"));
        assertTrue(claims.contains("\"iat\":" + now.getEpochSecond()));
        assertTrue(claims.contains("\"nbf\":" + now.getEpochSecond()));
        assertTrue(!jwt.contains("=") && !jwt.contains("+") && !jwt.contains("/"), "base64url without padding");

        String other = cert.createAssertion("https://login.example/t/oauth2/v2.0/token", "client-1", now);
        String otherClaims = new String(Base64.getUrlDecoder().decode(other.split("\\.")[1]), StandardCharsets.UTF_8);
        assertNotEquals(MiniJson.stringField(claims, "jti"), MiniJson.stringField(otherClaims, "jti"));
    }

    @Test
    void claimValuesAreJsonEscaped() {
        ClientCertificate cert = ClientCertificate.load("test-client.p12", PASSWORD, null, null);
        String jwt = cert.createAssertion("https://x/\"quoted\"", "id\\1", Instant.EPOCH);
        String claims = new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8);
        assertEquals("https://x/\"quoted\"", MiniJson.stringField(claims, "aud"));
        assertEquals("id\\1", MiniJson.stringField(claims, "iss"));
    }
}
