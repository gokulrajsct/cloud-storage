package com.acme.mule.signer.internal.core;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An Entra ID app registration's certificate, used instead of a client secret: Entra ID receives a short-lived
 * JWT ("client assertion") signed with the private key. Loaded keystores are cached per location.
 */
public final class ClientCertificate {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Map<String, ClientCertificate> CACHE = new ConcurrentHashMap<>();

    private final PrivateKey privateKey;
    private final X509Certificate certificate;

    private ClientCertificate(PrivateKey privateKey, X509Certificate certificate) {
        this.privateKey = privateKey;
        this.certificate = certificate;
    }

    /** Cached {@link #load}. The password is part of the cache key, so a corrected password is picked up. */
    public static ClientCertificate cached(String location, char[] password, String alias, String type) {
        String key = location + "|" + alias + "|" + type + "|" + (password == null ? 0 : new String(password).hashCode());
        return CACHE.computeIfAbsent(key, k -> load(location, password, alias, type));
    }

    /**
     * Loads the key pair from a PKCS12 (or JKS) keystore.
     *
     * @param location file path or classpath resource of the Mule app
     * @param alias    entry to use; null/empty picks the first entry holding a private key
     */
    public static ClientCertificate load(String location, char[] password, String alias, String type) {
        if (location == null || location.trim().isEmpty()) {
            throw new SignerException(SignerException.Kind.INVALID_INPUT, "Certificate keystore is required");
        }
        try (InputStream in = Resources.open(location.trim())) {
            KeyStore ks = KeyStore.getInstance(type == null || type.trim().isEmpty() ? "PKCS12" : type.trim());
            ks.load(in, password);
            String entry = alias == null || alias.trim().isEmpty() ? null : alias.trim();
            if (entry == null) {
                for (Enumeration<String> e = ks.aliases(); e.hasMoreElements(); ) {
                    String a = e.nextElement();
                    if (ks.isKeyEntry(a)) {
                        entry = a;
                        break;
                    }
                }
                if (entry == null) {
                    throw new IllegalArgumentException("the keystore holds no private key entry");
                }
            }
            Key key = ks.getKey(entry, password);
            if (!(key instanceof RSAPrivateKey)) {
                throw new IllegalArgumentException("entry '" + entry + "' is not an RSA private key (Entra ID needs RSA)");
            }
            X509Certificate cert = (X509Certificate) ks.getCertificate(entry);
            if (cert == null) {
                throw new IllegalArgumentException("entry '" + entry + "' has no certificate");
            }
            return new ClientCertificate((PrivateKey) key, cert);
        } catch (SignerException e) {
            throw e;
        } catch (Exception e) {
            throw new SignerException(SignerException.Kind.CERTIFICATE,
                    "Could not load the client certificate from '" + location + "': " + e.getMessage(), e);
        }
    }

    /** RS256 client assertion for Entra ID's v2.0 token endpoint, valid for 10 minutes. */
    public String createAssertion(String tokenEndpoint, String clientId, Instant now) {
        try {
            byte[] der = certificate.getEncoded();
            String header = "{\"alg\":\"RS256\",\"typ\":\"JWT\""
                    + ",\"x5t\":" + MiniJson.quote(B64URL.encodeToString(MessageDigest.getInstance("SHA-1").digest(der)))
                    + ",\"x5t#S256\":" + MiniJson.quote(B64URL.encodeToString(MessageDigest.getInstance("SHA-256").digest(der)))
                    + "}";
            long iat = now.getEpochSecond();
            String claims = "{\"aud\":" + MiniJson.quote(tokenEndpoint)
                    + ",\"iss\":" + MiniJson.quote(clientId)
                    + ",\"sub\":" + MiniJson.quote(clientId)
                    + ",\"jti\":" + MiniJson.quote(UUID.randomUUID().toString())
                    + ",\"iat\":" + iat + ",\"nbf\":" + iat + ",\"exp\":" + (iat + 600) + "}";
            String signingInput = B64URL.encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "."
                    + B64URL.encodeToString(claims.getBytes(StandardCharsets.UTF_8));
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(privateKey);
            sig.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            return signingInput + "." + B64URL.encodeToString(sig.sign());
        } catch (Exception e) {
            throw new SignerException(SignerException.Kind.CERTIFICATE, "Could not sign the client assertion: " + e.getMessage(), e);
        }
    }

    public X509Certificate getCertificate() {
        return certificate;
    }
}
