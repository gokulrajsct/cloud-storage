package com.acme.mule.signer.internal.core;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/** Everything about one S3 request that must be exact: the encoded path, the body hash and the SigV4 headers. */
public final class S3Requests {

    public static final String EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    private static final Pattern META_NAME = Pattern.compile("[a-z0-9][a-z0-9-]*");

    private S3Requests() {
    }

    /** Result of {@link #sign}: what the caller sends. */
    public static final class Signed {
        public final String path;
        public final Map<String, String> headers;
        public final String payloadHash;
        public final String canonicalRequest;

        Signed(String path, Map<String, String> headers, String payloadHash, String canonicalRequest) {
            this.path = path;
            this.headers = headers;
            this.payloadHash = payloadHash;
            this.canonicalRequest = canonicalRequest;
        }
    }

    /**
     * Signs an S3 object request.
     *
     * @param body read only for PUT/POST with signPayload=true; it is streamed through SHA-256, not buffered
     */
    public static Signed sign(String method, String signingHost, String region, String key, String pathPrefix,
                              InputStream body, boolean signPayload, String accessKeyId, String secretAccessKey,
                              String sessionToken, Map<String, String> userMetadata, Clock clock) {
        String m = require(method, "Method").toUpperCase(Locale.ROOT);
        String host = require(signingHost, "S3 signing host");
        if (host.contains("/") || host.contains(":")) {
            throw new SignerException(SignerException.Kind.INVALID_INPUT, "S3 signing host must be a bare host name such as "
                    + "my-bucket.s3.ap-southeast-2.amazonaws.com (no scheme, port or path), got '" + host + "'");
        }
        String path = objectPath(pathPrefix, key);
        Map<String, String> meta = metadataHeaders(userMetadata);

        boolean hasBody = m.equals("PUT") || m.equals("POST");
        String payloadHash = !hasBody ? EMPTY_SHA256 : signPayload ? sha256Hex(body) : S3SigV4Signer.UNSIGNED_PAYLOAD;

        Map<String, Object> req = new HashMap<>();
        req.put("method", m);
        req.put("host", host);
        req.put("uri", path);
        req.put("query", "");
        req.put("region", require(region, "Region"));
        req.put("payloadHash", payloadHash);
        req.put("accessKeyId", require(accessKeyId, "Access key ID"));
        req.put("secretAccessKey", require(secretAccessKey, "Secret access key"));
        req.put("sessionToken", sessionToken);
        req.put("headers", meta);

        Map<String, String> headers = new LinkedHashMap<>(S3SigV4Signer.signAt(req, clock));
        headers.putAll(meta);   // signed, so they must be sent exactly as signed
        return new Signed(path, headers, payloadHash, S3SigV4Signer.describeAt(req, clock));
    }

    /**
     * URI-encoded request path for a key. Keys with empty, "." or ".." segments are refused: proxies such as
     * Cloudflare normalise them, and S3 would then see a different path from the one that was signed.
     */
    public static String objectPath(String prefix, String key) {
        if (key == null || key.trim().isEmpty()) {
            throw new SignerException(SignerException.Kind.INVALID_INPUT, "An object key is required");
        }
        String k = key;
        while (k.startsWith("/")) {
            k = k.substring(1);
        }
        for (String seg : k.split("/", -1)) {
            if (seg.isEmpty() || seg.equals(".") || seg.equals("..")) {
                throw new SignerException(SignerException.Kind.INVALID_INPUT, "Object key '" + key
                        + "' contains an empty, '.' or '..' segment; proxies normalise these and the signature "
                        + "would no longer match");
            }
        }
        String p = prefix == null ? "" : prefix.trim();
        while (p.endsWith("/")) {
            p = p.substring(0, p.length() - 1);
        }
        if (!p.isEmpty() && !p.startsWith("/")) {
            p = "/" + p;
        }
        return S3SigV4Signer.encodePath(p + "/" + k);
    }

    static Map<String, String> metadataHeaders(Map<String, String> userMetadata) {
        Map<String, String> h = new LinkedHashMap<>();
        if (userMetadata == null) {
            return h;
        }
        userMetadata.forEach((name, value) -> {
            String n = name == null ? "" : name.trim().toLowerCase(Locale.ROOT);
            if (n.startsWith("x-amz-meta-")) {
                n = n.substring("x-amz-meta-".length());
            }
            if (!META_NAME.matcher(n).matches()) {
                throw new SignerException(SignerException.Kind.INVALID_INPUT,
                        "User metadata name '" + name + "' must use letters, digits and '-' only");
            }
            String v = value == null ? "" : value.trim();
            for (int i = 0; i < v.length(); i++) {
                char ch = v.charAt(i);
                if (ch < 0x20 || ch > 0x7e) {
                    throw new SignerException(SignerException.Kind.INVALID_INPUT,
                            "User metadata '" + name + "' must be printable ASCII");
                }
            }
            h.put("x-amz-meta-" + n, v);
        });
        return h;
    }

    /** SHA-256 of the stream, read in chunks (nothing is buffered). Null stream = empty body. */
    static String sha256Hex(InputStream in) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        if (in != null) {
            byte[] buf = new byte[64 * 1024];
            try (InputStream src = in) {
                int n;
                while ((n = src.read(buf)) != -1) {
                    md.update(buf, 0, n);
                }
            } catch (IOException e) {
                throw new SignerException(SignerException.Kind.BODY_UNREADABLE, "Could not read the body to hash it: " + e, e);
            }
        }
        byte[] d = md.digest();
        StringBuilder sb = new StringBuilder(64);
        for (byte b : d) {
            sb.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
        }
        return sb.toString();
    }

    private static String require(String v, String name) {
        if (v == null || v.trim().isEmpty()) {
            throw new SignerException(SignerException.Kind.INVALID_INPUT, name + " is required");
        }
        return v.trim();
    }
}
