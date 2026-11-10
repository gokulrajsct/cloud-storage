package com.acme.mule.signer.api;

import java.io.Serializable;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Output of Sign S3 request. Send {@link #getPath()} as the HTTP request path and every entry of
 * {@link #getHeaders()} as a header, unchanged: that is exactly what was signed.
 */
public class SignedS3Request implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String path;
    private final LinkedHashMap<String, String> headers;
    private final String payloadHash;
    private final String canonicalRequest;

    public SignedS3Request(String path, Map<String, String> headers, String payloadHash, String canonicalRequest) {
        this.path = path;
        this.headers = new LinkedHashMap<>(headers);
        this.payloadHash = payloadHash;
        this.canonicalRequest = canonicalRequest;
    }

    /** URI-encoded request path, e.g. /reports/Q3%20summary.pdf. Use it as the HTTP request path as is. */
    public String getPath() {
        return path;
    }

    /** Authorization, x-amz-date, x-amz-content-sha256, x-amz-security-token and any x-amz-meta-* headers. */
    public Map<String, String> getHeaders() {
        return Collections.unmodifiableMap(headers);
    }

    /** Hex SHA-256 of the body, the empty-body hash, or UNSIGNED-PAYLOAD. */
    public String getPayloadHash() {
        return payloadHash;
    }

    /** What was signed, with the session token masked. Log it to compare with S3's SignatureDoesNotMatch error. */
    public String getCanonicalRequest() {
        return canonicalRequest;
    }

    @Override
    public String toString() {
        return "SignedS3Request{path='" + path + "', payloadHash=" + payloadHash + "}";
    }
}
