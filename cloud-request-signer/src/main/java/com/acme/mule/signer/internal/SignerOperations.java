package com.acme.mule.signer.internal;

import com.acme.mule.signer.api.SignedS3Request;
import com.acme.mule.signer.internal.core.ClientCertificate;
import com.acme.mule.signer.internal.core.S3Requests;
import com.acme.mule.signer.internal.core.SignerException;
import com.acme.mule.signer.internal.error.SignerErrorProvider;
import com.acme.mule.signer.internal.error.SignerErrorType;
import org.mule.runtime.api.metadata.TypedValue;
import org.mule.runtime.extension.api.annotation.error.Throws;
import org.mule.runtime.extension.api.annotation.param.Content;
import org.mule.runtime.extension.api.annotation.param.MediaType;
import org.mule.runtime.extension.api.annotation.param.NullSafe;
import org.mule.runtime.extension.api.annotation.param.Optional;
import org.mule.runtime.extension.api.annotation.param.display.DisplayName;
import org.mule.runtime.extension.api.annotation.param.display.Example;
import org.mule.runtime.extension.api.annotation.param.display.Password;
import org.mule.runtime.extension.api.annotation.param.display.Summary;
import org.mule.runtime.extension.api.exception.ModuleException;

import java.io.InputStream;
import java.time.Clock;
import java.util.Map;

/** Config-less operations: everything they need is passed in. Thread-safe. */
public class SignerOperations {

    private static final Clock CLOCK = Clock.systemUTC();

    @DisplayName("Sign S3 request")
    @Summary("AWS SigV4-signs an S3 object request for the S3 host. Returns the encoded path and the headers to send unchanged.")
    @Throws(SignerErrorProvider.class)
    public SignedS3Request signS3Request(
            @DisplayName("Method") @Summary("PUT, GET, HEAD or DELETE.") @Example("PUT") String method,
            @DisplayName("S3 signing host") @Summary("Host S3 receives the request on (Cloudflare forwards to it). No scheme or port.")
            @Example("my-bucket.s3.ap-southeast-2.amazonaws.com") String signingHost,
            @DisplayName("Region") @Summary("Bucket region, used in the credential scope.") @Example("ap-southeast-2") String region,
            @DisplayName("Key") @Summary("Object key, unencoded, without the bucket.") @Example("invoices/2026/invoice-1001.pdf") String key,
            @Optional @DisplayName("Path prefix") @Summary("Empty for virtual-hosted style; /<bucket> for path style.") String pathPrefix,
            @Optional @Content @DisplayName("Body")
            @Summary("PUT only: the bytes that will be sent, hashed in a streaming pass. Ignored for GET, HEAD and DELETE.")
            TypedValue<InputStream> body,
            @Optional(defaultValue = "true") @DisplayName("Sign payload")
            @Summary("true signs the body's SHA-256. false sends UNSIGNED-PAYLOAD (body not read; still protected by HTTPS).")
            boolean signPayload,
            @DisplayName("Access key ID") String accessKeyId,
            @Password @DisplayName("Secret access key") String secretAccessKey,
            @Optional @Password @DisplayName("Session token") @Summary("Required for temporary (STS) credentials.") String sessionToken,
            @Optional @NullSafe @DisplayName("User metadata")
            @Summary("Signed and returned as x-amz-meta-* headers (names: letters, digits, '-'; values: printable ASCII).")
            Map<String, String> userMetadata) {
        try {
            InputStream in = body == null ? null : body.getValue();
            S3Requests.Signed s = S3Requests.sign(method, signingHost, region, key, pathPrefix, in, signPayload,
                    accessKeyId, secretAccessKey, sessionToken, userMetadata, CLOCK);
            return new SignedS3Request(s.path, s.headers, s.payloadHash, s.canonicalRequest);
        } catch (SignerException e) {
            throw toModuleException(e);
        }
    }

    @DisplayName("Create Entra client assertion")
    @Summary("Signs a 10-minute client assertion JWT with the app registration's certificate, for Entra ID's client-credentials grant (instead of a client secret).")
    @Throws(SignerErrorProvider.class)
    @MediaType(value = MediaType.TEXT_PLAIN, strict = false)
    public String createEntraClientAssertion(
            @DisplayName("Token endpoint") @Summary("Entra ID v2.0 token URL; becomes the assertion's audience.")
            @Example("https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token") String tokenEndpoint,
            @DisplayName("Client ID") @Summary("Application (client) ID of the app registration.") String clientId,
            @DisplayName("Keystore") @Summary("PKCS12/JKS file path or classpath resource with the certificate and RSA private key.")
            @Example("certs/mule-entra.p12") String keystore,
            @Password @DisplayName("Keystore password") String keystorePassword,
            @Optional @DisplayName("Alias") @Summary("Keystore entry. Empty uses the first entry with a private key.") String alias,
            @Optional(defaultValue = "PKCS12") @DisplayName("Keystore type") String keystoreType) {
        try {
            if (tokenEndpoint == null || tokenEndpoint.trim().isEmpty() || clientId == null || clientId.trim().isEmpty()) {
                throw new SignerException(SignerException.Kind.INVALID_INPUT, "Token endpoint and Client ID are required");
            }
            ClientCertificate cert = ClientCertificate.cached(keystore,
                    keystorePassword == null ? null : keystorePassword.toCharArray(), alias, keystoreType);
            return cert.createAssertion(tokenEndpoint.trim(), clientId.trim(), CLOCK.instant());
        } catch (SignerException e) {
            throw toModuleException(e);
        }
    }

    static ModuleException toModuleException(SignerException e) {
        return new ModuleException(e.getMessage(), SignerErrorType.valueOf(e.getKind().name()), e);
    }
}
