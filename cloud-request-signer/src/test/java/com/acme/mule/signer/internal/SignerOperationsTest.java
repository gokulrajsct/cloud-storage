package com.acme.mule.signer.internal;

import com.acme.mule.signer.api.SignedS3Request;
import com.acme.mule.signer.internal.core.SignerException;
import com.acme.mule.signer.internal.error.SignerErrorProvider;
import com.acme.mule.signer.internal.error.SignerErrorType;
import org.junit.jupiter.api.Test;
import org.mule.runtime.api.metadata.TypedValue;
import org.mule.runtime.extension.api.exception.ModuleException;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignerOperationsTest {

    private static final String HOST = "my-bucket.s3.ap-southeast-2.amazonaws.com";
    private final SignerOperations ops = new SignerOperations();

    @Test
    void errorTypesMatchExceptionKinds() {
        Set<String> kinds = Arrays.stream(SignerException.Kind.values()).map(Enum::name).collect(Collectors.toSet());
        Set<String> types = Arrays.stream(SignerErrorType.values()).map(Enum::name).collect(Collectors.toSet());
        assertEquals(kinds, types);
        assertEquals(SignerErrorType.values().length, new SignerErrorProvider().getErrorTypes().size());
    }

    @Test
    void toModuleExceptionKeepsMessageTypeAndCause() {
        for (SignerException.Kind kind : SignerException.Kind.values()) {
            SignerException e = new SignerException(kind, "msg-" + kind);
            ModuleException m = SignerOperations.toModuleException(e);
            assertEquals("msg-" + kind, m.getMessage());
            assertEquals(SignerErrorType.valueOf(kind.name()), m.getType());
            assertSame(e, m.getCause());
        }
    }

    @Test
    void signS3RequestReturnsPathAndHeaders() {
        TypedValue<InputStream> body = new TypedValue<>(new ByteArrayInputStream("abc".getBytes(StandardCharsets.US_ASCII)), null);
        SignedS3Request r = ops.signS3Request("PUT", HOST, "ap-southeast-2", "dir/a b.txt", "", body, true,
                "AK", "SK", "TOKEN", Map.of("source", "test"));

        assertEquals("/dir/a%20b.txt", r.getPath());
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", r.getPayloadHash());
        assertEquals("TOKEN", r.getHeaders().get("x-amz-security-token"));
        assertEquals("test", r.getHeaders().get("x-amz-meta-source"));
        assertTrue(r.getHeaders().get("Authorization").startsWith("AWS4-HMAC-SHA256 Credential=AK/"));
        assertFalse(r.getCanonicalRequest().contains("TOKEN"));
        assertFalse(r.toString().contains("TOKEN"));
        assertThrows(UnsupportedOperationException.class, () -> r.getHeaders().put("x", "y"));
    }

    @Test
    void signS3RequestWithoutBody() {
        SignedS3Request r = ops.signS3Request("GET", HOST, "ap-southeast-2", "a", null, null, true, "AK", "SK", null, null);
        assertEquals("/a", r.getPath());
        assertFalse(r.getHeaders().containsKey("x-amz-security-token"));
    }

    @Test
    void signS3RequestInvalidInputBecomesSignerInvalidInput() {
        ModuleException e = assertThrows(ModuleException.class,
                () -> ops.signS3Request("GET", HOST, "ap-southeast-2", "a/../b", "", null, true, "AK", "SK", null, null));
        assertEquals(SignerErrorType.INVALID_INPUT, e.getType());
    }

    @Test
    void createEntraClientAssertion() {
        String jwt = ops.createEntraClientAssertion(" https://login.example/t/oauth2/v2.0/token ", " client-1 ",
                "test-client.p12", "changeit", null, "PKCS12");
        assertEquals(3, jwt.split("\\.").length);
    }

    @Test
    void createEntraClientAssertionErrors() {
        for (String[] in : new String[][]{{null, "c"}, {" ", "c"}, {"https://x", null}, {"https://x", ""}}) {
            ModuleException e = assertThrows(ModuleException.class,
                    () -> ops.createEntraClientAssertion(in[0], in[1], "test-client.p12", "changeit", null, "PKCS12"));
            assertEquals(SignerErrorType.INVALID_INPUT, e.getType());
        }
        ModuleException bad = assertThrows(ModuleException.class,
                () -> ops.createEntraClientAssertion("https://x", "c", "test-client.p12", "wrong", null, "PKCS12"));
        assertEquals(SignerErrorType.CERTIFICATE, bad.getType());
        ModuleException noPassword = assertThrows(ModuleException.class,
                () -> ops.createEntraClientAssertion("https://x", "c", "missing.p12", null, null, "PKCS12"));
        assertEquals(SignerErrorType.CERTIFICATE, noPassword.getType());
    }
}
