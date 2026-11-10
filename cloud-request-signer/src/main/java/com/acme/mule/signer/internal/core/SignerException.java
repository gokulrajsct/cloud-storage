package com.acme.mule.signer.internal.core;

/** A signing input the caller must fix. {@link Kind} maps onto the SIGNER:* Mule error types. */
public class SignerException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public enum Kind {
        /** Missing/invalid parameter, bad object key or bad metadata. */
        INVALID_INPUT,
        /** The keystore could not be read or holds no usable RSA key. */
        CERTIFICATE,
        /** The body could not be read for hashing. */
        BODY_UNREADABLE
    }

    private final Kind kind;

    public SignerException(Kind kind, String message) {
        this(kind, message, null);
    }

    public SignerException(Kind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
    }

    public Kind getKind() {
        return kind;
    }
}
