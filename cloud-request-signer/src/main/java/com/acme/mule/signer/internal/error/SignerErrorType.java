package com.acme.mule.signer.internal.error;

import org.mule.runtime.extension.api.error.ErrorTypeDefinition;

/** Errors raised by the signer, catchable as SIGNER:&lt;NAME&gt;. Names match SignerException.Kind. */
public enum SignerErrorType implements ErrorTypeDefinition<SignerErrorType> {
    /** A parameter is missing or invalid (empty key, key with ".." or "//", bad metadata name, ...). */
    INVALID_INPUT,
    /** The certificate keystore could not be loaded or holds no RSA key. */
    CERTIFICATE,
    /** The body could not be read to hash it. */
    BODY_UNREADABLE
}
