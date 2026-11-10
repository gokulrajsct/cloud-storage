package com.acme.mule.signer;

import com.acme.mule.signer.internal.SignerOperations;
import com.acme.mule.signer.internal.error.SignerErrorType;
import org.mule.runtime.extension.api.annotation.Extension;
import org.mule.runtime.extension.api.annotation.Operations;
import org.mule.runtime.extension.api.annotation.dsl.xml.Xml;
import org.mule.runtime.extension.api.annotation.error.ErrorTypes;
import org.mule.sdk.api.annotation.JavaVersionSupport;

import static org.mule.sdk.api.meta.JavaVersion.JAVA_17;

/**
 * Cloud Request Signer: the cryptographic steps that must be exact, as plain Mule operations.
 * No configuration, no connection, no state: every input is an operation parameter.
 * <ul>
 *   <li>{@code signer:sign-s3-request}: AWS SigV4 for an S3 object request (works behind any proxy/gateway)</li>
 *   <li>{@code signer:create-entra-client-assertion}: certificate-signed JWT for Entra ID's client-credentials grant</li>
 * </ul>
 */
@Xml(prefix = "signer")
@Extension(name = "Cloud Request Signer", vendor = "Integration Team")
@Operations(SignerOperations.class)
@ErrorTypes(SignerErrorType.class)
@JavaVersionSupport({JAVA_17})
public class CloudRequestSignerExtension {
}
