# Cloudflare Storage (hybrid connector)

Mule access to **AWS S3 or Azure ADLS Gen2 through a Cloudflare gateway**, authenticated with **Entra ID**
(no stored S3 keys or storage account keys). One module, one set of operations; the **Storage type** field
picks the backend.

| Project | Type | What it does | Who maintains it |
|---|---|---|---|
| `cloud-request-signer/` | Java SDK extension, prefix `signer:` | The exact cryptographic steps: SigV4 signing of S3 requests, Entra ID certificate client assertions. No config, no state. | Java (small, unit-tested) |
| `cloudflare-storage-module/` | XML SDK module, prefix `cf-storage:` | Everything else: config fields, Entra ID / STS calls, token cache, requests to Cloudflare, error mapping, for both S3 and ADLS. | Any Mule developer (XML + DataWeave) |

Apps depend on `cloudflare-storage-module` only.

```
App ── cf-storage:put-object ──► module ── storageType?
   S3:   Entra token (aud = Client ID) → STS AssumeRoleWithWebIdentity → 1-hour keys (cached)
         → signer:sign-s3-request (SigV4 for the S3 host) → Cloudflare → S3
   ADLS: Entra token (scope https://storage.azure.com/.default, cached)
         → Authorization: Bearer + x-ms-version → Cloudflare → <account>.blob.core.windows.net
Cloudflare: Host := cloudFlareHostName, drops its cloudFlare* headers, forwards the rest unchanged
```

| | S3 | ADLS Gen2 |
|---|---|---|
| Credential | Entra token swapped at AWS STS for temporary keys | Entra token used directly |
| Per request | SigV4 signature (Java signer) | Bearer token, no signing |
| Cloudflare forwards to | `signingHost`, e.g. `my-bucket.s3.ap-southeast-2.amazonaws.com` | `<adlsAccount>.blob.core.windows.net` |
| Request path | `/<key>` (path style: `/<bucket>/<key>`) | `/<container>/<key>` (Blob API) |
| Metadata headers | `x-amz-meta-*` | `x-ms-meta-*` |
| Access control | IAM role trust policy + permissions policy | Azure RBAC on the account or container |

Each app usually has one config per backend it uses. For example, `S3_Storage` with `storageType="S3"` and
`ADLS_Storage` with `storageType="ADLS"`. Switching an app between backends is a config change only.

---

## 1. Config fields (`<cf-storage:config>`)

Studio lists every field. The XML SDK has no dropdowns or conditional fields, so the module checks the
combination at runtime and raises `CF-STORAGE:CONFIGURATION`, naming every missing field, on the first
operation call. Put every secret in secure properties.

### Common to both
| Field | Required | Default | Description |
|---|---|---|---|
| `storageType` | No | `S3` | `S3` or `ADLS`. Decides which fields below are required. |
| `gatewayHost` | **Yes** | | Cloudflare host Mule connects to, e.g. `storage-proxy.example.com`. No scheme or port. |
| `gatewayPort` | No | `443` | |
| `gatewayProtocol` | No | `HTTPS` | `HTTP` only for local mocks. |
| `hostNameHeader` | No | `cloudFlareHostName` | Header telling Cloudflare where to forward. Its value is set by the module: the S3 signing host or the ADLS account host. Empty = not sent. |
| `accessIdHeader` | No | `cloudFlareAccessId` | |
| `accessId` | Yes, if Cloudflare requires it | | Cloudflare access id. |
| `accessSecretHeader` | No | `cloudFlareAccessSecret` | |
| `accessSecret` | Yes, if Cloudflare requires it | | Cloudflare access secret (password field). |
| `tenantId` | **Yes** | | Entra ID directory (tenant) ID. |
| `clientId` | **Yes** | | Application (client) ID of the app registration. |
| `authMode` | No | `CLIENT_SECRET` | `CLIENT_SECRET` or `CERTIFICATE`. |
| `clientSecret` | **Yes when** `authMode=CLIENT_SECRET` | | Password field. |
| `certificateKeystore` | **Yes when** `authMode=CERTIFICATE` | | PKCS12 file path or classpath resource (e.g. `certs/mule-entra.p12`) with the app registration's certificate and RSA key. |
| `certificateKeystorePassword` | **Yes when** `authMode=CERTIFICATE` | | Password field. |
| `certificateAlias` | No | first key entry | |
| `authorityHost` | No | `https://login.microsoftonline.com` | Change only for sovereign clouds. |
| `responseTimeoutMillis` | No | `60000` | Timeout for calls through Cloudflare. Raise it for large objects. |

### S3 (`storageType="S3"`)
| Field | Required | Default | Description |
|---|---|---|---|
| `region` | **Yes** | | Bucket region, e.g. `ap-southeast-2`. |
| `signingHost` | **Yes** | | Host S3 receives the request on, and the host signed. Virtual-hosted: `my-bucket.s3.ap-southeast-2.amazonaws.com`; path style: `s3.ap-southeast-2.amazonaws.com` + `pathPrefix`. |
| `pathPrefix` | No | empty | `/my-bucket` for path style. |
| `signPayload` | No | `true` | `false` sends `UNSIGNED-PAYLOAD` (still protected by HTTPS). |
| `roleArn` | **Yes** | | IAM role trusting the Entra ID OIDC provider for this Client ID. |
| `stsRegion` | **Yes** | | STS endpoint region, usually the bucket's. |
| `scope` | No | `api://<clientId>/.default` | Entra scope of the token given to STS. |
| `sessionDurationSeconds` | No | `3600` | 900 up to the role's maximum. Also the cache's upper bound for both backends. |
| `sessionNamePrefix` | No | `mule` | CloudTrail shows `<prefix>-<random>`. Use the app name. |
| `debugSigning` | No | `false` | Logs the canonical request (token masked) under `cf-storage.signing`. |

### ADLS (`storageType="ADLS"`)
| Field | Required | Default | Description |
|---|---|---|---|
| `adlsAccount` | **Yes** | | Storage account name, e.g. `mystorageacct` (the part before `.blob.core.windows.net`). |
| `adlsContainer` | **Yes** | | Container (file system) the keys live in, e.g. `invoices`. |
| `adlsEndpointSuffix` | No | `blob.core.windows.net` | Change only for sovereign clouds. |
| `adlsApiVersion` | No | `2021-08-06` | Sent as `x-ms-version`. |
| `adlsScope` | No | `https://storage.azure.com/.default` | Entra scope of the storage token. |

**Test connection** in Studio checks that the gateway host is reachable. Tokens are fetched on the first
operation call.

---

## 2. Operations (same for both backends)

| Operation | Parameters | Output |
|---|---|---|
| `cf-storage:put-object` | `key` (**required**), `content` (default `#[payload]`), `contentType` (default `application/octet-stream`), `userMetadata` (optional object) | `{key, eTag, versionId, requestId, contentType, storageType}` |
| `cf-storage:get-object` | `key` (**required**) | payload = the object (binary); attributes = the storage response (`attributes.headers.etag`, ...) |
| `cf-storage:head-object` | `key` (**required**) | `{key, eTag, contentType, contentLength, lastModified, versionId, requestId, userMetadata, storageType}` |
| `cf-storage:delete-object` | `key` (**required**) | `{key, deleted: true, storageType}`; succeeds even if the key did not exist |

- **Keys** are unencoded and relative: S3 key without the bucket, or blob path without the container
  (`invoices/2026/invoice 1001.pdf`). Keys with an empty, `.` or `..` segment, or a trailing `/`, are
  rejected, because proxies normalise them.
- **User metadata names** must be letters, digits and `_`, not starting with a digit, to work on both
  backends. Azure only accepts identifier-style names; S3 also accepts `-`. Values must be printable ASCII.
- **ADLS** uses the Blob API (`Put Blob` with `BlockBlob`, `Get Blob`, `Get Blob Properties`,
  `Delete Blob`), which works on ADLS Gen2 (hierarchical namespace) accounts and uploads in one call.

### Errors (same types for both)
| Error | S3 example | ADLS example |
|---|---|---|
| `CF-STORAGE:CONFIGURATION` | Missing `roleArn` | Missing `adlsContainer` |
| `CF-STORAGE:NOT_FOUND` | `NoSuchKey`, `NoSuchBucket` | `BlobNotFound`, `ContainerNotFound` |
| `CF-STORAGE:ACCESS_DENIED` | `AccessDenied` (role permissions) | `AuthorizationPermissionMismatch` (missing RBAC role) |
| `CF-STORAGE:INVALID_CREDENTIALS` | `ExpiredToken`, `InvalidAccessKeyId` | `InvalidAuthenticationInfo` (bad or expired token) |
| `CF-STORAGE:SIGNATURE_MISMATCH` | `SignatureDoesNotMatch`: Cloudflare changed a signed part. The message includes S3's canonical request. | n/a |
| `CF-STORAGE:GATEWAY_REJECTED` | Cloudflare refused the call (401/403 with no storage response) | same |
| `CF-STORAGE:AUTHENTICATION` | Entra ID or STS refused (`InvalidIdentityToken`, trust policy) | Entra ID refused |
| `CF-STORAGE:BAD_DIGEST` | `XAmzContentSHA256Mismatch` | `Md5Mismatch` |
| `CF-STORAGE:BAD_REQUEST` | Invalid key/metadata, clock skew, other 4xx | same |
| `CF-STORAGE:SERVER_ERROR` | 5xx | 5xx |
| `CF-STORAGE:CONNECTIVITY` | Cloudflare / Entra ID / STS unreachable or timed out | same |

On `INVALID_CREDENTIALS` the cached keys or token are dropped, so a retry fetches fresh ones.

---

## 3. Using it in an app

```xml
<!-- pom.xml -->
<dependency>
    <groupId>YOUR_ORG_ID</groupId>
    <artifactId>cloudflare-storage-module</artifactId>
    <version>1.1.0</version>
    <classifier>mule-plugin</classifier>
</dependency>
```

```xml
<!-- S3 -->
<cf-storage:config name="S3_Storage" storageType="S3"
    gatewayHost="s3-proxy.example.com"
    accessId="${secure::cloudflare.accessId}" accessSecret="${secure::cloudflare.accessSecret}"
    tenantId="${entra.tenantId}" clientId="${entra.clientId}" clientSecret="${secure::entra.clientSecret}"
    region="ap-southeast-2" signingHost="my-bucket.s3.ap-southeast-2.amazonaws.com"
    roleArn="arn:aws:iam::123456789012:role/mule-s3-oidc-role" stsRegion="ap-southeast-2"
    sessionNamePrefix="orders-api"/>

<!-- ADLS -->
<cf-storage:config name="ADLS_Storage" storageType="ADLS"
    gatewayHost="adls-proxy.example.com"
    accessId="${secure::cloudflare.accessId}" accessSecret="${secure::cloudflare.accessSecret}"
    tenantId="${entra.tenantId}" clientId="${entra.clientId}" clientSecret="${secure::entra.clientSecret}"
    adlsAccount="mystorageacct" adlsContainer="invoices"/>

<flow name="store-invoice">
    <!-- the same operation for either backend: only config-ref changes -->
    <cf-storage:put-object config-ref="${storage.config}" key="#['2026/' ++ vars.invoiceId ++ '.pdf']"
                           contentType="application/pdf" userMetadata="#[{ source_system: 'salesforce' }]"/>
    <error-handler>
        <on-error-propagate type="CF-STORAGE:NOT_FOUND, CF-STORAGE:ACCESS_DENIED">
            <logger level="ERROR" message="#[error.description]"/>
        </on-error-propagate>
    </error-handler>
</flow>
```

To switch an app between backends with a property, set `config-ref="${storage.config}"` to `S3_Storage`
or `ADLS_Storage`. Alternatively keep one config and make `storageType` and the backend fields properties.

---

## 4. Setup per backend

**S3:** IAM OIDC provider for the Entra tenant; role trust policy with `aud` = Client ID and `sub` = the
service principal's object ID; permissions policy with `s3:GetObject`, `s3:PutObject` and `s3:DeleteObject`
(plus `s3:ListBucket` if you want HEAD on a missing key to return 404 instead of 403). Cloudflare must
forward to `cloudFlareHostName` and pass `Authorization`, `x-amz-date`, `x-amz-content-sha256`,
`x-amz-security-token` and `x-amz-meta-*` unchanged.

**ADLS:**
1. **RBAC:** give the app registration's service principal **Storage Blob Data Contributor** on the
   container (or the account). Reader is enough for get/head only. Role assignments can take a few minutes
   to apply.
2. **Cloudflare:** forward to `cloudFlareHostName` (`<account>.blob.core.windows.net`) and pass
   `Authorization`, `x-ms-*` and `Content-Type` through.
3. **Network:** if the storage account's firewall is restricted, allow Cloudflare's egress addresses.
4. **Token:** no extra Entra setup. The client-credentials token for `https://storage.azure.com/.default`
   works once the role assignment exists.

---

## 5. Build locally

Java 17 and Maven 3.9+, with access to `repository.mulesoft.org` and your Exchange.

```bash
cd cloud-request-signer         && mvn clean install    # runs the signer unit tests
cd ../cloudflare-storage-module && mvn clean install
```

---

## 6. Publish to Exchange

Publish the **signer first**, because the module depends on it.

1. **Find your organization ID.** Anypoint Platform → Access Management → Business Groups → your group → the
   ID. Put it in `<groupId>` in **both** `pom.xml` files, replacing `00000000-0000-0000-0000-000000000000`.
2. **Create a connected app for the build** (Access Management → Connected Apps → *App acts on its own
   behalf*) with the scope **Exchange Contributor** on that business group.
3. **Add the credentials to `~/.m2/settings.xml`** (in CI, a secure file or pipeline secret):
   ```xml
   <servers>
     <server>
       <id>anypoint-exchange-v3</id>
       <username>~~~Client~~~</username>
       <password>CONNECTED_APP_CLIENT_ID~?~CONNECTED_APP_CLIENT_SECRET</password>
     </server>
   </servers>
   ```
   For the EU control plane, change the host in the poms to `maven.eu1.anypoint.mulesoft.com`.
4. **Deploy the signer, then the module:**
   ```bash
   cd cloud-request-signer         && mvn clean deploy
   cd ../cloudflare-storage-module && mvn clean deploy
   ```
5. **Finish the Exchange page.** Open the module's asset, paste sections 1–4 of this README as its
   documentation, and check its visibility.
6. **Use it in the apps.** Add the dependency (section 3), or search Exchange from Studio's palette. App builds
   need read access to the same Exchange repository.
7. **Versioning.** Exchange versions can't be overwritten. Raise `<version>` for every change (1.0.1 for
   fixes, 1.1.0 for new fields or operations). When the signer changes, also bump
   `cloud.request.signer.version` in the module's pom. The module is at `1.1.0` (ADLS added); the signer is
   unchanged at `1.0.0`.

If Exchange rejects the upload, check three things: the `groupId` is the org ID, the connected app has
Exchange Contributor on that business group, and the version is new.

---

## 7. What has been verified, and what to check on the first build

Verified before handover:
- **Signer unit tests (13):** AWS SigV4 test vectors, path encoding, payload hashing, token and metadata
  signing, input validation, and the certificate client assertion.
- **S3 signing path end to end:** every S3 request the module makes was produced by the signer operation and
  sent with the module's headers through a simulated Cloudflare. **botocore** (AWS's SigV4) accepted each one.
- **Response parsing:** the regexes the module uses for STS, Entra ID and S3 responses were checked against
  real-shaped samples.
- **Module XML:** well-formed, and cross-checked so every variable resolves, every private operation gets its
  parameters, no parameter shadows a config field, and every error an operation can raise (including through
  nested calls) is declared.

Not run here, because it needs a Mule runtime, MuleSoft's Maven repository and an Azure account. Check these
on the first build:
- **Dependency versions:** `mule-modules-parent` 1.9.0, `mule-sdk-api` 0.9.0, HTTP connector 1.10.3, Object
  Store 1.2.2.
- **Config values in global elements:** gateway host, port and protocol, the timeout and the Object Store TTL
  use `#[vars.<field>]`.
- **Absolute URLs:** the Entra ID and STS calls use `http:request url="..."` with a host-less config.
- **DataWeave:** none of the module's expressions have been executed. To exercise every branch:
  - put, get and head on each backend;
  - head on a missing key on each backend;
  - one call with a wrong Cloudflare secret;
  - one ADLS call before the RBAC role exists, which should give `ACCESS_DENIED`;
  - one config with a missing required field.
- **`get-object` attributes:** check they reach the caller. If not, use `head-object` for metadata.
- **ADLS against Azure:** the request format (Put Blob headers, `x-ms-date`, URL encoding of keys) follows the
  Azure Storage REST API but hasn't been sent to a real account.

---

## 8. Limits of this version

- **Large uploads:** `put-object` sends the body with `requestStreamingMode="NEVER"`, because both S3 and
  Azure need a Content-Length. The HTTP connector holds the body in memory. Very large files would need S3
  multipart or Azure Put Block / Put Block List.
- **No automatic retry:** on `INVALID_CREDENTIALS` the cache is dropped but the call isn't retried. Use
  `until-successful maxRetries="1"` if wanted.
- **No list operation yet.** That needs query-string signing on S3 and `List Blobs` on ADLS.
- **No dropdowns:** the XML SDK can't show a dropdown or hide the other backend's fields; `storageType` is a
  text field validated at runtime.
