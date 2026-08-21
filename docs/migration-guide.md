# Lite PKI migration guide

This guide covers the application changes needed for the native-PKIX release.
For the exhaustive list of removed Java symbols, see [`API-Changes.txt`](../API-Changes.txt).
OCSP, CRL validation, OpenSSL-style trust stores, Java trust stores, credentials,
hostname checks, and JSSE integration remain supported.

## Constructing an OpenSSL validator

`OpensslCertChainValidator` now uses modern OpenSSL subject hashes and lazy
loading by default. Configure revocation explicitly when the deployment needs
behavior other than the defaults:

```java
import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.impl.OpensslCertChainValidator;
import eu.emi.security.authn.x509.impl.ValidatorParams;

RevocationParameters revocation = new RevocationParameters(
        CrlCheckingMode.IF_PRESENT,
        new OCSPParametes(OCSPCheckingMode.IF_AVAILABLE));
ValidatorParams parameters = new ValidatorParams(revocation);

OpensslCertChainValidator validator = new OpensslCertChainValidator(
        "/srv/example/trust", 600_000L, parameters);
try {
    ValidationResult result = validator.validate(peerChain);
    // Handle result as shown below.
} finally {
    validator.dispose();
}
```

Validators are thread-safe, relatively expensive objects. Share a validator
where practical and call `dispose()` when its application lifetime ends. Pass
`false` as the final argument of the four-argument constructor to load the
entire OpenSSL store eagerly at startup:

```java
OpensslCertChainValidator eager = new OpensslCertChainValidator(
        "/srv/example/trust", 600_000L, parameters, false);
```

The eager mode exposes trust-store loading problems at startup and has stable
per-validation performance at the cost of initialization time and memory. The
lazy mode resolves hashed certificates and CRLs on demand and caches them.

## Selecting revocation behavior

CRL modes have the following contracts:

| Mode | Behavior |
| --- | --- |
| `IGNORE` | Do not consult CRLs. |
| `IF_PRESENT` | If an applicable parsed CRL is present, validate it strictly; accept an edge with no applicable CRL. |
| `REQUIRE` | Require strict native CRL validation for every non-anchor certificate. |

`IF_VALID` is retained only as a deprecated compatibility alias for
`IF_PRESENT`. New code should use `IF_PRESENT`.

OCSP modes have the following contracts:

| Mode | Behavior |
| --- | --- |
| `IGNORE` | Do not perform OCSP requests. |
| `IF_AVAILABLE` | Accept a missing responder or exhausted HTTP transport failures, but reject any received response that native validation does not accept. |
| `REQUIRE` | Require a good, natively validated response for every non-anchor certificate. |

Configured responders and certificate AIA responders can be combined. The
following example prefers configured responders, then falls back to AIA
responders after transport failures:

```java
import java.net.URL;

import eu.emi.security.authn.x509.OCSPResponder;
import eu.emi.security.authn.x509.RevocationParameters.RevocationCheckingOrder;

OCSPResponder[] responders = {
    new OCSPResponder(new URL("https://ocsp.example.test"),
            responderSigningCertificate)
};
OCSPParametes ocsp = new OCSPParametes(
        OCSPCheckingMode.IF_AVAILABLE, responders, 300, "/var/cache/example/ocsp");
ocsp.setPreferLocalResponders(true);
ocsp.setUseNonce(false);

RevocationParameters revocation = new RevocationParameters(
        CrlCheckingMode.IF_PRESENT, ocsp, false,
        RevocationCheckingOrder.OCSP_CRL);
```

The OCSP cache TTL is in seconds. A negative value disables memory and disk
caching; zero limits cached responses by response metadata. Enabling nonces
bypasses response caching because responses are request-bound.

`RevocationCheckingOrder` selects whether combined validation tries OCSP or
CRL first. With `useAllEnabled == false`, one positively verified mechanism is
enough. With `useAllEnabled == true`, all enabled mechanisms are evaluated.
A definitive failure such as revocation, an invalid CRL, or any received OCSP
response rejected by native validation is terminal regardless of this flag.

## Handling validation errors

An invalid result has exactly one immutable primary error. Branch only on the
stable code and stage; provider messages are diagnostics and must not be
parsed:

```java
import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.ValidationStage;

ValidationResult result = validator.validate(peerChain);
if (!result.isValid()) {
    ValidationError error = result.getPrimaryError();

    if (error.getErrorCode() == ValidationErrorCode.CERTIFICATE_EXPIRED) {
        // Apply the application's stable expired-certificate policy.
    } else if (error.getStage() == ValidationStage.REVOCATION) {
        // Treat this as a revocation-stage failure.
    }

    logDiagnostic(error.getProviderMessage(), error.getCause());
}
```

`getErrors()` remains as an immutable empty-or-single-element compatibility
view. On failure, the JSSE trust managers retain `getPrimaryError().getCause()`
as the cause of their `CertificateException`.

Certificate-array validation treats element zero as the target and the
remaining elements as path-building candidates. A successful result returns
the resolved target-to-anchor chain through `getValidChain()`.

## Modern OpenSSL trust-store layout

The directory contains CA certificates and CRLs named with the current
OpenSSL subject hash:

```text
/srv/example/trust/
├── 12ab34cd.0       first CA certificate with this subject hash
├── 12ab34cd.1       hash collision or rollover certificate
├── 12ab34cd.r0      first CRL for the same issuer hash
└── 12ab34cd.r1      additional CRL with that hash
```

Use the OpenSSL supplied tooling to create the links rather than calculating
or hard-coding hashes:

```sh
install -m 0644 root-ca.pem /srv/example/trust/root-ca.pem
install -m 0644 root-ca.crl /srv/example/trust/root-ca.crl
openssl rehash /srv/example/trust
```

Legacy pre-OpenSSL-1.0 MD5 hashes are not loaded. Namespace files such as
`.signing_policy` and `.namespaces` are not interpreted. Use PKIX name
constraints in certificates when issuer-name scoping is required.

## Removed compatibility areas

The release intentionally removes proxy-certificate APIs and handling,
namespace-policy APIs, legacy OpenSSL hashes, the copied reviewer-based
validation engine, and the historical detailed error catalogue. Ordinary
native PKIX validation rejects proxy chains. The current stable error model,
constructor replacements, and exact removed symbols are recorded in
[`API-Changes.txt`](../API-Changes.txt).
