# Native OCSP responder discovery

This stacked change adds certificate AIA discovery to strict native OCSP
validation while retaining ambiguous multi-responder behavior on the
compatibility path.

## Migrated configuration

`CrlCheckingMode.IGNORE` combined with `OCSPCheckingMode.REQUIRE` now uses
native BC response validation when no explicit responder is configured and
every supplied non-anchor certificate contains exactly one HTTP or HTTPS OCSP
URI in its Authority Information Access extension. Responder preference,
timeout, cache, disk-cache, and nonce settings must retain their constructor
defaults.

Array inputs remain target-first with unordered path-building candidates, and
asserted `CertPath` inputs remain ordered. Configured trust-anchor
certificates are not required to contain an OCSP URI because trust anchors are
not revocation-checked.

## Per-certificate native validation

BC's standard `PKIXRevocationChecker` accepts only one responder override for
the whole validation pass. Its implicit AIA fetching also depends on the
JVM-wide `ocsp.enable` security setting. Changing that global setting would be
unsafe for a thread-safe library and one override would send certificates from
different issuers to the wrong responder.

The implementation therefore:

1. builds and validates the complete selected path with revocation disabled;
2. reads the single OCSP URI from each non-anchor certificate;
3. validates each certificate/issuer edge in a separate native BC OCSP pass,
   using the already validated issuer certificate as that edge's trust anchor;
4. remaps a failure to the certificate's position in the original selected
   path.

This does not replace path validation. The complete path has already passed
native PKIX validation, and native BC remains responsible for constructing the
OCSP request and validating the response, signer, status, and freshness.

Deterministic loopback tests use different responder paths for a leaf and its
intermediate CA. They cover successful array and asserted-path validation and
verify that an intermediate's revoked response is reported at its original
path index.

## Conservative compatibility boundary

The following configurations continue through the existing OCSP
implementation:

- a certificate with no discovered OCSP responder;
- a certificate with multiple discovered responders;
- a malformed, relative, non-HTTP(S), or otherwise unsupported responder URI;
- any combination of explicit and discovered responders;
- non-default timeout, cache, disk-cache, preference, or nonce settings;
- `OCSPCheckingMode.IF_AVAILABLE`;
- CRL/OCSP combinations, mechanism ordering, and `useAllEnabled`.

In particular, a multi-responder native loop is not implemented by treating
all native exceptions as retryable. BC 1.85 reports both responder problems
and definitive revocation with an unspecified standard reason. Retrying after
an unspecified failure could therefore turn a revoked result into success.
The existing implementation retains responder fallback until a later layer
can preserve that policy without provider-message parsing or a security
regression.
