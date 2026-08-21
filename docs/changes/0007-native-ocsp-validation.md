# Native required-OCSP validation

This stacked change establishes strict native Bouncy Castle OCSP validation
without removing the existing OCSP implementation or its remaining features.

## Migrated configuration

`CrlCheckingMode.IGNORE` combined with `OCSPCheckingMode.REQUIRE` now uses the
native BC `PKIXRevocationChecker` for the deliberately narrow case where:

- exactly one explicit `OCSPResponder` is configured with a URL and trusted
  responder certificate;
- every supplied certificate has no Authority Information Access extension;
- responder preference, timeout, cache, disk-cache, and nonce settings retain
  their constructor defaults.

The AIA restriction is conservative. If any supplied certificate has an AIA
extension, validation remains on the compatibility path so the existing
configured-versus-discovered responder fallback is not bypassed. Certificate
array and asserted `CertPath` entry points are both supported.

Validation is split into two passes:

1. Build and validate the selected path with revocation disabled.
2. Validate the same path using a BC `PKIXRevocationChecker` configured with
   the explicit responder URL/certificate and `NO_FALLBACK`.

Ordinary PKIX revocation remains disabled in the second pass. This is
necessary because BC's ordinary `PKIXParameters` revocation switch installs
its CRL checker; adding the returned `PKIXRevocationChecker` explicitly selects
native OCSP without silently falling back to CRLs.

Deterministic loopback HTTP tests cover a good response and strict rejection
of revoked, unknown, expired, malformed, and badly signed responses. The tests
also cover a separately issued responder certificate with the OCSP-signing
extended key usage. They exercise both native OCSP transport and response
validation without public responders.

## Error mapping

BC 1.85 reports all observed OCSP failures with an unspecified standard
reason, including definitive revocation. These failures therefore use
`PKIX_FAILURE` at the `REVOCATION` stage while preserving the provider message,
cause, and certificate position when BC supplies it. Malformed response bytes
can surface as a provider runtime exception before BC assigns a path index; in
that case the position remains `-1`. Provider English text is not parsed.

## Deliberately deferred behavior

All other OCSP configurations continue through the compatibility
implementation. In particular, this branch does not yet migrate:

- AIA responder discovery or fallback between configured and discovered
  responders;
- multiple configured responders and responder ordering;
- `OCSPCheckingMode.IF_AVAILABLE`;
- nonce requests;
- custom connection timeouts, cache TTLs, persistent caching, or OCSP update
  notifications;
- combinations with CRLs, mechanism ordering, or `useAllEnabled`.

The migrated slice uses BC's native 15-second HTTP timeout and native weak
in-memory response cache. The legacy default timeout/cache controls therefore
remain API-compatible but are not yet the transport authority for this narrow
slice. Configuring any non-default value keeps validation on the compatibility
path. Transport controls and caching will be layered onto native response
validation in dedicated changes.
