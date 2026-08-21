# Remove the legacy validation engine

This stacked change removes the copied Bouncy Castle reviewer and makes the
provider's native PKIX builder, validator, CRL checker, and OCSP checker the
only certificate-path validation authority.

## Native-only routing

Every retained combination of disabled, CRL, OCSP, and combined revocation
checking now routes directly through `NativeBCPKIXValidator` for both
certificate arrays and asserted `CertPath` inputs. There is no compatibility
fallback. Invalid configurations such as null modes, null responder arrays,
negative timeouts, or non-HTTP(S) responder URLs produce a staged
`INVALID_INPUT` result instead of reaching another validation implementation.

All previously migrated OCSP behavior remains present: AIA and configured
responder ordering, bounded transport, memory and persistent caches, nonces,
fallback after transport failures, update notifications, optional
availability, combined mechanism ordering, and `useAllEnabled`.

The small amount of custom OCSP code still required to create unsigned
requests and perform bounded HTTP transport is now package-private
`NativeOCSPClient`. It does not authenticate responses or decide certificate
status. Encoded responses continue to be accepted or rejected only by a fresh
native BC `PKIXRevocationChecker`.

## Removed implementation

The complete copied `helpers.pkipath.bc` source package is gone, together with
the legacy reviewer, non-validating path builder, detailed error mapper,
extended reviewer parameters, compatibility exceptions, and custom CRL/OCSP
revocation-checker packages. The old standalone OCSP verifier and its caches
are also removed; the independently implemented native encoded-response and
responder-failure caches remain.

The removed internal-package standalone client accepted an `X509Credential`
for signed requests. Validator configuration never exposed a request signer,
so retained validator OCSP requests remain unsigned as before. Applications
which used that unstable helper API directly must use Bouncy Castle's OCSP
request APIs; its custom response-verification result is deliberately not
reintroduced alongside native PKIX response validation.

The lowercase reviewer-specific `ValidationErrorCode` values and obsolete
error categories are removed. Stable native messages and category mappings
are held directly by the remaining enums, so the legacy message-bundle
resource and parameterized compatibility constructor are no longer needed.
`API-Changes.txt` records the exact removed public symbols.

The full NIST verdict corpus and focused native PKIX, CRL, OCSP, cache,
OpenSSL-store, notification, and TLS tests remain the behavioral gate. A
public-validator test additionally proves that an unsupported responder
transport is rejected as native input rather than invoking a fallback engine.
