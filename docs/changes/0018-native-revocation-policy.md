# Native combined revocation policy

This stacked change migrates combined strict-CRL and OCSP configurations to
the native validation path while preserving mechanism order and
`useAllEnabled`.

## Per-certificate policy

The selected path is base-validated before revocation checking. The configured
policy is then applied independently to each non-anchor certificate and its
already validated issuer.

The OCSP layer now retains three internal outcomes:

- `VERIFIED` means a response was fetched or loaded from cache and accepted by
  native BC validation;
- `UNAVAILABLE` means optional OCSP found no responder or exhausted all
  ordered responders through structured HTTP transport failures;
- `FAILURE` means required OCSP was unavailable or a response was received and
  rejected.

This distinction is not exposed as a new public API. It prevents optional
OCSP unavailability from being mistaken for successful verification when CRL
is the next configured mechanism.

With `useAllEnabled=false`, a verified first mechanism short-circuits the
second. An unavailable optional OCSP check advances to CRL. A failure is always
terminal and never causes mechanism fallback. This means revoked, unknown,
malformed, forged, stale, and otherwise invalid received OCSP responses remain
terminal even when a good CRL is available.

With `useAllEnabled=true`, both mechanisms are evaluated. Their individual
modes still apply: strict CRL and required OCSP must verify, while genuinely
unavailable optional OCSP is accepted after the configured attempts and
notifications have occurred.

## Migrated configurations

Both certificate-array and asserted-`CertPath` entry points now use this
policy when:

- CRL mode is `REQUIRE`;
- OCSP mode is `REQUIRE` or `IF_AVAILABLE`; and
- configured responders and transport settings are supported by the native
  OCSP path.

CRL checks use a one-certificate path anchored by that certificate's selected
issuer, with the complete candidate-certificate and CRL stores available to
BC. OCSP checks reuse configured/AIA responder ordering, timeouts, memory and
persistent caches, nonces, transport fallback, responder-failure caching, and
update notifications.

No provider English messages are parsed. No unsigned OCSP status is inspected
before native validation.

`RevocationParameters.clone()` also now retains `RevocationCheckingOrder` and
`useAllEnabled`; the previous implementation silently restored both defaults.

## Deferred compatibility mode

`CrlCheckingMode.IF_VALID` and combinations using it remain on the compatibility
implementation. Reliably distinguishing an absent applicable CRL from a
present but invalid CRL is the separate `IF_PRESENT` decision and is not
weakened here.

Deterministic tests cover both mechanism orders, verified short-circuiting,
optional OCSP transport fallback to CRL, the require-all policy, required OCSP
unavailability, terminal received responses, revoked CRLs, array and asserted
path inputs, public OpenSSL-validator routing, and policy cloning.
