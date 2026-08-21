# Native OCSP `IF_AVAILABLE` mode

This stacked change migrates OCSP-only `OCSPCheckingMode.IF_AVAILABLE`
validation to the native ordered fetch path.

## Availability boundary

Each certificate/issuer edge is base-validated before OCSP policy is applied.
The edge is accepted without an OCSP result only when:

- neither configured nor AIA discovery produces a responder; or
- every ordered responder attempt ends in a structurally classified HTTP
  transport failure.

Transport failures still trigger fallback, responder-failure caching, and
`StoreUpdateListener` warnings. The configuration and behavior for responder
ordering, timeouts, response caches, persistent caches, nonces, and update
notifications are otherwise identical to `REQUIRE`.

## Received responses remain strict

Once response bytes arrive, optional mode does not weaken validation.
Malformed or oversized data and nonce failures stop immediately. Every encoded
response is passed to a fresh native BC `PKIXRevocationChecker`; revoked,
unknown, forged, unauthorized, stale, and otherwise rejected responses are
terminal.

This is a deliberate tightening of the historical mode, which ignored unknown
and broad response errors. BC 1.85's OCSP checker returns no usable structured
soft-failure list and does not expose stable standard reasons that separate
unknown status from invalid signatures, signer authorization, or freshness
failures. Inspecting unsigned response status before native validation would
allow a forged `unknown` response to bypass checking, and inspecting provider
messages would be unstable. Neither is used.

The public enum documentation now defines `IF_AVAILABLE` as availability-only
soft failure: absence and transport outage are soft; a received response is
strict.

Deterministic tests cover good responses, missing responders, exhaustion of
multiple transport failures, malformed data, unknown and revoked status,
certificate arrays, asserted paths, and routing through the public OpenSSL
validator.

Combined CRL/OCSP policy, mechanism ordering, and `useAllEnabled` remain
separate layers.
