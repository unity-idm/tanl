# Native OCSP in-memory response cache

This stacked change adds bounded in-memory caching to the native OCSP response
fetch layer without making cached data a validation verdict.

## Migrated configuration

The single configured responder and single-per-certificate AIA configurations
migrated in the preceding OCSP layers now use native transport and response
validation for every in-memory cache setting:

- a negative cache TTL disables response caching;
- zero applies no configured TTL and leaves expiry to response metadata; and
- a positive cache TTL limits reuse to that many seconds.

Any non-negative connection/read timeout is supported. Persistent cache paths,
nonce, multiple responders and responder ordering,
`OCSPCheckingMode.IF_AVAILABLE`, and CRL/OCSP combinations remain on the
compatibility path.

## Cache and validation boundary

Each validator owns a thread-safe access-ordered cache capped at 100 entries.
The key includes:

- responder URI;
- checked certificate;
- its already validated issuer; and
- the explicit trusted responder certificate, when configured.

Encoded responses are cloned when inserted and returned. An entry expires at
the earliest applicable limit:

1. the configured TTL from the time it was fetched;
2. HTTP `Cache-Control: max-age`; or
3. the earliest OCSP `nextUpdate` in the response.

`OCSPParametes` documents its cache TTL in seconds. The native cache honors
that public unit, correcting the compatibility implementation's accidental
use of the value as milliseconds. Thus the default `3600` is one hour, still
capped by response metadata.

A response is cached only after `PKIXRevocationChecker` accepts it. Forged,
malformed, unknown, revoked, expired, and otherwise rejected responses are not
stored because BC 1.85 does not structurally distinguish definitive status
from other OCSP failures. This avoids turning an invalid response into a
persistent denial of service merely to emulate legacy negative caching.

On every cache hit, the encoded response is supplied to a fresh native checker
through `setOcspResponses()`. Native BC therefore revalidates the response
signature, signer, certificate status, and freshness against current inputs;
the cache never returns a status on its own. If revalidation fails, the entry
is discarded and one fresh response is fetched and validated.

Deterministic tests cover cache reuse across array and asserted `CertPath`
calls, rejection and non-caching of forged responses, HTTP expiry overriding a
longer configured TTL, seconds-based TTL expiry, zero and negative TTLs,
defensive byte copying, and least-recently-used eviction at the 100-entry
bound. A persistent raw-response cache remains a separate migration layer.
