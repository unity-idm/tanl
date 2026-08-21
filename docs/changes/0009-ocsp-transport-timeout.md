# Native OCSP connection timeout

This stacked change preserves the configured per-request OCSP connection and
read timeout for the precisely defined no-cache slice of strict native OCSP
validation.

## Migrated configuration

`CrlCheckingMode.IGNORE` combined with `OCSPCheckingMode.REQUIRE` now uses the
configured `OCSPParametes.getConntectTimeout()` value natively when:

- response caching is explicitly disabled with a negative cache TTL;
- no disk-cache path is configured;
- nonce and responder preference retain their existing migrated values; and
- there is either one explicit HTTP(S) responder with its trusted signing
  certificate and no certificate AIA, or exactly one discovered HTTP(S)
  responder for every non-anchor certificate.

Zero retains the documented infinite-timeout behavior. Negative timeout
values, cache-enabled custom timeouts, and every other deferred OCSP
configuration remain on the compatibility path.

## Fetch then validate

`PKIXRevocationChecker` has no per-instance timeout setting. The JDK and BC
timeout properties are process-wide, so changing them would make concurrent
validators interfere with one another.

For the migrated no-cache configuration the implementation instead validates
the complete selected path first, then handles each certificate/issuer edge as
follows:

1. create the ordinary unsigned, nonce-free OCSP request;
2. fetch it through the retained HTTP(S) client using the configured connect
   and read timeout;
3. supply the encoded response to
   `PKIXRevocationChecker.setOcspResponses()`; and
4. let native BC validate the response signature and signer, certificate
   status, and freshness against the already validated issuer.

The explicit responder's trusted signing certificate is passed to the native
checker. Discovered responders continue to use the certificate issuer or a
valid delegated signer embedded in the response. No JVM-global property is
changed.

Deterministic loopback tests cover successful configured and discovered
responders, an explicitly trusted delegated signer, rejection of a forged
prefetched response, and an actual read timeout. Array and asserted `CertPath`
entry points are both covered.

## Conservative cache boundary

Prefetching every response exactly implements a negative cache TTL. It would
not preserve a configured cache merely by ignoring it, so configurations with
the default or a custom non-negative cache TTL use this layer only when the
timeout/cache pair is still handled by BC's existing native route. A custom
timeout combined with caching remains on compatibility code until a bounded
raw-response cache can feed native validation.

Transport and response parsing failures are strict invalid results with the
original exception, original certificate index, and `REVOCATION` stage. They
use the broad `PKIX_FAILURE` code. In particular, this layer does not classify
failures as retryable from provider messages; responder fallback, nonce,
caching, notifications, and multi-mechanism policy remain separate changes.
