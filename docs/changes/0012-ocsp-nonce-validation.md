# Native OCSP nonce validation

This stacked change migrates request nonce generation and response nonce
enforcement into the strict native OCSP path.

## Request and response contract

When `OCSPParametes.isUseNonce()` is enabled, every certificate/responder
exchange receives a fresh 16-byte nonce from `SecureRandom`. The request
contains that value in the standard OCSP nonce extension.

The returned response must have a `BasicOCSPResp` body containing a nonce
extension with exactly the same value. A missing response extension, a
response without a basic body, or a mismatched nonce is an invalid result at
the `REVOCATION` stage. The comparison uses `MessageDigest.isEqual` and does
not parse provider messages.

This is intentionally only a structural nonce check. After it succeeds, the
complete encoded response is passed to a fresh `PKIXRevocationChecker`.
Native BC remains the authority for the response signature, responder signer,
certificate identity and status, and response freshness.

## Interaction with caching

Nonce-enabled validation bypasses both the bounded memory cache and the
configured persistent cache. It creates a new request for every validation
edge even when a non-negative cache TTL and disk-cache path are configured.
A cached response contains the nonce from its original request and therefore
cannot prove freshness for a later request.

Nonce-free validation keeps the existing cache behavior unchanged. Enabling
nonce does not read an earlier nonce-free cache entry and does not persist the
new nonce-bearing response.

## Verification and remaining layers

Deterministic local-responder tests cover matching nonce success for both
certificate-array and asserted-path entry points, fresh nonces and cache
bypass across repeated checks, and rejection of missing or altered response
nonces. The high-level OpenSSL validator test confirms that this strict mode
now selects the native path.

Multiple responders and responder ordering, optional OCSP, CRL/OCSP policy,
and OCSP update notifications remain separate migration layers.
