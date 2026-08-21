# Native OCSP responder failure cache

This stacked change restores responder-failure caching on the native OCSP
transport path while narrowing its authority to structurally classified HTTP
transport failures.

## Cache behavior

After a connection, request-write, timeout, response-read, or responder-wide
HTTP 502/503/504 failure, the responder URI receives a failure entry. A live
entry avoids a new connection and produces the same retryable control-flow
outcome, so an ordered validation can continue with its next configured or
AIA responder. Other HTTP errors remain retryable for the current ordered
request but are not cached because they can be request-specific.

The response cache is consulted first. A valid cached response can therefore
still be revalidated while its responder is temporarily unreachable. Any
non-cacheable HTTP response clears the failure entry. Nonce-enabled requests
continue to bypass response caching, but can use failure entries because
transport availability is independent of replay protection.

The existing `OCSPParametes` cache TTL controls both caches:

- a negative value disables response and failure caching;
- a positive value expires a failure in that many seconds; and
- zero leaves response expiry to response metadata, but bounds failures to
  `OCSPParametes.DEFAULT_CACHE` (one hour) because failures have no validity
  metadata.

## Responder identity and persistence

Unlike the compatibility cache, which hashes the issuer certificate, the
native failure cache keys directly by responder URI. A failed service cannot
suppress another responder serving the same issuer.

Each validator owns an access-ordered in-memory cache capped at 100 responders.
When persistence is configured, files use this distinct form:

```text
ocspfail-v1-<sha256>.cache
```

The digest covers the length-delimited responder URI. The fixed-size,
versioned binary record contains only a fetch-failure timestamp; it never
serializes an exception or provider message. Writes use same-directory atomic
replacement when supported. Corrupt, truncated, future-dated, and expired
records are deleted as cache misses, and filesystem failures leave normal
validation behavior intact.

## Trust boundary

Only transport failures that indicate responder-wide unavailability create an
entry. HTTP 502, 503, and 504 statuses are classified explicitly; request-
specific client errors and other HTTP statuses can still fall back to the next
responder without suppressing later certificate requests to the same URI.
Response decoding, nonce enforcement, and all native BC status, signature,
signer-authorization, and freshness failures remain terminal and are not
cached as responder outages. No provider text is parsed.

Deterministic tests cover seconds-based expiry, zero and negative TTLs,
responder-specific keys, LRU eviction, versioned persistence, corrupt-file
removal, fallback through a cached outage, recovery with caching disabled, and
isolation of request-specific HTTP failures at one responder URI.

Optional OCSP, CRL/OCSP policy, and OCSP update notifications remain separate
layers.
