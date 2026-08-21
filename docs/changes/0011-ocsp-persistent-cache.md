# Native OCSP persistent response cache

This stacked change extends the bounded native OCSP response cache to the
configured `OCSPParametes` disk-cache directory.

## Persistence contract

When a disk-cache path is configured and the cache TTL is non-negative, a
response accepted by native BC is stored in memory and in a versioned cache
file. A later validator instance can load that encoded response without
contacting the responder, but it must pass the bytes to a fresh
`PKIXRevocationChecker` before returning a valid result.

A negative cache TTL disables both memory and disk caching. Zero and positive
TTLs retain the seconds-based behavior introduced by the memory-cache layer.
The original fetch time and the earliest HTTP/OCSP expiry are stored, so a
restart cannot reset or extend an entry's lifetime.

## File safety

Native cache filenames have the form:

```text
ocspresp-v1-<sha256>.cache
```

The digest covers length-delimited encodings of the responder URI, checked
certificate, issuer, and optional explicit trusted responder certificate.
This produces a fixed safe filename and prevents entries for different
validation contexts from sharing a cache slot.

The cache uses a small binary format containing a magic value, version, fetch
time, response-expiry time, encoded-response length, and response bytes. It
does not deserialize Java objects. File size and internal length are checked
against a 64 KiB limit, timestamps are checked, final-component symbolic links
are not followed, and malformed or truncated files are deleted as cache
misses.

Writes use a temporary file in the configured directory followed by atomic
replacement when the filesystem supports it, with same-directory replacement
as the fallback. The directory is created when necessary. A read or write
failure degrades to the in-memory cache or a normal network fetch; persistence
is never validation authority.

Existing compatibility-cache `ocspresp_` files are intentionally not loaded.
They use Java serialization and store a parsed `SingleResp`, which cannot be
fed back into the native checker with its complete signed response. Native
cache files use the distinct `ocspresp-v1-` prefix.

## Failure handling and verification

Every disk hit is natively revalidated. If that check fails, both memory and
disk entries are removed and one fresh response is fetched. Only the fresh
response is considered, and it is persisted only after native acceptance.
Rejected and revoked responses are not negative-cached because BC 1.85 does
not provide a structured distinction that would make such persistence safe.

Deterministic tests cover binary round trips, safe filenames, automatic
directory creation, expiry across cache instances, corrupt-file removal,
successful offline reuse by a new native validator, and network recovery that
replaces a corrupt entry. Nonce, responder fallback/ordering, optional OCSP,
CRL/OCSP policy, and OCSP update notifications remain separate layers.
