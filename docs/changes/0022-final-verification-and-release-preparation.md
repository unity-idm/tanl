# Final verification and release preparation

This stacked change closes the lite PKI validation plan without removing OCSP
or any other retained validator, credential, trust-store, hostname, or TLS
capability.

## TLS boundary coverage

`SSLTrustManagerTest` now exercises the public validator and TLS adapter
together with real certificate material. It accepts a valid chain and rejects
untrusted, expired, strictly CRL-revoked, and unsupported-critical-extension
chains. The rejection assertions use stable validation codes and stages and
prove that the TLS `CertificateException` retains the exact native primary
cause observed by the validation listener. They never classify failures by
parsing provider text.

The focused native and OpenSSL suites remain the release gate. Together they
cover lazy and eager stores, modern certificate and CRL hashes, collision
suffixes, refresh behavior, malformed and absent CRLs, concurrency, native
PKIX paths, strict and optional CRLs, and the complete retained native OCSP
configuration and transport behavior.

The plain CRL loading integration test no longer relies on a mutable external
Grid CRL endpoint. An embedded HTTP server now exercises the same remote load,
disk-cache write, wildcard source, and issuer lookup behavior with retained
local CRL fixtures, making the full integration profile reproducible.

## Migration and release documentation

`docs/migration-guide.md` contains compile-oriented examples for validator
construction and disposal, lazy and eager loading, CRL and OCSP mode
selection, configured/AIA responder ordering, `useAllEnabled`, immutable
primary errors, and the modern OpenSSL trust-store layout. The README, manual,
and Maven site point readers to it.

`API-Changes.txt` remains the exhaustive release note for removed types,
constructors, enum values, implementation packages, and historical deployment
material. The guide supplies replacements and operational examples. OCSP is
explicitly retained.

## Release checks

Verification completed on Java 25:

- `mvn clean package site source:jar` passed with 358 tests and no failures,
  errors, or skips in the default suite;
- the focused TLS and OpenSSL-store gate passed all 30 tests;
- the optional risky profile passed its active CRL stress test, while its
  pre-existing ignored external OCSP test remained skipped;
- runtime, source, and Javadoc JARs and the Maven site were generated and
  inspected;
- removed legacy classes were absent from the artifacts and public Javadocs,
  while the retained OCSP API and implementation were present; and
- `jdeps --jdk-internals` reported no JDK-internal dependencies.

The old Maven site dependency report emits non-fatal bytecode-analysis
warnings for Bouncy Castle's multi-release JAR entries. Site generation still
completes successfully and the warnings do not originate from the library
artifact or Javadocs.
