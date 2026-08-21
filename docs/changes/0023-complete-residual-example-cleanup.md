# Complete residual example cleanup

The final roadmap audit found three textual remnants of the historical Grid
deployment model outside the public documentation audited in the preceding
change.

The compile-checked validator example now uses an application-selected
OpenSSL trust-store path, describes the current default OCSP and CRL policy,
uses the immutable primary-error API, and disposes its validator. The
standalone key-pair validator now requires its trust-store directory argument
instead of silently defaulting to `/etc/grid-security/certificates`.

The modern OpenSSL subject-hash test retains its whitespace-normalization and
known-hash assertion with a neutral example CA distinguished name. The new
expected value was independently calculated with the installed OpenSSL
`subject_hash` implementation.

These are documentation and test-fixture identity corrections only. They do
not change validator behavior, public APIs, CRL support, or OCSP support.
