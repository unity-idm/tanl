# Lite PKI validation plan

## Objective

Produce a deliberately breaking, smaller version of the library that retains standard PKI and TLS validation while removing proxy certificates, namespace-policy extensions to OpenSSL truststores, and the copied/custom Bouncy Castle path-validation implementation.

Native Bouncy Castle `CertPathBuilder` and `CertPathValidator` are to be the validation authority. Compatibility is defined primarily by validation verdicts, useful first-error reporting, and certificate position—not by returning every error detectable in a chain.

## Accepted direction

- Remove proxy certificate support and its public APIs completely.
- Remove both Globus `.signing_policy` and EUGridPMA `.namespaces` handling.
- Retain an OpenSSL-style store containing hashed CA certificates and CRLs only.
- Support modern OpenSSL subject hashes; remove the pre-1.0 MD5 hash mode.
- Treat the work as a major-version API break; do not retain no-op compatibility flags.
- Use native BC path building and validation, not either the copied or upstream BC path reviewer.
- Preserve one useful primary validation error, its cause, certificate/index, and a stable broad category where possible.
- Make validation-error listeners notification-only; listeners must not turn an invalid chain into a valid one.
- Treat the first certificate in an array as the target and the remainder as path-building candidates.
- Accept an exact trusted self-signed input and keep trust anchors outside PKIX path validation.
- Use native revocation behavior for the modes that BC represents accurately. Do not emulate optional behavior through exception-message matching.
- Retain OCSP validation. Migrate its core validation to native BC first, then preserve responder configuration, fallback and ordering, caching, and nonce behavior in separately reviewed layers wherever each feature can be implemented precisely and tested deterministically.
- Remove residual gLite/Grid compatibility utilities, test corpora, documentation, and obsolete build metadata while preserving required attribution for retained derived code.

## Sequence

### 1. Freeze the behavioral contract and baseline

- Record the breaking API and behavior changes in release/migration notes.
- Preserve the current full-suite result as the comparison baseline.
- Define the retained revocation modes and their defaults before changing public configuration.
- Define the smaller stable validation-error categories and result contract.

Exit condition: the intended public surface and accepted behavior changes are explicit enough that subsequent test changes can be reviewed against them.

### 2. Remove proxy certificate support

- Delete the public proxy package, proxy helpers, configuration flags, validator branches, dedicated errors, documentation, tests, and resources used only by proxies.
- Remove proxy parameters from validator construction and from extended validator APIs.
- Remove proxy cases from mixed test matrices while retaining their ordinary X.509 cases.
- Add regression coverage showing that RFC 3820 and legacy proxy chains are rejected by normal PKIX processing.

Exit condition: the project builds without proxy APIs or proxy-aware validation logic, and the retained non-proxy suite passes.

### 3. Simplify the OpenSSL-style truststore

- Delete both namespace-policy implementations and their public configuration.
- Remove namespace stores, policy update notifications, errors, parsers, tests, documentation, and policy resources.
- Restrict the store to modern OpenSSL hashed certificate and CRL filenames.
- Preserve lazy/eager loading, hash-collision suffixes, refresh behavior, and loading notifications for certificates and CRLs.
- Adapt the useful OpenSSL validator tests so they test store loading and path construction without namespace files.

Exit condition: `.signing_policy`, `.namespaces`, and pre-1.0 hash behavior have no code path, while hashed CA and CRL loading works in lazy and eager modes.

### 4. Replace custom path validation with native BC

- Introduce a small native-BC validation component using the BC provider explicitly.
- Build array inputs from the target certificate plus candidate intermediates; validate `CertPath` inputs directly.
- Normalize paths so an included trust anchor is not validated as a path certificate.
- Handle exact trusted self-signed inputs explicitly.
- Preserve the resolved valid path, including the selected trust anchor, in successful results.
- On invalid input, use native direct validation for a coherent supplied path; otherwise report a path-building failure.
- Initially exercise this step with revocation disabled so base PKIX behavior is isolated.

Exit condition: retained NIST and ordinary PKIX tests preserve every valid/invalid verdict using native BC only.

### 5. Simplify errors, listeners, and TLS propagation

- Replace copied-reviewer error conversion with a small adapter around native builder and validator exceptions.
- Preserve the primary cause, raw provider message, certificate/path index, and validation stage.
- Map only stable standard reasons to specific codes; use a general PKIX failure for provider-specific or unspecified reasons.
- Preserve unresolved critical-extension information where it can be collected without implementing another validator.
- Make validation-error listeners notification-only.
- Attach the primary validation cause to TLS-facing `CertificateException`s.
- Rewrite tests that assert exact error counts to assert verdict, position, and stable category instead.

Exit condition: invalid TLS and direct-validation calls provide an actionable primary failure without permitting listeners to suppress validation failures.

### 6. Implement the retained native revocation modes

- Implement revocation-disabled and strict native CRL behavior.
- Implement required OCSP and native preferred-mechanism fallback.
- Preserve certificate AIA responder discovery and explicitly configured responders.
- Migrate responder ordering, cache, nonce, and multi-mechanism semantics in separate changes. Retain each behavior that can be specified precisely and tested without replacing native BC as the validation authority.
- Add focused tests for missing, expired, malformed, badly signed, and revoking CRLs, plus equivalent OCSP outcomes.

Exit condition: every advertised revocation mode has precise tests and no mode claims optional/soft-fail semantics that BC does not actually provide.

### 7. Decision gate: optional CRL `IF_PRESENT` mode

This is a separate, optional piece of work. Decide whether heterogeneous CA bundles require the old behavior where an absent applicable CRL is accepted but a present CRL is enforced.

If required, prototype a small policy layer around native BC:

1. Build and validate the selected path with native BC and revocation disabled.
2. Inspect each non-anchor certificate/issuer edge for a potentially applicable CRL in the configured store.
3. Skip an edge when no candidate CRL exists.
4. When a candidate exists, perform strict native BC revocation validation for that certificate using its already-validated issuer.

The prototype must cover:

- no CRLs anywhere;
- a partially populated chain;
- a revoked leaf when another chain CRL is absent;
- expired and badly signed CRLs;
- unrelated CRLs from other trust anchors;
- indirect, delta, and distribution-point CRLs where supported by the retained store contract.

Adopt the mode only if those cases can be implemented without copied BC validation code, fragile provider-message matching, or silently weakening a present-CRL failure. If adopted, name it `IF_PRESENT` rather than `IF_VALID` and document its exact definition.

Exit condition: either the tested `IF_PRESENT` adapter is accepted, or the mode is explicitly omitted from the lite API.

### 8. Delete obsolete validation and revocation code

- Delete the copied `helpers/pkipath/bc` package.
- Delete the non-validating path builder, old reviewer/error mapper, proxy checker, and custom CRL integration that depended on copied BC internals.
- Delete custom OCSP/revocation components made obsolete by the accepted revocation surface.
- Remove dead error codes, message resources, configuration types, tests, and documentation.
- Verify that no production code imports BC provider internals solely to reproduce path validation.

Exit condition: native BC is the sole certificate-path validation authority and the copied implementation is absent from the source tree.

### 9. Remove residual gLite and EMI material

- Delete `OpensslNameUtils` and its dedicated tests after namespace-policy removal leaves it without production callers.
- Replace `GLiteValidatorTest` with focused PKIX, OpenSSL-store, and revocation tests. Retain useful coverage for modern hashes, missing CRLs, expiry, revocation, unusual DNs, and concurrency without retaining the gLite compatibility matrix.
- Move the small number of certificates still needed by hostname, OpenSSL, and stress tests into purpose-specific fixture directories, then delete the remaining `glite-utiljava` test corpus.
- Remove proxy-generation sections from retained test-CA OpenSSL configurations.
- Rewrite the README, manual, examples, Javadocs, and site content so they no longer describe proxies, namespace policies, or `/etc/grid-security/certificates` as the default deployment model.
- Remove obsolete EMI project links, mailing lists, SCM metadata, SVN-based documentation tooling, and unused RPM/Deb packaging support from the build.
- Use distinct Maven project metadata for the fork when its publication coordinates are chosen. Keep Java package renaming outside this work unless it is approved separately.
- Preserve EGEE/gLite and other copyright or license attribution wherever derived code remains.

Exit condition: no gLite/Grid-specific behavior, fixtures, documentation, or build infrastructure remains except legally required provenance, and retained tests describe the behavior they exercise rather than their historical source.

### 10. Final verification and release preparation

- Run the full unit and integration suite on a clean checkout.
- Run targeted TLS trust-manager tests for valid, untrusted, expired, revoked, and unsupported-critical-extension chains.
- Exercise lazy and eager OpenSSL stores, refresh behavior, hash collisions, and CRL loading.
- Build Javadocs and distribution artifacts and review their public API for removed legacy types.
- Document migration examples for validator construction, revocation selection, error handling, and modern OpenSSL truststore layout.

Exit condition: all retained functionality is covered, removed functionality is absent from APIs and artifacts, and the release notes describe every intentional compatibility break.
