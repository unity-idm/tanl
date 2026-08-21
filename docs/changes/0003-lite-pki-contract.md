# Lite PKI behavioral and migration contract

This document freezes the intended externally observable behavior before the
implementation is replaced. It describes the final target. Intermediate
branches may deliberately support a smaller subset while the stacked changes
are under review, but each such limitation must be stated in that branch.

## Compatibility boundary

Compatibility is defined by validation verdicts and actionable primary error
reporting. The new implementation is not required to reproduce the legacy
reviewer's complete list or ordering of errors.

The refactor deliberately removes:

- proxy certificate generation, inspection, configuration, and validation;
- Globus `.signing_policy` and EUGridPMA `.namespaces` processing;
- pre-OpenSSL-1.0 subject hashes;
- copied Bouncy Castle path-validation code and its detailed error catalogue;
- gLite/Grid-specific utilities that have no retained callers.

The corresponding public packages, types, constructor arguments, flags,
listeners, and error codes will be removed rather than retained as no-ops.
Removal PRs must extend the migration notes with the exact symbols they delete.

Standard X.509 path validation, TLS trust management, OpenSSL-style hashed CA
and CRL stores, CRL revocation, and OCSP revocation are retained.

## Certificate input and path contract

- For an `X509Certificate[]`, element zero is the target. Remaining elements
  are unordered path-building candidates; their supplied order is not treated
  as an asserted path.
- A `CertPath` is an asserted coherent path and is validated directly.
- Trust anchors are configured separately and are never validated as path
  certificates.
- If an asserted or built path contains its trust anchor certificate, that
  certificate is removed from the path passed to native validation.
- An input consisting of an exact trusted self-signed certificate is valid.
- Successful results contain the resolved target-to-anchor chain, including
  the selected trust-anchor certificate.
- Native Bouncy Castle `CertPathBuilder` and `CertPathValidator`, selected with
  the BC provider explicitly, are the path-building and validation authority.

## Validation result contract

A result contains:

- the validation verdict;
- no validation errors for a valid result;
- one primary error for an invalid result;
- unresolved critical-extension OIDs when the provider exposes them without a
  second validation implementation;
- the resolved chain only for a valid result.

`getErrors()` remains as a compatibility convenience, but returns an immutable
empty or single-element list. `getPrimaryError()` returns the single error or
`null` for a valid result. The public `ValidationResult` constructors,
`addErrors()`, and `setErrors()` are removed from the consumer API.

The primary error contains:

- a stable error code and broad category;
- the validation stage (`INPUT`, `PATH_BUILDING`, `PATH_VALIDATION`, or
  `REVOCATION`);
- a zero-based certificate index and certificate when a position is known;
- the original provider message;
- the original exception as its cause.

Index zero denotes the target. An unknown or whole-path position is `-1`.
Provider-specific text is diagnostic data and is not a stable API value.

The stable error-code set is limited to standard reasons:

- `INVALID_INPUT`;
- `PATH_BUILDING_FAILED` and `NO_TRUST_ANCHOR`;
- `CERTIFICATE_EXPIRED` and `CERTIFICATE_NOT_YET_VALID`;
- `INVALID_SIGNATURE` and `ALGORITHM_CONSTRAINED`;
- `INVALID_NAME_CHAINING`;
- `INVALID_KEY_USAGE`, `NOT_CA`, and `PATH_TOO_LONG`;
- `INVALID_NAME_CONSTRAINT` and `INVALID_POLICY`;
- `UNRESOLVED_CRITICAL_EXTENSION`;
- `CERTIFICATE_REVOKED` and `UNDETERMINED_REVOCATION_STATUS`;
- `PKIX_FAILURE` for all unspecified/provider-specific reasons.

The retained broad categories are `INPUT`, `PATH`, `CERTIFICATE`,
`NAME_CONSTRAINT`, `POLICY`, `REVOCATION`, and `OTHER`.

Validation-error listeners are notification-only. A listener cannot suppress
an error, change an invalid verdict, or mutate the primary error. TLS-facing
`CertificateException`s preserve the primary validation exception as their
cause.

## Revocation contract

OCSP is required retained functionality. The implementation will be migrated
in layers so that custom mechanics do not remain entangled with path
validation.

The required core modes are:

- disabled revocation;
- strict CRL validation;
- strict OCSP validation;
- native OCSP-first fallback to CRL;
- native CRL-first fallback to OCSP;
- native soft-fail OCSP-first fallback for compatibility with the current
  default.

The compatibility default is OCSP first, followed by CRL, with native
soft-fail behavior when status cannot be obtained. A definitive revoked status
always fails. Malformed, forged, badly signed, or otherwise invalid revocation
data is not converted into success by soft-fail handling.

The following OCSP capabilities are migration requirements, each implemented
and reviewed separately after core native OCSP validation:

- responder discovery from certificate AIA;
- explicitly configured responder URL and trusted responder certificate;
- preference and ordering between configured and discovered responders;
- connection timeout;
- request nonce generation and response nonce enforcement;
- bounded in-memory response caching and configured cache TTL;
- optional persistent response caching;
- ordering between OCSP and CRL mechanisms;
- the existing require-all-enabled-mechanisms behavior where it can be layered
  around independent native validation without weakening either result.

No item in this compatibility list is silently dropped. If a capability cannot
be retained without copied validation code, provider-message matching, or a
security regression, its dedicated PR must demonstrate that limitation and
make the final decision explicit.

The optional CRL mode is named `IF_PRESENT`. The legacy `IF_VALID` name may be
retained only as a deprecated compatibility alias with identical behavior.

## Review and verification rule

Every behavior-changing branch must state which contract clauses it implements
or intentionally defers. Valid/invalid verdict comparisons use the recorded
baseline where the behavior remains in scope. New native revocation behavior
uses deterministic local CRL and OCSP fixtures rather than public responders.
