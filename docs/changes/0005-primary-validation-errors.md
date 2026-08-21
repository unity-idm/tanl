# Primary validation errors

This branch implements the lite validation-result, error-listener, and TLS
failure contract without changing revocation selection or removing OCSP.

## Result contract

`ValidationResult` is immutable. A valid result has no error; an invalid result
has exactly one primary error. `getErrors()` remains as an immutable empty or
single-element compatibility view, and `getPrimaryError()` provides direct
access to that error. Unresolved-extension sets and successful resolved chains
are also immutable defensive copies.

The public constructors and the `addErrors()` and `setErrors()` mutators were
removed. Code which must create a result uses the `valid(...)` and
`invalid(...)` factories.

## Native failure adapter

Native base-PKIX failures now preserve:

- a stable `ValidationErrorCode` and broad `ValidationErrorCategory`;
- the `ValidationStage` (`INPUT`, `PATH_BUILDING`, `PATH_VALIDATION`, or
  `REVOCATION`);
- the path index and certificate when BC provides a position;
- the unmodified provider message as diagnostic data; and
- the original exception as the cause.

Only standard `CertPathValidatorException` reasons and typed standard causes
are mapped to specific stable codes. When BC reports `UNSPECIFIED`, the error
uses `PKIX_FAILURE`; provider English text is never parsed to infer a code. In
particular, the current BC provider does not expose a reason or structured OID
set for its unsupported-critical-extension failure, so that case retains its
raw message and position but does not invent unresolved-extension OIDs.

## Listeners and TLS

`ValidationErrorListener.onValidationError(...)` now returns `void`.
Listeners observe the immutable primary error but cannot suppress it or turn
an invalid result into a valid one. All three TLS trust-manager implementations
(`CommonX509TrustManager`, `SSLTrustManager`, and
`SSLTrustManagerWithHostnameChecking`) attach the primary validation exception
as the cause of their thrown `CertificateException`.

## Revocation transition

CRL- or OCSP-enabled validation still uses the existing revocation path in
this stacked branch. Its verdicts and OCSP behavior remain active, but its
multiple reviewer errors are collapsed to the first primary error so the
result invariant is universal. Legacy revocation error codes/categories remain
temporarily available and are replaced when native CRL and OCSP validation is
introduced in the next step.
