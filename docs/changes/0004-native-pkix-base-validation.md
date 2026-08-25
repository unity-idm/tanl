# Native PKIX base-validation scope

This branch implements the base certificate-path portion of the lite PKI
contract with revocation disabled.

## Implemented here

- Native Bouncy Castle `CertPathBuilder` and `CertPathValidator` are selected
  explicitly from the BC provider.
- For certificate arrays, element zero is the target and all later elements
  are unordered path-building candidates.
- `CertPath` inputs are validated directly.
- A configured trust anchor included in a path is kept outside native path
  validation and restored in the successful resolved chain.
- An exact configured self-signed certificate is accepted as a one-certificate
  input. An exact non-self-signed anchor is not accepted as a zero-length path.
- Invalid native base validation returns one error. Detailed stable error
  adaptation is intentionally deferred to the next branch.
- The non-revocation NIST corpus asserts verdicts instead of legacy reviewer
  error counts.

## Intentionally deferred

CRL- or OCSP-enabled calls continue through the existing revocation path in
this intermediate branch. This preserves all configured OCSP behavior while
native CRL and OCSP modes are implemented in their dedicated steps. The copied
reviewer and its revocation support therefore remain temporarily reachable
only for revocation-enabled validation.

Stable native error codes, provider causes and stages, notification-only error
listeners, TLS cause propagation, unresolved-extension reporting, and native
revocation behavior are not claimed by this branch. They remain assigned to
steps 5 and 6 of the migration plan.
