# Native CRL `IF_PRESENT` mode

This stacked change migrates optional CRL validation to the native path and
gives the mode a name that states its actual contract.

## Public contract

`CrlCheckingMode.IF_PRESENT` is the default CRL mode. The historical
`IF_VALID` value is deprecated but remains a source- and binary-compatible
alias with identical behavior.

For every non-anchor certificate in the base-validated path, optional CRL
checking has two outcomes:

- no potentially applicable parsed CRL is present, so CRL status is
  unavailable and validation may continue; or
- at least one candidate is present, so strict native BC CRL validation is
  required and every rejection is terminal.

This preserves the useful absence behavior without treating an expired,
badly signed, out-of-scope, incomplete, revoking, or otherwise invalid CRL as
though it were missing.

## Candidate boundary

Candidate discovery queries the configured `CertStore` for parsed `X509CRL`
objects issued by either:

- the certificate issuer; or
- an explicit directory-name `cRLIssuer` in the certificate's CRL
  Distribution Points extension.

Discovery deliberately does not pre-validate dates, signatures,
distribution-point scope, reason coverage, delta relationships, or
revocation status. Those decisions remain exclusively with the native BC
validator. Store-query and CRL Distribution Points parsing failures are
terminal.

Malformed source bytes which a configured CRL store cannot decode are not
parsed candidates. Existing CRL loading-error notifications still report
those inputs, while optional mode treats the resulting absence like the
historical implementation did.

## Combined policy

Optional CRL now participates in the native per-certificate CRL/OCSP policy.
With short-circuit policy, an unavailable CRL advances to OCSP and a verified
CRL skips it. With `useAllEnabled=true`, both enabled mechanisms are evaluated
according to their individual required or optional modes. A present CRL that
native validation rejects is terminal in either case.

Certificate-array and asserted-`CertPath` entry points share the same logic.
Tests cover absent and partially populated stores, revoked, expired and badly
signed CRLs, unrelated issuers, distribution points, base/delta CRLs,
explicit indirect CRL issuers, combined ordering, both mechanisms being
unavailable, `useAllEnabled`, the deprecated alias, and the new default.

No provider English messages are parsed and no CRL result is trusted outside
native BC validation.
