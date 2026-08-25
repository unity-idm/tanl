# Native strict CRL validation

This stacked change migrates strict CRL-only validation to native Bouncy
Castle without changing or removing OCSP support.

## Migrated configuration

`CrlCheckingMode.REQUIRE` combined with `OCSPCheckingMode.IGNORE` now uses the
native BC `CertPathValidator` for CRL validation. This applies to certificate
array and asserted `CertPath` inputs.

Validation is deliberately split into two passes:

1. Build and validate the selected path with revocation disabled.
2. Validate that same path with strict native CRL checking enabled.

This keeps path construction independent of CRL availability and gives CRL
failures the `REVOCATION` stage. Trust anchors remain outside the validated
path and are not themselves revocation-checked.

All supplied certificate candidates remain available to native validation so
BC can discover separate and indirect CRL signer certificates. Native
delta-CRL processing is enabled. The retained NIST revocation corpus preserves
its verdicts, including separate signing keys, indirect CRLs, and delta CRLs.

Strict mode rejects:

- a missing applicable CRL;
- an expired CRL;
- a malformed CRL that the configured store cannot load;
- a CRL whose signature cannot be verified;
- a certificate listed as revoked.

Malformed store entries continue to emit the existing CRL loading error
notification and are not treated as usable CRLs.

## Error mapping

BC 1.85 reports CRL-validation failures using an unspecified standard reason,
including a definitive revoked result. The implementation therefore follows
the primary-error contract and uses `PKIX_FAILURE` rather than parsing provider
English text. It preserves the `REVOCATION` stage, affected certificate/index,
original provider message, and original exception. If a provider supplies the
standard `REVOKED` or `UNDETERMINED_REVOCATION_STATUS` reason, the existing
stable mappings are used.

## Deliberately deferred behavior

This branch leaves the following configurations on the existing compatibility
implementation:

- `CrlCheckingMode.IF_VALID`;
- every OCSP-enabled configuration;
- CRL/OCSP ordering and `useAllEnabled` combinations.

OCSP responder discovery, configured responders, ordering, timeouts, nonce,
and caches are unchanged and remain available. Native OCSP and the optional
`IF_PRESENT` decision are handled in separate stacked changes.
