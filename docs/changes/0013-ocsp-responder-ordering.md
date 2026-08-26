# Native OCSP responder ordering

This stacked change migrates deterministic responder selection for strict
native OCSP validation. It supports configured and certificate-discovered
responders in the same validation without changing native BC's authority over
the response.

## Ordering contract

For each certificate/issuer edge, two responder groups are assembled:

1. configured `OCSPResponder` entries in their array order; and
2. HTTP(S) OCSP locations from certificate AIA in access-description order.

When `OCSPParametes.isPreferLocalResponders()` is true, the configured group
comes first. When it is false, the AIA group comes first. If the preferred
group is empty, the first entry from the other group is selected. An empty
combined list causes strict OCSP validation to fail at the certificate's
original path position.

Configured entries retain their responder certificate. Discovered responders
use the already validated issuer context. The selected responder inherits the
native timeout, nonce, memory-cache, and persistent-cache behavior implemented
by the preceding layers.

A non-empty preferred configured group can be selected without parsing unused
AIA metadata. AIA remains strict when the discovered group is preferred or no
configured responder exists.

## Retry boundary

This layer performs selection, not fallback. If the selected responder's
response is rejected by native BC, validation stops and later entries are not
queried. In BC 1.85 the observed native exceptions do not structurally
distinguish revoked, unknown, expired, badly signed, and other invalid OCSP
responses. The implementation does not parse provider text to guess whether a
later responder is safe to try.

Deterministic tests cover configured-first and discovered-first selection,
order within the configured group, multiple AIA routing through the high-level
validator, and the rule that a definitive native failure is not skipped for a
later good responder.

Transport-failure fallback remains a separate layer because it can be based
on structured transport outcomes. Optional OCSP, CRL/OCSP policy, and OCSP
update notifications also remain separate.
