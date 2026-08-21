# Native OCSP update notifications

This stacked change reconnects the native OCSP fetch path to the public
`StoreUpdateListener` mechanism used by the compatibility implementation.

## Observable contract

The native validator now shares its owning validator's `ObserversHandler`.
This means listeners supplied during construction and listeners registered
later with `addUpdateListener` observe the same native OCSP events.

For each structured request or response-processing failure, listeners receive:

- the responder URI as `location`;
- `StoreUpdateListener.OCSP` as `type`;
- `Severity.WARNING`; and
- the original exception as `cause`.

Notifications are generated for request construction, actual and cached HTTP
transport failures, bounded response decoding, nonce enforcement, and encoded
response processing. A failed responder still emits a warning when fallback
later succeeds, preserving the operational visibility that validation results
alone cannot provide.

Successful fetches and response-cache hits do not emit notifications, matching
the previous behavior.

## Native status boundary

Native `CertPathValidatorException` response rejections are not sent to update
listeners. BC 1.85 does not reliably distinguish revoked and unknown status
from bad signatures, unauthorized responders, stale data, and other response
failures through standard reasons. Reporting all of them as responder-update
warnings would mislabel definitive certificate status as infrastructure
failure. The implementation does not inspect provider messages to guess.

The validation result remains strict and terminal for every native response
rejection; this layer changes only the separate update-listener side channel.

Tests cover notification of a transport failure hidden by successful fallback,
preservation of the original cause and metadata, delivery through the public
validator after late listener registration, and absence of a responder warning
for definitive revoked status.

Optional OCSP and combined CRL/OCSP policy remain separate layers.
