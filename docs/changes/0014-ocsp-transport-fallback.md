# Native OCSP transport fallback

This stacked change adds responder fallback for failures that can be
identified structurally as HTTP(S) transport failures. It builds on the
configured/AIA ordering layer without guessing from native provider text.

## Fallback contract

Responders are attempted in the previously defined order. A connection,
request-write, HTTP response, timeout, or response-read `IOException` advances
to the next configured or discovered responder. If all attempted responders
fail at the transport boundary, the final failure is returned at the checked
certificate's position.

The fallback crosses responder groups. For example, when configured
responders are preferred, transport failure of every configured entry allows
the AIA group to be discovered and attempted. When AIA is preferred, exhausted
AIA transport failures allow configured entries to be tried.

Each candidate keeps its own memory and persistent cache key. A cache hit is
still natively revalidated, and nonce-enabled validation still creates a new
uncached request for every candidate.

## Response failures remain terminal

`OCSPClientImpl` now exposes a bounded response-decoding exception distinct
from HTTP transport failures. Oversized responses and bytes that cannot be
parsed as an OCSP response stop validation and are not retried.

The following outcomes also remain terminal:

- missing or mismatched response nonces;
- native revoked or unknown status;
- stale responses;
- invalid signatures or responder authorization; and
- every other native response-validation failure.

BC 1.85 does not give those native failures reliably distinct standard
reasons, so the implementation does not parse provider messages or attempt a
later responder after any of them.

Deterministic tests cover configured-to-discovered and
discovered-to-configured fallback, exhaustion of multiple preferred
responders, rejection of malformed bytes without fallback, and the existing
rule that a native revoked result does not query a later good responder.

Optional OCSP, CRL/OCSP policy, responder-failure caching, and OCSP update
notifications remain separate layers.
