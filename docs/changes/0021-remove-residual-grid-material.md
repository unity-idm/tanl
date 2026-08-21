# Remove residual Grid and EMI material

This stacked change removes the historical deployment model, compatibility
fixtures, and build infrastructure left after proxy, namespace-policy, and
legacy-validator removal. It does not remove OCSP, CRL, OpenSSL trust-store,
hostname, credential, or TLS functionality.

## Focused validation fixtures

`GLiteValidatorTest` and the complete `glite-utiljava` compatibility corpus are
removed. The retained certificates and CRLs are grouped by the behavior they
exercise: hostname matching, OpenSSL validation, concurrent validation, and
proxy rejection. Their bytes are unchanged, and `LICENSE.txt` continues to
carry the original EGEE/gLite attribution. A fixture-local provenance note
records their origin.

Focused tests preserve the useful coverage formerly hidden in the broad
matrix. Native PKIX and revocation tests cover expiry, revocation, required and
absent CRLs, and invalid trust paths. OpenSSL tests cover current subject
hashes, unusual distinguished names, present and absent CRLs, lazy and eager
stores, refresh, collisions, and shared-validator concurrency. Hostname and
proxy-rejection tests retain their dedicated certificate inputs.

The timing-dependent load-speed assertion and memory benchmark were not
correctness tests. They are replaced by a deterministic test that performs
1,000 validations from four threads against one shared OpenSSL validator.

## Removed compatibility surface

`OpensslNameUtils` and its dedicated tests are removed because namespace-policy
removal left the public class without a production caller. Its conversion to a
slash-delimited DN syntax was ambiguous by design. `X500NameUtils` and
`X500Principal` remain the supported standards-based parsing, comparison, and
display APIs.

Proxy certificate inputs remain only to verify rejection by ordinary native
PKIX validation. Proxy-generation extension sections are removed from the
retained test-CA OpenSSL configurations.

## Project and build cleanup

The README, manual, Javadoc overview, and Maven site now describe a general
X.509 library and application-selected trust-store locations. The Maven POM
points to the current source project and no longer contains obsolete EMI
organization links, mailing lists, WebDAV support, SVN-fetched documentation,
the obsolete `tools.jar`-dependent site reports, or the Packman RPM/Deb
profile. The unused RPM and Debian packaging trees are deleted.

The existing Maven group/artifact coordinates and `eu.emi` Java package names
remain unchanged. Choosing new publication coordinates or renaming packages is
explicitly outside this change.
