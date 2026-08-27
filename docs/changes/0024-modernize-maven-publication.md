# Modernize Maven publication

The library now publishes under `io.imunity.tanl:tanl`. Java packages remain
under `eu.emi.security`, so consumers update only their Maven coordinates when
moving to the new artifact.

Development starts at version `0.0.1-SNAPSHOT` under the new coordinates.

The build targets Java 21 with `--release 21` and requires Maven 3.9.2 or newer.
All declared lifecycle, packaging, release, signing, site, and reporting plugins
use current stable Maven 3 releases.

Compiler deprecation diagnostics remain enabled. Project-owned uses of JDK and
dependency APIs deprecated on the Java 21 toolchain were migrated to their
current replacements. Deprecated APIs inherited from CANL are removed rather
than retained as TANL compatibility aliases; migration details are listed in
`API-Changes.txt` and the migration guide.

The two bounded OCSP caches now qualify their private entry types explicitly in
`LinkedHashMap.removeEldestEntry` overrides. This avoids the inherited
`Map.Entry` name-resolution clash diagnosed by the modern Java 21 compiler.

Publishing no longer uses the retired OSSRH Nexus staging service. The
`org.sonatype.central:central-publishing-maven-plugin` extension sends signed
binary, source, Javadoc, and POM artifacts to the Sonatype Central Portal using
the `central` server entry from Maven settings. Successful deployments are
validated, published automatically, and awaited until publication completes.

The project metadata now includes the full BSD 3-Clause license name, canonical
license URL, and repository distribution marker required by Central validation.
