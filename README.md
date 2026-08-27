# tanl

TLS X.509 Authentication Library for Java. The library provides native
Bouncy Castle PKIX certificate-path validation, CRL and OCSP revocation
checking, Java and OpenSSL-style trust stores, credential loading, and JSSE
trust-manager/socket integration.

## Maven dependency

```xml
<dependency>
    <groupId>io.imunity.tanl</groupId>
    <artifactId>tanl</artifactId>
    <version>...</version>
</dependency>
```

## Relationship to canl-java

This library is a lightweight fork of the original `canl-java` library. It removes
all grid specific code, including proxy-certificates support. What is important
X.509 chain validation is based on the native Bouncy Castle library code, unlike canl. 

The Maven publication coordinates have moved from `eu.eu-emi.security:canl` 
to `io.imunity.tanl:tanl`.

## Build

Java 21 or newer and Maven 3.9.2 or newer are required.

```sh
mvn clean test
```

Tests categorized as risky integration tests can be run with
`mvn -PriskyTests test`.

## Publishing

Releases are signed during `verify` and published through the Sonatype Central
Portal. Configure a Central user token under the `central` server ID in Maven
`settings.xml`, make the signing key available to GnuPG, and run
`mvn clean deploy` from the release version. The Central plugin validates and
automatically publishes the deployment.

See `src/main/doc/manual.txt` for the user guide,
`docs/migration-guide.md` for construction and revocation migration examples,
`API-Changes.txt` for the exhaustive compatibility notes, and `docs/changes/`
for the validation-modernization design record. Licensing and retained
upstream attribution are in `LICENSE.txt`.
