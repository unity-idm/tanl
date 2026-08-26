# canl

Common X.509 Authentication Library for Java. The library provides native
Bouncy Castle PKIX certificate-path validation, CRL and OCSP revocation
checking, Java and OpenSSL-style trust stores, credential loading, and JSSE
trust-manager/socket integration.

## Maven dependency

```xml
<dependency>
    <groupId>eu.eu-emi.security</groupId>
    <artifactId>canl</artifactId>
    <version>2.8.4-SNAPSHOT</version>
</dependency>
```

The publication coordinates and Java package names remain unchanged for
compatibility while new release coordinates are being decided.

## Build

Java 8 or newer and Maven 3.1.1 or newer are required.

```sh
mvn clean test
```

Tests categorized as risky integration tests can be run with
`mvn -PriskyTests test`.

See `src/main/doc/manual.txt` for the user guide,
`docs/migration-guide.md` for construction and revocation migration examples,
`API-Changes.txt` for the exhaustive compatibility notes, and `docs/changes/`
for the validation-modernization design record. Licensing and retained
upstream attribution are in `LICENSE.txt`.
