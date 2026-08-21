# Validation baseline

This records the test-suite baseline before the lite PKI validation refactor.
It is a comparison point, not a statement that every legacy behavior will be
retained.

## Source and environment

- Source commit: `89762d4` (`master`, "The grand refactoring plan")
- Recorded: 2026-08-21
- Maven: 3.9.12
- Java: OpenJDK 25.0.3

## Default suite

Command:

```console
mvn clean test
```

Result: **BUILD SUCCESS**

```text
Tests run: 274, Failures: 0, Errors: 0, Skipped: 1
```

The skipped test is in `ProxyGenerationTest`; its existing skip reason is
`TODO: test certificates have expired`.

## Opt-in risky integration suite

Command:

```console
mvn test -PriskyTests
```

Result: **BUILD FAILURE**

```text
Tests run: 8, Failures: 1, Errors: 0, Skipped: 3
```

The failure is `CRLTest.testLoadPlain`, which expects one CRL but loads none
from an external fixture URL. The three skipped tests are the existing OCSP
integration/cache/client tests. The OpenSSL validator stress tests pass.

The risky profile depends on external services and fixtures. Its failure is
therefore preserved as part of the baseline rather than treated as a failure
introduced by the refactor.
