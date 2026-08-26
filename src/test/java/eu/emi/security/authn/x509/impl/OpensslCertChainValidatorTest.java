/*
 *     Copyright 2023 Deutsches Elektronen-Synchrotron (DESY)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *          http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.emi.security.authn.x509.impl;

import static java.time.Duration.of;
import static java.time.temporal.ChronoUnit.DAYS;
import static java.time.temporal.ChronoUnit.HOURS;
import static java.time.temporal.ChronoUnit.MINUTES;
import static java.util.Objects.requireNonNull;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;

import javax.security.auth.x500.X500Principal;

import com.sun.net.httpserver.HttpServer;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.OCSPResponder;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.ValidationStage;
import eu.emi.security.authn.x509.helpers.ObserversHandler;
import eu.emi.security.authn.x509.helpers.crl.LazyOpensslCRLStoreSpi;
import eu.emi.security.authn.x509.helpers.trust.LazyOpensslTrustAnchorStoreImpl;
import eu.emi.security.authn.x509.helpers.trust.OpensslTruststoreHelper;

/**
 * A set of unit-tests to verify correct behaviour of
 * OpensslCertChainValidator that follow the BDD style.
 */
public class OpensslCertChainValidatorTest
{
	private OpensslCertChainValidator validator;
	private Path trustStore;
	private HttpServer ocspServer;

	@Before
	public void setup() throws IOException {
		validator = null;
		ocspServer = null;
		trustStore = Paths.get("target/openssl-trust-stores/" +
				ThreadLocalRandom.current().nextLong(0, Long.MAX_VALUE));
		Files.createDirectories(trustStore);
	}

	@After
	public void tearDown() throws IOException {
		if (ocspServer != null) {
			ocspServer.stop(0);
		}
		if (Files.exists(trustStore)) {
			Files.walk(trustStore)
			.sorted(Comparator.reverseOrder())
			.map(Path::toFile)
			.forEach(File::delete);
		}

		if (validator != null) {
			validator.dispose();
		}
	}

	@Test
	public void shouldValidateRootIssuedEEC() throws Exception {
		List<String> loadedTypes = Collections.synchronizedList(new ArrayList<String>());
		CA rootCA = given(aCertificateAuthority()
				.selfSigned()
				.withName("DC=org, DC=example, CN=root CA"));

		given(anOpensslTrustStore()
				.trustingCA(rootCA));

		given(anOpensslCertChainValidator()
				.with(OCSPCheckingMode.IGNORE)
				.with(CrlCheckingMode.REQUIRE)
				.with(recordingListener(loadedTypes))
				.withUpdateInterval(of(2, MINUTES))
				.withLazyLoading());

		X509Certificate serviceCertificate = given(anEEC()
				.withSubject("DC=org, DC=example, CN=remote host")
				.signedBy(rootCA));

		ValidationResult result = whenValidating(serviceCertificate);

		assertThat(result.isValid(), is(equalTo(true)));
		assertThat(result.getErrors(), is(empty()));
		assertThat(result.getUnresolvedCriticalExtensions(), is(empty()));
		assertThat(loadedTypes.contains(StoreUpdateListener.CA_CERT), is(true));
		assertThat(loadedTypes.contains(StoreUpdateListener.CRL), is(true));
	}

	@Test
	public void shouldValidateRootIssuedEecWithEagerLoading() throws Exception {
		List<String> loadedTypes = Collections.synchronizedList(new ArrayList<String>());
		CA rootCA = given(aCertificateAuthority()
				.selfSigned()
				.withName("DC=org, DC=example, CN=eager root CA"));

		given(anOpensslTrustStore().trustingCA(rootCA));
		given(anOpensslCertChainValidator()
				.with(OCSPCheckingMode.IGNORE)
				.with(CrlCheckingMode.REQUIRE)
				.with(recordingListener(loadedTypes))
				.withUpdateInterval(of(2, MINUTES))
				.withEagerLoading());

		X509Certificate serviceCertificate = given(anEEC()
				.withSubject("DC=org, DC=example, CN=eager remote host")
				.signedBy(rootCA));

		ValidationResult result = whenValidating(serviceCertificate);

		assertThat(result.toString(), result.isValid(), is(true));
		assertThat(loadedTypes.contains(StoreUpdateListener.CA_CERT), is(true));
		assertThat(loadedTypes.contains(StoreUpdateListener.CRL), is(true));
	}

	@Test
	public void shouldLoadCertificateAndCrlHashCollisionSuffixes() throws Exception {
		String subject = "DC=org, DC=example, CN=rollover root CA";
		CA firstRoot = given(aCertificateAuthority().selfSigned().withName(subject));
		CA secondRoot = given(aCertificateAuthority().selfSigned().withName(subject));

		given(anOpensslTrustStore()
				.trustingCA(firstRoot)
				.andTrustingCA(secondRoot));

		String hash = OpensslTruststoreHelper.getOpenSSLCAHash(firstRoot.getSubject());
		assertThat(Files.exists(trustStore.resolve(hash + ".1")), is(true));
		assertThat(Files.exists(trustStore.resolve(hash + ".r1")), is(true));

		LazyOpensslTrustAnchorStoreImpl caStore = new LazyOpensslTrustAnchorStoreImpl(
				trustStore.toString(), -1, new ObserversHandler());
		assertThat(caStore.getTrustedCertificates().length, is(equalTo(2)));

		LazyOpensslCRLStoreSpi crlStore = new LazyOpensslCRLStoreSpi(
				trustStore.toString(), -1, new ObserversHandler());
		try {
			X509CRLSelector selector = new X509CRLSelector();
			selector.addIssuer(firstRoot.getSubject());
			Collection<? extends CRL> crls = crlStore.engineGetCRLs(selector);
			assertThat(crls.size(), is(equalTo(2)));
		} finally {
			crlStore.dispose();
		}
	}

	@Test
	public void shouldRefreshLazyStoreAfterCacheExpiry() throws Exception {
		CA rootCA = given(aCertificateAuthority()
				.selfSigned()
				.withName("DC=org, DC=example, CN=lazy refresh root CA"));
		X509Certificate serviceCertificate = given(anEEC()
				.withSubject("DC=org, DC=example, CN=lazy refresh host")
				.signedBy(rootCA));

		given(anOpensslCertChainValidator()
				.with(OCSPCheckingMode.IGNORE)
				.with(CrlCheckingMode.IGNORE)
				.withUpdateInterval(Duration.ofMillis(25))
				.withLazyLoading());

		assertThat(whenValidating(serviceCertificate).isValid(), is(false));
		given(anOpensslTrustStore().trustingCA(rootCA));
		Thread.sleep(75);

		ValidationResult result = whenValidating(serviceCertificate);
		assertThat(result.toString(), result.isValid(), is(true));
	}

	@Test
	public void shouldRefreshEagerStoreOnSchedule() throws Exception {
		CA rootCA = given(aCertificateAuthority()
				.selfSigned()
				.withName("DC=org, DC=example, CN=eager refresh root CA"));
		X509Certificate serviceCertificate = given(anEEC()
				.withSubject("DC=org, DC=example, CN=eager refresh host")
				.signedBy(rootCA));

		given(anOpensslCertChainValidator()
				.with(OCSPCheckingMode.IGNORE)
				.with(CrlCheckingMode.IGNORE)
				.withUpdateInterval(Duration.ofMillis(25))
				.withEagerLoading());

		assertThat(whenValidating(serviceCertificate).isValid(), is(false));
		given(anOpensslTrustStore().trustingCA(rootCA));

		ValidationResult result = waitForValid(serviceCertificate, Duration.ofSeconds(2));
		assertThat(result.toString(), result.isValid(), is(true));
	}

	@Test
	public void shouldValidateIntermediateCaIssuedEEC() throws Exception {
		CA rootCA = given(aCertificateAuthority()
				.selfSigned()
				.withName("DC=org, DC=example, CN=root CA"));
		CA interCA = given(aCertificateAuthority()
				.signedBy(rootCA)
				.withName("DC=org, DC=example, CN=intermediate CA 1"));

		given(anOpensslTrustStore()
				.trustingCA(rootCA)
				.andTrustingCA(interCA));

		given(anOpensslCertChainValidator()
				.with(OCSPCheckingMode.IGNORE)
				.with(CrlCheckingMode.REQUIRE)
				.withUpdateInterval(of(2, MINUTES))
				.withLazyLoading());

		X509Certificate serviceCertificate = given(anEEC()
				.withSubject("DC=org, DC=example, CN=remote host")
				.signedBy(interCA));

		ValidationResult result = whenValidating(serviceCertificate);

		assertThat(result.isValid(), is(equalTo(true)));
		assertThat(result.getErrors(), is(empty()));
		assertThat(result.getUnresolvedCriticalExtensions(), is(empty()));
	}

	@Test
	public void shouldIgnoreIrrelevantCAWithWrongSubject() throws Exception {
		CA root = given(aCertificateAuthority()
				.selfSigned()
				.withName("DC=org, DC=example, CN=first root"));
		CA inter1 = given(aCertificateAuthority()
				.signedBy(root)
				.withName("DC=org, DC=example, CN=first intermediate"));
		CA inter2 = given(aCertificateAuthority()
				.signedBy(root)
				.withName("DC=ch, DC=cern, CN=second intermediate"));

		given(anOpensslTrustStore()
				.trustingCA(root)
				.andTrustingCA(inter1));

		given(anOpensslCertChainValidator()
				.with(OCSPCheckingMode.IGNORE)
				.with(CrlCheckingMode.REQUIRE)
				.withUpdateInterval(of(2, MINUTES))
				.withLazyLoading());

		X509Certificate serviceCertificate = given(anEEC()
				.withSubject("DC=org, DC=example, CN=remote host")
				.signedBy(inter1));

		ValidationResult result = whenValidating(
				serviceCertificate,
				inter1.getCertificate(),
				inter2.getCertificate(),
				root.getCertificate()
				);

		assertThat(result.toString(), result.isValid(), is(equalTo(true)));
		assertThat(result.getErrors(), is(empty()));
		assertThat(result.getUnresolvedCriticalExtensions(), is(empty()));
	}

	@Test
	public void shouldRejectMalformedCRLInStrictMode() throws Exception {
		CA rootCA = given(aCertificateAuthority()
				.selfSigned()
				.withName("DC=org, DC=example, CN=malformed CRL root CA"));
		given(anOpensslTrustStore().trustingCA(rootCA));
		String hash = OpensslTruststoreHelper.getOpenSSLCAHash(rootCA.getSubject());
		Files.write(trustStore.resolve(hash + ".r0"),
				"not a certificate revocation list".getBytes(StandardCharsets.US_ASCII));
		List<Exception> loadingFailures =
				Collections.synchronizedList(new ArrayList<Exception>());

		given(anOpensslCertChainValidator()
				.with(OCSPCheckingMode.IGNORE)
				.with(CrlCheckingMode.REQUIRE)
				.with(recordingCRLErrors(loadingFailures))
				.withUpdateInterval(of(2, MINUTES))
				.withLazyLoading());
		X509Certificate serviceCertificate = given(anEEC()
				.withSubject("DC=org, DC=example, CN=malformed CRL host")
				.signedBy(rootCA));

		ValidationResult result = whenValidating(serviceCertificate);

		assertThat(result.isValid(), is(false));
		assertThat(result.getPrimaryError().getErrorCode(),
				is(ValidationErrorCode.PKIX_FAILURE));
		assertThat(result.getPrimaryError().getStage(),
				is(ValidationStage.REVOCATION));
		assertThat(loadingFailures.size(), is(1));
	}

	@Test
	public void shouldUseNativeValidationForOneConfiguredRequiredOCSPResponder()
			throws Exception {
		CA rootCA = given(aCertificateAuthority()
				.selfSigned()
				.withName("DC=org, DC=example, CN=native OCSP root CA"));
		given(anOpensslTrustStore().trustingCA(rootCA));
		OCSPResponder malformedResponder = startMalformedOCSPResponder(
				rootCA.getCertificate());

		given(anOpensslCertChainValidator()
				.with(OCSPCheckingMode.REQUIRE)
				.with(malformedResponder)
				.with(CrlCheckingMode.IGNORE)
				.withUpdateInterval(of(2, MINUTES))
				.withLazyLoading());
		X509Certificate serviceCertificate = given(anEEC()
				.withSubject("DC=org, DC=example, CN=native OCSP host")
				.signedBy(rootCA));

		ValidationResult result = whenValidating(serviceCertificate);

		assertThat(result.isValid(), is(false));
		assertThat(result.getPrimaryError().getErrorCode(),
				is(ValidationErrorCode.PKIX_FAILURE));
		assertThat(result.getPrimaryError().getStage(),
				is(ValidationStage.REVOCATION));
	}

	@Test
	public void shouldKeepNonceOCSPOnCompatibilityPath() throws Exception {
		CA rootCA = given(aCertificateAuthority()
				.selfSigned()
				.withName("DC=org, DC=example, CN=nonce OCSP root CA"));
		given(anOpensslTrustStore().trustingCA(rootCA));
		OCSPResponder malformedResponder = startMalformedOCSPResponder(
				rootCA.getCertificate());

		given(anOpensslCertChainValidator()
				.with(OCSPCheckingMode.REQUIRE)
				.with(malformedResponder)
				.withNonce()
				.with(CrlCheckingMode.IGNORE)
				.withUpdateInterval(of(2, MINUTES))
				.withLazyLoading());
		X509Certificate serviceCertificate = given(anEEC()
				.withSubject("DC=org, DC=example, CN=nonce OCSP host")
				.signedBy(rootCA));

		ValidationResult result = whenValidating(serviceCertificate);

		assertThat(result.isValid(), is(false));
		assertThat(result.getPrimaryError().getErrorCode(),
				is(ValidationErrorCode.ocspResponderQueryError));
	}

	@Test
	public void shouldUseNativeValidationForOneDiscoveredRequiredOCSPResponder()
			throws Exception {
		CA rootCA = given(aCertificateAuthority()
				.selfSigned()
				.withName("DC=org, DC=example, CN=discovered OCSP root CA"));
		given(anOpensslTrustStore().trustingCA(rootCA));
		URL responder = startMalformedOCSPServer();

		given(anOpensslCertChainValidator()
				.with(OCSPCheckingMode.REQUIRE)
				.with(CrlCheckingMode.IGNORE)
				.withUpdateInterval(of(2, MINUTES))
				.withLazyLoading());
		X509Certificate serviceCertificate = given(anEEC()
				.withSubject("DC=org, DC=example, CN=discovered OCSP host")
				.withOCSPResponder(responder)
				.signedBy(rootCA));

		ValidationResult result = whenValidating(serviceCertificate);

		assertThat(result.isValid(), is(false));
		assertThat(result.getPrimaryError().getErrorCode(),
				is(ValidationErrorCode.PKIX_FAILURE));
		assertThat(result.getPrimaryError().getStage(),
				is(ValidationStage.REVOCATION));
	}

	@Test
	public void shouldKeepMultipleDiscoveredRespondersOnCompatibilityPath()
			throws Exception {
		CA rootCA = given(aCertificateAuthority()
				.selfSigned()
				.withName("DC=org, DC=example, CN=multiple OCSP root CA"));
		given(anOpensslTrustStore().trustingCA(rootCA));
		URL firstResponder = startMalformedOCSPServer();
		URL secondResponder = new URL(firstResponder.toExternalForm() + "?second");

		given(anOpensslCertChainValidator()
				.with(OCSPCheckingMode.REQUIRE)
				.with(CrlCheckingMode.IGNORE)
				.withUpdateInterval(of(2, MINUTES))
				.withLazyLoading());
		X509Certificate serviceCertificate = given(anEEC()
				.withSubject("DC=org, DC=example, CN=multiple OCSP host")
				.withOCSPResponders(firstResponder, secondResponder)
				.signedBy(rootCA));

		ValidationResult result = whenValidating(serviceCertificate);

		assertThat(result.isValid(), is(false));
		assertThat(result.getPrimaryError().getErrorCode(),
				is(ValidationErrorCode.ocspResponderQueryError));
	}

	private OCSPResponder startMalformedOCSPResponder(X509Certificate certificate)
			throws IOException {
		return new OCSPResponder(startMalformedOCSPServer(), certificate);
	}

	private URL startMalformedOCSPServer() throws IOException {
		final byte[] malformedResponse = {1, 2, 3, 4};
		ocspServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		ocspServer.createContext("/", exchange -> {
			try {
				while (exchange.getRequestBody().read() >= 0) {
					// Consume the complete OCSP request before responding.
				}
				exchange.getResponseHeaders().set("Content-Type", "application/ocsp-response");
				exchange.sendResponseHeaders(200, malformedResponse.length);
				exchange.getResponseBody().write(malformedResponse);
			} finally {
				exchange.close();
			}
		});
		ocspServer.start();
		URL address = new URL("http://127.0.0.1:" +
				ocspServer.getAddress().getPort() + "/");
		return address;
	}

	private ValidationResult whenValidating(X509Certificate... certificates) {
		return validator.validate(certificates);
	}

	private ValidationResult waitForValid(X509Certificate certificate, Duration timeout)
			throws InterruptedException {
		long deadline = System.currentTimeMillis() + timeout.toMillis();
		ValidationResult result;
		do {
			result = whenValidating(certificate);
			if (result.isValid()) {
				return result;
			}
			Thread.sleep(25);
		} while (System.currentTimeMillis() < deadline);
		return result;
	}

	private StoreUpdateListener recordingListener(final List<String> loadedTypes) {
		return new StoreUpdateListener() {
			@Override
			public void loadingNotification(String location, String type,
					Severity level, Exception cause) {
				if (level == Severity.NOTIFICATION) {
					loadedTypes.add(type);
				}
			}
		};
	}

	private StoreUpdateListener recordingCRLErrors(final List<Exception> failures) {
		return new StoreUpdateListener() {
			@Override
			public void loadingNotification(String location, String type,
					Severity level, Exception cause) {
				if (StoreUpdateListener.CRL.equals(type) && level == Severity.ERROR) {
					failures.add(cause);
				}
			}
		};
	}

	private OpensslCertChainValidatorBuilder anOpensslCertChainValidator() {
		return new OpensslCertChainValidatorBuilder();
	}

	private CABuilder aCertificateAuthority() {
		return new CABuilder();
	}

	private CertificateBuilder anEEC() {
		return new CertificateBuilder().asEEC().ofLostCredental();
	}

	private OpensslTrustStoreBuilder anOpensslTrustStore() throws IOException {
		return new OpensslTrustStoreBuilder();
	}

	private void given(OpensslCertChainValidatorBuilder builder) {
		validator = builder.build();
	}

	private void given(OpensslTrustStoreBuilder.TrustBuilder builder) throws IOException {
		builder.and().build();
	}

	private CA given(CABuilder builder) throws OperatorCreationException, CertIOException, CertificateException {
		return builder.build();
	}

	private X509Certificate given(CertificateBuilder builder) throws OperatorCreationException, CertIOException, CertificateException {
		return builder.build();
	}

	/**
	 * Builder pattern class for creating and configuring an
	 * OpensslCertChainValidator instance.
	 */
	private class OpensslCertChainValidatorBuilder {
		private OCSPCheckingMode ocspMode;
		private OCSPResponder ocspResponder;
		private CrlCheckingMode crlCheckingMode;
		private Duration updateInterval;
		private final List<StoreUpdateListener> listeners = new ArrayList<>();
		private boolean isLazy;
		private boolean useNonce;

		public OpensslCertChainValidatorBuilder with(OCSPCheckingMode mode) {
			ocspMode = requireNonNull(mode);
			return this;
		}

		public OpensslCertChainValidatorBuilder with(OCSPResponder responder) {
			ocspResponder = requireNonNull(responder);
			return this;
		}

		public OpensslCertChainValidatorBuilder withNonce() {
			useNonce = true;
			return this;
		}

		public OpensslCertChainValidatorBuilder with(CrlCheckingMode mode) {
			crlCheckingMode = requireNonNull(mode);
			return this;
		}

		public OpensslCertChainValidatorBuilder with(StoreUpdateListener listener) {
			listeners.add(requireNonNull(listener));
			return this;
		}

		public OpensslCertChainValidatorBuilder withUpdateInterval(Duration interval) {
			updateInterval = requireNonNull(interval);
			return this;
		}

		public OpensslCertChainValidatorBuilder withLazyLoading() {
			this.isLazy = true;
			return this;
		}

		public OpensslCertChainValidatorBuilder withEagerLoading() {
			this.isLazy = false;
			return this;
		}

		public OpensslCertChainValidator build() {
			assertThat(ocspMode, not(nullValue()));
			assertThat(crlCheckingMode, not(nullValue()));
			assertThat(updateInterval, not(nullValue()));

			OCSPParametes ocspParameters = ocspResponder == null ?
					new OCSPParametes(ocspMode) :
					new OCSPParametes(ocspMode, ocspResponder);
			ocspParameters.setUseNonce(useNonce);
			RevocationParameters revocationParams =
					new RevocationParameters(crlCheckingMode, ocspParameters);
			ValidatorParams validatorParams = new ValidatorParams(revocationParams, listeners);

			return new OpensslCertChainValidator(trustStore.toString(), updateInterval.toMillis(),
					validatorParams, isLazy);
		}
	}

	/**
	 * Builder pattern class for creating the OpenSSL trust store.
	 */
	private class OpensslTrustStoreBuilder {
		private final List<TrustBuilder> trusts = new ArrayList<>();

		public OpensslTrustStoreBuilder() throws IOException {
			Files.createDirectories(trustStore);
		}

		public TrustBuilder trustingCA(CA ca) {
			TrustBuilder trust = new TrustBuilder(ca);
			trusts.add(trust);
			return trust;
		}

		public void build() throws IOException {
			Map<String, Integer> nextIndexes = new HashMap<>();
			for (TrustBuilder tb : trusts) {
				Integer index = nextIndexes.get(tb.hash);
				if (index == null) {
					index = 0;
				}
				tb.build(index);
				nextIndexes.put(tb.hash, index + 1);
			}
		}

		/**
		 * Builder pattern class for configuring trust of a specific CA.
		 */
		private class TrustBuilder {
			private final CA ca;
			private final String hash;

			private TrustBuilder(CA ca) {
				this.ca = ca;
				hash = OpensslTruststoreHelper.getOpenSSLCAHash(ca.getSubject());
			}

			private void writeHashFile(String suffix, String contents) throws IOException {
				Path filePath = trustStore.resolve(hash + suffix);
				Files.write(filePath, contents.getBytes(StandardCharsets.UTF_8));
			}

			private OpensslTrustStoreBuilder and() {
				return OpensslTrustStoreBuilder.this;
			}

			private TrustBuilder andTrustingCA(CA ca) {
				return and().trustingCA(ca);
			}

			private void build(int index) throws IOException {
				writeHashFile("." + index, ca.buildPemCertificate());
				writeHashFile(".r" + index, ca.buildPemCrl());
			}
		}
	}

	/**
	 * A class that represents a certificate authority.  The CA may be either a
	 * root CA or intermediate CA.
	 */
	private static class CA {
		private final X509Certificate certificate;
		private final PrivateKey privateKey;

		public CA(X509Certificate certificate, PrivateKey privateKey) {
			this.certificate = requireNonNull(certificate);
			this.privateKey = requireNonNull(privateKey);
		}

		public X509Certificate getCertificate() {
			return certificate;
		}

		private String pemEncode(Object input) {
			try {
				StringWriter stringWriter = new StringWriter();
				JcaPEMWriter writer = new JcaPEMWriter(stringWriter);
				writer.writeObject(input);
				writer.flush();
				return stringWriter.toString();
			} catch (IOException e) {
				throw new RuntimeException("Unexpected IOException " + e, e);
			}
		}

		public String buildPemCertificate() {
			return pemEncode(certificate);
		}

		public String buildPemCrl() {
			Instant validFrom = Instant.now().minus(10, MINUTES);
			X509v2CRLBuilder builder = new JcaX509v2CRLBuilder(certificate, Date.from(validFrom));
			builder.setNextUpdate(Date.from(validFrom.plus(7, DAYS)));
			try {
				ContentSigner signer = new JcaContentSignerBuilder("SHA256WITHRSAENCRYPTION")
						.setProvider("BC")
						.build(privateKey);
				X509CRL crl = new JcaX509CRLConverter().setProvider("BC").getCRL(builder.build(signer));
				return pemEncode(crl);
			} catch (CRLException | OperatorCreationException e) {
				throw new RuntimeException("Unexpected exception " + e, e);
			}
		}

		public void sign(CertificateBuilder builder) {
			builder.withIssuer(getDn());
			builder.signedBy(privateKey);
		}

		public X500Principal getSubject() {
			return certificate.getSubjectX500Principal();
		}

		public String getDn() {
			return X500Name.getInstance(getSubject().getEncoded()).toString();
		}

	}

	/**
	 * A builder pattern class for creating a new CA.
	 */
	private static class CABuilder {
		private String name;
		private Optional<CA> signedBy = Optional.empty();
		private final PublicKey publicKey;
		private final PrivateKey privateKey;

		public CABuilder() {
			KeyPair kp = buildKeyPair();
			publicKey = kp.getPublic();
			privateKey = kp.getPrivate();
		}

		public CABuilder withName(String name) {
			this.name = name;
			return this;
		}

		public CABuilder selfSigned() {
			signedBy = Optional.empty();
			return this;
		}

		public CABuilder signedBy(CA ca) {
			signedBy = Optional.of(ca);
			return this;
		}

		private KeyPair buildKeyPair() {
			KeyPairGenerator keyGen;
			try {
				keyGen = KeyPairGenerator.getInstance("RSA");
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException("RSA not supported: " + e.getMessage(), e);
			}
			keyGen.initialize(2048);
			return keyGen.generateKeyPair();
		}

		private X509Certificate buildCertificate() throws OperatorCreationException, CertIOException, CertificateException {
			CertificateBuilder certBuilder = new CertificateBuilder()
					.withPublicKey(publicKey)
					.withSubject(name)
					.asCA();
			CertificateBuilder certBuilderWithSigner = signedBy
					.map(ca -> certBuilder.signedBy(ca))
					.orElseGet(() -> certBuilder.withIssuer(name).signedBy(privateKey));
			X509Certificate certificate = certBuilderWithSigner.build();
			return certificate;
		}

		public CA build() throws OperatorCreationException, OperatorCreationException, CertIOException, CertificateException {
			assertThat(name, not(nullValue()));

			X509Certificate certificate = buildCertificate();

			return new CA(certificate, privateKey);
		}
	}

	/**
	 * A builder pattern class for creating a certificate.  It can do this from
	 * either an existing public key or by generating a fresh public/private
	 * key-pair and discarding the private key.
	 */
	private static class CertificateBuilder {
		private PrivateKey signingKey;
		private PublicKey publicKey;
		private X500Name subject;
		private X500Name issuer;
		private Instant notBefore = Instant.now().minus(2, HOURS);
		private Instant notAfter = Instant.now().plus(2, HOURS);
		private BigInteger serial = new BigInteger(Long.toString(Instant.now().getEpochSecond()));
		private String algorithm = "SHA256WithRSA";
		private boolean isCA;
		private URL[] ocspResponders;

		public CertificateBuilder signedBy(CA ca) {
			ca.sign(this);
			return this;
		}

		public CertificateBuilder signedBy(PrivateKey key) {
			signingKey = key;
			return this;
		}

		public CertificateBuilder withSubject(String dn) {
			this.subject = new X500Name(dn);
			return this;
		}

		public CertificateBuilder withIssuer(String dn) {
			try {
				X500Principal p = X500NameUtils.getX500Principal(dn);
				this.issuer = new X500Name(p.getName());
				return this;
			} catch (IOException e) {
				throw new RuntimeException(e.toString(), e);
			}
		}

		public CertificateBuilder asCA() {
			isCA = true;
			return this;
		}

		public CertificateBuilder asEEC() {
			isCA = false;
			return this;
		}

		public CertificateBuilder withPublicKey(PublicKey key) {
			publicKey = requireNonNull(key);
			return this;
		}

		public CertificateBuilder withOCSPResponder(URL responder) {
			return withOCSPResponders(responder);
		}

		public CertificateBuilder withOCSPResponders(URL... responders) {
			ocspResponders = requireNonNull(responders).clone();
			for (URL responder: ocspResponders) {
				requireNonNull(responder);
			}
			return this;
		}

		public CertificateBuilder ofLostCredental() {
			KeyPairGenerator keyGen;
			try {
				keyGen = KeyPairGenerator.getInstance("RSA");
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException("RSA not supported: " + e.getMessage(), e);
			}
			keyGen.initialize(2048);
			KeyPair kp = keyGen.generateKeyPair();
			publicKey = kp.getPublic();
			return this; // Whoopsie, we just lost the private key.
		}

		public X509Certificate build() throws OperatorCreationException,
		CertIOException, CertificateException {
			assertThat(publicKey, not(nullValue()));
			assertThat(signingKey, not(nullValue()));
			assertThat(subject, not(nullValue()));
			assertThat(issuer, not(nullValue()));

			ContentSigner contentSigner = new JcaContentSignerBuilder(algorithm).build(signingKey);
			JcaX509v3CertificateBuilder certBuilder =
					new JcaX509v3CertificateBuilder(issuer, serial,
							Date.from(notBefore), Date.from(notAfter), subject,
							publicKey);
			BasicConstraints basicConstraints = new BasicConstraints(isCA);
			certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true,
					basicConstraints);
			if (ocspResponders != null) {
				AccessDescription[] descriptions =
						new AccessDescription[ocspResponders.length];
				for (int i=0; i<descriptions.length; i++) {
					descriptions[i] = new AccessDescription(
							AccessDescription.id_ad_ocsp,
							new GeneralName(GeneralName.uniformResourceIdentifier,
									ocspResponders[i].toExternalForm()));
				}
				certBuilder.addExtension(Extension.authorityInfoAccess, false,
						new AuthorityInformationAccess(descriptions));
			}
			X509CertificateHolder holder = certBuilder.build(contentSigner);
			return new JcaX509CertificateConverter().setProvider("BC")
					.getCertificate(holder);
		}
	}
}
