/*
 * Copyright (c) 2026 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Set;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.sun.net.httpserver.HttpServer;

import eu.emi.security.authn.x509.OCSPResponder;
import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.ValidationStage;
import eu.emi.security.authn.x509.impl.CertificateUtils;

public class NativeBCPKIXOCSPTest
{
	private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
	private static final long MINUTE = 60L * 1000L;

	private NativeBCPKIXValidator validator;
	private KeyPair rootKeyPair;
	private X509Certificate root;
	private X509Certificate target;
	private Set<TrustAnchor> anchors;
	private HttpServer responderServer;

	@Before
	public void setUp() throws Exception
	{
		CertificateUtils.configureSecProvider();
		validator = new NativeBCPKIXValidator();
		rootKeyPair = keyPair();
		root = certificate("CN=Native OCSP Root", "CN=Native OCSP Root",
				BigInteger.ONE, rootKeyPair.getPublic(), rootKeyPair.getPrivate(), true);
		KeyPair targetKeyPair = keyPair();
		target = certificate("CN=Native OCSP Target", "CN=Native OCSP Root",
				BigInteger.valueOf(2), targetKeyPair.getPublic(),
				rootKeyPair.getPrivate(), false);
		anchors = Collections.singleton(new TrustAnchor(root, null));
	}

	@After
	public void tearDown()
	{
		if (responderServer != null)
			responderServer.stop(0);
	}

	@Test
	public void shouldValidateGoodResponseForArrayAndAssertedPath() throws Exception
	{
		OCSPResponder responder = startResponder(response(null, rootKeyPair.getPrivate(),
				new Date(System.currentTimeMillis() + 10 * MINUTE)));

		ValidationResult arrayResult = validator.validateWithOCSP(
				new X509Certificate[] {target, root}, anchors, responder);
		ValidationResult pathResult = validator.validateWithOCSP(
				path(target, root), anchors, responder);

		assertTrue(arrayResult.toString(), arrayResult.isValid());
		assertTrue(pathResult.toString(), pathResult.isValid());
		assertThat(arrayResult.getValidChain(), contains(target, root));
		assertThat(pathResult.getValidChain(), contains(target, root));
	}

	@Test
	public void shouldTrustConfiguredDelegatedResponderCertificate() throws Exception
	{
		KeyPair responderKeyPair = keyPair();
		X509Certificate responderCertificate = certificate(
				"CN=Native OCSP Responder", "CN=Native OCSP Root",
				BigInteger.valueOf(3), responderKeyPair.getPublic(),
				rootKeyPair.getPrivate(), false, true);
		byte[] goodResponse = response(null, responderKeyPair.getPrivate(),
				responderKeyPair.getPublic(),
				new Date(System.currentTimeMillis() + 10 * MINUTE));

		ValidationResult result = validator.validateWithOCSP(
				new X509Certificate[] {target, root}, anchors,
				startResponder(goodResponse, responderCertificate));

		assertTrue(result.toString(), result.isValid());
		assertThat(result.getValidChain(), contains(target, root));
	}

	@Test
	public void shouldRejectRevokedResponse() throws Exception
	{
		CertificateStatus revoked = new RevokedStatus(
				new Date(System.currentTimeMillis() - MINUTE), 1);
		ValidationResult result = validate(response(revoked, rootKeyPair.getPrivate(),
				new Date(System.currentTimeMillis() + 10 * MINUTE)));

		assertNativeOCSPFailure(result);
	}

	@Test
	public void shouldRejectUnknownResponse() throws Exception
	{
		ValidationResult result = validate(response(new UnknownStatus(),
				rootKeyPair.getPrivate(),
				new Date(System.currentTimeMillis() + 10 * MINUTE)));

		assertNativeOCSPFailure(result);
	}

	@Test
	public void shouldRejectExpiredResponse() throws Exception
	{
		ValidationResult result = validate(response(null, rootKeyPair.getPrivate(),
				new Date(System.currentTimeMillis() - MINUTE)));

		assertNativeOCSPFailure(result);
	}

	@Test
	public void shouldRejectMalformedResponse() throws Exception
	{
		ValidationResult result = validate(new byte[] {1, 2, 3, 4});

		assertNativeOCSPFailure(result, -1, false);
	}

	@Test
	public void shouldRejectBadlySignedResponse() throws Exception
	{
		ValidationResult result = validate(response(null, keyPair().getPrivate(),
				new Date(System.currentTimeMillis() + 10 * MINUTE)));

		assertNativeOCSPFailure(result);
	}

	private ValidationResult validate(byte[] response) throws Exception
	{
		return validator.validateWithOCSP(new X509Certificate[] {target, root},
				anchors, startResponder(response));
	}

	private void assertNativeOCSPFailure(ValidationResult result)
	{
		assertNativeOCSPFailure(result, 0, true);
	}

	private void assertNativeOCSPFailure(ValidationResult result, int position,
			boolean validatorException)
	{
		assertFalse(result.toString(), result.isValid());
		ValidationError error = result.getPrimaryError();
		assertThat(error.getErrorCode(), is(ValidationErrorCode.PKIX_FAILURE));
		assertThat(error.getStage(), is(ValidationStage.REVOCATION));
		assertThat(error.getPosition(), is(position));
		if (position == 0)
			assertSame(target, error.getCertificate());
		assertNotNull(error.getProviderMessage());
		assertNotNull(error.getCause());
		assertThat(error.getCause() instanceof CertPathValidatorException,
				is(validatorException));
	}

	private OCSPResponder startResponder(final byte[] response) throws Exception
	{
		return startResponder(response, root);
	}

	private OCSPResponder startResponder(final byte[] response,
			X509Certificate responderCertificate) throws Exception
	{
		responderServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		responderServer.createContext("/", exchange -> {
			try
			{
				while (exchange.getRequestBody().read() >= 0)
				{
					// Consume the complete OCSP request before responding.
				}
				exchange.getResponseHeaders().set("Content-Type", "application/ocsp-response");
				exchange.sendResponseHeaders(200, response.length);
				exchange.getResponseBody().write(response);
			} finally
			{
				exchange.close();
			}
		});
		responderServer.start();
		URL address = new URL("http://127.0.0.1:" +
				responderServer.getAddress().getPort() + "/");
		return new OCSPResponder(address, responderCertificate);
	}

	private byte[] response(CertificateStatus status, PrivateKey signingKey,
			Date nextUpdate) throws Exception
	{
		return response(status, signingKey, root.getPublicKey(), nextUpdate);
	}

	private byte[] response(CertificateStatus status, PrivateKey signingKey,
			PublicKey responderPublicKey, Date nextUpdate) throws Exception
	{
		DigestCalculator idDigest = new JcaDigestCalculatorProviderBuilder()
				.setProvider(BC).build().get(CertificateID.HASH_SHA1);
		CertificateID id = new CertificateID(idDigest,
				new X509CertificateHolder(root.getEncoded()), target.getSerialNumber());
		DigestCalculator responderIdDigest = new JcaDigestCalculatorProviderBuilder()
				.setProvider(BC).build().get(CertificateID.HASH_SHA1);
		BasicOCSPRespBuilder builder = new JcaBasicOCSPRespBuilder(
				responderPublicKey, responderIdDigest);
		Date thisUpdate = new Date(System.currentTimeMillis() - MINUTE);
		builder.addResponse(id, status, thisUpdate, nextUpdate);
		ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
				.setProvider(BC).build(signingKey);
		BasicOCSPResp basic = builder.build(signer,
				new X509CertificateHolder[0], new Date());
		OCSPResp response = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic);
		return response.getEncoded();
	}

	private X509Certificate certificate(String subject, String issuer,
			BigInteger serial, PublicKey publicKey,
			PrivateKey signingKey, boolean ca) throws Exception
	{
		return certificate(subject, issuer, serial, publicKey, signingKey, ca, false);
	}

	private X509Certificate certificate(String subject, String issuer,
			BigInteger serial, PublicKey publicKey,
			PrivateKey signingKey, boolean ca, boolean ocspSigning) throws Exception
	{
		Date notBefore = new Date(System.currentTimeMillis() - 10 * MINUTE);
		Date notAfter = new Date(System.currentTimeMillis() + 60 * MINUTE);
		JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
				new X500Name(issuer), serial, notBefore, notAfter,
				new X500Name(subject), publicKey);
		builder.addExtension(Extension.basicConstraints, true,
				new BasicConstraints(ca));
		builder.addExtension(Extension.keyUsage, true, ca ?
				new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign) :
				new KeyUsage(KeyUsage.digitalSignature));
		if (ocspSigning)
			builder.addExtension(Extension.extendedKeyUsage, false,
					new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
		ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
				.setProvider(BC).build(signingKey);
		return new JcaX509CertificateConverter().setProvider(BC)
				.getCertificate(builder.build(signer));
	}

	private KeyPair keyPair() throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", BC);
		generator.initialize(2048);
		return generator.generateKeyPair();
	}

	private CertPath path(X509Certificate... certificates) throws Exception
	{
		return CertificateFactory.getInstance("X.509", BC)
				.generateCertPath(Arrays.asList(certificates));
	}
}
