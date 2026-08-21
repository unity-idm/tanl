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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
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
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

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

	@Rule
	public TemporaryFolder temporary = new TemporaryFolder();

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
	public void shouldValidatePrefetchedResponseForArrayAndAssertedPath() throws Exception
	{
		OCSPResponder responder = startResponder(response(null, rootKeyPair.getPrivate(),
				new Date(System.currentTimeMillis() + 10 * MINUTE)));

		ValidationResult arrayResult = validator.validateWithOCSP(
				new X509Certificate[] {target, root}, anchors, responder, 1000);
		ValidationResult pathResult = validator.validateWithOCSP(
				path(target, root), anchors, responder, 1000);

		assertTrue(arrayResult.toString(), arrayResult.isValid());
		assertTrue(pathResult.toString(), pathResult.isValid());
		assertThat(arrayResult.getValidChain(), contains(target, root));
		assertThat(pathResult.getValidChain(), contains(target, root));
	}

	@Test
	public void shouldReuseNativelyValidatedResponseFromMemoryCache() throws Exception
	{
		responderServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		AtomicInteger queries = new AtomicInteger();
		addResponse("/", response(null, rootKeyPair.getPrivate(),
				new Date(System.currentTimeMillis() + 10 * MINUTE)), queries);
		responderServer.start();
		OCSPResponder responder = new OCSPResponder(responderURI("/").toURL(), root);

		ValidationResult arrayResult = validator.validateWithOCSP(
				new X509Certificate[] {target, root}, anchors, responder, 1000, 60);
		ValidationResult pathResult = validator.validateWithOCSP(
				path(target, root), anchors, responder, 1000, 60);

		assertTrue(arrayResult.toString(), arrayResult.isValid());
		assertTrue(pathResult.toString(), pathResult.isValid());
		assertThat(queries.get(), is(1));
	}

	@Test
	public void shouldNotCacheResponseRejectedByNativeValidation() throws Exception
	{
		responderServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		AtomicInteger queries = new AtomicInteger();
		addResponse("/", response(null, keyPair().getPrivate(),
				new Date(System.currentTimeMillis() + 10 * MINUTE)), queries);
		responderServer.start();
		OCSPResponder responder = new OCSPResponder(responderURI("/").toURL(), root);

		ValidationResult first = validator.validateWithOCSP(
				new X509Certificate[] {target, root}, anchors, responder, 1000, 60);
		ValidationResult second = validator.validateWithOCSP(
				new X509Certificate[] {target, root}, anchors, responder, 1000, 60);

		assertNativeOCSPFailure(first);
		assertNativeOCSPFailure(second);
		assertThat(queries.get(), is(2));
	}

	@Test
	public void shouldHonorHTTPExpiryBeforeConfiguredCacheTtl() throws Exception
	{
		responderServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		AtomicInteger queries = new AtomicInteger();
		addResponse("/", response(null, rootKeyPair.getPrivate(),
				new Date(System.currentTimeMillis() + 10 * MINUTE)), queries,
				"max-age=0");
		responderServer.start();
		OCSPResponder responder = new OCSPResponder(responderURI("/").toURL(), root);

		ValidationResult first = validator.validateWithOCSP(
				new X509Certificate[] {target, root}, anchors, responder, 1000, 60);
		ValidationResult second = validator.validateWithOCSP(
				new X509Certificate[] {target, root}, anchors, responder, 1000, 60);

		assertTrue(first.toString(), first.isValid());
		assertTrue(second.toString(), second.isValid());
		assertThat(queries.get(), is(2));
	}

	@Test
	public void shouldLoadPersistentResponseInANewValidator() throws Exception
	{
		File diskCache = temporary.newFolder("native-ocsp-cache");
		responderServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		AtomicInteger queries = new AtomicInteger();
		addResponse("/", response(null, rootKeyPair.getPrivate(),
				new Date(System.currentTimeMillis() + 10 * MINUTE)), queries);
		responderServer.start();
		OCSPResponder responder = new OCSPResponder(responderURI("/").toURL(), root);

		ValidationResult first = validator.validateWithOCSP(
				new X509Certificate[] {target, root}, anchors, responder, 1000, 60,
				diskCache.getAbsolutePath());
		responderServer.stop(0);
		responderServer = null;
		ValidationResult reloaded = new NativeBCPKIXValidator().validateWithOCSP(
				path(target, root), anchors, responder, 1000, 60,
				diskCache.getAbsolutePath());

		assertTrue(first.toString(), first.isValid());
		assertTrue(reloaded.toString(), reloaded.isValid());
		assertThat(queries.get(), is(1));
		assertThat(diskCache.listFiles().length, is(1));
	}

	@Test
	public void shouldRecoverFromCorruptPersistentResponse() throws Exception
	{
		File diskCache = temporary.newFolder("corrupt-native-ocsp-cache");
		responderServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		AtomicInteger queries = new AtomicInteger();
		addResponse("/", response(null, rootKeyPair.getPrivate(),
				new Date(System.currentTimeMillis() + 10 * MINUTE)), queries);
		responderServer.start();
		OCSPResponder responder = new OCSPResponder(responderURI("/").toURL(), root);
		ValidationResult first = validator.validateWithOCSP(
				new X509Certificate[] {target, root}, anchors, responder, 1000, 60,
				diskCache.getAbsolutePath());
		Files.write(diskCache.listFiles()[0].toPath(), new byte[] {1, 2, 3},
				StandardOpenOption.TRUNCATE_EXISTING);

		ValidationResult recovered = new NativeBCPKIXValidator().validateWithOCSP(
				new X509Certificate[] {target, root}, anchors, responder, 1000, 60,
				diskCache.getAbsolutePath());

		assertTrue(first.toString(), first.isValid());
		assertTrue(recovered.toString(), recovered.isValid());
		assertThat(queries.get(), is(2));
		assertThat(diskCache.listFiles().length, is(1));
	}

	@Test
	public void shouldRequireAndAcceptExactFreshNonce() throws Exception
	{
		File diskCache = temporary.newFolder("nonce-cache");
		AtomicInteger queries = new AtomicInteger();
		List<byte[]> requestedNonces = new ArrayList<byte[]>();
		OCSPResponder responder = startNonceResponder(NonceReply.MATCH, queries,
				requestedNonces);

		ValidationResult arrayResult = validator.validateWithOCSP(
				new X509Certificate[] {target, root}, anchors, responder, 1000, 60,
				diskCache.getAbsolutePath(), true);
		ValidationResult pathResult = validator.validateWithOCSP(
				path(target, root), anchors, responder, 1000, 60,
				diskCache.getAbsolutePath(), true);

		assertTrue(arrayResult.toString(), arrayResult.isValid());
		assertTrue(pathResult.toString(), pathResult.isValid());
		assertThat(queries.get(), is(2));
		assertThat(requestedNonces.size(), is(2));
		assertThat(requestedNonces.get(0).length, is(16));
		assertThat(requestedNonces.get(1).length, is(16));
		assertFalse(Arrays.equals(requestedNonces.get(0), requestedNonces.get(1)));
		assertThat(diskCache.listFiles().length, is(0));
	}

	@Test
	public void shouldRejectMissingResponseNonce() throws Exception
	{
		ValidationResult result = validateWithNonce(NonceReply.OMIT);

		assertNativeOCSPFailure(result, 0, false);
		assertTrue(result.getPrimaryError().getProviderMessage().contains("no nonce"));
	}

	@Test
	public void shouldRejectMismatchedResponseNonce() throws Exception
	{
		ValidationResult result = validateWithNonce(NonceReply.MISMATCH);

		assertNativeOCSPFailure(result, 0, false);
		assertTrue(result.getPrimaryError().getProviderMessage().contains(
				"does not match"));
	}

	@Test
	public void shouldApplyTimeoutWhileFetchingResponse() throws Exception
	{
		final CountDownLatch requestReceived = new CountDownLatch(1);
		final CountDownLatch releaseResponse = new CountDownLatch(1);
		responderServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		responderServer.createContext("/", exchange -> {
			try
			{
				while (exchange.getRequestBody().read() >= 0)
				{
					// Consume the complete OCSP request before blocking the response.
				}
				requestReceived.countDown();
				releaseResponse.await(5, TimeUnit.SECONDS);
			} catch (InterruptedException e)
			{
				Thread.currentThread().interrupt();
			} finally
			{
				exchange.close();
			}
		});
		responderServer.start();
		OCSPResponder responder = new OCSPResponder(responderURI("/").toURL(), root);

		ValidationResult result;
		try
		{
			result = validator.validateWithOCSP(
					new X509Certificate[] {target, root}, anchors, responder, 100);
		} finally
		{
			releaseResponse.countDown();
		}

		assertTrue("The responder did not receive the request",
				requestReceived.await(1, TimeUnit.SECONDS));
		assertFalse(result.toString(), result.isValid());
		ValidationError error = result.getPrimaryError();
		assertThat(error.getErrorCode(), is(ValidationErrorCode.PKIX_FAILURE));
		assertThat(error.getStage(), is(ValidationStage.REVOCATION));
		assertThat(error.getPosition(), is(0));
		assertSame(target, error.getCertificate());
		assertTrue(error.getCause() instanceof SocketTimeoutException);
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
		ValidationResult prefetchedResult = validator.validateWithOCSP(
				new X509Certificate[] {target, root}, anchors,
				new OCSPResponder(responderURI("/").toURL(), responderCertificate),
				1000);

		assertTrue(result.toString(), result.isValid());
		assertTrue(prefetchedResult.toString(), prefetchedResult.isValid());
		assertThat(result.getValidChain(), contains(target, root));
		assertThat(prefetchedResult.getValidChain(), contains(target, root));
	}

	@Test
	public void shouldDiscoverOneResponderForEachCertificateInThePath() throws Exception
	{
		responderServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		URI intermediateResponder = responderURI("/intermediate");
		URI rootResponder = responderURI("/root");
		KeyPair intermediateKeyPair = keyPair();
		X509Certificate intermediate = certificate("CN=Native OCSP Intermediate",
				"CN=Native OCSP Root", BigInteger.valueOf(10),
				intermediateKeyPair.getPublic(), rootKeyPair.getPrivate(), true,
				false, rootResponder);
		KeyPair aiaTargetKeyPair = keyPair();
		X509Certificate aiaTarget = certificate("CN=Native OCSP AIA Target",
				"CN=Native OCSP Intermediate", BigInteger.valueOf(11),
				aiaTargetKeyPair.getPublic(), intermediateKeyPair.getPrivate(), false,
				false, intermediateResponder);
		Date nextUpdate = new Date(System.currentTimeMillis() + 10 * MINUTE);
		AtomicInteger intermediateQueries = new AtomicInteger();
		AtomicInteger rootQueries = new AtomicInteger();
		addResponse("/intermediate", response(aiaTarget, intermediate, null,
				intermediateKeyPair.getPrivate(), intermediateKeyPair.getPublic(),
				nextUpdate), intermediateQueries);
		addResponse("/root", response(intermediate, root, null,
				rootKeyPair.getPrivate(), rootKeyPair.getPublic(), nextUpdate), rootQueries);
		responderServer.start();

		ValidationResult arrayResult = validator.validateWithOCSPFromAIA(
				new X509Certificate[] {aiaTarget, root, intermediate}, anchors);
		ValidationResult pathResult = validator.validateWithOCSPFromAIA(
				path(aiaTarget, intermediate, root), anchors);
		ValidationResult prefetchedArrayResult = validator.validateWithOCSPFromAIA(
				new X509Certificate[] {aiaTarget, root, intermediate}, anchors, 1000);
		ValidationResult prefetchedPathResult = validator.validateWithOCSPFromAIA(
				path(aiaTarget, intermediate, root), anchors, 1000);

		assertTrue(arrayResult.toString(), arrayResult.isValid());
		assertTrue(pathResult.toString(), pathResult.isValid());
		assertTrue(prefetchedArrayResult.toString(), prefetchedArrayResult.isValid());
		assertTrue(prefetchedPathResult.toString(), prefetchedPathResult.isValid());
		assertThat(arrayResult.getValidChain(), contains(aiaTarget, intermediate, root));
		assertThat(pathResult.getValidChain(), contains(aiaTarget, intermediate, root));
		assertThat(prefetchedArrayResult.getValidChain(),
				contains(aiaTarget, intermediate, root));
		assertThat(prefetchedPathResult.getValidChain(),
				contains(aiaTarget, intermediate, root));
		assertTrue(intermediateQueries.get() > 0);
		assertTrue(rootQueries.get() > 0);
	}

	@Test
	public void shouldSelectConfiguredAndDiscoveredRespondersInConfiguredOrder()
			throws Exception
	{
		responderServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		URI firstLocalURI = responderURI("/first-local");
		URI secondLocalURI = responderURI("/second-local");
		URI discoveredURI = responderURI("/discovered");
		X509Certificate aiaTarget = certificate("CN=Ordered OCSP Target",
				"CN=Native OCSP Root", BigInteger.valueOf(30), keyPair().getPublic(),
				rootKeyPair.getPrivate(), false, false, discoveredURI);
		byte[] goodResponse = response(aiaTarget, root, null,
				rootKeyPair.getPrivate(), rootKeyPair.getPublic(),
				new Date(System.currentTimeMillis() + 10 * MINUTE));
		AtomicInteger firstLocalQueries = new AtomicInteger();
		AtomicInteger secondLocalQueries = new AtomicInteger();
		AtomicInteger discoveredQueries = new AtomicInteger();
		addResponse("/first-local", goodResponse, firstLocalQueries);
		addResponse("/second-local", goodResponse, secondLocalQueries);
		addResponse("/discovered", goodResponse, discoveredQueries);
		responderServer.start();
		OCSPResponder[] localResponders = {
				new OCSPResponder(firstLocalURI.toURL(), root),
				new OCSPResponder(secondLocalURI.toURL(), root)};

		ValidationResult localFirst = validator.validateWithOCSP(
				new X509Certificate[] {aiaTarget, root}, anchors, localResponders,
				true, 1000, -1, null, false);
		ValidationResult discoveredFirst = validator.validateWithOCSP(
				path(aiaTarget, root), anchors, localResponders, false, 1000, -1,
				null, false);

		assertTrue(localFirst.toString(), localFirst.isValid());
		assertTrue(discoveredFirst.toString(), discoveredFirst.isValid());
		assertThat(firstLocalQueries.get(), is(1));
		assertThat(secondLocalQueries.get(), is(0));
		assertThat(discoveredQueries.get(), is(1));
	}

	@Test
	public void shouldNotSkipNativeFailureForALaterResponder() throws Exception
	{
		responderServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		AtomicInteger firstQueries = new AtomicInteger();
		AtomicInteger secondQueries = new AtomicInteger();
		addResponse("/revoked-first", response(new RevokedStatus(
				new Date(System.currentTimeMillis() - MINUTE), 1),
				rootKeyPair.getPrivate(),
				new Date(System.currentTimeMillis() + 10 * MINUTE)), firstQueries);
		addResponse("/good-second", response(null, rootKeyPair.getPrivate(),
				new Date(System.currentTimeMillis() + 10 * MINUTE)), secondQueries);
		responderServer.start();
		OCSPResponder[] responders = {
				new OCSPResponder(responderURI("/revoked-first").toURL(), root),
				new OCSPResponder(responderURI("/good-second").toURL(), root)};

		ValidationResult result = validator.validateWithOCSP(
				new X509Certificate[] {target, root}, anchors, responders, true,
				1000, -1, null, false);

		assertNativeOCSPFailure(result);
		assertThat(firstQueries.get(), is(1));
		assertThat(secondQueries.get(), is(0));
	}

	@Test
	public void shouldReportDiscoveredResponderFailureAtOriginalPathPosition()
			throws Exception
	{
		responderServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		URI intermediateResponder = responderURI("/intermediate-revoked");
		URI rootResponder = responderURI("/root-revoked");
		KeyPair intermediateKeyPair = keyPair();
		X509Certificate intermediate = certificate("CN=Revoked OCSP Intermediate",
				"CN=Native OCSP Root", BigInteger.valueOf(20),
				intermediateKeyPair.getPublic(), rootKeyPair.getPrivate(), true,
				false, rootResponder);
		X509Certificate aiaTarget = certificate("CN=Child of Revoked Intermediate",
				"CN=Revoked OCSP Intermediate", BigInteger.valueOf(21),
				keyPair().getPublic(), intermediateKeyPair.getPrivate(), false,
				false, intermediateResponder);
		Date nextUpdate = new Date(System.currentTimeMillis() + 10 * MINUTE);
		addResponse("/intermediate-revoked", response(aiaTarget, intermediate, null,
				intermediateKeyPair.getPrivate(), intermediateKeyPair.getPublic(),
				nextUpdate), new AtomicInteger());
		addResponse("/root-revoked", response(intermediate, root,
				new RevokedStatus(new Date(System.currentTimeMillis() - MINUTE), 1),
				rootKeyPair.getPrivate(), rootKeyPair.getPublic(), nextUpdate),
				new AtomicInteger());
		responderServer.start();

		ValidationResult result = validator.validateWithOCSPFromAIA(
				new X509Certificate[] {aiaTarget, intermediate, root}, anchors);

		assertFalse(result.toString(), result.isValid());
		ValidationError error = result.getPrimaryError();
		assertThat(error.getErrorCode(), is(ValidationErrorCode.PKIX_FAILURE));
		assertThat(error.getStage(), is(ValidationStage.REVOCATION));
		assertThat(error.getPosition(), is(1));
		assertSame(intermediate, error.getCertificate());
		assertTrue(error.getCause() instanceof CertPathValidatorException);
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

	@Test
	public void shouldRejectBadlySignedPrefetchedResponse() throws Exception
	{
		byte[] response = response(null, keyPair().getPrivate(),
				new Date(System.currentTimeMillis() + 10 * MINUTE));
		ValidationResult result = validator.validateWithOCSP(
				new X509Certificate[] {target, root}, anchors,
				startResponder(response), 1000);

		assertNativeOCSPFailure(result);
	}

	private ValidationResult validate(byte[] response) throws Exception
	{
		return validator.validateWithOCSP(new X509Certificate[] {target, root},
				anchors, startResponder(response));
	}

	private ValidationResult validateWithNonce(NonceReply reply) throws Exception
	{
		return validator.validateWithOCSP(new X509Certificate[] {target, root},
				anchors, startNonceResponder(reply, new AtomicInteger(),
						new ArrayList<byte[]>()), 1000, 60, null, true);
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
		addResponse("/", response, new AtomicInteger());
		responderServer.start();
		return new OCSPResponder(responderURI("/").toURL(), responderCertificate);
	}

	private OCSPResponder startNonceResponder(final NonceReply reply,
			final AtomicInteger queries, final List<byte[]> requestedNonces)
			throws Exception
	{
		responderServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		String path = longResponderPath();
		responderServer.createContext(path, exchange -> {
			try
			{
				queries.incrementAndGet();
				ByteArrayOutputStream encodedRequest = new ByteArrayOutputStream();
				byte[] buffer = new byte[256];
				int read;
				while ((read = exchange.getRequestBody().read(buffer)) >= 0)
					encodedRequest.write(buffer, 0, read);
				OCSPReq request = new OCSPReq(encodedRequest.toByteArray());
				Extension nonceExtension = request.getExtension(
						OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
				if (nonceExtension == null)
					throw new IllegalStateException("Request has no nonce");
				byte[] requestedNonce = nonceExtension.getExtnValue().getOctets();
				requestedNonces.add(requestedNonce.clone());
				byte[] responseNonce = reply == NonceReply.OMIT ? null :
						requestedNonce.clone();
				if (reply == NonceReply.MISMATCH)
					responseNonce[0] ^= 1;
				byte[] encodedResponse = response(null, rootKeyPair.getPrivate(),
						rootKeyPair.getPublic(),
						new Date(System.currentTimeMillis() + 10 * MINUTE),
						responseNonce);
				exchange.getResponseHeaders().set("Content-Type",
						"application/ocsp-response");
				exchange.sendResponseHeaders(200, encodedResponse.length);
				exchange.getResponseBody().write(encodedResponse);
			} catch (Exception e)
			{
				throw new java.io.IOException(e);
			} finally
			{
				exchange.close();
			}
		});
		responderServer.start();
		return new OCSPResponder(responderURI(path).toURL(), root);
	}

	private String longResponderPath()
	{
		char[] suffix = new char[200];
		Arrays.fill(suffix, 'n');
		return "/" + new String(suffix);
	}

	private void addResponse(String path, final byte[] response,
			final AtomicInteger queries)
	{
		addResponse(path, response, queries, null);
	}

	private void addResponse(String path, final byte[] response,
			final AtomicInteger queries, final String cacheControl)
	{
		responderServer.createContext(path, exchange -> {
			try
			{
				queries.incrementAndGet();
				while (exchange.getRequestBody().read() >= 0)
				{
					// Consume the complete OCSP request before responding.
				}
				exchange.getResponseHeaders().set("Content-Type", "application/ocsp-response");
				if (cacheControl != null)
					exchange.getResponseHeaders().set("Cache-Control", cacheControl);
				exchange.sendResponseHeaders(200, response.length);
				exchange.getResponseBody().write(response);
			} finally
			{
				exchange.close();
			}
		});
	}

	private URI responderURI(String path) throws Exception
	{
		return new URI("http://127.0.0.1:" +
				responderServer.getAddress().getPort() + path);
	}

	private byte[] response(CertificateStatus status, PrivateKey signingKey,
			Date nextUpdate) throws Exception
	{
		return response(status, signingKey, root.getPublicKey(), nextUpdate);
	}

	private byte[] response(CertificateStatus status, PrivateKey signingKey,
			PublicKey responderPublicKey, Date nextUpdate) throws Exception
	{
		return response(target, root, status, signingKey, responderPublicKey,
				nextUpdate, null);
	}

	private byte[] response(CertificateStatus status, PrivateKey signingKey,
			PublicKey responderPublicKey, Date nextUpdate, byte[] nonce)
			throws Exception
	{
		return response(target, root, status, signingKey, responderPublicKey,
				nextUpdate, nonce);
	}

	private byte[] response(X509Certificate certificate,
			X509Certificate issuer, CertificateStatus status, PrivateKey signingKey,
			PublicKey responderPublicKey, Date nextUpdate) throws Exception
	{
		return response(certificate, issuer, status, signingKey, responderPublicKey,
				nextUpdate, null);
	}

	private byte[] response(X509Certificate certificate,
			X509Certificate issuer, CertificateStatus status, PrivateKey signingKey,
			PublicKey responderPublicKey, Date nextUpdate, byte[] nonce)
			throws Exception
	{
		DigestCalculator idDigest = new JcaDigestCalculatorProviderBuilder()
				.setProvider(BC).build().get(CertificateID.HASH_SHA1);
		CertificateID id = new CertificateID(idDigest,
				new X509CertificateHolder(issuer.getEncoded()),
				certificate.getSerialNumber());
		DigestCalculator responderIdDigest = new JcaDigestCalculatorProviderBuilder()
				.setProvider(BC).build().get(CertificateID.HASH_SHA1);
		BasicOCSPRespBuilder builder = new JcaBasicOCSPRespBuilder(
				responderPublicKey, responderIdDigest);
		Date thisUpdate = new Date(System.currentTimeMillis() - MINUTE);
		builder.addResponse(id, status, thisUpdate, nextUpdate);
		if (nonce != null)
			builder.setResponseExtensions(new Extensions(new Extension(
					OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
					new DEROctetString(nonce))));
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
		return certificate(subject, issuer, serial, publicKey, signingKey, ca,
				false, null);
	}

	private X509Certificate certificate(String subject, String issuer,
			BigInteger serial, PublicKey publicKey,
			PrivateKey signingKey, boolean ca, boolean ocspSigning) throws Exception
	{
		return certificate(subject, issuer, serial, publicKey, signingKey, ca,
				ocspSigning, null);
	}

	private X509Certificate certificate(String subject, String issuer,
			BigInteger serial, PublicKey publicKey, PrivateKey signingKey,
			boolean ca, boolean ocspSigning, URI ocspResponder) throws Exception
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
		if (ocspResponder != null)
			builder.addExtension(Extension.authorityInfoAccess, false,
					new AuthorityInformationAccess(new AccessDescription(
							AccessDescription.id_ad_ocsp,
							new GeneralName(GeneralName.uniformResourceIdentifier,
									ocspResponder.toASCIIString()))));
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

	private enum NonceReply
	{
		MATCH,
		OMIT,
		MISMATCH
	}
}
