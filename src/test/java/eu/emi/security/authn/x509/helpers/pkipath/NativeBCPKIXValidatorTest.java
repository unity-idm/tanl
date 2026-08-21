/*
 * Copyright (c) 2026 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.FileInputStream;
import java.security.cert.CertPath;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

public class NativeBCPKIXValidatorTest
{
	private NativeBCPKIXValidator validator;
	private X509Certificate root;
	private X509Certificate intermediate;
	private X509Certificate target;
	private X509Certificate irrelevantCandidate;
	private Set<TrustAnchor> anchors;

	@Before
	public void setUp() throws Exception
	{
		validator = new NativeBCPKIXValidator();
		root = load("TrustAnchorRootCertificate");
		intermediate = load("GoodCACert");
		target = load("ValidCertificatePathTest1EE");
		irrelevantCandidate = load("DSACACert");
		anchors = Collections.singleton(new TrustAnchor(root, null));
	}

	@Test
	public void shouldBuildFromUnorderedCandidatesAndReturnSelectedAnchor() throws Exception
	{
		ValidationResult result = validator.validate(new X509Certificate[] {
				target, root, irrelevantCandidate, intermediate}, anchors);

		assertTrue(result.toString(), result.isValid());
		assertThat(result.getErrors(), is(empty()));
		assertThat(result.getValidChain(), contains(target, intermediate, root));
	}

	@Test
	public void shouldValidateAssertedPathDirectlyAndRemoveIncludedAnchor() throws Exception
	{
		CertPath path = path(target, intermediate, root);

		ValidationResult result = validator.validate(path, anchors);

		assertTrue(result.toString(), result.isValid());
		assertThat(result.getValidChain(), contains(target, intermediate, root));
	}

	@Test
	public void shouldIgnoreCertificatesAfterIncludedAnchorInAssertedPath() throws Exception
	{
		CertPath path = path(target, intermediate, root, irrelevantCandidate);

		ValidationResult result = validator.validate(path, anchors);

		assertTrue(result.toString(), result.isValid());
		assertThat(result.getValidChain(), contains(target, intermediate, root));
	}

	@Test
	public void shouldRejectEmptyAssertedPath() throws Exception
	{
		ValidationResult result = validator.validate(path(), anchors);

		assertFalse(result.toString(), result.isValid());
		assertThat(result.getErrors(), hasSize(1));
	}

	@Test
	public void shouldNotReorderAnAssertedPath() throws Exception
	{
		X509Certificate[] candidates = {target, irrelevantCandidate, intermediate};
		ValidationResult builtResult = validator.validate(candidates, anchors);
		assertTrue(builtResult.toString(), builtResult.isValid());

		ValidationResult assertedResult = validator.validate(path(candidates), anchors);

		assertFalse(assertedResult.toString(), assertedResult.isValid());
		assertThat(assertedResult.getErrors(), hasSize(1));
	}

	@Test
	public void shouldAcceptExactTrustedSelfSignedCertificate() throws Exception
	{
		ValidationResult arrayResult = validator.validate(new X509Certificate[] {root}, anchors);
		ValidationResult pathResult = validator.validate(path(root), anchors);

		assertTrue(arrayResult.toString(), arrayResult.isValid());
		assertTrue(pathResult.toString(), pathResult.isValid());
		assertThat(arrayResult.getValidChain(), contains(root));
		assertThat(pathResult.getValidChain(), contains(root));
	}

	@Test
	public void shouldNotAcceptExactNonSelfSignedAnchorAsAZeroLengthPath() throws Exception
	{
		Set<TrustAnchor> nonSelfSignedAnchor =
				Collections.singleton(new TrustAnchor(intermediate, null));

		ValidationResult result = validator.validate(
				new X509Certificate[] {intermediate}, nonSelfSignedAnchor);

		assertFalse(result.toString(), result.isValid());
		assertThat(result.getErrors(), hasSize(1));
	}

	@Test
	public void shouldReportOneNativeFailureForAnInvalidCoherentPath() throws Exception
	{
		X509Certificate expired = load("InvalidEEnotAfterDateTest6EE");

		ValidationResult result = validator.validate(path(expired, intermediate, root), anchors);

		assertFalse(result.toString(), result.isValid());
		assertThat(result.getErrors(), hasSize(1));
		assertThat(result.getValidChain(), is((java.util.List<X509Certificate>) null));
	}

	@Test
	public void shouldRejectInputWithoutTrustAnchors() throws Exception
	{
		ValidationResult result = validator.validate(new X509Certificate[] {
				target, intermediate}, new HashSet<TrustAnchor>());

		assertFalse(result.toString(), result.isValid());
		assertThat(result.getErrors(), hasSize(1));
	}

	private CertPath path(X509Certificate... certificates) throws Exception
	{
		return CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME)
				.generateCertPath(Arrays.asList(certificates));
	}

	private X509Certificate load(String name) throws Exception
	{
		try (FileInputStream input = new FileInputStream(
				"src/test/resources/NIST/certs/" + name + ".crt"))
		{
			return CertificateUtils.loadCertificate(input, Encoding.DER);
		}
	}
}
