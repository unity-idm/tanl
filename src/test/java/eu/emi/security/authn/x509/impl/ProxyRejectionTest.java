/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.FileInputStream;
import java.security.cert.X509Certificate;
import java.util.Collections;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

public class ProxyRejectionTest
{
	private static final String CERTIFICATE_DIR =
			"src/test/resources/fixtures/proxy-rejection/";
	private static final String TRUST_ANCHOR =
			CERTIFICATE_DIR + "trust-anchor.pem";
	private static final String ISSUER =
			"src/test/resources/fixtures/shared/trusted-client.pem";
	private DirectoryCertChainValidator validator;
	private X509Certificate issuer;

	@Before
	public void setUp() throws Exception
	{
		validator = new DirectoryCertChainValidator(
				Collections.singletonList(TRUST_ANCHOR), Encoding.PEM,
				-1, 0, null, new ValidatorParamsExt(RevocationParametersExt.IGNORE));
		issuer = loadCertificate(ISSUER);
		assertTrue("The non-proxy issuer must remain valid", validator.validate(
				new X509Certificate[] {issuer}).isValid());
	}

	@After
	public void tearDown()
	{
		validator.dispose();
	}

	@Test
	public void shouldRejectLegacyProxyThroughNormalPkixValidation() throws Exception
	{
		ValidationResult result = validate("legacy-proxy.pem");

		assertFalse(result.toString(), result.isValid());
		assertEquals(result.toString(), 1, result.getErrors().size());
	}

	@Test
	public void shouldRejectRfc3820ProxyThroughNormalPkixValidation() throws Exception
	{
		ValidationResult result = validate("rfc3820-proxy.pem");

		assertFalse(result.toString(), result.isValid());
		assertEquals(result.toString(), 1, result.getErrors().size());
	}

	private ValidationResult validate(String proxyCertificate) throws Exception
	{
		return validator.validate(new X509Certificate[] {
				loadCertificate(CERTIFICATE_DIR + proxyCertificate), issuer});
	}

	private X509Certificate loadCertificate(String path) throws Exception
	{
		try (FileInputStream input = new FileInputStream(path))
		{
			return CertificateUtils.loadCertificate(input, Encoding.PEM);
		}
	}
}
