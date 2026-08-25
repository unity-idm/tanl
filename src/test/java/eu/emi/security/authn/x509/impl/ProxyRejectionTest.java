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
			"src/test/resources/glite-utiljava/trusted-certs/";
	private static final String TRUST_ANCHOR =
			"src/test/resources/glite-utiljava/grid-security/certificates/5a762d74.0";
	private DirectoryCertChainValidator validator;
	private X509Certificate issuer;

	@Before
	public void setUp() throws Exception
	{
		validator = new DirectoryCertChainValidator(
				Collections.singletonList(TRUST_ANCHOR), Encoding.PEM,
				-1, 0, null, new ValidatorParamsExt(RevocationParametersExt.IGNORE));
		issuer = loadCertificate("trusted_client.cert");
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
		ValidationResult result = validate("trusted_client.proxy.cert");

		assertFalse(result.toString(), result.isValid());
		assertEquals(result.toString(), 1, result.getErrors().size());
	}

	@Test
	public void shouldRejectRfc3820ProxyThroughNormalPkixValidation() throws Exception
	{
		ValidationResult result = validate("trusted_client.proxy_rfc.cert");

		assertFalse(result.toString(), result.isValid());
		assertEquals(result.toString(), 1, result.getErrors().size());
	}

	private ValidationResult validate(String proxyCertificate) throws Exception
	{
		return validator.validate(new X509Certificate[] {
				loadCertificate(proxyCertificate), issuer});
	}

	private X509Certificate loadCertificate(String name) throws Exception
	{
		try (FileInputStream input = new FileInputStream(CERTIFICATE_DIR + name))
		{
			return CertificateUtils.loadCertificate(input, Encoding.PEM);
		}
	}
}
