/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.FileInputStream;
import java.security.cert.X509Certificate;
import java.util.Collections;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

public class ProxyRejectionTest
{
	private static final String CERTIFICATE_DIR =
			"src/test/resources/glite-utiljava/trusted-certs/";
	private static final String TRUST_ANCHOR =
			"src/test/resources/glite-utiljava/grid-security/certificates/5a762d74.0";
	private static final String RFC_3820_PROXY_CERT_INFO_OID = "1.3.6.1.5.5.7.1.14";

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
		assertTrue(result.toString(), hasCaConstraintError(result));
	}

	@Test
	public void shouldRejectRfc3820ProxyThroughNormalPkixValidation() throws Exception
	{
		ValidationResult result = validate("trusted_client.proxy_rfc.cert");

		assertFalse(result.toString(), result.isValid());
		assertTrue(result.toString(), hasCaConstraintError(result));
		assertTrue(result.toString(), result.getUnresolvedCriticalExtensions()
				.contains(RFC_3820_PROXY_CERT_INFO_OID));
	}

	private ValidationResult validate(String proxyCertificate) throws Exception
	{
		return validator.validate(new X509Certificate[] {
				loadCertificate(proxyCertificate), issuer});
	}

	private boolean hasCaConstraintError(ValidationResult result)
	{
		for (ValidationError error: result.getErrors())
		{
			ValidationErrorCode code = error.getErrorCode();
			if (code == ValidationErrorCode.noBasicConstraints ||
					code == ValidationErrorCode.noCACert ||
					code == ValidationErrorCode.noCertSign)
				return true;
		}
		return false;
	}

	private X509Certificate loadCertificate(String name) throws Exception
	{
		try (FileInputStream input = new FileInputStream(CERTIFICATE_DIR + name))
		{
			return CertificateUtils.loadCertificate(input, Encoding.PEM);
		}
	}
}
