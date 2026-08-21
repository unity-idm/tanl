/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.Collections;

import org.junit.Assert;

import org.junit.Test;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.ValidationStage;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;


public class OpensslValidatorTest
{
	@Test
	public void shouldValidateUnusualDnsFromHashedStore() throws Exception
	{
		ValidatorParamsExt params = new ValidatorParamsExt();
		params.setInitialListeners(Collections.singleton(new StoreUpdateListener()
		{
			@Override
			public void loadingNotification(String location, String type, Severity level,
					Exception cause)
			{
				System.out.println(level + " " + type + " location: " + location + " cause: " + cause);
				if (cause != null && level != Severity.NOTIFICATION) {
					cause.printStackTrace();
					Assert.fail("Got error");
				}
			}
		}));
		OpensslCertChainValidator validator1 = new OpensslCertChainValidator(
				"src/test/resources/fixtures/openssl-validation/trust",
				-1, params);
		X509Certificate[] cert = CertificateUtils.loadCertificateChain(new FileInputStream(
				"src/test/resources/fixtures/openssl-validation/chains/unusual-dn.pem"),
				Encoding.PEM);
		ValidationResult result = validator1.validate(cert);
		Assert.assertTrue(result.toString(), result.isValid());

		X509Certificate[] cert2 = CertificateUtils.loadCertificateChain(new FileInputStream(
				"src/test/resources/fixtures/openssl-validation/chains/sub-ca-issued.pem"),
				Encoding.PEM);
		ValidationResult result2 = validator1.validate(cert2);
		Assert.assertTrue(result2.toString(), result2.isValid());
		validator1.dispose();
	}
	
	@Test
	public void shouldAcceptAbsentCrlsInDefaultIfPresentMode() throws Exception
	{
		OpensslCertChainValidator validator1 = new OpensslCertChainValidator(
				"src/test/resources/fixtures/openssl-validation/trust-no-crls");
		X509Certificate[] cert = CertificateUtils.loadCertificateChain(new FileInputStream(
				"src/test/resources/fixtures/openssl-validation/chains/unusual-dn.pem"),
				Encoding.PEM);
		ValidationResult result = validator1.validate(cert);
		Assert.assertTrue(result.toString(), result.isValid());

		X509Certificate[] cert2 = CertificateUtils.loadCertificateChain(new FileInputStream(
				"src/test/resources/fixtures/openssl-validation/chains/sub-ca-issued.pem"),
				Encoding.PEM);
		ValidationResult result2 = validator1.validate(cert2);
		Assert.assertTrue(result2.toString(), result2.isValid());
		validator1.dispose();
	}
	
	@Test
	public void testExpiredWithCrl() throws Exception
	{
		RevocationParameters revocationParams = new RevocationParameters(CrlCheckingMode.REQUIRE, 
				new OCSPParametes(OCSPCheckingMode.IGNORE));
		OpensslCertChainValidator validator1 = new OpensslCertChainValidator(
				"src/test/resources/expired-and-crl/openssl-trustdir",
				-1, new ValidatorParams(revocationParams));
		
		InputStream is = new FileInputStream("src/test/resources/test-pems/expiredcert.pem");
		X509Certificate[] certChain = CertificateUtils.loadCertificateChain(is, Encoding.PEM);
		ValidationResult result = validator1.validate(certChain);
		Assert.assertFalse("Expired certificate is valid", result.isValid());
		Assert.assertEquals("Expected one primary error: " + result, 1,
				result.getErrors().size());
		Assert.assertEquals(0, result.getPrimaryError().getPosition());
		Assert.assertEquals(ValidationStage.PATH_VALIDATION,
				result.getPrimaryError().getStage());
		Assert.assertTrue("Got wrong primary message: " + result.getPrimaryError(),
				result.getPrimaryError().getMessage().contains("expired"));
		
		validator1.dispose();
	}
}
