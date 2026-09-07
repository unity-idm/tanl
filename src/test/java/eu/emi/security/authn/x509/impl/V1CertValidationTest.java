/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.FileInputStream;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;

import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

public class V1CertValidationTest
{
	@Test
	public void test() throws Exception
	{
		DirectoryCertChainValidator validator = new DirectoryCertChainValidator(
				"src/test/resources/ca-v1/cacert.pem", 
				"src/test/resources/ca-v1/*.crl", null);
		
		X509Certificate[] cert1 = CertificateUtils.loadCertificateChain(
				new FileInputStream("src/test/resources/ca-v1/usercert.pem"), 
				Encoding.PEM);
		
		ValidationResult result = validator.validate(cert1);
		assertTrue(result.isValid());
		validator.dispose();
	}
}
