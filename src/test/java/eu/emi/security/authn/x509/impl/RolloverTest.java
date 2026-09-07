/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 21-12-2011
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.emi.security.authn.x509.impl;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.FileInputStream;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;

import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

public class RolloverTest
{
	@Test
	public void test() throws Exception
	{
		OpensslCertChainValidator validator = new OpensslCertChainValidator(
				"src/test/resources/rollover/openssl-trustdir");
		
		X509Certificate[] cert1 = CertificateUtils.loadCertificateChain(
				new FileInputStream("src/test/resources/rollover/user-from-old.pem"), 
				Encoding.PEM);
		ValidationResult result = validator.validate(cert1);
		assertTrue(result.isValid());

		X509Certificate[] cert2 = CertificateUtils.loadCertificateChain(
				new FileInputStream("src/test/resources/rollover/user-from-new.pem"), 
				Encoding.PEM);
		ValidationResult result2 = validator.validate(cert2);
		assertTrue(result2.isValid());
	}
}
