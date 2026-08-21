/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509;

import static org.junit.Assert.*;

import java.io.FileInputStream;
import java.security.cert.CertPathValidatorException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;

import org.junit.Test;

import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;
import eu.emi.security.authn.x509.impl.CertificateUtilsTest;

public class ErrorTest
{
	/**
	 * Checks that the stable native error catalogue has a category and message.
	 */
	@Test
	public void testMessages()
	{
		assertEquals(17, ValidationErrorCode.values().length);
		for (ValidationErrorCode code: ValidationErrorCode.values())
		{
			assertNotNull(ValidationErrorCategory.getErrorCategory(code));
			ValidationError error = new ValidationError(null, -1, code,
					ValidationStage.PATH_VALIDATION, null, null);
			assertFalse(error.getMessage().isEmpty());
		}
	}

	@Test
	public void testValidationErrorToString() throws Exception
	{
		CertPathValidatorException cause = new CertPathValidatorException("FOO");
		ValidationError pathError = new ValidationError(null, -1,
				ValidationErrorCode.PKIX_FAILURE, ValidationStage.PATH_VALIDATION,
				cause.getMessage(), cause);
		String str = pathError.toString();
		assertTrue(str.contains("FOO"));
		assertTrue(str.contains("OTHER"));
		assertTrue(str.contains("PATH_VALIDATION"));
		assertFalse(str.contains("-1"));
		assertSame(cause, pathError.getCause());
		assertEquals("FOO", pathError.getProviderMessage());
		
		
		X509Certificate[] certChain = new X509Certificate[2];
		certChain[0] = CertificateUtils.loadCertificate(
				new FileInputStream(CertificateUtilsTest.PFX + "cacert.pem"), 
				Encoding.PEM);
		certChain[1] = CertificateUtils.loadCertificate(
				new FileInputStream(CertificateUtilsTest.PFX + "cert-1.pem"), 
				Encoding.PEM);
		ValidationError certificateError = new ValidationError(certChain, 1,
				ValidationErrorCode.INVALID_SIGNATURE, ValidationStage.PATH_VALIDATION,
				cause.getMessage(), cause);
		str = certificateError.toString();
		assertTrue(str.contains("FOO"));
		assertTrue(str.contains("CERTIFICATE"));
		assertTrue(str.contains("1"));
		assertSame(certChain[1], certificateError.getCertificate());

		X509Certificate[] returnedChain = certificateError.getChain();
		returnedChain[1] = null;
		assertSame(certChain[1], certificateError.getCertificate());
	}
	
	@Test
	public void testValidationResult()
	{
		ValidationResult valid = ValidationResult.valid(Collections.<X509Certificate>emptyList());
		assertTrue(valid.isValid());
		assertNull(valid.getPrimaryError());
		assertTrue(valid.getErrors().isEmpty());
		assertEquals("OK", valid.toString());

		ValidationError error = new ValidationError(null, -1,
				ValidationErrorCode.PKIX_FAILURE, ValidationStage.PATH_VALIDATION,
				"provider detail", new CertPathValidatorException("provider detail"));
		HashSet<String> unresolved = new HashSet<String>();
		unresolved.add("1.2.3");
		ValidationResult invalid = ValidationResult.invalid(error, unresolved);
		unresolved.clear();

		assertFalse(invalid.isValid());
		assertSame(error, invalid.getPrimaryError());
		assertEquals(Collections.singletonList(error), invalid.getErrors());
		assertEquals(Collections.singleton("1.2.3"),
				invalid.getUnresolvedCriticalExtensions());
		assertNull(invalid.getValidChain());
		assertTrue(invalid.toString().contains("FAILED"));

		try
		{
			invalid.getErrors().clear();
			fail("Validation error list must be immutable");
		} catch (UnsupportedOperationException e)
		{
			//EXPECTED, OK
		}
		try
		{
			invalid.getUnresolvedCriticalExtensions().clear();
			fail("Unresolved extension set must be immutable");
		} catch (UnsupportedOperationException e)
		{
			//EXPECTED, OK
		}
	}
}
