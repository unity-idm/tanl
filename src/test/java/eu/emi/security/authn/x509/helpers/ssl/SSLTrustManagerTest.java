/*
 * Copyright (c) 2026 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ssl;

import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

import org.junit.Test;

import eu.emi.security.authn.x509.CommonX509TrustManager;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.ValidationErrorListener;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.ValidationStage;
import eu.emi.security.authn.x509.X509CertChainValidator;

public class SSLTrustManagerTest
{
	@Test
	public void shouldAttachPrimaryCauseInBasicTrustManager() throws Exception
	{
		ValidationResult result = rejectingResult();
		assertPrimaryCause(new SSLTrustManager(fixedValidator(result)), result);
	}

	@Test
	public void shouldAttachPrimaryCauseInHostnameCheckingTrustManager() throws Exception
	{
		ValidationResult result = rejectingResult();
		assertPrimaryCause(new SSLTrustManagerWithHostnameChecking(
				fixedValidator(result), null), result);
	}

	@Test
	public void shouldAttachPrimaryCauseInCommonTrustManager() throws Exception
	{
		ValidationResult result = rejectingResult();
		assertPrimaryCause(new CommonX509TrustManager(fixedValidator(result)), result);
	}

	private void assertPrimaryCause(X509TrustManager trustManager,
			ValidationResult result) throws Exception
	{
		try
		{
			trustManager.checkServerTrusted(new X509Certificate[0], "RSA");
			fail("Invalid validation result should reject the TLS peer");
		} catch (CertificateException e)
		{
			assertSame(result.getPrimaryError().getCause(), e.getCause());
			assertTrue(e.getMessage().contains("provider failure"));
		}
	}

	private ValidationResult rejectingResult()
	{
		CertPathValidatorException cause = new CertPathValidatorException("provider failure");
		ValidationError error = new ValidationError(null, -1,
				ValidationErrorCode.PKIX_FAILURE, ValidationStage.PATH_VALIDATION,
				cause.getMessage(), cause);
		return ValidationResult.invalid(error);
	}

	private X509CertChainValidator fixedValidator(final ValidationResult result)
	{
		return new X509CertChainValidator()
		{
			@Override
			public ValidationResult validate(CertPath certPath)
			{
				return result;
			}

			@Override
			public ValidationResult validate(X509Certificate[] certChain)
			{
				return result;
			}

			@Override
			public X509Certificate[] getTrustedIssuers()
			{
				return new X509Certificate[0];
			}

			@Override
			public void addValidationListener(ValidationErrorListener listener)
			{
			}

			@Override
			public void removeValidationListener(ValidationErrorListener listener)
			{
			}

			@Override
			public void addUpdateListener(StoreUpdateListener listener)
			{
			}

			@Override
			public void removeUpdateListener(StoreUpdateListener listener)
			{
			}
		};
	}
}
