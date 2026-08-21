/*
 * Copyright (c) 2026 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.ssl;

import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.FileInputStream;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.X509TrustManager;

import org.junit.Test;

import eu.emi.security.authn.x509.CommonX509TrustManager;
import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.ValidationErrorListener;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.ValidationStage;
import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.impl.CRLParameters;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;
import eu.emi.security.authn.x509.impl.DirectoryCertChainValidator;
import eu.emi.security.authn.x509.impl.RevocationParametersExt;
import eu.emi.security.authn.x509.impl.ValidatorParamsExt;

public class SSLTrustManagerTest
{
	private static final String CERTIFICATE_DIRECTORY =
			"src/test/resources/NIST/certs/";
	private static final String CRL_DIRECTORY =
			"src/test/resources/NIST/crls/";

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

	@Test
	public void shouldAcceptValidChainAtTlsBoundary() throws Exception
	{
		DirectoryCertChainValidator validator = validator(
				Collections.singletonList(certificate("TrustAnchorRootCertificate")),
				CrlCheckingMode.IGNORE, Collections.<String>emptyList());
		try
		{
			new SSLTrustManager(validator).checkServerTrusted(chain(
					"ValidCertificatePathTest1EE", "GoodCACert"), "RSA");
		} finally
		{
			validator.dispose();
		}
	}

	@Test
	public void shouldRejectUntrustedChainAtTlsBoundary() throws Exception
	{
		DirectoryCertChainValidator validator = validator(
				Collections.<String>emptyList(), CrlCheckingMode.IGNORE,
				Collections.<String>emptyList());
		try
		{
			assertTlsRejection(validator, chain(
					"ValidCertificatePathTest1EE", "GoodCACert"),
					ValidationErrorCode.NO_TRUST_ANCHOR,
					ValidationStage.PATH_BUILDING, CertPathBuilderException.class);
		} finally
		{
			validator.dispose();
		}
	}

	@Test
	public void shouldRejectExpiredChainAtTlsBoundary() throws Exception
	{
		DirectoryCertChainValidator validator = validator(
				Collections.singletonList(certificate("TrustAnchorRootCertificate")),
				CrlCheckingMode.IGNORE, Collections.<String>emptyList());
		try
		{
			assertTlsRejection(validator, chain(
					"InvalidEEnotAfterDateTest6EE", "GoodCACert"),
					ValidationErrorCode.CERTIFICATE_EXPIRED,
					ValidationStage.PATH_VALIDATION,
					CertPathValidatorException.class);
		} finally
		{
			validator.dispose();
		}
	}

	@Test
	public void shouldRejectRevokedChainAtTlsBoundary() throws Exception
	{
		DirectoryCertChainValidator validator = validator(
				Collections.singletonList(certificate("TrustAnchorRootCertificate")),
				CrlCheckingMode.REQUIRE, Arrays.asList(
						crl("GoodCACRL"), crl("TrustAnchorRootCRL")));
		try
		{
			assertTlsRejection(validator, chain(
					"InvalidRevokedEETest3EE", "GoodCACert"),
					ValidationErrorCode.PKIX_FAILURE,
					ValidationStage.REVOCATION,
					CertPathValidatorException.class);
		} finally
		{
			validator.dispose();
		}
	}

	@Test
	public void shouldRejectUnsupportedCriticalExtensionAtTlsBoundary()
			throws Exception
	{
		DirectoryCertChainValidator validator = validator(
				Collections.singletonList(certificate("TrustAnchorRootCertificate")),
				CrlCheckingMode.IGNORE, Collections.<String>emptyList());
		try
		{
			assertTlsRejection(validator, chain(
					"InvalidUnknownCriticalCertificateExtensionTest2EE"),
					ValidationErrorCode.PKIX_FAILURE,
					ValidationStage.PATH_VALIDATION,
					CertPathValidatorException.class);
		} finally
		{
			validator.dispose();
		}
	}

	private void assertTlsRejection(DirectoryCertChainValidator validator,
			X509Certificate[] chain, ValidationErrorCode expectedCode,
			ValidationStage expectedStage, Class<? extends Throwable> causeType)
			throws Exception
	{
		final List<ValidationError> observed = new ArrayList<ValidationError>();
		validator.addValidationListener(error -> observed.add(error));
		try
		{
			new SSLTrustManager(validator).checkServerTrusted(chain, "RSA");
			fail("Invalid certificate chain should be rejected at the TLS boundary");
		} catch (CertificateException e)
		{
			assertTrue("The validator should notify exactly one primary error",
					observed.size() == 1);
			ValidationError primary = observed.get(0);
			assertTrue("Unexpected primary error code",
					primary.getErrorCode() == expectedCode);
			assertTrue("Unexpected validation stage",
					primary.getStage() == expectedStage);
			assertSame("TLS must retain the native primary cause",
					primary.getCause(), e.getCause());
			assertTrue("Unexpected native failure type",
					causeType.isInstance(e.getCause()));
		}
	}

	private DirectoryCertChainValidator validator(List<String> trusted,
			CrlCheckingMode crlMode, List<String> crls) throws Exception
	{
		RevocationParametersExt revocation = new RevocationParametersExt(
				crlMode, new CRLParameters(crls, -1, 0, null),
				new OCSPParametes(OCSPCheckingMode.IGNORE));
		return new DirectoryCertChainValidator(trusted, Encoding.DER, -1, 0,
				null, new ValidatorParamsExt(revocation));
	}

	private X509Certificate[] chain(String... names) throws Exception
	{
		X509Certificate[] certificates = new X509Certificate[names.length];
		for (int i = 0; i < names.length; i++)
		{
			try (FileInputStream input = new FileInputStream(certificate(names[i])))
			{
				certificates[i] = CertificateUtils.loadCertificate(input, Encoding.DER);
			}
		}
		return certificates;
	}

	private String certificate(String name)
	{
		return CERTIFICATE_DIRECTORY + name + ".crt";
	}

	private String crl(String name)
	{
		return CRL_DIRECTORY + name + ".crl";
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
