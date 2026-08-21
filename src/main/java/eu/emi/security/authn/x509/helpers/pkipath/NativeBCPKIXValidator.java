/*
 * Copyright (c) 2026 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorException.BasicReason;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.PKIXReason;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.jcajce.PKIXExtendedParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import eu.emi.security.authn.x509.OCSPResponder;
import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.ValidationStage;
import eu.emi.security.authn.x509.impl.CertificateUtils;

/**
 * Native Bouncy Castle PKIX path builder and validator. Base validation and
 * strict CRL or OCSP validation are kept as separate passes so failures have
 * an unambiguous validation stage.
 */
final class NativeBCPKIXValidator
{
	private static final String PKIX = "PKIX";
	private static final String X509 = "X.509";
	private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

	static
	{
		CertificateUtils.configureSecProvider();
	}

	/**
	 * Builds a path from the first certificate as the target and all remaining
	 * certificates as unordered candidates, then validates the selected path.
	 */
	ValidationResult validate(X509Certificate[] input, Set<TrustAnchor> configuredAnchors)
			throws CertificateException
	{
		return validate(input, configuredAnchors, null, null, null);
	}

	/**
	 * Builds and validates a path, then performs strict native CRL checking on
	 * every non-anchor certificate in the selected path.
	 */
	ValidationResult validateWithCRLs(X509Certificate[] input,
			Set<TrustAnchor> configuredAnchors, CertStore crlStore)
			throws CertificateException
	{
		if (crlStore == null)
			return invalidInput(input, -1, "CRL store must not be null");
		return validate(input, configuredAnchors, crlStore, null, null);
	}

	/**
	 * Builds and validates a path, then performs strict native OCSP checking
	 * against one explicitly configured responder.
	 */
	ValidationResult validateWithOCSP(X509Certificate[] input,
			Set<TrustAnchor> configuredAnchors, OCSPResponder responder)
			throws CertificateException
	{
		if (responder == null)
			return invalidInput(input, -1, "OCSP responder must not be null");
		if (responder.getAddress() == null)
			return invalidInput(input, -1, "OCSP responder address must not be null");
		if (responder.getCertificate() == null)
			return invalidInput(input, -1, "OCSP responder certificate must not be null");
		try
		{
			return validate(input, configuredAnchors, null,
					responder.getAddress().toURI(), responder.getCertificate());
		} catch (URISyntaxException e)
		{
			return invalid(input, -1, ValidationErrorCode.INVALID_INPUT,
					ValidationStage.INPUT, e);
		}
	}

	private ValidationResult validate(X509Certificate[] input,
			Set<TrustAnchor> configuredAnchors, CertStore crlStore,
			URI ocspResponder, X509Certificate ocspResponderCertificate)
			throws CertificateException
	{
		ValidationResult inputFailure = checkInput(input);
		if (inputFailure != null)
			return inputFailure;
		Set<TrustAnchor> anchors = copyAnchors(configuredAnchors);
		if (anchors.isEmpty())
			return noTrustAnchor(input, ValidationStage.PATH_BUILDING);

		TrustAnchor exactTargetAnchor = findExactAnchor(input[0], anchors);
		if (exactTargetAnchor != null)
		{
			if (isSelfSigned(input[0]))
				return valid(Collections.singletonList(input[0]));
			// A non-self-signed target is not made valid merely by also being
			// configured as an anchor. It may still build to a different anchor.
			anchors.remove(exactTargetAnchor);
			if (anchors.isEmpty())
				return noTrustAnchor(input, ValidationStage.PATH_BUILDING);
		}

		try
		{
			PKIXCertPathBuilderResult built = build(input, anchors);
			// CertPathBuilder performs validation itself. Validate once more with
			// the selected anchor so both native entry points remain explicit.
			return validatePath(built.getCertPath(),
					Collections.singleton(built.getTrustAnchor()), crlStore,
					collectionStore(Arrays.asList(input)), ocspResponder,
					ocspResponderCertificate);
		} catch (CertPathBuilderException e)
		{
			List<X509Certificate> asserted = normalize(Arrays.asList(input), anchors);
			if (asserted.isEmpty())
				return invalid(input, -1, ValidationErrorCode.PATH_BUILDING_FAILED,
						ValidationStage.PATH_BUILDING, e);
			if (isCoherent(asserted))
				return validatePath(toCertPath(asserted), anchors, crlStore,
						collectionStore(Arrays.asList(input)), ocspResponder,
						ocspResponderCertificate);
			return invalid(input, -1, ValidationErrorCode.PATH_BUILDING_FAILED,
					ValidationStage.PATH_BUILDING, e);
		} catch (InvalidAlgorithmParameterException e)
		{
			throw new IllegalStateException("Native BC PKIX builder rejected its parameters", e);
		}
	}

	/**
	 * Validates an asserted path directly. An included trust-anchor certificate
	 * and anything supplied after it are removed before invoking the native
	 * validator.
	 */
	ValidationResult validate(CertPath suppliedPath, Set<TrustAnchor> configuredAnchors)
			throws CertificateException
	{
		return validate(suppliedPath, configuredAnchors, null, null, null);
	}

	/**
	 * Validates an asserted path with strict native CRL checking.
	 */
	ValidationResult validateWithCRLs(CertPath suppliedPath,
			Set<TrustAnchor> configuredAnchors, CertStore crlStore)
			throws CertificateException
	{
		if (crlStore == null)
			return invalidInput(null, -1, "CRL store must not be null");
		return validate(suppliedPath, configuredAnchors, crlStore, null, null);
	}

	/**
	 * Validates an asserted path with strict native OCSP checking against one
	 * explicitly configured responder.
	 */
	ValidationResult validateWithOCSP(CertPath suppliedPath,
			Set<TrustAnchor> configuredAnchors, OCSPResponder responder)
			throws CertificateException
	{
		if (responder == null)
			return invalidInput(null, -1, "OCSP responder must not be null");
		if (responder.getAddress() == null)
			return invalidInput(null, -1, "OCSP responder address must not be null");
		if (responder.getCertificate() == null)
			return invalidInput(null, -1, "OCSP responder certificate must not be null");
		try
		{
			return validate(suppliedPath, configuredAnchors, null,
					responder.getAddress().toURI(), responder.getCertificate());
		} catch (URISyntaxException e)
		{
			return invalid(null, -1, ValidationErrorCode.INVALID_INPUT,
					ValidationStage.INPUT, e);
		}
	}

	private ValidationResult validate(CertPath suppliedPath,
			Set<TrustAnchor> configuredAnchors, CertStore crlStore,
			URI ocspResponder, X509Certificate ocspResponderCertificate)
			throws CertificateException
	{
		if (suppliedPath == null)
			return invalidInput(null, -1, "Certificate path must not be null");
		List<X509Certificate> supplied;
		try
		{
			supplied = toX509Certificates(suppliedPath);
		} catch (IllegalArgumentException e)
		{
			return invalid(null, -1, ValidationErrorCode.INVALID_INPUT,
					ValidationStage.INPUT, e);
		}
		X509Certificate[] diagnosticChain = supplied.toArray(new X509Certificate[supplied.size()]);
		if (supplied.isEmpty())
			return invalidInput(diagnosticChain, -1, "Certificate path must not be empty");

		Set<TrustAnchor> anchors = copyAnchors(configuredAnchors);
		if (anchors.isEmpty())
			return noTrustAnchor(diagnosticChain, ValidationStage.PATH_VALIDATION);

		List<X509Certificate> normalized = normalize(supplied, anchors);
		if (normalized.isEmpty())
		{
			X509Certificate target = supplied.get(0);
			if (supplied.size() == 1 && findExactAnchor(target, anchors) != null && isSelfSigned(target))
				return valid(Collections.singletonList(target));
			return noTrustAnchor(diagnosticChain, ValidationStage.PATH_VALIDATION);
		}
		return validatePath(toCertPath(normalized), anchors, crlStore,
				collectionStore(supplied), ocspResponder,
				ocspResponderCertificate);
	}

	private PKIXCertPathBuilderResult build(X509Certificate[] input, Set<TrustAnchor> anchors)
			throws CertPathBuilderException, InvalidAlgorithmParameterException
	{
		X509CertSelector target = new X509CertSelector();
		target.setCertificate(input[0]);
		PKIXBuilderParameters params = new PKIXBuilderParameters(anchors, target);
		params.setRevocationEnabled(false);
		params.setMaxPathLength(-1);
		params.addCertStore(collectionStore(Arrays.asList(input)));
		return (PKIXCertPathBuilderResult) certPathBuilder().build(params);
	}

	private ValidationResult validatePath(CertPath path, Set<TrustAnchor> anchors,
			CertStore crlStore, CertStore certificateStore, URI ocspResponder,
			X509Certificate ocspResponderCertificate)
	{
		X509Certificate[] diagnosticChain = pathCertificates(path);
		PKIXCertPathValidatorResult result;
		try
		{
			result = validateNative(path, anchors,
					certificateStore, null);
		} catch (CertPathValidatorException e)
		{
			return invalidValidation(diagnosticChain, e,
					ValidationStage.PATH_VALIDATION);
		} catch (InvalidAlgorithmParameterException e)
		{
			throw new IllegalStateException("Native BC PKIX validator rejected its parameters", e);
		} catch (RuntimeException e)
		{
			// Malformed signature encodings can surface as provider runtime
			// exceptions rather than CertPathValidatorException.
			return invalid(diagnosticChain, -1, ValidationErrorCode.PKIX_FAILURE,
					ValidationStage.PATH_VALIDATION, e);
		}

		if (crlStore != null)
		{
			try
			{
				result = validateNative(path, anchors, certificateStore, crlStore);
			} catch (CertPathValidatorException e)
			{
				return invalidValidation(diagnosticChain, e,
						ValidationStage.REVOCATION);
			} catch (InvalidAlgorithmParameterException e)
			{
				throw new IllegalStateException(
						"Native BC PKIX validator rejected its CRL parameters", e);
			} catch (RuntimeException e)
			{
				return invalid(diagnosticChain, -1, ValidationErrorCode.PKIX_FAILURE,
						ValidationStage.REVOCATION, e);
			}
		}
		else if (ocspResponder != null)
		{
			try
			{
				result = validateNativeWithOCSP(path, anchors, certificateStore,
						ocspResponder, ocspResponderCertificate);
			} catch (CertPathValidatorException e)
			{
				return invalidValidation(diagnosticChain, e,
						ValidationStage.REVOCATION);
			} catch (InvalidAlgorithmParameterException e)
			{
				throw new IllegalStateException(
						"Native BC PKIX validator rejected its OCSP parameters", e);
			} catch (RuntimeException e)
			{
				return invalid(diagnosticChain, -1, ValidationErrorCode.PKIX_FAILURE,
						ValidationStage.REVOCATION, e);
			}
		}
		return valid(resolvedChain(path, result.getTrustAnchor()));
	}

	private PKIXCertPathValidatorResult validateNative(CertPath path,
			Set<TrustAnchor> anchors, CertStore certificateStore, CertStore crlStore)
			throws CertPathValidatorException, InvalidAlgorithmParameterException
	{
		PKIXParameters params = new PKIXParameters(anchors);
		params.setRevocationEnabled(crlStore != null);
		params.addCertStore(certificateStore);
		if (crlStore != null)
			params.addCertStore(crlStore);
		PKIXExtendedParameters.Builder extended =
				new PKIXExtendedParameters.Builder(params);
		extended.setUseDeltasEnabled(crlStore != null);
		return (PKIXCertPathValidatorResult) certPathValidator().validate(path,
				extended.build());
	}

	private PKIXCertPathValidatorResult validateNativeWithOCSP(CertPath path,
			Set<TrustAnchor> anchors, CertStore certificateStore,
			URI responder, X509Certificate responderCertificate)
			throws CertPathValidatorException, InvalidAlgorithmParameterException
	{
		CertPathValidator validator = certPathValidator();
		PKIXRevocationChecker checker =
				(PKIXRevocationChecker) validator.getRevocationChecker();
		checker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));
		checker.setOcspResponder(responder);
		checker.setOcspResponderCert(responderCertificate);

		PKIXParameters params = new PKIXParameters(anchors);
		params.setRevocationEnabled(false);
		params.addCertStore(certificateStore);
		params.addCertPathChecker(checker);
		return (PKIXCertPathValidatorResult) validator.validate(path, params);
	}

	private ValidationResult invalidValidation(X509Certificate[] chain,
			CertPathValidatorException failure, ValidationStage failureStage)
	{
		int position = failure.getIndex();
		if (position < 0 || chain == null || position >= chain.length)
			position = -1;

		CertPathValidatorException.Reason reason = failure.getReason();
		if (failureStage == ValidationStage.REVOCATION)
		{
			if (reason == BasicReason.REVOKED)
				return invalid(chain, position, ValidationErrorCode.CERTIFICATE_REVOKED,
						ValidationStage.REVOCATION, failure);
			if (reason == BasicReason.UNDETERMINED_REVOCATION_STATUS)
				return invalid(chain, position,
						ValidationErrorCode.UNDETERMINED_REVOCATION_STATUS,
						ValidationStage.REVOCATION, failure);
			return invalid(chain, position, ValidationErrorCode.PKIX_FAILURE,
					ValidationStage.REVOCATION, failure);
		}
		if (reason == BasicReason.EXPIRED ||
				hasCause(failure, CertificateExpiredException.class))
			return invalid(chain, position, ValidationErrorCode.CERTIFICATE_EXPIRED,
					ValidationStage.PATH_VALIDATION, failure);
		if (reason == BasicReason.NOT_YET_VALID ||
				hasCause(failure, CertificateNotYetValidException.class))
			return invalid(chain, position, ValidationErrorCode.CERTIFICATE_NOT_YET_VALID,
					ValidationStage.PATH_VALIDATION, failure);
		if (reason == BasicReason.INVALID_SIGNATURE ||
				hasCause(failure, SignatureException.class))
			return invalid(chain, position, ValidationErrorCode.INVALID_SIGNATURE,
					ValidationStage.PATH_VALIDATION, failure);
		if (reason == BasicReason.ALGORITHM_CONSTRAINED)
			return invalid(chain, position, ValidationErrorCode.ALGORITHM_CONSTRAINED,
					ValidationStage.PATH_VALIDATION, failure);
		if (reason == PKIXReason.NOT_CA_CERT)
			return invalid(chain, position, ValidationErrorCode.NOT_CA,
					ValidationStage.PATH_VALIDATION, failure);
		if (reason == PKIXReason.INVALID_KEY_USAGE)
			return invalid(chain, position, ValidationErrorCode.INVALID_KEY_USAGE,
					ValidationStage.PATH_VALIDATION, failure);
		if (reason == PKIXReason.PATH_TOO_LONG)
			return invalid(chain, position, ValidationErrorCode.PATH_TOO_LONG,
					ValidationStage.PATH_VALIDATION, failure);
		if (reason == PKIXReason.NAME_CHAINING)
			return invalid(chain, position, ValidationErrorCode.INVALID_NAME_CHAINING,
					ValidationStage.PATH_VALIDATION, failure);
		if (reason == PKIXReason.INVALID_NAME)
			return invalid(chain, position, ValidationErrorCode.INVALID_NAME_CONSTRAINT,
					ValidationStage.PATH_VALIDATION, failure);
		if (reason == PKIXReason.INVALID_POLICY)
			return invalid(chain, position, ValidationErrorCode.INVALID_POLICY,
					ValidationStage.PATH_VALIDATION, failure);
		if (reason == PKIXReason.NO_TRUST_ANCHOR)
			return invalid(chain, position, ValidationErrorCode.NO_TRUST_ANCHOR,
					ValidationStage.PATH_VALIDATION, failure);
		if (reason == PKIXReason.UNRECOGNIZED_CRIT_EXT)
			return invalid(chain, position, ValidationErrorCode.UNRESOLVED_CRITICAL_EXTENSION,
					ValidationStage.PATH_VALIDATION, failure);
		return invalid(chain, position, ValidationErrorCode.PKIX_FAILURE,
				failureStage, failure);
	}

	private boolean hasCause(Throwable failure, Class<? extends Throwable> expected)
	{
		Throwable current = failure;
		while (current != null)
		{
			if (expected.isInstance(current))
				return true;
			current = current.getCause();
		}
		return false;
	}

	private X509Certificate[] pathCertificates(CertPath path)
	{
		List<? extends Certificate> certificates = path.getCertificates();
		X509Certificate[] result = new X509Certificate[certificates.size()];
		for (int i=0; i<result.length; i++)
			result[i] = (X509Certificate) certificates.get(i);
		return result;
	}

	private List<X509Certificate> resolvedChain(CertPath path, TrustAnchor anchor)
	{
		List<X509Certificate> result = new ArrayList<X509Certificate>();
		for (Certificate certificate: path.getCertificates())
			result.add((X509Certificate) certificate);
		X509Certificate trustedCertificate = anchor.getTrustedCert();
		if (trustedCertificate != null &&
				(result.isEmpty() || !trustedCertificate.equals(result.get(result.size() - 1))))
			result.add(trustedCertificate);
		return result;
	}

	private List<X509Certificate> normalize(List<X509Certificate> supplied,
			Set<TrustAnchor> anchors)
	{
		for (int i=0; i<supplied.size(); i++)
			if (findExactAnchor(supplied.get(i), anchors) != null)
				return new ArrayList<X509Certificate>(supplied.subList(0, i));
		return new ArrayList<X509Certificate>(supplied);
	}

	private boolean isCoherent(List<X509Certificate> path)
	{
		for (int i=0; i<path.size()-1; i++)
			if (!path.get(i).getIssuerX500Principal().equals(
					path.get(i+1).getSubjectX500Principal()))
				return false;
		return true;
	}

	private TrustAnchor findExactAnchor(X509Certificate certificate, Set<TrustAnchor> anchors)
	{
		for (TrustAnchor anchor: anchors)
			if (anchor.getTrustedCert() != null && anchor.getTrustedCert().equals(certificate))
				return anchor;
		return null;
	}

	private boolean isSelfSigned(X509Certificate certificate)
	{
		if (!certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal()))
			return false;
		try
		{
			certificate.verify(certificate.getPublicKey(), BC);
			return true;
		} catch (GeneralSecurityException e)
		{
			return false;
		}
	}

	private ValidationResult checkInput(X509Certificate[] input)
	{
		if (input == null)
			return invalidInput(null, -1, "Certificate chain must not be null");
		if (input.length == 0)
			return invalidInput(input, -1, "Certificate chain must not be empty");
		for (int i=0; i<input.length; i++)
			if (input[i] == null)
				return invalidInput(input, i,
						"Certificate chain must not contain null elements");
		return null;
	}

	private List<X509Certificate> toX509Certificates(CertPath path)
	{
		List<X509Certificate> result = new ArrayList<X509Certificate>();
		for (Certificate certificate: path.getCertificates())
		{
			if (!(certificate instanceof X509Certificate))
				throw new IllegalArgumentException("Can validate only X509Certificate paths. Found: " +
						certificate.getClass().getName());
			result.add((X509Certificate) certificate);
		}
		return result;
	}

	private Set<TrustAnchor> copyAnchors(Set<TrustAnchor> anchors)
	{
		return anchors == null ? new HashSet<TrustAnchor>() : new HashSet<TrustAnchor>(anchors);
	}

	private CertPath toCertPath(List<X509Certificate> certificates) throws CertificateException
	{
		try
		{
			return CertificateFactory.getInstance(X509, BC).generateCertPath(certificates);
		} catch (GeneralSecurityException e)
		{
			throw new IllegalStateException("Native BC X.509 certificate factory is unavailable", e);
		}
	}

	private CertStore collectionStore(List<X509Certificate> certificates)
	{
		try
		{
			return CertStore.getInstance("Collection",
					new CollectionCertStoreParameters(certificates), BC);
		} catch (GeneralSecurityException e)
		{
			throw new IllegalStateException("Native BC collection certificate store is unavailable", e);
		}
	}

	private CertPathBuilder certPathBuilder()
	{
		try
		{
			return CertPathBuilder.getInstance(PKIX, BC);
		} catch (GeneralSecurityException e)
		{
			throw new IllegalStateException("Native BC PKIX path builder is unavailable", e);
		}
	}

	private CertPathValidator certPathValidator()
	{
		try
		{
			return CertPathValidator.getInstance(PKIX, BC);
		} catch (GeneralSecurityException e)
		{
			throw new IllegalStateException("Native BC PKIX path validator is unavailable", e);
		}
	}

	private ValidationResult valid(List<X509Certificate> chain)
	{
		return ValidationResult.valid(chain);
	}

	private ValidationResult invalid(X509Certificate[] chain, int position,
			ValidationErrorCode code, ValidationStage stage, Throwable cause)
	{
		String providerMessage = cause == null ? null : cause.getMessage();
		ValidationError error = new ValidationError(chain, position, code, stage,
				providerMessage, cause);
		return ValidationResult.invalid(error);
	}

	private ValidationResult invalidInput(X509Certificate[] chain, int position,
			String message)
	{
		return invalid(chain, position, ValidationErrorCode.INVALID_INPUT,
				ValidationStage.INPUT, new IllegalArgumentException(message));
	}

	private ValidationResult noTrustAnchor(X509Certificate[] chain, ValidationStage stage)
	{
		Throwable failure = stage == ValidationStage.PATH_BUILDING ?
				new CertPathBuilderException("No trust anchors are configured") :
				new CertPathValidatorException("No trust anchors are configured", null,
						null, -1, PKIXReason.NO_TRUST_ANCHOR);
		return invalid(chain, -1, ValidationErrorCode.NO_TRUST_ANCHOR, stage, failure);
	}
}
