/*
 * Copyright (c) 2026 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorException.BasicReason;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXReason;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.impl.CertificateUtils;

/**
 * Native Bouncy Castle PKIX path builder and validator used for base
 * certificate validation. Revocation is deliberately disabled here; native
 * revocation configuration is layered on separately.
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
		checkInput(input);
		Set<TrustAnchor> anchors = copyAnchors(configuredAnchors);
		if (anchors.isEmpty())
			return invalid(input, -1, ValidationErrorCode.noTrustAnchorFound);

		TrustAnchor exactTargetAnchor = findExactAnchor(input[0], anchors);
		if (exactTargetAnchor != null)
		{
			if (isSelfSigned(input[0]))
				return valid(Collections.singletonList(input[0]));
			// A non-self-signed target is not made valid merely by also being
			// configured as an anchor. It may still build to a different anchor.
			anchors.remove(exactTargetAnchor);
			if (anchors.isEmpty())
				return invalid(input, -1, ValidationErrorCode.noTrustAnchorFound);
		}

		try
		{
			PKIXCertPathBuilderResult built = build(input, anchors);
			// CertPathBuilder performs validation itself. Validate once more with
			// the selected anchor so both native entry points remain explicit.
			return validatePath(built.getCertPath(),
					Collections.singleton(built.getTrustAnchor()), input);
		} catch (CertPathBuilderException e)
		{
			List<X509Certificate> asserted = normalize(Arrays.asList(input), anchors);
			if (asserted.isEmpty())
				return invalid(input, -1, ValidationErrorCode.noTrustAnchorFound, e);
			if (isCoherent(asserted))
				return validatePath(toCertPath(asserted), anchors, input);
			return invalid(input, -1, ValidationErrorCode.noTrustAnchorFound, e);
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
		if (suppliedPath == null)
			throw new IllegalArgumentException("Certificate path must not be null");
		List<X509Certificate> supplied = toX509Certificates(suppliedPath);
		X509Certificate[] diagnosticChain = supplied.toArray(new X509Certificate[supplied.size()]);
		if (supplied.isEmpty())
			return invalid(diagnosticChain, -1, ValidationErrorCode.emptyCertPath);

		Set<TrustAnchor> anchors = copyAnchors(configuredAnchors);
		if (anchors.isEmpty())
			return invalid(diagnosticChain, -1, ValidationErrorCode.noTrustAnchorFound);

		List<X509Certificate> normalized = normalize(supplied, anchors);
		if (normalized.isEmpty())
		{
			X509Certificate target = supplied.get(0);
			if (supplied.size() == 1 && findExactAnchor(target, anchors) != null && isSelfSigned(target))
				return valid(Collections.singletonList(target));
			return invalid(diagnosticChain, -1, ValidationErrorCode.noTrustAnchorFound);
		}
		return validatePath(toCertPath(normalized), anchors, diagnosticChain);
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
			X509Certificate[] diagnosticChain)
	{
		try
		{
			PKIXParameters params = new PKIXParameters(anchors);
			params.setRevocationEnabled(false);
			PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)
					certPathValidator().validate(path, params);
			return valid(resolvedChain(path, result.getTrustAnchor()));
		} catch (CertPathValidatorException e)
		{
			return invalidValidation(diagnosticChain, e);
		} catch (InvalidAlgorithmParameterException e)
		{
			throw new IllegalStateException("Native BC PKIX validator rejected its parameters", e);
		} catch (RuntimeException e)
		{
			// Malformed signature encodings can surface as provider runtime
			// exceptions rather than CertPathValidatorException.
			return invalid(diagnosticChain, -1, ValidationErrorCode.unknownMsg, e);
		}
	}

	private ValidationResult invalidValidation(X509Certificate[] chain,
			CertPathValidatorException failure)
	{
		int position = failure.getIndex();
		if (position < 0 || position >= chain.length)
			position = -1;

		CertPathValidatorException.Reason reason = failure.getReason();
		if (reason == BasicReason.EXPIRED && position >= 0)
			return invalid(chain, position, ValidationErrorCode.certificateExpired,
					chain[position].getNotAfter());
		if (reason == BasicReason.NOT_YET_VALID && position >= 0)
			return invalid(chain, position, ValidationErrorCode.certificateNotYetValid,
					chain[position].getNotBefore());
		if (reason == BasicReason.INVALID_SIGNATURE)
			return invalid(chain, position, ValidationErrorCode.signatureNotVerified, failure);
		if (reason == PKIXReason.NOT_CA_CERT)
			return invalid(chain, position, ValidationErrorCode.noCACert, failure);
		if (reason == PKIXReason.INVALID_KEY_USAGE)
			return invalid(chain, position, ValidationErrorCode.noCertSign, failure);
		if (reason == PKIXReason.PATH_TOO_LONG)
			return invalid(chain, position, ValidationErrorCode.pathLenghtExtended, failure);
		if (reason == PKIXReason.NAME_CHAINING || reason == PKIXReason.INVALID_NAME)
			return invalid(chain, position, ValidationErrorCode.invalidCertificatePath, failure);
		if (reason == PKIXReason.NO_TRUST_ANCHOR)
			return invalid(chain, position, ValidationErrorCode.noTrustAnchorFound, failure);
		if (reason == PKIXReason.UNRECOGNIZED_CRIT_EXT)
			return invalid(chain, position, ValidationErrorCode.unknownCriticalExt,
					"OID not exposed by the provider");
		return invalid(chain, position, ValidationErrorCode.unknownMsg, failure);
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

	private void checkInput(X509Certificate[] input)
	{
		if (input == null || input.length == 0)
			throw new IllegalArgumentException("Chain to be validated must be non-empty");
		for (X509Certificate certificate: input)
			if (certificate == null)
				throw new IllegalArgumentException("Certificate chain must not contain null elements");
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
		return new ValidationResult(true, Collections.<ValidationError>emptyList(),
				Collections.<String>emptySet(), chain);
	}

	private ValidationResult invalid(X509Certificate[] chain, int position,
			ValidationErrorCode code, Object... arguments)
	{
		ValidationError error = new ValidationError(chain, position, code, arguments);
		return new ValidationResult(false, Collections.singletonList(error),
				Collections.<String>emptySet(), null);
	}
}
