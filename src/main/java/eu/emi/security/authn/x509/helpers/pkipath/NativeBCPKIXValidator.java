/*
 * Copyright (c) 2026 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
import java.security.cert.CertificateEncodingException;
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
import java.util.Date;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jcajce.PKIXExtendedParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPResponder;
import eu.emi.security.authn.x509.RevocationParameters.RevocationCheckingOrder;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.StoreUpdateListener.Severity;
import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.ValidationStage;
import eu.emi.security.authn.x509.helpers.ObserversHandler;
import eu.emi.security.authn.x509.helpers.ocsp.OCSPClientImpl;
import eu.emi.security.authn.x509.helpers.ocsp.OCSPClientImpl.OCSPHTTPException;
import eu.emi.security.authn.x509.helpers.ocsp.OCSPClientImpl.OCSPResponseDecodingException;
import eu.emi.security.authn.x509.helpers.ocsp.OCSPResponseStructure;
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
	private final NativeOCSPResponseCache<OCSPCacheKey> ocspResponseCache =
			new NativeOCSPResponseCache<OCSPCacheKey>();
	private final NativeOCSPResponderFailureCache ocspResponderFailureCache =
			new NativeOCSPResponderFailureCache();
	private final ObserversHandler observers;

	NativeBCPKIXValidator()
	{
		this(new ObserversHandler());
	}

	NativeBCPKIXValidator(ObserversHandler observers)
	{
		if (observers == null)
			throw new IllegalArgumentException("Observers handler must not be null");
		this.observers = observers;
	}

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
		return validate(input, configuredAnchors, null, null, null, false, null);
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
		return validate(input, configuredAnchors, crlStore, null, null, false, null);
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
					responder.getAddress().toURI(), responder.getCertificate(), false, null);
		} catch (URISyntaxException e)
		{
			return invalid(input, -1, ValidationErrorCode.INVALID_INPUT,
					ValidationStage.INPUT, e);
		}
	}

	/**
	 * Builds and validates a path, fetches responses using the configured
	 * per-request timeout, and delegates response validation to native BC.
	 */
	ValidationResult validateWithOCSP(X509Certificate[] input,
			Set<TrustAnchor> configuredAnchors, OCSPResponder responder,
			int timeout) throws CertificateException
	{
		return validateWithOCSP(input, configuredAnchors, responder, timeout, -1);
	}

	/**
	 * Builds and validates a path, fetches responses using the configured
	 * timeout, and caches successfully validated encoded responses in memory.
	 */
	ValidationResult validateWithOCSP(X509Certificate[] input,
			Set<TrustAnchor> configuredAnchors, OCSPResponder responder,
			int timeout, int cacheTtl) throws CertificateException
	{
		return validateWithOCSP(input, configuredAnchors, responder, timeout,
				cacheTtl, null);
	}

	/**
	 * Builds and validates a path using configured transport controls and
	 * optional memory and persistent raw-response caching.
	 */
	ValidationResult validateWithOCSP(X509Certificate[] input,
			Set<TrustAnchor> configuredAnchors, OCSPResponder responder,
			int timeout, int cacheTtl, String diskCachePath)
			throws CertificateException
	{
		return validateWithOCSP(input, configuredAnchors, responder, timeout,
				cacheTtl, diskCachePath, false);
	}

	/**
	 * Builds and validates a path using configured transport, cache, and nonce
	 * controls. Nonce-enabled requests bypass response caching.
	 */
	ValidationResult validateWithOCSP(X509Certificate[] input,
			Set<TrustAnchor> configuredAnchors, OCSPResponder responder,
			int timeout, int cacheTtl, String diskCachePath, boolean useNonce)
			throws CertificateException
	{
		if (timeout < 0)
			return invalidInput(input, -1, "OCSP timeout must not be negative");
		if (responder == null)
			return invalidInput(input, -1, "OCSP responder must not be null");
		if (responder.getAddress() == null)
			return invalidInput(input, -1, "OCSP responder address must not be null");
		if (responder.getCertificate() == null)
			return invalidInput(input, -1, "OCSP responder certificate must not be null");
		try
		{
			return validate(input, configuredAnchors, null,
					responder.getAddress().toURI(), responder.getCertificate(), false,
					new OCSPFetchPolicy(timeout, cacheTtl, diskCachePath, useNonce));
		} catch (URISyntaxException e)
		{
			return invalid(input, -1, ValidationErrorCode.INVALID_INPUT,
					ValidationStage.INPUT, e);
		}
	}

	/**
	 * Builds and validates a path using the first responder selected from the
	 * configured and certificate-discovered responder groups.
	 */
	ValidationResult validateWithOCSP(X509Certificate[] input,
			Set<TrustAnchor> configuredAnchors, OCSPResponder[] localResponders,
			boolean preferLocalResponders, int timeout, int cacheTtl,
			String diskCachePath, boolean useNonce) throws CertificateException
	{
		return validateWithOrderedOCSP(input, configuredAnchors, localResponders,
				preferLocalResponders, timeout, cacheTtl, diskCachePath, useNonce,
				false);
	}

	/**
	 * Builds and validates a path using OCSP when a responder is reachable.
	 * Missing responders and exhausted transport failures are accepted, while
	 * every received response remains subject to strict native validation.
	 */
	ValidationResult validateWithOCSPIfAvailable(X509Certificate[] input,
			Set<TrustAnchor> configuredAnchors, OCSPResponder[] localResponders,
			boolean preferLocalResponders, int timeout, int cacheTtl,
			String diskCachePath, boolean useNonce) throws CertificateException
	{
		return validateWithOrderedOCSP(input, configuredAnchors, localResponders,
				preferLocalResponders, timeout, cacheTtl, diskCachePath, useNonce,
				true);
	}

	/**
	 * Builds and validates a path, then applies strict CRL and native OCSP
	 * checking to each certificate in the configured order.
	 */
	ValidationResult validateWithCRLsAndOCSP(X509Certificate[] input,
			Set<TrustAnchor> configuredAnchors, CertStore crlStore,
			OCSPCheckingMode ocspMode, OCSPResponder[] localResponders,
			boolean preferLocalResponders, int timeout, int cacheTtl,
			String diskCachePath, boolean useNonce, boolean useAllEnabled,
			RevocationCheckingOrder order) throws CertificateException
	{
		if (crlStore == null)
			return invalidInput(input, -1, "CRL store must not be null");
		if (ocspMode == null || ocspMode == OCSPCheckingMode.IGNORE)
			return invalidInput(input, -1, "OCSP must be enabled");
		if (order == null)
			return invalidInput(input, -1,
					"Revocation checking order must not be null");
		if (timeout < 0)
			return invalidInput(input, -1, "OCSP timeout must not be negative");
		List<OCSPResponderTarget> configured;
		try
		{
			configured = configuredResponderTargets(localResponders);
		} catch (IllegalArgumentException e)
		{
			return invalid(input, -1, ValidationErrorCode.INVALID_INPUT,
					ValidationStage.INPUT, e);
		}
		OCSPFetchPolicy fetchPolicy = new OCSPFetchPolicy(timeout, cacheTtl,
				diskCachePath, useNonce, configured, preferLocalResponders,
				ocspMode == OCSPCheckingMode.IF_AVAILABLE, order, useAllEnabled);
		return validate(input, configuredAnchors, crlStore, null, null, true,
				fetchPolicy);
	}

	private ValidationResult validateWithOrderedOCSP(X509Certificate[] input,
			Set<TrustAnchor> configuredAnchors, OCSPResponder[] localResponders,
			boolean preferLocalResponders, int timeout, int cacheTtl,
			String diskCachePath, boolean useNonce, boolean softFailUnavailable)
			throws CertificateException
	{
		if (timeout < 0)
			return invalidInput(input, -1, "OCSP timeout must not be negative");
		List<OCSPResponderTarget> configured;
		try
		{
			configured = configuredResponderTargets(localResponders);
		} catch (IllegalArgumentException e)
		{
			return invalid(input, -1, ValidationErrorCode.INVALID_INPUT,
					ValidationStage.INPUT, e);
		}
		return validate(input, configuredAnchors, null, null, null, true,
				new OCSPFetchPolicy(timeout, cacheTtl, diskCachePath, useNonce,
						configured, preferLocalResponders, softFailUnavailable));
	}

	/**
	 * Builds and validates a path, then performs strict native OCSP checking
	 * using the single responder URI discovered on each certificate.
	 */
	ValidationResult validateWithOCSPFromAIA(X509Certificate[] input,
			Set<TrustAnchor> configuredAnchors) throws CertificateException
	{
		return validate(input, configuredAnchors, null, null, null, true, null);
	}

	/**
	 * Builds and validates a path, discovers one responder per certificate,
	 * and fetches responses using the configured per-request timeout.
	 */
	ValidationResult validateWithOCSPFromAIA(X509Certificate[] input,
			Set<TrustAnchor> configuredAnchors, int timeout) throws CertificateException
	{
		return validateWithOCSPFromAIA(input, configuredAnchors, timeout, -1);
	}

	/**
	 * Builds and validates a path using discovered responders, the configured
	 * timeout, and bounded in-memory response caching.
	 */
	ValidationResult validateWithOCSPFromAIA(X509Certificate[] input,
			Set<TrustAnchor> configuredAnchors, int timeout, int cacheTtl)
			throws CertificateException
	{
		return validateWithOCSPFromAIA(input, configuredAnchors, timeout,
				cacheTtl, null);
	}

	/**
	 * Builds and validates a path using discovered responders and optional
	 * memory and persistent raw-response caching.
	 */
	ValidationResult validateWithOCSPFromAIA(X509Certificate[] input,
			Set<TrustAnchor> configuredAnchors, int timeout, int cacheTtl,
			String diskCachePath) throws CertificateException
	{
		return validateWithOCSPFromAIA(input, configuredAnchors, timeout,
				cacheTtl, diskCachePath, false);
	}

	/**
	 * Builds and validates a path using discovered responders and configured
	 * transport, cache, and nonce controls.
	 */
	ValidationResult validateWithOCSPFromAIA(X509Certificate[] input,
			Set<TrustAnchor> configuredAnchors, int timeout, int cacheTtl,
			String diskCachePath, boolean useNonce) throws CertificateException
	{
		if (timeout < 0)
			return invalidInput(input, -1, "OCSP timeout must not be negative");
		return validate(input, configuredAnchors, null, null, null, true,
				new OCSPFetchPolicy(timeout, cacheTtl, diskCachePath, useNonce));
	}

	private ValidationResult validate(X509Certificate[] input,
			Set<TrustAnchor> configuredAnchors, CertStore crlStore,
			URI ocspResponder, X509Certificate ocspResponderCertificate,
			boolean discoverOCSPResponders, OCSPFetchPolicy ocspFetchPolicy)
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
					ocspResponderCertificate, discoverOCSPResponders, ocspFetchPolicy);
		} catch (CertPathBuilderException e)
		{
			List<X509Certificate> asserted = normalize(Arrays.asList(input), anchors);
			if (asserted.isEmpty())
				return invalid(input, -1, ValidationErrorCode.PATH_BUILDING_FAILED,
						ValidationStage.PATH_BUILDING, e);
			if (isCoherent(asserted))
				return validatePath(toCertPath(asserted), anchors, crlStore,
						collectionStore(Arrays.asList(input)), ocspResponder,
						ocspResponderCertificate, discoverOCSPResponders, ocspFetchPolicy);
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
		return validate(suppliedPath, configuredAnchors, null, null, null, false, null);
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
		return validate(suppliedPath, configuredAnchors, crlStore, null, null, false, null);
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
					responder.getAddress().toURI(), responder.getCertificate(), false, null);
		} catch (URISyntaxException e)
		{
			return invalid(null, -1, ValidationErrorCode.INVALID_INPUT,
					ValidationStage.INPUT, e);
		}
	}

	/**
	 * Validates an asserted path after fetching OCSP responses with the
	 * configured per-request timeout.
	 */
	ValidationResult validateWithOCSP(CertPath suppliedPath,
			Set<TrustAnchor> configuredAnchors, OCSPResponder responder,
			int timeout) throws CertificateException
	{
		return validateWithOCSP(suppliedPath, configuredAnchors, responder,
				timeout, -1);
	}

	/**
	 * Validates an asserted path after fetching and caching encoded OCSP
	 * responses with the configured transport and cache controls.
	 */
	ValidationResult validateWithOCSP(CertPath suppliedPath,
			Set<TrustAnchor> configuredAnchors, OCSPResponder responder,
			int timeout, int cacheTtl) throws CertificateException
	{
		return validateWithOCSP(suppliedPath, configuredAnchors, responder,
				timeout, cacheTtl, null);
	}

	/**
	 * Validates an asserted path using configured transport controls and
	 * optional memory and persistent raw-response caching.
	 */
	ValidationResult validateWithOCSP(CertPath suppliedPath,
			Set<TrustAnchor> configuredAnchors, OCSPResponder responder,
			int timeout, int cacheTtl, String diskCachePath)
			throws CertificateException
	{
		return validateWithOCSP(suppliedPath, configuredAnchors, responder,
				timeout, cacheTtl, diskCachePath, false);
	}

	/**
	 * Validates an asserted path using configured transport, cache, and nonce
	 * controls. Nonce-enabled requests bypass response caching.
	 */
	ValidationResult validateWithOCSP(CertPath suppliedPath,
			Set<TrustAnchor> configuredAnchors, OCSPResponder responder,
			int timeout, int cacheTtl, String diskCachePath, boolean useNonce)
			throws CertificateException
	{
		if (timeout < 0)
			return invalidInput(null, -1, "OCSP timeout must not be negative");
		if (responder == null)
			return invalidInput(null, -1, "OCSP responder must not be null");
		if (responder.getAddress() == null)
			return invalidInput(null, -1, "OCSP responder address must not be null");
		if (responder.getCertificate() == null)
			return invalidInput(null, -1, "OCSP responder certificate must not be null");
		try
		{
			return validate(suppliedPath, configuredAnchors, null,
					responder.getAddress().toURI(), responder.getCertificate(), false,
					new OCSPFetchPolicy(timeout, cacheTtl, diskCachePath, useNonce));
		} catch (URISyntaxException e)
		{
			return invalid(null, -1, ValidationErrorCode.INVALID_INPUT,
					ValidationStage.INPUT, e);
		}
	}

	/**
	 * Validates an asserted path using the first responder selected from the
	 * configured and certificate-discovered responder groups.
	 */
	ValidationResult validateWithOCSP(CertPath suppliedPath,
			Set<TrustAnchor> configuredAnchors, OCSPResponder[] localResponders,
			boolean preferLocalResponders, int timeout, int cacheTtl,
			String diskCachePath, boolean useNonce) throws CertificateException
	{
		return validateWithOrderedOCSP(suppliedPath, configuredAnchors,
				localResponders, preferLocalResponders, timeout, cacheTtl,
				diskCachePath, useNonce, false);
	}

	/**
	 * Validates an asserted path using OCSP when a responder is reachable.
	 * Missing responders and exhausted transport failures are accepted, while
	 * every received response remains subject to strict native validation.
	 */
	ValidationResult validateWithOCSPIfAvailable(CertPath suppliedPath,
			Set<TrustAnchor> configuredAnchors, OCSPResponder[] localResponders,
			boolean preferLocalResponders, int timeout, int cacheTtl,
			String diskCachePath, boolean useNonce) throws CertificateException
	{
		return validateWithOrderedOCSP(suppliedPath, configuredAnchors,
				localResponders, preferLocalResponders, timeout, cacheTtl,
				diskCachePath, useNonce, true);
	}

	/**
	 * Validates an asserted path, then applies strict CRL and native OCSP
	 * checking to each certificate in the configured order.
	 */
	ValidationResult validateWithCRLsAndOCSP(CertPath suppliedPath,
			Set<TrustAnchor> configuredAnchors, CertStore crlStore,
			OCSPCheckingMode ocspMode, OCSPResponder[] localResponders,
			boolean preferLocalResponders, int timeout, int cacheTtl,
			String diskCachePath, boolean useNonce, boolean useAllEnabled,
			RevocationCheckingOrder order) throws CertificateException
	{
		if (crlStore == null)
			return invalidInput(null, -1, "CRL store must not be null");
		if (ocspMode == null || ocspMode == OCSPCheckingMode.IGNORE)
			return invalidInput(null, -1, "OCSP must be enabled");
		if (order == null)
			return invalidInput(null, -1,
					"Revocation checking order must not be null");
		if (timeout < 0)
			return invalidInput(null, -1, "OCSP timeout must not be negative");
		List<OCSPResponderTarget> configured;
		try
		{
			configured = configuredResponderTargets(localResponders);
		} catch (IllegalArgumentException e)
		{
			return invalid(null, -1, ValidationErrorCode.INVALID_INPUT,
					ValidationStage.INPUT, e);
		}
		OCSPFetchPolicy fetchPolicy = new OCSPFetchPolicy(timeout, cacheTtl,
				diskCachePath, useNonce, configured, preferLocalResponders,
				ocspMode == OCSPCheckingMode.IF_AVAILABLE, order, useAllEnabled);
		return validate(suppliedPath, configuredAnchors, crlStore, null, null,
				true, fetchPolicy);
	}

	private ValidationResult validateWithOrderedOCSP(CertPath suppliedPath,
			Set<TrustAnchor> configuredAnchors, OCSPResponder[] localResponders,
			boolean preferLocalResponders, int timeout, int cacheTtl,
			String diskCachePath, boolean useNonce, boolean softFailUnavailable)
			throws CertificateException
	{
		if (timeout < 0)
			return invalidInput(null, -1, "OCSP timeout must not be negative");
		List<OCSPResponderTarget> configured;
		try
		{
			configured = configuredResponderTargets(localResponders);
		} catch (IllegalArgumentException e)
		{
			return invalid(null, -1, ValidationErrorCode.INVALID_INPUT,
					ValidationStage.INPUT, e);
		}
		return validate(suppliedPath, configuredAnchors, null, null, null, true,
				new OCSPFetchPolicy(timeout, cacheTtl, diskCachePath, useNonce,
						configured, preferLocalResponders, softFailUnavailable));
	}

	/**
	 * Validates an asserted path with strict native OCSP checking using the
	 * single responder URI discovered on each certificate.
	 */
	ValidationResult validateWithOCSPFromAIA(CertPath suppliedPath,
			Set<TrustAnchor> configuredAnchors) throws CertificateException
	{
		return validate(suppliedPath, configuredAnchors, null, null, null, true, null);
	}

	/**
	 * Validates an asserted path using discovered responders and the configured
	 * per-request timeout.
	 */
	ValidationResult validateWithOCSPFromAIA(CertPath suppliedPath,
			Set<TrustAnchor> configuredAnchors, int timeout) throws CertificateException
	{
		return validateWithOCSPFromAIA(suppliedPath, configuredAnchors, timeout, -1);
	}

	/**
	 * Validates an asserted path using discovered responders and bounded
	 * in-memory response caching.
	 */
	ValidationResult validateWithOCSPFromAIA(CertPath suppliedPath,
			Set<TrustAnchor> configuredAnchors, int timeout, int cacheTtl)
			throws CertificateException
	{
		return validateWithOCSPFromAIA(suppliedPath, configuredAnchors, timeout,
				cacheTtl, null);
	}

	/**
	 * Validates an asserted path using discovered responders and optional
	 * memory and persistent raw-response caching.
	 */
	ValidationResult validateWithOCSPFromAIA(CertPath suppliedPath,
			Set<TrustAnchor> configuredAnchors, int timeout, int cacheTtl,
			String diskCachePath) throws CertificateException
	{
		return validateWithOCSPFromAIA(suppliedPath, configuredAnchors, timeout,
				cacheTtl, diskCachePath, false);
	}

	/**
	 * Validates an asserted path using discovered responders and configured
	 * transport, cache, and nonce controls.
	 */
	ValidationResult validateWithOCSPFromAIA(CertPath suppliedPath,
			Set<TrustAnchor> configuredAnchors, int timeout, int cacheTtl,
			String diskCachePath, boolean useNonce) throws CertificateException
	{
		if (timeout < 0)
			return invalidInput(null, -1, "OCSP timeout must not be negative");
		return validate(suppliedPath, configuredAnchors, null, null, null, true,
				new OCSPFetchPolicy(timeout, cacheTtl, diskCachePath, useNonce));
	}

	private ValidationResult validate(CertPath suppliedPath,
			Set<TrustAnchor> configuredAnchors, CertStore crlStore,
			URI ocspResponder, X509Certificate ocspResponderCertificate,
			boolean discoverOCSPResponders, OCSPFetchPolicy ocspFetchPolicy)
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
				ocspResponderCertificate, discoverOCSPResponders, ocspFetchPolicy);
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
			X509Certificate ocspResponderCertificate, boolean discoverOCSPResponders,
			OCSPFetchPolicy ocspFetchPolicy)
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

		if (crlStore != null && ocspFetchPolicy != null &&
				ocspFetchPolicy.revocationOrder != null)
		{
			ValidationResult revocationResult = validateCombinedRevocation(path,
					result.getTrustAnchor(), crlStore, certificateStore,
					diagnosticChain, ocspFetchPolicy);
			if (revocationResult != null)
				return revocationResult;
		}
		else if (crlStore != null)
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
			if (ocspFetchPolicy != null)
			{
				ValidationResult ocspResult = validateExplicitOCSP(path,
						result.getTrustAnchor(), certificateStore, diagnosticChain,
						ocspResponder, ocspResponderCertificate, ocspFetchPolicy);
				if (ocspResult != null)
					return ocspResult;
				return valid(resolvedChain(path, result.getTrustAnchor()));
			}
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
		else if (discoverOCSPResponders)
		{
			ValidationResult ocspResult = validateDiscoveredOCSP(path,
					result.getTrustAnchor(), certificateStore, diagnosticChain,
					ocspFetchPolicy);
			if (ocspResult != null)
				return ocspResult;
		}
		return valid(resolvedChain(path, result.getTrustAnchor()));
	}

	private ValidationResult validateCombinedRevocation(CertPath path,
			TrustAnchor selectedAnchor, CertStore crlStore,
			CertStore certificateStore, X509Certificate[] diagnosticChain,
			OCSPFetchPolicy fetchPolicy)
	{
		if (fetchPolicy == null || fetchPolicy.revocationOrder == null)
			throw new IllegalStateException(
					"Combined revocation validation requires an ordered policy");
		List<? extends Certificate> certificates = path.getCertificates();
		for (int i=0; i<certificates.size(); i++)
		{
			X509Certificate certificate = (X509Certificate) certificates.get(i);
			X509Certificate issuer = issuer(certificates, selectedAnchor, i);
			if (issuer == null)
				return ocspDiscoveryFailure(diagnosticChain, path, i,
						"Revocation validation requires the issuer trust-anchor certificate",
						null);

			if (fetchPolicy.revocationOrder == RevocationCheckingOrder.CRL_OCSP)
			{
				ValidationResult crlFailure = validateCRLEdge(certificate, issuer,
						crlStore, certificateStore, diagnosticChain, i);
				if (crlFailure != null)
					return crlFailure;
				if (!fetchPolicy.useAllEnabled)
					continue;
				RevocationCheckResult ocsp = validateOrderedOCSPEdge(certificate,
						issuer, path, fetchPolicy, certificateStore,
						diagnosticChain, i);
				if (ocsp.failure != null)
					return ocsp.failure;
			} else
			{
				RevocationCheckResult ocsp = validateOrderedOCSPEdge(certificate,
						issuer, path, fetchPolicy, certificateStore,
						diagnosticChain, i);
				if (ocsp.failure != null)
					return ocsp.failure;
				if (ocsp.verified && !fetchPolicy.useAllEnabled)
					continue;
				ValidationResult crlFailure = validateCRLEdge(certificate, issuer,
						crlStore, certificateStore, diagnosticChain, i);
				if (crlFailure != null)
					return crlFailure;
			}
		}
		return null;
	}

	private ValidationResult validateCRLEdge(X509Certificate certificate,
			X509Certificate issuer, CertStore crlStore, CertStore certificateStore,
			X509Certificate[] diagnosticChain, int position)
	{
		CertPath edgePath = toCertPath(Collections.singletonList(certificate));
		Set<TrustAnchor> edgeAnchor = Collections.singleton(
				new TrustAnchor(issuer, null));
		try
		{
			validateNative(edgePath, edgeAnchor, certificateStore, crlStore);
			return null;
		} catch (CertPathValidatorException e)
		{
			return invalidRevocationValidation(diagnosticChain, e, position);
		} catch (InvalidAlgorithmParameterException e)
		{
			throw new IllegalStateException(
					"Native BC PKIX validator rejected per-certificate CRL parameters", e);
		} catch (RuntimeException e)
		{
			return invalid(diagnosticChain, position, ValidationErrorCode.PKIX_FAILURE,
					ValidationStage.REVOCATION, e);
		}
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
		if (responderCertificate != null)
			checker.setOcspResponderCert(responderCertificate);

		PKIXParameters params = new PKIXParameters(anchors);
		params.setRevocationEnabled(false);
		params.addCertStore(certificateStore);
		params.addCertPathChecker(checker);
		return (PKIXCertPathValidatorResult) validator.validate(path, params);
	}

	private PKIXCertPathValidatorResult validateNativeWithOCSPResponse(CertPath path,
			Set<TrustAnchor> anchors, CertStore certificateStore,
			X509Certificate certificate, byte[] response,
			X509Certificate responderCertificate)
			throws CertPathValidatorException, InvalidAlgorithmParameterException
	{
		CertPathValidator validator = certPathValidator();
		PKIXRevocationChecker checker =
				(PKIXRevocationChecker) validator.getRevocationChecker();
		checker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));
		Map<X509Certificate, byte[]> responses =
				Collections.singletonMap(certificate, response);
		checker.setOcspResponses(responses);
		if (responderCertificate != null)
			checker.setOcspResponderCert(responderCertificate);

		PKIXParameters params = new PKIXParameters(anchors);
		params.setRevocationEnabled(false);
		params.addCertStore(certificateStore);
		params.addCertPathChecker(checker);
		return (PKIXCertPathValidatorResult) validator.validate(path, params);
	}

	private ValidationResult validateExplicitOCSP(CertPath path,
			TrustAnchor selectedAnchor, CertStore certificateStore,
			X509Certificate[] diagnosticChain, URI responder,
			X509Certificate responderCertificate, OCSPFetchPolicy fetchPolicy)
	{
		List<? extends Certificate> certificates = path.getCertificates();
		for (int i=0; i<certificates.size(); i++)
		{
			X509Certificate certificate = (X509Certificate) certificates.get(i);
			X509Certificate issuer = issuer(certificates, selectedAnchor, i);
			if (issuer == null)
				return ocspDiscoveryFailure(diagnosticChain, path, i,
						"OCSP validation requires the issuer trust-anchor certificate", null);
			OCSPResponderAttempt attempt = validateFetchedOCSPEdge(certificate, issuer,
					responder, responderCertificate, fetchPolicy, certificateStore,
					diagnosticChain, i);
			if (attempt.failure != null)
				return attempt.failure;
		}
		return null;
	}

	/**
	 * BC exposes only one responder URI per checker. Validate one already
	 * base-validated certificate/issuer edge at a time so each certificate can
	 * select its own ordered configured/AIA responder without changing global
	 * security properties. A non-null return value is the first strict OCSP
	 * failure.
	 */
	private ValidationResult validateDiscoveredOCSP(CertPath path,
			TrustAnchor selectedAnchor, CertStore certificateStore,
			X509Certificate[] diagnosticChain, OCSPFetchPolicy fetchPolicy)
	{
		List<? extends Certificate> certificates = path.getCertificates();
		for (int i=0; i<certificates.size(); i++)
		{
			X509Certificate certificate = (X509Certificate) certificates.get(i);
			X509Certificate issuer = issuer(certificates, selectedAnchor, i);
			if (issuer == null)
				return ocspDiscoveryFailure(diagnosticChain, path, i,
						"OCSP validation requires the issuer trust-anchor certificate", null);

			if (fetchPolicy != null)
			{
				RevocationCheckResult checked = validateOrderedOCSPEdge(certificate, issuer,
						path, fetchPolicy, certificateStore, diagnosticChain, i);
				if (checked.failure != null)
					return checked.failure;
				continue;
			}

			List<URI> responders;
			try
			{
				responders = OCSPResponderDiscovery.getResponderURIs(certificate);
			} catch (CertificateException e)
			{
				return ocspDiscoveryFailure(diagnosticChain, path, i,
						"Can not discover an OCSP responder", e);
			}
			if (responders.size() != 1)
				return ocspDiscoveryFailure(diagnosticChain, path, i,
						"Strict native OCSP requires exactly one discovered responder", null);
			CertPath edgePath = toCertPath(Collections.singletonList(certificate));
			Set<TrustAnchor> edgeAnchor = Collections.singleton(
					new TrustAnchor(issuer, null));
			try
			{
				validateNativeWithOCSP(edgePath, edgeAnchor, certificateStore,
						responders.get(0), null);
			} catch (CertPathValidatorException e)
			{
				return invalidRevocationValidation(diagnosticChain, e, i);
			} catch (InvalidAlgorithmParameterException e)
			{
				throw new IllegalStateException(
						"Native BC PKIX validator rejected discovered OCSP parameters", e);
			} catch (RuntimeException e)
			{
				return invalid(diagnosticChain, i, ValidationErrorCode.PKIX_FAILURE,
						ValidationStage.REVOCATION, e);
			}
		}
		return null;
	}

	private RevocationCheckResult validateOrderedOCSPEdge(X509Certificate certificate,
			X509Certificate issuer, CertPath path, OCSPFetchPolicy fetchPolicy,
			CertStore certificateStore, X509Certificate[] diagnosticChain,
			int position)
	{
		List<OCSPResponderTarget> first;
		List<OCSPResponderTarget> second;
		if (fetchPolicy.preferLocalResponders)
		{
			first = fetchPolicy.localResponders;
			second = null;
		} else
		{
			try
			{
				first = discoveredResponderTargets(certificate);
			} catch (CertificateException e)
			{
				return RevocationCheckResult.failure(ocspDiscoveryFailure(
						diagnosticChain, path, position,
						"Can not discover an OCSP responder", e));
			}
			second = fetchPolicy.localResponders;
		}

		OCSPResponderGroupResult firstResult = validateResponderGroup(first,
				certificate, issuer, fetchPolicy, certificateStore, diagnosticChain,
				position);
		if (firstResult.success)
			return RevocationCheckResult.verified();
		if (firstResult.terminalFailure)
			return RevocationCheckResult.failure(firstResult.failure);

		if (second == null)
			try
			{
				second = discoveredResponderTargets(certificate);
			} catch (CertificateException e)
			{
				return RevocationCheckResult.failure(ocspDiscoveryFailure(
						diagnosticChain, path, position,
						"Can not discover an OCSP responder", e));
			}
		OCSPResponderGroupResult secondResult = validateResponderGroup(second,
				certificate, issuer, fetchPolicy, certificateStore, diagnosticChain,
				position);
		if (secondResult.success)
			return RevocationCheckResult.verified();
		if (secondResult.terminalFailure)
			return RevocationCheckResult.failure(secondResult.failure);
		if (fetchPolicy.softFailUnavailable)
			return RevocationCheckResult.unavailable();
		if (secondResult.failure != null)
			return RevocationCheckResult.failure(secondResult.failure);
		if (firstResult.failure != null)
			return RevocationCheckResult.failure(firstResult.failure);
		return RevocationCheckResult.failure(ocspDiscoveryFailure(diagnosticChain,
				path, position,
				"Strict native OCSP requires at least one responder", null));
	}

	private List<OCSPResponderTarget> discoveredResponderTargets(
			X509Certificate certificate) throws CertificateException
	{
		List<URI> discovered = OCSPResponderDiscovery.getResponderURIs(certificate);
		List<OCSPResponderTarget> result =
				new ArrayList<OCSPResponderTarget>(discovered.size());
		for (URI responder: discovered)
			result.add(new OCSPResponderTarget(responder, null));
		return result;
	}

	private OCSPResponderGroupResult validateResponderGroup(
			List<OCSPResponderTarget> responders, X509Certificate certificate,
			X509Certificate issuer, OCSPFetchPolicy fetchPolicy,
			CertStore certificateStore, X509Certificate[] diagnosticChain,
			int position)
	{
		ValidationResult lastTransportFailure = null;
		for (OCSPResponderTarget responder: responders)
		{
			OCSPResponderAttempt attempt = validateFetchedOCSPEdge(certificate, issuer,
					responder.responder, responder.certificate, fetchPolicy,
					certificateStore, diagnosticChain, position);
			if (attempt.failure == null)
				return OCSPResponderGroupResult.success();
			if (!attempt.retryableTransportFailure)
				return OCSPResponderGroupResult.terminal(attempt.failure);
			lastTransportFailure = attempt.failure;
		}
		return OCSPResponderGroupResult.retryable(lastTransportFailure);
	}

	private OCSPResponderAttempt validateFetchedOCSPEdge(X509Certificate certificate,
			X509Certificate issuer, URI responder,
			X509Certificate responderCertificate, OCSPFetchPolicy fetchPolicy,
			CertStore certificateStore, X509Certificate[] diagnosticChain,
			int position)
	{
		CertPath edgePath = toCertPath(Collections.singletonList(certificate));
		Set<TrustAnchor> edgeAnchor = Collections.singleton(
				new TrustAnchor(issuer, null));
		OCSPCacheKey cacheKey = new OCSPCacheKey(responder, certificate, issuer,
				responderCertificate);
		byte[] cachedResponse = fetchPolicy.useNonce ? null :
				ocspResponseCache.get(cacheKey, fetchPolicy.cacheTtl,
						fetchPolicy.diskCache, cacheKey.diskKey);
		if (cachedResponse != null)
		{
			try
			{
				validateNativeWithOCSPResponse(edgePath, edgeAnchor, certificateStore,
						certificate, cachedResponse, responderCertificate);
				return OCSPResponderAttempt.success();
			} catch (CertPathValidatorException e)
			{
				ocspResponseCache.remove(cacheKey, fetchPolicy.diskCache,
						cacheKey.diskKey);
			} catch (InvalidAlgorithmParameterException e)
			{
				throw new IllegalStateException(
						"Native BC PKIX validator rejected cached OCSP parameters", e);
			} catch (RuntimeException e)
			{
				ocspResponseCache.remove(cacheKey, fetchPolicy.diskCache,
						cacheKey.diskKey);
			}
		}
		if (ocspResponderFailureCache.contains(responder, fetchPolicy.cacheTtl,
				fetchPolicy.diskCache))
		{
			IOException failure = new IOException(
					"OCSP responder has a cached transport failure: " + responder);
			return notifiedOCSPFailure(responder, invalid(diagnosticChain, position,
					ValidationErrorCode.PKIX_FAILURE, ValidationStage.REVOCATION,
					failure), true);
		}
		OCSPClientImpl client = new OCSPClientImpl();
		OCSPReq request;
		try
		{
			request = client.createRequest(certificate, issuer, null,
					fetchPolicy.useNonce);
		} catch (OCSPException e)
		{
			return notifiedOCSPFailure(responder, invalid(diagnosticChain, position,
					ValidationErrorCode.PKIX_FAILURE, ValidationStage.REVOCATION, e), false);
		} catch (RuntimeException e)
		{
			return notifiedOCSPFailure(responder, invalid(diagnosticChain, position,
					ValidationErrorCode.PKIX_FAILURE, ValidationStage.REVOCATION, e), false);
		}

		OCSPResponseStructure fetched;
		try
		{
			fetched = client.send(responder.toURL(), request,
					fetchPolicy.timeout);
		} catch (OCSPResponseDecodingException e)
		{
			ocspResponderFailureCache.remove(responder, fetchPolicy.diskCache);
			return notifiedOCSPFailure(responder, invalid(diagnosticChain, position,
					ValidationErrorCode.PKIX_FAILURE, ValidationStage.REVOCATION, e), false);
		} catch (IOException e)
		{
			if (isResponderWideTransportFailure(e))
				ocspResponderFailureCache.put(responder, fetchPolicy.cacheTtl,
						fetchPolicy.diskCache);
			else
				ocspResponderFailureCache.remove(responder, fetchPolicy.diskCache);
			return notifiedOCSPFailure(responder, invalid(diagnosticChain, position,
					ValidationErrorCode.PKIX_FAILURE, ValidationStage.REVOCATION, e), true);
		} catch (RuntimeException e)
		{
			return notifiedOCSPFailure(responder, invalid(diagnosticChain, position,
					ValidationErrorCode.PKIX_FAILURE, ValidationStage.REVOCATION, e), false);
		}
		ocspResponderFailureCache.remove(responder, fetchPolicy.diskCache);

		try
		{
			if (fetchPolicy.useNonce)
				validateResponseNonce(request, fetched.getResponse());
			byte[] response = fetched.getResponse().getEncoded();
			validateNativeWithOCSPResponse(edgePath, edgeAnchor, certificateStore,
					certificate, response, responderCertificate);
			if (!fetchPolicy.useNonce)
				ocspResponseCache.put(cacheKey, response, responseExpiry(fetched),
						fetchPolicy.cacheTtl, fetchPolicy.diskCache, cacheKey.diskKey);
			return OCSPResponderAttempt.success();
		} catch (CertPathValidatorException e)
		{
			return OCSPResponderAttempt.failure(
					invalidRevocationValidation(diagnosticChain, e, position), false);
		} catch (InvalidAlgorithmParameterException e)
		{
			throw new IllegalStateException(
					"Native BC PKIX validator rejected prefetched OCSP parameters", e);
		} catch (IOException e)
		{
			return notifiedOCSPFailure(responder, invalid(diagnosticChain, position,
					ValidationErrorCode.PKIX_FAILURE, ValidationStage.REVOCATION, e), false);
		} catch (OCSPException e)
		{
			return notifiedOCSPFailure(responder, invalid(diagnosticChain, position,
					ValidationErrorCode.PKIX_FAILURE, ValidationStage.REVOCATION, e), false);
		} catch (RuntimeException e)
		{
			return OCSPResponderAttempt.failure(invalid(diagnosticChain, position,
					ValidationErrorCode.PKIX_FAILURE, ValidationStage.REVOCATION, e), false);
		}
	}

	private boolean isResponderWideTransportFailure(IOException failure)
	{
		if (!(failure instanceof OCSPHTTPException))
			return true;
		int status = ((OCSPHTTPException) failure).getStatusCode();
		return status == HttpURLConnection.HTTP_BAD_GATEWAY ||
				status == HttpURLConnection.HTTP_UNAVAILABLE ||
				status == HttpURLConnection.HTTP_GATEWAY_TIMEOUT;
	}

	private OCSPResponderAttempt notifiedOCSPFailure(URI responder,
			ValidationResult failure, boolean retryableTransportFailure)
	{
		Throwable cause = failure.getPrimaryError().getCause();
		Exception notificationCause = cause instanceof Exception ?
				(Exception) cause : new Exception(
						failure.getPrimaryError().getProviderMessage(), cause);
		observers.notifyObservers(responder.toString(), StoreUpdateListener.OCSP,
				Severity.WARNING, notificationCause);
		return OCSPResponderAttempt.failure(failure, retryableTransportFailure);
	}

	private void validateResponseNonce(OCSPReq request, OCSPResp response)
			throws OCSPException
	{
		Extension requested = request.getExtension(
				OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
		if (requested == null)
			throw new IllegalStateException("Nonce-enabled OCSP request has no nonce");
		Object responseBody = response.getResponseObject();
		if (!(responseBody instanceof BasicOCSPResp))
			throw new OCSPException("Nonce-enabled OCSP response has no basic response");
		Extension received = ((BasicOCSPResp) responseBody).getExtension(
				OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
		if (received == null)
			throw new OCSPException("Nonce-enabled OCSP response has no nonce");
		byte[] requestedValue = requested.getExtnValue().getOctets();
		byte[] receivedValue = received.getExtnValue().getOctets();
		if (!MessageDigest.isEqual(requestedValue, receivedValue))
			throw new OCSPException("OCSP response nonce does not match the request");
	}

	private Date responseExpiry(OCSPResponseStructure response)
	{
		Date result = response.getMaxCache();
		try
		{
			Object body = response.getResponse().getResponseObject();
			if (!(body instanceof BasicOCSPResp))
				return result;
			for (SingleResp single: ((BasicOCSPResp) body).getResponses())
			{
				Date nextUpdate = single.getNextUpdate();
				if (nextUpdate != null &&
						(result == null || nextUpdate.before(result)))
					result = nextUpdate;
			}
		} catch (OCSPException e)
		{
			// Native validation has already accepted the response. If metadata
			// can not be extracted, the configured TTL remains authoritative.
		}
		return result;
	}

	private X509Certificate issuer(List<? extends Certificate> certificates,
			TrustAnchor selectedAnchor, int position)
	{
		return position+1 < certificates.size() ?
				(X509Certificate) certificates.get(position+1) :
				selectedAnchor.getTrustedCert();
	}

	private List<OCSPResponderTarget> configuredResponderTargets(
			OCSPResponder[] responders)
	{
		if (responders == null)
			throw new IllegalArgumentException(
					"Configured OCSP responder array must not be null");
		List<OCSPResponderTarget> result =
				new ArrayList<OCSPResponderTarget>(responders.length);
		for (OCSPResponder responder: responders)
		{
			if (responder == null)
				throw new IllegalArgumentException(
						"Configured OCSP responder must not be null");
			if (responder.getAddress() == null)
				throw new IllegalArgumentException(
						"Configured OCSP responder address must not be null");
			if (responder.getCertificate() == null)
				throw new IllegalArgumentException(
						"Configured OCSP responder certificate must not be null");
			String protocol = responder.getAddress().getProtocol();
			if (!"http".equalsIgnoreCase(protocol) &&
					!"https".equalsIgnoreCase(protocol))
				throw new IllegalArgumentException(
						"Configured OCSP responder must use HTTP or HTTPS");
			try
			{
				result.add(new OCSPResponderTarget(responder.getAddress().toURI(),
						responder.getCertificate()));
			} catch (URISyntaxException e)
			{
				throw new IllegalArgumentException(
						"Configured OCSP responder address is not a valid URI", e);
			}
		}
		return result;
	}

	private static final class OCSPFetchPolicy
	{
		private final int timeout;
		private final int cacheTtl;
		private final File diskCache;
		private final boolean useNonce;
		private final List<OCSPResponderTarget> localResponders;
		private final boolean preferLocalResponders;
		private final boolean softFailUnavailable;
		private final RevocationCheckingOrder revocationOrder;
		private final boolean useAllEnabled;

		private OCSPFetchPolicy(int timeout, int cacheTtl, String diskCachePath,
				boolean useNonce)
		{
			this(timeout, cacheTtl, diskCachePath, useNonce,
					Collections.<OCSPResponderTarget>emptyList(), true, false,
					null, false);
		}

		private OCSPFetchPolicy(int timeout, int cacheTtl, String diskCachePath,
				boolean useNonce, List<OCSPResponderTarget> localResponders,
				boolean preferLocalResponders, boolean softFailUnavailable)
		{
			this(timeout, cacheTtl, diskCachePath, useNonce, localResponders,
					preferLocalResponders, softFailUnavailable, null, false);
		}

		private OCSPFetchPolicy(int timeout, int cacheTtl, String diskCachePath,
				boolean useNonce, List<OCSPResponderTarget> localResponders,
				boolean preferLocalResponders, boolean softFailUnavailable,
				RevocationCheckingOrder revocationOrder, boolean useAllEnabled)
		{
			this.timeout = timeout;
			this.cacheTtl = cacheTtl;
			this.diskCache = diskCachePath == null || diskCachePath.trim().isEmpty() ?
					null : new File(diskCachePath);
			this.useNonce = useNonce;
			this.localResponders = Collections.unmodifiableList(
					new ArrayList<OCSPResponderTarget>(localResponders));
			this.preferLocalResponders = preferLocalResponders;
			this.softFailUnavailable = softFailUnavailable;
			this.revocationOrder = revocationOrder;
			this.useAllEnabled = useAllEnabled;
		}
	}

	private static final class OCSPResponderTarget
	{
		private final URI responder;
		private final X509Certificate certificate;

		private OCSPResponderTarget(URI responder, X509Certificate certificate)
		{
			this.responder = responder;
			this.certificate = certificate;
		}
	}

	private static final class OCSPResponderAttempt
	{
		private final ValidationResult failure;
		private final boolean retryableTransportFailure;

		private OCSPResponderAttempt(ValidationResult failure,
				boolean retryableTransportFailure)
		{
			this.failure = failure;
			this.retryableTransportFailure = retryableTransportFailure;
		}

		private static OCSPResponderAttempt success()
		{
			return new OCSPResponderAttempt(null, false);
		}

		private static OCSPResponderAttempt failure(ValidationResult failure,
				boolean retryableTransportFailure)
		{
			return new OCSPResponderAttempt(failure, retryableTransportFailure);
		}
	}

	private static final class RevocationCheckResult
	{
		private final boolean verified;
		private final ValidationResult failure;

		private RevocationCheckResult(boolean verified, ValidationResult failure)
		{
			this.verified = verified;
			this.failure = failure;
		}

		private static RevocationCheckResult verified()
		{
			return new RevocationCheckResult(true, null);
		}

		private static RevocationCheckResult unavailable()
		{
			return new RevocationCheckResult(false, null);
		}

		private static RevocationCheckResult failure(ValidationResult failure)
		{
			return new RevocationCheckResult(false, failure);
		}
	}

	private static final class OCSPResponderGroupResult
	{
		private final boolean success;
		private final boolean terminalFailure;
		private final ValidationResult failure;

		private OCSPResponderGroupResult(boolean success, boolean terminalFailure,
				ValidationResult failure)
		{
			this.success = success;
			this.terminalFailure = terminalFailure;
			this.failure = failure;
		}

		private static OCSPResponderGroupResult success()
		{
			return new OCSPResponderGroupResult(true, false, null);
		}

		private static OCSPResponderGroupResult terminal(ValidationResult failure)
		{
			return new OCSPResponderGroupResult(false, true, failure);
		}

		private static OCSPResponderGroupResult retryable(ValidationResult failure)
		{
			return new OCSPResponderGroupResult(false, false, failure);
		}
	}

	private static final class OCSPCacheKey
	{
		private final URI responder;
		private final X509Certificate certificate;
		private final X509Certificate issuer;
		private final X509Certificate responderCertificate;
		private final String diskKey;

		private OCSPCacheKey(URI responder, X509Certificate certificate,
				X509Certificate issuer, X509Certificate responderCertificate)
		{
			this.responder = responder;
			this.certificate = certificate;
			this.issuer = issuer;
			this.responderCertificate = responderCertificate;
			this.diskKey = createDiskKey();
		}

		@Override
		public boolean equals(Object other)
		{
			if (this == other)
				return true;
			if (!(other instanceof OCSPCacheKey))
				return false;
			OCSPCacheKey that = (OCSPCacheKey) other;
			return responder.equals(that.responder) &&
					certificate.equals(that.certificate) &&
					issuer.equals(that.issuer) &&
					Objects.equals(responderCertificate, that.responderCertificate);
		}

		@Override
		public int hashCode()
		{
			return Objects.hash(responder, certificate, issuer, responderCertificate);
		}

		private String createDiskKey()
		{
			try
			{
				MessageDigest digest = MessageDigest.getInstance("SHA-256");
				updateDigest(digest, responder.toASCIIString().getBytes(
						StandardCharsets.UTF_8));
				updateDigest(digest, certificate.getEncoded());
				updateDigest(digest, issuer.getEncoded());
				updateDigest(digest, responderCertificate == null ? null :
						responderCertificate.getEncoded());
				return toHex(digest.digest());
			} catch (NoSuchAlgorithmException e)
			{
				throw new IllegalStateException("SHA-256 digest is unavailable", e);
			} catch (CertificateEncodingException e)
			{
				return null;
			}
		}

		private void updateDigest(MessageDigest digest, byte[] value)
		{
			int length = value == null ? -1 : value.length;
			digest.update((byte) (length >>> 24));
			digest.update((byte) (length >>> 16));
			digest.update((byte) (length >>> 8));
			digest.update((byte) length);
			if (value != null)
				digest.update(value);
		}

		private String toHex(byte[] value)
		{
			char[] result = new char[value.length * 2];
			char[] digits = "0123456789abcdef".toCharArray();
			for (int i=0; i<value.length; i++)
			{
				int unsigned = value[i] & 0xff;
				result[i*2] = digits[unsigned >>> 4];
				result[i*2+1] = digits[unsigned & 0x0f];
			}
			return new String(result);
		}
	}

	private ValidationResult ocspDiscoveryFailure(X509Certificate[] chain,
			CertPath path, int position, String message, Throwable cause)
	{
		CertPathValidatorException failure = new CertPathValidatorException(
				message, cause, path, position);
		return invalidRevocationValidation(chain, failure, position);
	}

	private ValidationResult invalidValidation(X509Certificate[] chain,
			CertPathValidatorException failure, ValidationStage failureStage)
	{
		int position = failure.getIndex();
		if (position < 0 || chain == null || position >= chain.length)
			position = -1;

		CertPathValidatorException.Reason reason = failure.getReason();
		if (failureStage == ValidationStage.REVOCATION)
			return invalidRevocationValidation(chain, failure, position);
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

	private ValidationResult invalidRevocationValidation(X509Certificate[] chain,
			CertPathValidatorException failure, int position)
	{
		CertPathValidatorException.Reason reason = failure.getReason();
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

	private CertPath toCertPath(List<X509Certificate> certificates)
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
