/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.ValidationErrorListener;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.ValidationStage;
import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509CertChainValidatorExt;
import eu.emi.security.authn.x509.helpers.ObserversHandler;
import eu.emi.security.authn.x509.helpers.crl.AbstractCRLStoreSPI;
import eu.emi.security.authn.x509.helpers.crl.SimpleCRLStore;
import eu.emi.security.authn.x509.helpers.trust.TrustAnchorStore;
import eu.emi.security.authn.x509.impl.CertificateUtils;

/**
 * Base implementation of {@link X509CertChainValidator}.
 * It is configured with {@link CertStore} providing CRLs and {@link TrustAnchorStore}
 * providing trusted CAs. Certificate paths and revocation data are validated
 * by the native Bouncy Castle PKIX implementation.
 * <p>
 * This class is thread safe and its extensions should also guarantee this.
 * 
 * @author K. Benedyczak
 */
public abstract class AbstractValidator implements X509CertChainValidatorExt
{
	static 
	{
		CertificateUtils.configureSecProvider();
	}

	protected Set<ValidationErrorListener> listeners;
	protected final ObserversHandler observers;
	private TrustAnchorStore caStore;
	private AbstractCRLStoreSPI crlStore;
	private NativeBCPKIXValidator nativeValidator;
	private RevocationParameters revocationMode;
	protected boolean disposed;
	
	/**
	 * Default constructor is available, the subclass must initialize the parent 
	 * with the init() method. Note that it is strongly suggested to call the init() method
	 * from the child class constructor. 
	 * <p>
	 * This is not a cleanest design possible but it is required as arguments to the init()
	 * method require some code to be created in subclasses. Therefore we have a trade off:
	 * a bit unclean design inside the library and a clean external API without factory methods.
	 * @param initialListeners initial listeners
	 */
	public AbstractValidator(Collection<? extends StoreUpdateListener> initialListeners)
	{
		observers = new ObserversHandler(initialListeners);
		listeners = new LinkedHashSet<ValidationErrorListener>();
	}

	/**
	 * Use this method to initialize the parent from the extension class, if not using
	 * the non-default constructor.
	 * @param caStore CA store
	 * @param crlStore CRL store
	 * @param revocationCheckingMode revocation checking mode
	 */
	protected synchronized void init(TrustAnchorStore caStore, AbstractCRLStoreSPI crlStore, 
			RevocationParameters revocationCheckingMode)
	{
		disposed = false;
		if (caStore != null)
			this.caStore = caStore;
		if (crlStore != null)
			this.crlStore = crlStore;
		this.nativeValidator = new NativeBCPKIXValidator(observers);
		this.revocationMode = revocationCheckingMode;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public ValidationResult validate(CertPath certPath)
	{
		if (isDisposed())
			throw new IllegalStateException("The validator instance was disposed");
		if (certPath == null)
			return processInputError(null,
					new IllegalArgumentException("Certificate path must not be null"));
		List<? extends Certificate> certs = certPath.getCertificates();
		X509Certificate[] certsA = new X509Certificate[certs.size()];
		for (int i=0; i<certsA.length; i++)
		{
			Certificate c = certs.get(i);
			if (!(c instanceof X509Certificate))
				return processInputError(certsA, new IllegalArgumentException("Can validate only " +
						"X509Certificate chains. Found instance of: " + 
						c.getClass().getName()));
			certsA[i] = (X509Certificate) c;
		}
		Set<TrustAnchor> anchors = getTrustAnchors(certsA);
		ValidationResult configurationFailure = validateConfiguration(certsA);
		if (configurationFailure != null)
			return processResult(configurationFailure);
		try
		{
			ValidationResult result;
			if (isBaseValidation())
				result = nativeValidator.validate(certPath, anchors);
			else if (isCRLValidation())
				result = validateNativeCRL(certPath, anchors);
			else if (isOCSPValidation())
				result = validateNativeOCSP(certPath, anchors);
			else
				result = validateNativeRevocation(certPath, anchors);
			return processResult(result);
		} catch (CertificateException e)
		{
			return processInputError(certsA, e);
		}
	}

	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public ValidationResult validate(X509Certificate[] certChain)
	{
		return validate(certChain, getTrustAnchors(certChain));
	}

	protected Set<TrustAnchor> getTrustAnchors(X509Certificate[] certChain)
	{
		return caStore.getTrustAnchors();
	}

	protected ValidationResult validate(X509Certificate[] certChain, Set<TrustAnchor> anchors)
	{
		if (isDisposed())
			throw new IllegalStateException("The validator instance was disposed");
		ValidationResult configurationFailure = validateConfiguration(certChain);
		if (configurationFailure != null)
			return processResult(configurationFailure);
		ValidationResult result;
		try
		{
			if (isBaseValidation())
				result = nativeValidator.validate(certChain, anchors);
			else if (isCRLValidation())
				result = validateNativeCRL(certChain, anchors);
			else if (isOCSPValidation())
				result = validateNativeOCSP(certChain, anchors);
			else
				result = validateNativeRevocation(certChain, anchors);
		} catch (CertificateException e)
		{
			return processInputError(certChain, e);
		}
		return processResult(result);
	}

	private ValidationResult validateConfiguration(X509Certificate[] certChain)
	{
		if (revocationMode == null)
			return inputFailure(certChain,
					"Revocation parameters must not be null");
		if (revocationMode.getCrlCheckingMode() == null)
			return inputFailure(certChain,
					"CRL checking mode must not be null");
		if (revocationMode.getOcspParameters() == null)
			return inputFailure(certChain,
					"OCSP parameters must not be null");
		if (revocationMode.getOcspParameters().getCheckingMode() == null)
			return inputFailure(certChain,
					"OCSP checking mode must not be null");
		return null;
	}

	private ValidationResult inputFailure(X509Certificate[] certChain,
			String message)
	{
		IllegalArgumentException failure = new IllegalArgumentException(message);
		return ValidationResult.invalid(new ValidationError(certChain, -1,
				ValidationErrorCode.INVALID_INPUT, ValidationStage.INPUT,
				message, failure));
	}

	private boolean isBaseValidation()
	{
		return revocationMode.getCrlCheckingMode() == CrlCheckingMode.IGNORE &&
				revocationMode.getOcspParameters().getCheckingMode() ==
					OCSPCheckingMode.IGNORE;
	}

	private boolean isCRLValidation()
	{
		return revocationMode.getCrlCheckingMode() != CrlCheckingMode.IGNORE &&
				revocationMode.getOcspParameters().getCheckingMode() ==
					OCSPCheckingMode.IGNORE;
	}

	private boolean isOCSPValidation()
	{
		return revocationMode.getCrlCheckingMode() == CrlCheckingMode.IGNORE &&
				revocationMode.getOcspParameters().getCheckingMode() !=
					OCSPCheckingMode.IGNORE;
	}

	private ValidationResult validateNativeOCSP(X509Certificate[] certificates,
			Set<TrustAnchor> anchors) throws CertificateException
	{
		OCSPParametes parameters = revocationMode.getOcspParameters();
		if (parameters.getCheckingMode() == OCSPCheckingMode.IF_AVAILABLE)
			return nativeValidator.validateWithOCSPIfAvailable(certificates, anchors,
					parameters.getLocalResponders(),
					parameters.isPreferLocalResponders(), getOCSPTimeout(),
					getOCSPCacheTtl(), getOCSPDiskCachePath(), usesOCSPNonce());
		return nativeValidator.validateWithOCSP(certificates, anchors,
				parameters.getLocalResponders(), parameters.isPreferLocalResponders(),
				getOCSPTimeout(), getOCSPCacheTtl(), getOCSPDiskCachePath(),
				usesOCSPNonce());
	}

	@SuppressWarnings("deprecation")
	private boolean usesCRLIfPresent()
	{
		CrlCheckingMode mode = revocationMode.getCrlCheckingMode();
		return mode == CrlCheckingMode.IF_PRESENT ||
				mode == CrlCheckingMode.IF_VALID;
	}

	private ValidationResult validateNativeCRL(X509Certificate[] certificates,
			Set<TrustAnchor> anchors) throws CertificateException
	{
		SimpleCRLStore store = new SimpleCRLStore(crlStore);
		return usesCRLIfPresent() ?
				nativeValidator.validateWithCRLsIfPresent(certificates, anchors, store) :
				nativeValidator.validateWithCRLs(certificates, anchors, store);
	}

	private ValidationResult validateNativeCRL(CertPath path,
			Set<TrustAnchor> anchors) throws CertificateException
	{
		SimpleCRLStore store = new SimpleCRLStore(crlStore);
		return usesCRLIfPresent() ?
				nativeValidator.validateWithCRLsIfPresent(path, anchors, store) :
				nativeValidator.validateWithCRLs(path, anchors, store);
	}

	private ValidationResult validateNativeOCSP(CertPath path,
			Set<TrustAnchor> anchors) throws CertificateException
	{
		OCSPParametes parameters = revocationMode.getOcspParameters();
		if (parameters.getCheckingMode() == OCSPCheckingMode.IF_AVAILABLE)
			return nativeValidator.validateWithOCSPIfAvailable(path, anchors,
					parameters.getLocalResponders(),
					parameters.isPreferLocalResponders(), getOCSPTimeout(),
					getOCSPCacheTtl(), getOCSPDiskCachePath(), usesOCSPNonce());
		return nativeValidator.validateWithOCSP(path, anchors,
				parameters.getLocalResponders(), parameters.isPreferLocalResponders(),
				getOCSPTimeout(), getOCSPCacheTtl(), getOCSPDiskCachePath(),
				usesOCSPNonce());
	}

	private ValidationResult validateNativeRevocation(X509Certificate[] certificates,
			Set<TrustAnchor> anchors) throws CertificateException
	{
		OCSPParametes parameters = revocationMode.getOcspParameters();
		return nativeValidator.validateWithCRLsAndOCSP(certificates, anchors,
				new SimpleCRLStore(crlStore), revocationMode.getCrlCheckingMode(),
				parameters.getCheckingMode(),
				parameters.getLocalResponders(), parameters.isPreferLocalResponders(),
				getOCSPTimeout(), getOCSPCacheTtl(), getOCSPDiskCachePath(),
				usesOCSPNonce(), revocationMode.isUseAllEnabled(),
				revocationMode.getOrder());
	}

	private ValidationResult validateNativeRevocation(CertPath path,
			Set<TrustAnchor> anchors) throws CertificateException
	{
		OCSPParametes parameters = revocationMode.getOcspParameters();
		return nativeValidator.validateWithCRLsAndOCSP(path, anchors,
				new SimpleCRLStore(crlStore), revocationMode.getCrlCheckingMode(),
				parameters.getCheckingMode(),
				parameters.getLocalResponders(), parameters.isPreferLocalResponders(),
				getOCSPTimeout(), getOCSPCacheTtl(), getOCSPDiskCachePath(),
				usesOCSPNonce(), revocationMode.isUseAllEnabled(),
				revocationMode.getOrder());
	}

	private int getOCSPTimeout()
	{
		return revocationMode.getOcspParameters().getConntectTimeout();
	}

	private int getOCSPCacheTtl()
	{
		return revocationMode.getOcspParameters().getCacheTtl();
	}

	private String getOCSPDiskCachePath()
	{
		return revocationMode.getOcspParameters().getDiskCachePath();
	}

	private boolean usesOCSPNonce()
	{
		return revocationMode.getOcspParameters().isUseNonce();
	}

	private ValidationResult processInputError(X509Certificate[] certChain, Throwable failure)
	{
		ValidationError error = new ValidationError(certChain, -1,
				ValidationErrorCode.INVALID_INPUT, ValidationStage.INPUT,
				failure.getMessage(), failure);
		return processResult(ValidationResult.invalid(error));
	}

	private ValidationResult processResult(ValidationResult result)
	{
		if (!result.isValid())
			notifyListeners(result.getPrimaryError());
		return result;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public synchronized X509Certificate[] getTrustedIssuers()
	{
		return caStore.getTrustedCertificates();
	}
	

	/**
	 * Notifies all registered listeners.
	 * @param error validation error
	 */
	protected void notifyListeners(ValidationError error)
	{
		synchronized (listeners)
		{
			for (ValidationErrorListener listener: listeners)
				listener.onValidationError(error);
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addValidationListener(ValidationErrorListener listener)
	{
		synchronized (listeners)
		{
			listeners.add(listener);
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void removeValidationListener(ValidationErrorListener listener)
	{
		synchronized (listeners)
		{
			listeners.remove(listener);
		}
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public synchronized RevocationParameters getRevocationCheckingMode()
	{
		return revocationMode;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public synchronized void dispose()
	{
		disposed = true;
		observers.removeAllObservers();
		crlStore.dispose();
		caStore.dispose();
	}
	
	protected synchronized boolean isDisposed()
	{
		return disposed;
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public void addUpdateListener(StoreUpdateListener listener)
	{
		observers.addObserver(listener);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void removeUpdateListener(StoreUpdateListener listener)
	{
		observers.addObserver(listener);
	}
}
