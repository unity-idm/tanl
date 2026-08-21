/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.OCSPResponder;
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
 * providing trusted CAs. The implementation validates certificates using 
 * the {@link BCCertPathValidator}.
 * <p>
 * This class is thread safe and its extensions should also guarantee this.
 * 
 * @author K. Benedyczak
 */
public abstract class AbstractValidator implements X509CertChainValidatorExt
{
	private static final String AUTHORITY_INFORMATION_ACCESS_OID =
			"1.3.6.1.5.5.7.1.1";

	static 
	{
		CertificateUtils.configureSecProvider();
	}

	protected Set<ValidationErrorListener> listeners;
	protected final ObserversHandler observers;
	private TrustAnchorStore caStore;
	private AbstractCRLStoreSPI crlStore;
	protected BCCertPathValidator validator;
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
		this.validator = new BCCertPathValidator();
		this.nativeValidator = new NativeBCPKIXValidator();
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
		if (isNativeBaseValidation())
		{
			try
			{
				return processResult(nativeValidator.validate(certPath, anchors));
			} catch (CertificateException e)
			{
				return processInputError(certsA, e);
			}
		}
		if (isNativeCRLValidation())
		{
			try
			{
				return processResult(nativeValidator.validateWithCRLs(certPath,
						anchors, new SimpleCRLStore(crlStore)));
			} catch (CertificateException e)
			{
				return processInputError(certsA, e);
			}
		}
		if (isNativeOCSPValidation(certsA, anchors))
		{
			try
			{
				ValidationResult result = usesDiscoveredOCSPResponders() ?
						nativeValidator.validateWithOCSPFromAIA(certPath,
								anchors) :
						nativeValidator.validateWithOCSP(certPath,
								anchors, getNativeOCSPResponder());
				return processResult(result);
			} catch (CertificateException e)
			{
				return processInputError(certsA, e);
			}
		}
		return validate(certsA);	
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
		ValidationResult result;
		try
		{
			if (isNativeBaseValidation())
				result = nativeValidator.validate(certChain, anchors);
			else if (isNativeCRLValidation())
				result = nativeValidator.validateWithCRLs(certChain, anchors,
						new SimpleCRLStore(crlStore));
			else if (isNativeOCSPValidation(certChain, anchors))
				result = usesDiscoveredOCSPResponders() ?
						nativeValidator.validateWithOCSPFromAIA(certChain, anchors) :
						nativeValidator.validateWithOCSP(certChain, anchors,
							getNativeOCSPResponder());
			else
				result = validator.validate(certChain, anchors,
						new SimpleCRLStore(crlStore), revocationMode, observers);
		} catch (CertificateException e)
		{
			return processInputError(certChain, e);
		}
		return processResult(result);
	}

	private boolean isNativeBaseValidation()
	{
		return revocationMode.getCrlCheckingMode() == CrlCheckingMode.IGNORE &&
				revocationMode.getOcspParameters().getCheckingMode() ==
					OCSPCheckingMode.IGNORE;
	}

	private boolean isNativeCRLValidation()
	{
		return revocationMode.getCrlCheckingMode() == CrlCheckingMode.REQUIRE &&
				revocationMode.getOcspParameters().getCheckingMode() ==
					OCSPCheckingMode.IGNORE;
	}

	private boolean isNativeOCSPValidation(X509Certificate[] certificates,
			Set<TrustAnchor> anchors)
	{
		if (revocationMode.getCrlCheckingMode() != CrlCheckingMode.IGNORE)
			return false;
		OCSPParametes parameters = revocationMode.getOcspParameters();
		if (parameters == null || parameters.getCheckingMode() != OCSPCheckingMode.REQUIRE)
			return false;
		OCSPResponder[] responders = parameters.getLocalResponders();
		if (responders == null || responders.length > 1 ||
				parameters.getConntectTimeout() != OCSPParametes.DEFAULT_TIMEOUT ||
				!parameters.isPreferLocalResponders() || parameters.isUseNonce() ||
				parameters.getCacheTtl() != OCSPParametes.DEFAULT_CACHE ||
				parameters.getDiskCachePath() != null)
			return false;
		if (responders.length == 0)
			return hasOneResponderPerUntrustedCertificate(certificates, anchors);
		return !hasAuthorityInformationAccess(certificates) &&
				responders[0] != null && responders[0].getAddress() != null &&
				responders[0].getCertificate() != null;
	}

	private boolean hasOneResponderPerUntrustedCertificate(
			X509Certificate[] certificates, Set<TrustAnchor> anchors)
	{
		if (certificates == null)
			return true;
		for (X509Certificate certificate: certificates)
		{
			if (certificate == null || isTrustAnchor(certificate, anchors))
				continue;
			try
			{
				if (OCSPResponderDiscovery.getResponderURIs(certificate).size() != 1)
					return false;
			} catch (CertificateParsingException e)
			{
				return false;
			}
		}
		return true;
	}

	private boolean isTrustAnchor(X509Certificate certificate,
			Set<TrustAnchor> anchors)
	{
		if (anchors == null)
			return false;
		for (TrustAnchor anchor: anchors)
			if (certificate.equals(anchor.getTrustedCert()))
				return true;
		return false;
	}

	private boolean hasAuthorityInformationAccess(X509Certificate[] certificates)
	{
		if (certificates == null)
			return false;
		for (X509Certificate certificate: certificates)
			if (certificate != null && certificate.getExtensionValue(
					AUTHORITY_INFORMATION_ACCESS_OID) != null)
				return true;
		return false;
	}

	private OCSPResponder getNativeOCSPResponder()
	{
		return revocationMode.getOcspParameters().getLocalResponders()[0];
	}

	private boolean usesDiscoveredOCSPResponders()
	{
		return revocationMode.getOcspParameters().getLocalResponders().length == 0;
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
