/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.util.ArrayList;
import java.util.Collection;

import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.X509CertChainValidator;

/**
 * Contains parameters common for all {@link X509CertChainValidator} implementations.
 * 
 * @author K. Benedyczak
 */
public class ValidatorParams
{
	protected Collection<? extends StoreUpdateListener> initialListeners;
	protected RevocationParameters revocationSettings;
	
	/**
	 * Default constructor: no initial update listeners and default revocation settings.
	 */
	public ValidatorParams()
	{
		this(new RevocationParameters(),
			new ArrayList<StoreUpdateListener>());
	}

	/**
	 * Allows for setting revocation parameters without initial listeners.
	 * @param revocationSettings desired revocation settings
	 */
	public ValidatorParams(RevocationParameters revocationSettings)
	{
		this(revocationSettings, new ArrayList<StoreUpdateListener>());
	}
	
	/**
	 * Full version, allows for setting all parameters.
	 * @param revocationSettings desired revocation settings
	 * @param initialListeners initial trust store update listeners
	 */
	public ValidatorParams(RevocationParameters revocationSettings,
			Collection<? extends StoreUpdateListener> initialListeners)
	{
		this.initialListeners = initialListeners;
		this.revocationSettings = revocationSettings;
	}

	/**
	 * @return collection of initial listeners of trust store updates
	 */
	public Collection<? extends StoreUpdateListener> getInitialListeners()
	{
		return initialListeners;
	}

	/**
	 * @param initialListeners  collection of initial listeners of trust store updates
	 */
	public void setInitialListeners(Collection<? extends StoreUpdateListener> initialListeners)
	{
		this.initialListeners = initialListeners;
	}

	/**
	 * @return revocation checking settings
	 */
	public RevocationParameters getRevocationSettings()
	{
		return revocationSettings;
	}

	/**
	 * @param revocationSettings  revocation checking settings
	 */
	public void setRevocationSettings(RevocationParameters revocationSettings)
	{
		this.revocationSettings = revocationSettings;
	}
}
