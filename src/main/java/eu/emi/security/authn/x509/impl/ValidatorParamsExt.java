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
 * Contains parameters common for all {@link X509CertChainValidator} implementations
 * which use {@link RevocationParametersExt}
 * 
 * @author K. Benedyczak
 */
public class ValidatorParamsExt extends ValidatorParams
{
	protected RevocationParametersExt revocationSettings;
	
	/**
	 * Default constructor: no initial update listeners and default revocation settings.
	 */
	public ValidatorParamsExt()
	{
		this(new RevocationParametersExt(),
			new ArrayList<StoreUpdateListener>());
	}

	/**
	 * Allows for setting revocation parameters without initial listeners.
	 * @param revocationSettings desired revocation settings
	 */
	public ValidatorParamsExt(RevocationParametersExt revocationSettings)
	{
		this(revocationSettings, new ArrayList<StoreUpdateListener>());
	}
	
	/**
	 * Full version, allows for setting all parameters.
	 * @param revocationSettings desired revocation settings
	 * @param initialListeners initial trust store update listeners
	 */
	public ValidatorParamsExt(RevocationParametersExt revocationSettings,
			Collection<? extends StoreUpdateListener> initialListeners)
	{
		super(revocationSettings, initialListeners);
		setRevocationSettings(revocationSettings);
	}

	/**
	 * @return revocation checking settings
	 */
	@Override
	public RevocationParametersExt getRevocationSettings()
	{
		return revocationSettings;
	}

	/**
	 * @param revocationSettings  revocation checking settings
	 */
	public void setRevocationSettings(RevocationParametersExt revocationSettings)
	{
		this.revocationSettings = revocationSettings;
	}

	/**
	 * Do not use this method - it will always throw an exception. Use the one 
	 * with extended parameters.
	 * @param revocationSettings  revocation checking settings
	 * 
	 */
	@Override
	public void setRevocationSettings(RevocationParameters revocationSettings)
	{
		throw new IllegalArgumentException("This class can be configured " +
				"only using " + RevocationParametersExt.class);
	}
}
