/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;


import java.security.InvalidAlgorithmParameterException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Set;
import java.util.Timer;

import eu.emi.security.authn.x509.helpers.crl.AbstractCRLStoreSPI;
import eu.emi.security.authn.x509.helpers.crl.LazyOpensslCRLStoreSpi;
import eu.emi.security.authn.x509.helpers.crl.OpensslCRLStoreSpi;
import eu.emi.security.authn.x509.helpers.pkipath.AbstractValidator;
import eu.emi.security.authn.x509.helpers.trust.LazyOpensslTrustAnchorStoreImpl;
import eu.emi.security.authn.x509.helpers.trust.OpensslTrustAnchorStoreImpl;
import eu.emi.security.authn.x509.helpers.trust.TrustAnchorStore;


/**
 * The certificate validator which uses OpenSSL directory as a truststore. The validator can work in two modes:
 * the default <b>lazy</b> mode when the truststore contents is loaded on-demand and in a classic mode,
 * when the whole truststore is loaded to the memory at startup. The latter mode can be useful for server-side
 * as allows to get an information about truststore problems (as expired certificates or invalid files) at startup.
 * Also the performance characteristic is better: validation can be faster and operation time more stable.
 * Unfortunately both advantages are at the cost of a longer initialization time and bigger memory footprint.
 * Therefore the lazy mode is strongly suggested for client tools, where this is a concern.
 * 
 *   
 * @author K. Benedyczak
 */
public class OpensslCertChainValidator extends AbstractValidator
{
	private TrustAnchorStore trustStore;
	private AbstractCRLStoreSPI crlStore;
	private String path;
	private final boolean lazyMode;
	protected static final Timer timer=new Timer("caNl validator (openssl) timer", true);

	/**
	 * Constructs a new validator instance using modern OpenSSL subject hashes and lazy loading.
	 *  
	 * @param directory path where trusted certificates are stored.
	 * @param updateInterval specifies in miliseconds how often the directory should be 
	 * checked for updates. The files are reloaded only if their modification timestamp
	 * was changed since last load. Use a &lt;= 0 value to disable automatic updates.
	 * @param params common validator settings (revocation and initial listeners)
	 */
	public OpensslCertChainValidator(String directory, long updateInterval, ValidatorParams params)
	{
		this(directory, updateInterval, params, true);
	}
	
	/**
	 * Constructs a new validator instance using modern OpenSSL subject hashes.
	 *  
	 * @since 2.0.0
	 * @param directory path where trusted certificates are stored.
	 * @param updateInterval specifies in miliseconds how often the directory should be 
	 * checked for updates. The files are reloaded only if their modification timestamp
	 * was changed since last load. Use a &lt;= 0 value to disable automatic updates.
	 * @param params common validator settings (revocation and initial listeners)
	 * @param lazyMode if true then certificates and CRLs are loaded on-demand
	 *  (with in-memory caching). If false then the whole truststore contents is loaded at startup and kept in memory. 
	 */
	public OpensslCertChainValidator(String directory, long updateInterval,
			ValidatorParams params, boolean lazyMode)
	{
		super(params.getInitialListeners());
		path = directory;
		this.lazyMode = lazyMode;
		trustStore = lazyMode ?  
				new LazyOpensslTrustAnchorStoreImpl(directory, updateInterval, observers)
				:
				new OpensslTrustAnchorStoreImpl(directory, timer, updateInterval, observers);
		try
		{
			crlStore = lazyMode ? 
				new LazyOpensslCRLStoreSpi(directory, updateInterval, observers)
				:
				new OpensslCRLStoreSpi(directory, updateInterval, timer, observers);
		} catch (InvalidAlgorithmParameterException e)
		{
			throw new RuntimeException("BUG: OpensslCRLStoreSpi " +
					"can not be initialized", e);
		}
		init(trustStore, crlStore, params.getRevocationSettings());
	}
	
	/**
	 * Constructs a new validator instance with default additional settings
	 * (see {@link ValidatorParams#ValidatorParams()}).
	 * 
	 * @param directory path where trusted certificates are stored.
	 * @param updateInterval specifies in miliseconds how often the directory should be 
	 * checked for updates. The files are reloaded only if their modification timestamp
	 * was changed since last load.
	 */
	public OpensslCertChainValidator(String directory, long updateInterval)
	{
		this(directory, updateInterval, new ValidatorParams());
	}

	/**
	 * Constructs a new validator instance using the default settings:
	 * CRLs are used if present, the directory is rescanned every 10 minutes,
	 * modern OpenSSL subject hashes are required, and lazy loading is enabled.
	 *  
	 * @param directory path where trusted certificates are stored.
	 */
	public OpensslCertChainValidator(String directory)
	{
		this(directory, 600000, new ValidatorParamsExt());
	}
	
	/**
	 * Returns the trusted certificates directory path
	 * @return the path
	 */
	public String getTruststorePath()
	{
		return path;
	}
	
	/**
	 * Returns the interval between subsequent checks of the trusted certificates
	 * directory. Note that files are actually reread only if their modification
	 * time has changed.
	 * @return the current refresh interval in milliseconds
	 */
	public long getUpdateInterval()
	{
		return trustStore.getUpdateInterval();
	}

	/**
	 * Sets a new interval between subsequent checks of the trusted certificates
	 * directory. Note that files are actually reread only if their modification
	 * time has changed.
	 * @param updateInterval the new interval to be set in milliseconds
	 */
	public void setUpdateInterval(long updateInterval)
	{
		trustStore.setUpdateInterval(updateInterval);
		crlStore.setUpdateInterval(updateInterval);
	}

	@Override
	public void dispose()
	{
		super.dispose();
		trustStore.dispose();
		crlStore.dispose();
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Set<TrustAnchor> getTrustAnchors(X509Certificate[] certChain)
	{
		if (certChain == null || certChain.length == 0)
			return Collections.emptySet();
		Set<TrustAnchor> anchors;
		if (lazyMode)
		{
			LazyOpensslTrustAnchorStoreImpl lazyTAStore = (LazyOpensslTrustAnchorStoreImpl) trustStore;
			anchors = lazyTAStore.getTrustAnchorsFor(certChain);
		} else
		{
			anchors = trustStore.getTrustAnchors(); 
		}
		return anchors;
	}
}
