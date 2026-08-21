/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

/**
 * This class wraps X509CertChainValidator so it can be easily used in 
 * the standard Java SSL API.
 * 
 * @author K. Benedyczak
 */
public class CommonX509TrustManager implements X509TrustManager
{
	private X509CertChainValidator validator;
	
	/**
	 * The constructor.
	 * @param validator wrapped implementation that performs an actual validation
	 */
	public CommonX509TrustManager(X509CertChainValidator validator)
	{
		this.validator = validator;
	}
	
	/**
	 * {@inheritDoc}
	 */
	public void checkClientTrusted(X509Certificate[] chain, String authType)
			throws CertificateException
	{
		ValidationResult result = validator.validate(chain);
		if (result.isValid())
			return;
		throw validationException(result);
	}

	/**
	 * {@inheritDoc}
	 */
	public void checkServerTrusted(X509Certificate[] chain, String authType)
			throws CertificateException
	{
		ValidationResult result = validator.validate(chain);
		if (result.isValid())
			return;
		throw validationException(result);
	}

	private CertificateException validationException(ValidationResult result)
	{
		ValidationError primaryError = result.getPrimaryError();
		Throwable cause = primaryError == null ? null : primaryError.getCause();
		return cause == null ? new CertificateException(result.toString()) :
				new CertificateException(result.toString(), cause);
	}

	/**
	 * {@inheritDoc}
	 */
	public X509Certificate[] getAcceptedIssuers()
	{
		return validator.getTrustedIssuers();
	}
}
