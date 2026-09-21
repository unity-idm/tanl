/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package io.imunity.tanl.x509.helpers.trust;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import io.imunity.tanl.x509.StoreUpdateListener;
import io.imunity.tanl.x509.StoreUpdateListener.Severity;
import io.imunity.tanl.x509.helpers.ObserversHandler;
import io.imunity.tanl.x509.impl.X500NameUtils;

/**
 * Base implementation of Trust Anchor stores. Provides observers support and utility methods to warn
 * about expired certs.
 *  
 * @author K. Benedyczak
 */
public abstract class AbstractTrustAnchorStore implements TrustAnchorStore 
{
	protected final ObserversHandler observers;
	private long updateInterval;
	
	public AbstractTrustAnchorStore(long updateInterval, ObserversHandler observers)
	{
		this.observers = observers;
		this.updateInterval = updateInterval;
	}
	
	@Override
	public synchronized long getUpdateInterval()
	{
		return updateInterval;
	}
	
	@Override
	public synchronized void setUpdateInterval(long newInterval)
	{
		updateInterval = newInterval;
	}
	
	protected void checkValidity(String location, X509Certificate certificate, boolean addSubject)
	{
		try
		{
			certificate.checkValidity();
		} catch (CertificateExpiredException e)
		{
			StringBuilder sb = prepErrorMsgPfx(certificate, addSubject);
			sb.append(" is EXPIRED: ").append(e.getMessage());
			observers.notifyObservers(location, StoreUpdateListener.CA_CERT, Severity.WARNING, 
				new Exception(sb.toString()));
		} catch (CertificateNotYetValidException e)
		{
			StringBuilder sb = prepErrorMsgPfx(certificate, addSubject);
			sb.append(" is NOT YET VALID: ").append(e.getMessage());
			observers.notifyObservers(location, 
				StoreUpdateListener.CA_CERT, Severity.WARNING, 
				new Exception(sb.toString()));
		} 
	}
	
	private static StringBuilder prepErrorMsgPfx(X509Certificate certificate, boolean addSubject)
	{
		StringBuilder sb = new StringBuilder();
		sb.append("Trusted CA certificate");
		if (addSubject)
		{
			sb.append(" with subject ");
			sb.append(X500NameUtils.getReadableForm(
				certificate.getSubjectX500Principal()));
		}
		return sb;
	}
}
