/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.trust;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.Timer;

import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.StoreUpdateListener.Severity;
import eu.emi.security.authn.x509.helpers.ObserversHandler;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

/**
 * Implementation of the truststore which uses CA certificates from a single directory 
 * in OpenSSL format. Each certificate should be stored in a file named HASH.NUM,
 * where HASH is an 8 digit hex number. The NUM must be a number, starting from 0.
 * The hash uses the OpenSSL 1.0.0 and above format (SHA-1 hash of a normalized DN).
 * <p>
 * This class is extending the {@link DirectoryTrustAnchorStore} and restricts 
 * the certificates which are loaded.
 * 
 * @author K. Benedyczak
 */
public class OpensslTrustAnchorStoreImpl extends DirectoryTrustAnchorStore
{
	public static final String CERT_WILDCARD = "????????.*";
	
	public OpensslTrustAnchorStoreImpl(String basePath, Timer t, long updateInterval,
			ObserversHandler observers)
	{
		super(Collections.singletonList(basePath+File.separator+CERT_WILDCARD), 
				null, 0, t, updateInterval, Encoding.PEM, observers, true);
		update();
		scheduleUpdate();
	}
	
	/**
	 * For all URLs tries to load a CA certificate.
	 */
	@Override
	protected void reloadCerts(Collection<URL> locations)
	{
		Set<TrustAnchorExt> tmpAnchors = new HashSet<TrustAnchorExt>();
		
		for (URL location: locations)
			tryLoadCert(location, tmpAnchors);
		
		synchronized(this)
		{
			anchors.clear();
			anchors.addAll(tmpAnchors);
		}
	}
	
	protected boolean tryLoadCert(URL location, Set<TrustAnchorExt> tmpAnchors)
	{
		String fileHash = OpensslTruststoreHelper.getFileHash(location.getPath(), 
				OpensslTruststoreHelper.CERT_REGEXP);
		if (fileHash == null)
			return false;

		X509Certificate cert;
		try
		{
			X509Certificate[] certs = loadCerts(location);
			if (certs.length != 1)
				throw new IOException("Each of the certificate files in the Openssl style truststore "
						+ "must contain exactly one certificate");
			cert = certs[0];
		} catch (Exception e)
		{
			observers.notifyObservers(location.toExternalForm(), StoreUpdateListener.CA_CERT,
					Severity.ERROR, e);
			return false;
		}

		String certHash = OpensslTruststoreHelper.getOpenSSLCAHash(cert.getSubjectX500Principal());
		if (!fileHash.equalsIgnoreCase(certHash))
			return false;

		TrustAnchorExt anchor = new TrustAnchorExt(cert, null);
		tmpAnchors.add(anchor);
		return true;
	}
}

