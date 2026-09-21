/*
 * Copyright (c) 2021 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package io.imunity.tanl.x509.helpers.ssl;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import io.imunity.tanl.x509.impl.HostnameMismatchCallback2;

public class DisabledNameMismatchCallback implements HostnameMismatchCallback2
{
	@Override
	public void nameMismatch(X509Certificate peerCertificate, String hostName) throws CertificateException
	{
	}
}