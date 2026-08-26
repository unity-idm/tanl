/*
 * Copyright (c) 2026 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

/**
 * Finds parsed CRLs whose issuer makes them potentially applicable to a
 * certificate. Native BC remains responsible for every validity,
 * distribution-point, signature, scope, reason, delta, and status decision.
 */
final class CRLCandidateDiscovery
{
	private CRLCandidateDiscovery()
	{
	}

	static boolean hasPotentialCRL(X509Certificate certificate, CertStore crlStore)
			throws CertificateParsingException, CertStoreException
	{
		X509CRLSelector selector = new X509CRLSelector();
		for (X500Principal issuer: candidateIssuers(certificate))
			selector.addIssuer(issuer);
		selector.setCertificateChecking(certificate);
		Collection<? extends CRL> candidates = crlStore.getCRLs(selector);
		return !candidates.isEmpty();
	}

	private static Set<X500Principal> candidateIssuers(X509Certificate certificate)
			throws CertificateParsingException
	{
		Set<X500Principal> result = new LinkedHashSet<X500Principal>();
		result.add(certificate.getIssuerX500Principal());
		byte[] encoded = certificate.getExtensionValue(
				Extension.cRLDistributionPoints.getId());
		if (encoded == null)
			return result;

		try
		{
			ASN1OctetString octets = ASN1OctetString.getInstance(encoded);
			CRLDistPoint points = CRLDistPoint.getInstance(octets.getOctets());
			for (DistributionPoint point: points.getDistributionPoints())
			{
				GeneralNames crlIssuers = point.getCRLIssuer();
				if (crlIssuers == null)
					continue;
				for (GeneralName name: crlIssuers.getNames())
					if (name.getTagNo() == GeneralName.directoryName)
					{
						X500Name issuer = X500Name.getInstance(name.getName());
						result.add(new X500Principal(issuer.getEncoded()));
					}
			}
			return result;
		} catch (Exception e)
		{
			CertificateParsingException failure = new CertificateParsingException(
					"Can not parse CRL issuer from CRL Distribution Points");
			failure.initCause(e);
			throw failure;
		}
	}
}
