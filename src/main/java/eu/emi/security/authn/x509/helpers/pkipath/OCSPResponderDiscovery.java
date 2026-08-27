/*
 * Copyright (c) 2026 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENSE.txt for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * Extracts HTTP OCSP responder URIs from a certificate's Authority
 * Information Access extension.
 */
final class OCSPResponderDiscovery
{
	private OCSPResponderDiscovery()
	{
	}

	static List<URI> getResponderURIs(X509Certificate certificate)
			throws CertificateParsingException
	{
		List<URI> result = new ArrayList<URI>();
		byte[] encoded = certificate.getExtensionValue(
				Extension.authorityInfoAccess.getId());
		if (encoded == null)
			return result;

		try
		{
			ASN1OctetString octets = ASN1OctetString.getInstance(encoded);
			AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(
					octets.getOctets());
			for (AccessDescription description: aia.getAccessDescriptions())
			{
				if (!AccessDescription.id_ad_ocsp.equals(description.getAccessMethod()))
					continue;
				GeneralName location = description.getAccessLocation();
				if (location.getTagNo() != GeneralName.uniformResourceIdentifier)
					continue;
				String value = DERIA5String.getInstance(location.getName()).getString();
				URI uri = new URI(value);
				String scheme = uri.getScheme();
				if (!uri.isAbsolute() || scheme == null ||
						(!"http".equals(scheme.toLowerCase(Locale.ROOT)) &&
						 !"https".equals(scheme.toLowerCase(Locale.ROOT))))
					throw new CertificateParsingException(
							"Unsupported OCSP responder URI: " + value);
				result.add(uri);
			}
			return result;
		} catch (IllegalArgumentException e)
		{
			throw parsingFailure(e);
		} catch (URISyntaxException e)
		{
			throw parsingFailure(e);
		}
	}

	private static CertificateParsingException parsingFailure(Exception cause)
	{
		CertificateParsingException failure = new CertificateParsingException(
				"Can not parse OCSP responder URI from Authority Information Access");
		failure.initCause(cause);
		return failure;
	}
}
