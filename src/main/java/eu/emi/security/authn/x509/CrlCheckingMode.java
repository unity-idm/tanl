/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509;

import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.emi.security.authn.x509.impl.OpensslCertChainValidator;

/**
 * Defines Certificate Revocation List verification mode.
 * 
 * @author K. Benedyczak
 * @see OpensslCertChainValidator
 * @see KeystoreCertChainValidator
 */
public enum CrlCheckingMode
{
	/**
	 * A CRL for CA which issued a certificate being validated 
	 * must be present and valid and the certificate must not be on the list.
	 */
	REQUIRE,
	
	/**
	 * Legacy name for optional, present-but-enforced CRL checking.
	 * @deprecated Use {@link #IF_PRESENT}. This value is retained as a
	 * compatibility alias with the same behavior.
	 */
	@Deprecated
	IF_VALID,

	/**
	 * If a potentially applicable parsed CRL is present, require strict native
	 * CRL validation. If no CRL issued by the certificate issuer or an explicit
	 * distribution-point CRL issuer is present, the revocation status is left
	 * undetermined without failing validation.
	 */
	IF_PRESENT,

	/**
	 * CRL is not checked even if it exists.
	 */
	IGNORE
}
