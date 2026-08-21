/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509;

/**
 * Stable codes for native certificate-path validation failures.
 * 
 * @author K. Benedyczak
 */
public enum ValidationErrorCode
{
	INVALID_INPUT("Invalid certificate input"),
	PATH_BUILDING_FAILED("Certificate path building failed"),
	NO_TRUST_ANCHOR("No trusted CA certificate was found for the certificate path"),
	CERTIFICATE_EXPIRED("Certificate has expired"),
	CERTIFICATE_NOT_YET_VALID("Certificate is not yet valid"),
	INVALID_SIGNATURE("Certificate signature is invalid"),
	ALGORITHM_CONSTRAINED("Certificate uses a constrained cryptographic algorithm"),
	INVALID_NAME_CHAINING("Certificate issuer and subject names do not chain"),
	INVALID_KEY_USAGE("Certificate key usage does not permit the required operation"),
	NOT_CA("Certificate is not permitted to act as a CA"),
	PATH_TOO_LONG("Certificate path exceeds a path-length constraint"),
	INVALID_NAME_CONSTRAINT("Certificate violates a name constraint"),
	INVALID_POLICY("Certificate path does not satisfy the required policy"),
	UNRESOLVED_CRITICAL_EXTENSION("Certificate contains an unsupported critical extension"),
	CERTIFICATE_REVOKED("Certificate has been revoked"),
	UNDETERMINED_REVOCATION_STATUS("Certificate revocation status could not be determined"),
	PKIX_FAILURE("PKIX certificate validation failed");

	private final String description;

	ValidationErrorCode(String description)
	{
		this.description = description;
	}

	String getDescription()
	{
		return description;
	}
}
