/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509;

/**
 * This enumeration contains general classes of errors that can be signaled 
 * during certificate path validation. This classification is provided
 * to allow applications to have coarse grained error handling.
 * 
 * 
 * @author K. Benedyczak
 */
public enum ValidationErrorCategory
{
	INPUT,
	PATH,
	CERTIFICATE,
	POLICY,
	NAME_CONSTRAINT,
	REVOCATION,
	OTHER;
	
	public static ValidationErrorCategory getErrorCategory(ValidationErrorCode code)
	{
		switch (code)
		{
		case INVALID_INPUT:
			return INPUT;
		case PATH_BUILDING_FAILED:
		case NO_TRUST_ANCHOR:
		case INVALID_NAME_CHAINING:
		case PATH_TOO_LONG:
			return PATH;
		case CERTIFICATE_EXPIRED:
		case CERTIFICATE_NOT_YET_VALID:
		case INVALID_SIGNATURE:
		case ALGORITHM_CONSTRAINED:
		case INVALID_KEY_USAGE:
		case NOT_CA:
		case UNRESOLVED_CRITICAL_EXTENSION:
			return CERTIFICATE;
		case INVALID_NAME_CONSTRAINT:
			return NAME_CONSTRAINT;
		case INVALID_POLICY:
			return POLICY;
		case CERTIFICATE_REVOKED:
		case UNDETERMINED_REVOCATION_STATUS:
			return REVOCATION;
		case PKIX_FAILURE:
		default:
			return OTHER;
		}
	}
}
