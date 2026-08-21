/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509;


/**
 * Invoked when there is an error found during certificate chain validation.
 * The implementation class can react to the error in an application-defined
 * way. Listeners are notification-only and can not change the validation
 * verdict.
 * 
 * @author K. Benedyczak
 */
public interface ValidationErrorListener
{
	/**
	 * Invoked upon validation error during chain processing. 
	 * @param error immutable primary error details
	 */
	void onValidationError(ValidationError error);
}
