/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509;

/**
 * Defines On-line Certificate Status Protocol usage mode.
 * 
 * @author K. Benedyczak
 */
public enum OCSPCheckingMode
{
	/**
	 * Require, for each checked certificate, that at least one valid OCSP responder is defined and
	 * that an ordered responder returns a good, natively validated certificate status. HTTP
	 * transport failures advance to the next responder; any received response which is revoked,
	 * unknown, malformed, forged, stale, or otherwise invalid is a terminal validation error.
	 * Not suggested, unless it is guaranteed that well configured responder(s) is(are) defined 
	 * and can handle all queries without timeouts.
	 */
	REQUIRE,
	
	/**
	 * Use OCSP for each certificate if a responder is reachable. A lack of a
	 * configured or discovered responder and exhausted HTTP transport failures
	 * do not cause validation to fail. Once response bytes are received, the
	 * response is validated strictly: revoked, unknown, malformed, forged,
	 * stale, and otherwise invalid responses fail validation.
	 */
	IF_AVAILABLE,
	
	/**
	 * Do not use OCSP.
	 */
	IGNORE
}
