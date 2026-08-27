/*
 * Copyright (c) 2026 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENSE.txt for licensing information.
 */
package eu.emi.security.authn.x509;

/**
 * Identifies the validation phase which produced a primary error.
 */
public enum ValidationStage
{
	INPUT,
	PATH_BUILDING,
	PATH_VALIDATION,
	REVOCATION
}
