/*
 * Copyright (c) 2011-2026 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Immutable certificate-validation result with at most one primary error.
 *
 * @author K. Benedyczak
 * @see X509CertChainValidator
 */
public final class ValidationResult
{
	private final boolean valid;
	private final ValidationError primaryError;
	private final List<ValidationError> errors;
	private final Set<String> unresolvedCriticalExtensions;
	private final List<X509Certificate> validChain;

	private ValidationResult(boolean valid, ValidationError primaryError,
			Set<String> unresolvedCriticalExtensions, List<X509Certificate> validChain)
	{
		if (valid && primaryError != null)
			throw new IllegalArgumentException("A valid result can not contain an error");
		if (!valid && primaryError == null)
			throw new IllegalArgumentException("An invalid result must contain a primary error");
		if (unresolvedCriticalExtensions == null)
			throw new IllegalArgumentException(
					"Set of unresolved critical extensions can not be null");
		if (!valid && validChain != null)
			throw new IllegalArgumentException("An invalid result can not contain a valid chain");

		this.valid = valid;
		this.primaryError = primaryError;
		this.errors = primaryError == null ? Collections.<ValidationError>emptyList() :
				Collections.singletonList(primaryError);
		this.unresolvedCriticalExtensions = Collections.unmodifiableSet(
				new HashSet<String>(unresolvedCriticalExtensions));
		this.validChain = validChain == null ? null : Collections.unmodifiableList(
				new ArrayList<X509Certificate>(validChain));
	}

	/**
	 * Creates a successful result.
	 *
	 * @param validChain resolved target-to-anchor chain, or {@code null} for a
	 * special-purpose validator which does not resolve paths
	 */
	public static ValidationResult valid(List<X509Certificate> validChain)
	{
		return new ValidationResult(true, null, Collections.<String>emptySet(), validChain);
	}

	/** Creates an invalid result with one primary error. */
	public static ValidationResult invalid(ValidationError primaryError)
	{
		return invalid(primaryError, Collections.<String>emptySet());
	}

	/** Creates an invalid result with one primary error and unresolved OIDs. */
	public static ValidationResult invalid(ValidationError primaryError,
			Set<String> unresolvedCriticalExtensions)
	{
		return new ValidationResult(false, primaryError,
				unresolvedCriticalExtensions, null);
	}

	/** @return {@code true} only when validation succeeded */
	public boolean isValid()
	{
		return valid;
	}

	/**
	 * Compatibility view of the primary error. The returned list is immutable
	 * and is either empty or contains one element.
	 */
	public List<ValidationError> getErrors()
	{
		return errors;
	}

	/** @return the primary error, or {@code null} for a valid result */
	public ValidationError getPrimaryError()
	{
		return primaryError;
	}

	/** @return immutable unresolved critical-extension OIDs */
	public Set<String> getUnresolvedCriticalExtensions()
	{
		return unresolvedCriticalExtensions;
	}

	/** @return immutable resolved chain, or {@code null} if validation failed */
	public List<X509Certificate> getValidChain()
	{
		return validChain;
	}

	/** @return a short representation containing the primary failure */
	public String toShortString()
	{
		return valid ? "OK" : "FAILED: " + primaryError.getMessage();
	}

	/** @return a full representation containing the primary failure */
	@Override
	public String toString()
	{
		return valid ? "OK" : "FAILED The following validation error was found:\n" +
				primaryError;
	}
}
