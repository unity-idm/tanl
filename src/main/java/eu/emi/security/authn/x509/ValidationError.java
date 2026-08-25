/*
 * Copyright (c) 2011-2026 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509;

import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import eu.emi.security.authn.x509.impl.X500NameUtils;

/**
 * Immutable information about the primary certificate-validation failure.
 * Provider-specific text is diagnostic and is not a stable API value; callers
 * should branch on {@link #getErrorCode()} and {@link #getStage()}.
 *
 * @author K. Benedyczak
 * @see ValidationResult
 * @see ValidationErrorListener
 * @see ValidationErrorCategory
 */
public final class ValidationError
{
	private static final String BUNDLE_NAME = ValidationError.class.getPackage().getName() +
			"." + "valiadationErrors";

	private final int position;
	private final ValidationErrorCode errorCode;
	private final ValidationErrorCategory errorCategory;
	private final ValidationStage stage;
	private final String message;
	private final String providerMessage;
	private final Throwable cause;
	private final Object[] parameters;
	private final X509Certificate[] chain;
	private final X509Certificate certificate;

	/**
	 * Creates an error adapted from a native validation failure.
	 *
	 * @param chain validation path in target-to-anchor order
	 * @param position zero-based certificate position, or {@code -1}
	 * @param errorCode stable error code
	 * @param stage validation stage
	 * @param providerMessage original provider message, if available
	 * @param cause original validation exception, if available
	 */
	public ValidationError(X509Certificate[] chain, int position,
			ValidationErrorCode errorCode, ValidationStage stage,
			String providerMessage, Throwable cause)
	{
		if (errorCode == null)
			throw new IllegalArgumentException("errorCode can not be null");
		if (stage == null)
			throw new IllegalArgumentException("stage can not be null");
		this.chain = chain == null ? null : chain.clone();
		this.position = normalizePosition(position, this.chain);
		this.certificate = this.position < 0 ? null : this.chain[this.position];
		this.errorCode = errorCode;
		this.errorCategory = ValidationErrorCategory.getErrorCategory(errorCode);
		this.stage = stage;
		this.providerMessage = providerMessage;
		this.cause = cause;
		this.parameters = new Object[0];
		String stableMessage = formatMessage(errorCode, this.parameters);
		this.message = providerMessage == null || providerMessage.length() == 0 ||
				providerMessage.equals(stableMessage) ? stableMessage :
				stableMessage + ": " + providerMessage;
	}

	/**
	 * Temporary compatibility constructor for errors emitted by the legacy
	 * revocation path. Native validation uses the staged constructor.
	 */
	public ValidationError(X509Certificate[] chain, int position,
			ValidationErrorCode errorCode, Object... params)
	{
		if (errorCode == null)
			throw new IllegalArgumentException("errorCode can not be null");
		this.chain = chain == null ? null : chain.clone();
		this.position = normalizePosition(position, this.chain);
		this.certificate = this.position < 0 ? null : this.chain[this.position];
		this.errorCode = errorCode;
		this.errorCategory = ValidationErrorCategory.getErrorCategory(errorCode);
		this.stage = inferLegacyStage(errorCategory);
		this.parameters = params == null ? new Object[0] : params.clone();
		this.cause = findCause(this.parameters);
		this.providerMessage = cause == null ? null : makeReason(cause);
		String formatted = formatMessage(errorCode, this.parameters);
		if (cause != null && !hasMessageParameter(errorCode))
			formatted += makeReasonFromStack(cause);
		this.message = formatted;
	}

	private static int normalizePosition(int position, X509Certificate[] chain)
	{
		return position >= 0 && chain != null && position < chain.length ? position : -1;
	}

	private static String formatMessage(ValidationErrorCode code, Object[] params)
	{
		ResourceBundle bundle = ResourceBundle.getBundle(BUNDLE_NAME);
		String pattern;
		try
		{
			pattern = bundle.getString(code.name());
		} catch (MissingResourceException e)
		{
			pattern = "Other validation error";
		}
		return MessageFormat.format(pattern, params);
	}

	private static boolean hasMessageParameter(ValidationErrorCode code)
	{
		try
		{
			return ResourceBundle.getBundle(BUNDLE_NAME).getString(code.name())
					.matches(".*\\{[0-9]\\}.*");
		} catch (MissingResourceException e)
		{
			return false;
		}
	}

	private static Throwable findCause(Object[] params)
	{
		for (Object parameter: params)
			if (parameter instanceof Throwable)
				return (Throwable) parameter;
		return null;
	}

	private static ValidationStage inferLegacyStage(ValidationErrorCategory category)
	{
		if (category == ValidationErrorCategory.GENERAL_INPUT ||
				category == ValidationErrorCategory.INPUT)
			return ValidationStage.INPUT;
		if (category == ValidationErrorCategory.CRL ||
				category == ValidationErrorCategory.OCSP ||
				category == ValidationErrorCategory.REVOCATION)
			return ValidationStage.REVOCATION;
		return ValidationStage.PATH_VALIDATION;
	}

	public static String makeReasonFromStack(Throwable failure)
	{
		StringBuilder result = new StringBuilder();
		Throwable current = failure;
		do
		{
			result.append(" Cause: ").append(makeReason(current));
			current = current.getCause();
		} while (current != null);
		return result.toString();
	}

	public static String makeReason(Throwable failure)
	{
		return failure.getMessage() != null ? failure.getMessage() :
				failure.getClass().getSimpleName();
	}

	/** @return zero-based position or {@code -1} when unknown */
	public int getPosition()
	{
		return position;
	}

	/** @return stable human-readable description plus provider detail */
	public String getMessage()
	{
		return message;
	}

	/** @return stable error code */
	public ValidationErrorCode getErrorCode()
	{
		return errorCode;
	}

	/** @return defensive copy of legacy formatting parameters */
	public Object[] getParameters()
	{
		return parameters.clone();
	}

	/** @return broad stable error category */
	public ValidationErrorCategory getErrorCategory()
	{
		return errorCategory;
	}

	/** @return validation phase which produced the error */
	public ValidationStage getStage()
	{
		return stage;
	}

	/** @return original provider message, or {@code null} */
	public String getProviderMessage()
	{
		return providerMessage;
	}

	/** @return original validation exception, or {@code null} */
	public Throwable getCause()
	{
		return cause;
	}

	/** @return certificate at {@link #getPosition()}, or {@code null} */
	public X509Certificate getCertificate()
	{
		return certificate;
	}

	/** @return defensive copy of the diagnostic validation path */
	public X509Certificate[] getChain()
	{
		return chain == null ? null : chain.clone();
	}

	@Override
	public String toString()
	{
		StringBuilder result = new StringBuilder("error");
		if (position != -1)
		{
			result.append(" at position ").append(position).append(" in chain");
			if (certificate != null)
				result.append(", problematic certificate subject: ").append(
						X500NameUtils.getReadableForm(certificate.getSubjectX500Principal()));
		} else
			result.append(" affecting the whole chain");
		result.append(" (stage: ").append(stage).append(", category: ")
				.append(errorCategory).append("): ").append(message);
		return result.toString();
	}
}
