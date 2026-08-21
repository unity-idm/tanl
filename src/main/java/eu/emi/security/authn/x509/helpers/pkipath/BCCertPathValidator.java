/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.jcajce.PKIXExtendedParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.CertPathReviewerException;
import org.bouncycastle.x509.PKIXCertPathReviewer;

import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationErrorCode;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.helpers.CertificateHelpers;
import eu.emi.security.authn.x509.helpers.ObserversHandler;
import eu.emi.security.authn.x509.helpers.pkipath.bc.FixedBCPKIXCertPathReviewer;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.FormatMode;

/**
 * Low-level certificate validator based on the BC {@link PKIXCertPathReviewer}.
 * @author K. Benedyczak
 */
public class BCCertPathValidator
{
	/**
	 * Performs validation. Expects correctly set up parameters.
	 * <p>
	 * Path validation is performed as follows:
	 * <ul>
	 * <li> First all basically correct (i.e. fulfilling name chaining rules) 
	 * certificate paths are tried to be constructed from the input chain. This step
	 * produces from zero to many paths (in 99%: 0 or 1). 
	 * Those paths can differ from the input e.g. by having self-signed intermediary 
	 * CA certificate removed.
	 * <li> If there were no path constructed, the input chain is used as-is, as the only 
	 * possible path. At this step we already know it is invalid, but we anyway continue to
	 * establish complete and detailed list of errors.
	 * <li> All constructed paths are validated using PKIX rules, and errors found are
	 * recorded. If at least one path validates successfully the algorithm ends.
	 * <li> If all paths were invalid, the one with the least number of errors is selected
	 * and those errors are reported as the validation result.
	 * </ul>
	 * 
	 * @param toCheck chain to check
	 * @param trustAnchors trust anchors
	 * @param crlStore crl store
	 * @param revocationParams revocation params
	 * @param observersHandler observers handler
	 * @return validation result
	 * @throws CertificateException if some of the certificates in the chain can not 
	 * be parsed
	 */
	public ValidationResult validate(X509Certificate[] toCheck, Set<TrustAnchor> trustAnchors,
			CertStore crlStore,
			RevocationParameters revocationParams, ObserversHandler observersHandler)
			throws CertificateException
	{
		if (toCheck == null || toCheck.length == 0)
			throw new IllegalArgumentException("Chain to be validated must be non-empty");
		
		List<ValidationError> errors = new ArrayList<ValidationError>();
		Set<String> unresolvedExtensions = new HashSet<String>();

		if (trustAnchors.isEmpty())
		{
			//Empty trust anchors set is fine for ExtPKIXParameters but not for plain PKIXParameters.
			//Make a proper error and return it instead of an opaque exception.
			errors.add(new ValidationError(toCheck, -1, ValidationErrorCode.noTrustAnchorFound));
			errors.add(new ValidationError(toCheck, 0, ValidationErrorCode.noIssuerPublicKey));
			return new ValidationResult(false, errors, unresolvedExtensions, null);
		}

		ExtPKIXParameters2 params = createPKIXParameters(toCheck,
				trustAnchors, crlStore, revocationParams, observersHandler);
		List<X509Certificate> chain = checkChain(toCheck, params, errors, unresolvedExtensions, 0, toCheck);
		return new ValidationResult(errors.size() == 0, errors, unresolvedExtensions, chain);
	}
	
	protected ExtPKIXParameters2 createPKIXParameters(X509Certificate[] toCheck,
			Set<TrustAnchor> trustAnchors, CertStore crlStore,
			RevocationParameters revocationParams, ObserversHandler observersHandler)
	{
		X509CertSelector endSelector = new X509CertSelector();
		endSelector.setCertificate(toCheck[0]);
		PKIXParameters baseOfBase;
		try
		{
			baseOfBase = new PKIXParameters(trustAnchors);
		} catch (InvalidAlgorithmParameterException e)
		{
			throw new IllegalStateException("Can't create PKIXParameters, shouldn't happen", e);
		}
		baseOfBase.setTargetCertConstraints(endSelector);
		baseOfBase.setDate(new Date());
		baseOfBase.addCertStore(crlStore);
		CertStore certStore;
		try
		{
			certStore = CertStore.getInstance("Collection",
					new CollectionCertStoreParameters(Arrays.asList(toCheck)), 
					BouncyCastleProvider.PROVIDER_NAME);
		} catch (Exception e1)
		{
			throw new RuntimeException("Can't create an instance of a " +
					"simple Collection certificate store, using the BC provider, BUG?", e1);
		}
		baseOfBase.addCertStore(certStore);
		
		PKIXExtendedParameters.Builder baseBuilder = new PKIXExtendedParameters.Builder(baseOfBase);
		ExtPKIXParameters2.Builder paramsBuilder = new ExtPKIXParameters2.Builder(
				baseBuilder, baseOfBase, trustAnchors, observersHandler);
		paramsBuilder.setRevocationParams(revocationParams);
		return paramsBuilder.build();
	}
	
	/**
	 * Performs checking of the chain
	 * using {@link FixedBCPKIXCertPathReviewer}. In future, when BC implementation is fixed
	 * it should use {@link PKIXCertPathReviewer} instead.  
	 * @param baseChain base chain
	 * @param params parameters
	 * @param errors errors
	 * @param unresolvedExtensions unresolved extensions
	 * @param posDelta position delta
	 * @param cc certificate chain
	 * @return validated chain or null
	 * @throws CertificateException certificate exception
	 */
	protected List<X509Certificate> checkChain(X509Certificate[] baseChain,
			ExtPKIXParameters2 params, List<ValidationError> errors, 
			Set<String> unresolvedExtensions, int posDelta, X509Certificate[] cc) 
					throws CertificateException
	{
		NonValidatingCertPathBuilder builder = new NonValidatingCertPathBuilder();
		List<CertPath> certPaths;
		List<ValidationError> buildPathErrors = null;
		try
		{
			certPaths = builder.buildPath(params.getBaseBuildParameters(), baseChain[0], cc);
		} catch (ValidationErrorException e1)
		{
			buildPathErrors = e1.getErrors();
			certPaths = Collections.singletonList(CertificateHelpers.toCertPath(baseChain));
		}
//		PKIXCertPathReviewer baseReviewer;
		FixedBCPKIXCertPathReviewer baseReviewer;
		List<ValidationError> validationErrors = null;
		List<?>[] rawErrors = null;

		for (int i=0; i<certPaths.size(); i++)
		{
			try
			{
				baseReviewer = new FixedBCPKIXCertPathReviewer(certPaths.get(i), params);
//				baseReviewer = new PKIXCertPathReviewer(certPaths.get(i), params);
			} catch (CertPathReviewerException e)
			{
				//really shoudn't happen - we have checked the arguments
				throw new IllegalStateException("Can't init PKIXCertPathReviewer, bug?", e);
			}
			if (buildPathErrors != null && baseReviewer.isValidCertPath())
			{
				//ups!!! bad! PKIXCertPAthReviewer validated while the path was not even build
				throw new IllegalStateException("PKIXCertPAthReviewer validated while the path was not even " +
					"build correctly. Build path error: " + buildPathErrors.get(0));
			}
			
			List<ValidationError> processedErrors = convertErrors(baseReviewer.getErrors(), posDelta, cc);
			if (processedErrors.size() == 0) 
			{
				X509Certificate ta = baseReviewer.getTrustAnchor().getTrustedCert();
				if (ta == null)
					return null;
				List<? extends Certificate> path = certPaths.get(i).getCertificates();
				List<X509Certificate> ret = new ArrayList<X509Certificate>(path.size()+1);
				for (int j=0; j<path.size(); j++)
					ret.add((X509Certificate) path.get(j));
				ret.add(ta);
				return ret;
			}
			if (validationErrors == null || validationErrors.size() > processedErrors.size())
			{
				validationErrors = processedErrors;
				rawErrors = baseReviewer.getErrors();
			}
		}

		if (validationErrors != null)
		{
			//let's report errors from the validation which had a smallest number of them
			errors.addAll(validationErrors);
			if (rawErrors != null)
				unresolvedExtensions.addAll(getUnresolvedExtensionons(rawErrors));
		} else
		{
			throw new IllegalStateException("PKIXCertPAthReviewer BUG: validationErrors is null, " +
					"tested chain: " + CertificateUtils.format(baseChain, FormatMode.FULL));
		}
		return null;
	}
	
	protected List<ValidationError> convertErrors(List<?>[] bcErrorsA,
			int positionDelta, X509Certificate[] cc)
	{
		List<ValidationError> ret = new ArrayList<ValidationError>();
		for (int i=0; i<bcErrorsA.length; i++)
		{
			List<?> bcErrors = bcErrorsA[i];
			for (Object bcError: bcErrors)
			{
				if (bcError instanceof ErrorBundle)
				{
					ErrorBundle error = (ErrorBundle) bcError;
					ret.add(BCErrorMapper.map(error, i-1+positionDelta, cc));
				} else 
				{
					SimpleValidationErrorException error = (SimpleValidationErrorException) bcError;
					ret.add(new ValidationError(cc, i-1+positionDelta, 
						error.getCode(), error.getArguments()));
				}
					
			}
		}
		return ret;
	}
	
	protected Set<String> getUnresolvedExtensionons(List<?>[] bcErrorsA)
	{
		Set<String> ret = new HashSet<String>();
		for (int i=0; i<bcErrorsA.length; i++)
		{
			List<?> bcErrors = bcErrorsA[i];
			for (Object bcError: bcErrors)
			{
				if (bcError instanceof ErrorBundle)
				{
					ErrorBundle error = (ErrorBundle) bcError;
					if (error.getId().equals("CertPathReviewer.unknownCriticalExt"))
					{
						ASN1ObjectIdentifier extId = (ASN1ObjectIdentifier) error.getArguments()[0];
						ret.add(extId.getId());
					}
				} else
				{
					SimpleValidationErrorException error = (SimpleValidationErrorException) bcError;
					if (error.getCode().equals(ValidationErrorCode.unknownCriticalExt))
					{
						ASN1ObjectIdentifier extId = (ASN1ObjectIdentifier) error.getArguments()[0];
						ret.add(extId.getId());
					}
				}
			}
		}
		return ret;
	}
}
