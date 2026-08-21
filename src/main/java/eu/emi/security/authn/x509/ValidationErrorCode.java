/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509;

/**
 * This enumeration contains codes of errors that can be signaled 
 * during certificate path validation. This classification is provided
 * to allow applications to have fine grained error handling.
 * <p>
 * This codes are used as keys for getting the messages from the 
 * message bundle 'validationErrors' (defined in a properties file). 
 * 
 * @author K. Benedyczak
 */
public enum ValidationErrorCode
{
	INVALID_INPUT,
	PATH_BUILDING_FAILED,
	NO_TRUST_ANCHOR,
	CERTIFICATE_EXPIRED,
	CERTIFICATE_NOT_YET_VALID,
	INVALID_SIGNATURE,
	ALGORITHM_CONSTRAINED,
	INVALID_NAME_CHAINING,
	INVALID_KEY_USAGE,
	NOT_CA,
	PATH_TOO_LONG,
	INVALID_NAME_CONSTRAINT,
	INVALID_POLICY,
	UNRESOLVED_CRITICAL_EXTENSION,
	CERTIFICATE_REVOKED,
	UNDETERMINED_REVOCATION_STATUS,
	PKIX_FAILURE,

	/*
	 * Legacy reviewer codes remain temporarily for the revocation compatibility
	 * path. Native validation never emits them, and the native-revocation change
	 * removes the remaining callers.
	 */
	unknown,
	unknownMsg,
	
	inputError,
	emptyCertPath,
	invalidCertificatePath,
	
	noIssuerPublicKey,
	noBasicConstraints,
	pathLenghtExtended,
	conflictingTrustAnchors,
	noTrustAnchorFound,
	trustButInvalidCert,
	signatureNotVerified,
	certificateNotYetValid,
	certificateExpired,
	noCACert,
	noCertSign,
	unknownCriticalExt,
	certWrongIssuer,
	errorProcesingBC,
	QcStatementExtError,
	certPathCheckerError,
	criticalExtensionError,
	unknownCriticalExts,
	pubKeyError,
	processLengthConstError,
	rootKeyIsValidButNotATrustAnchor,
	trustAnchorIssuerError,
	trustDNInvalid,
	trustKeyUsage,
	trustPubKeyError,

	explicitPolicy,
	invalidPolicyMapping,
	invalidPolicy,
	noValidPolicyTree,
	policyConstExtError,
	policyExtError,
	policyInhibitExtError,
	policyMapExtError,
	policyQualifierError,

	excludedDN,
	excludedEmail,
	excludedIP,
	ncExtError,
	ncSubjectNameError,
	notPermittedDN,
	notPermittedEmail,
	notPermittedIP,
	subjAltNameExtError,
	
	certRevoked,
	noBaseCRL,
	noValidCrlFound,
	noCrlForExpiredCert,
	crlVerifyFailed,
	distrPtExtError,
	crlAuthInfoAccError,
	crlBCExtError,
	crlDistPtExtError,
	crlExtractionError,
	crlIssuerException,
	crlNoIssuerPublicKey,
	crlOnlyAttrCert,
	crlOnlyCaCert,
	crlOnlyUserCert,
	crlReasonExtError,
	onlineCRLWrongCA,
	onlineInvalidCRL,
	noCrlInCertstore,
	noCrlSigningPermited,
	loadCrlDistPointError,
	localInvalidCRL,
	crlUnknownCritExt,
	crlNoIssuerForDP,
	crlNoIssuerAndDP,
	crlIDPAndDPMismatch,
	crlDeltaProblem,
	crlAKIExtError,
	
	ocspCertRevoked,
	ocspNoResponder,
	ocspResponderQueryError,
	ocspResponseInvalid,
	ocspOtherError,
}
