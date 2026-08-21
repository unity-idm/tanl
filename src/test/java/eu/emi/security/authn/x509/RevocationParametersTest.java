/*
 * Copyright (c) 2026 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;

import org.junit.Test;

import eu.emi.security.authn.x509.RevocationParameters.RevocationCheckingOrder;

public class RevocationParametersTest
{
	@Test
	public void shouldPreserveOverallPolicyWhenCloned()
	{
		OCSPParametes ocsp = new OCSPParametes(OCSPCheckingMode.REQUIRE);
		RevocationParameters original = new RevocationParameters(
				CrlCheckingMode.REQUIRE, ocsp, true,
				RevocationCheckingOrder.CRL_OCSP);

		RevocationParameters cloned = original.clone();

		assertThat(cloned.getCrlCheckingMode(), is(CrlCheckingMode.REQUIRE));
		assertThat(cloned.getOcspParameters(), sameInstance(ocsp));
		assertThat(cloned.isUseAllEnabled(), is(true));
		assertThat(cloned.getOrder(), is(RevocationCheckingOrder.CRL_OCSP));
	}
}
