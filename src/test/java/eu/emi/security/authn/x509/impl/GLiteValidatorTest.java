/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 *
 * Derived from the code copyrighted and licensed as follows:
 * 
 * Copyright (c) Members of the EGEE Collaboration. 2004.
 * See http://www.eu-egee.org/partners/ for details on the copyright
 * holders.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 *    
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.emi.security.authn.x509.impl;

import java.io.FileInputStream;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;


public class GLiteValidatorTest
{
	private static final TestCase[] trustedTestCases = {
			new TestCase("trusted-certs/trusted_client", true),
			new TestCase("trusted-certs/trusted_client_exp", false),
			new TestCase("trusted-certs/trusted_clientserver", true),
			new TestCase("trusted-certs/trusted_clientserver_exp", false),
			new TestCase("trusted-certs/trusted_fclient", true),
			new TestCase("trusted-certs/trusted_fclient_exp", false),
			new TestCase("trusted-certs/trusted_none", true),
			new TestCase("trusted-certs/trusted_none_exp", false),
			new TestCase("trusted-certs/trusted_server", true),
			new TestCase("trusted-certs/trusted_server_exp", false),
			new TestCase("trusted-certs/trusted_bigclient", true)
	};
	
	private static final TestCase[] trustedRevokedTestCases = {
			new TestCase("trusted-certs/trusted_client_rev", false),
			new TestCase("trusted-certs/trusted_clientserver_rev", false),
			new TestCase("trusted-certs/trusted_fclient_rev", false),
			new TestCase("trusted-certs/trusted_none_rev", false),
			new TestCase("trusted-certs/trusted_server_rev", false)
	};
	
	private static final TestCase[] fakeCertsTestCases = {
			new TestCase("fake-certs/fake_client", false)
	};

	protected void gliteTest(boolean reverse, TestCase tc,
			String trustStore, boolean revocation, boolean openssl1Mode)
	{
		try
		{
			gliteTestInternalWithOpensslStore(reverse, tc, trustStore, revocation, openssl1Mode);
		} catch (Exception e)
		{
			e.printStackTrace();
			Assert.fail("Exception when processing " + tc.name
					+ ": " + e);
		}
	}
	
	protected void gliteTestInternalWithOpensslStore(boolean reverse, TestCase tc, 
			String trustStore, boolean revocation, boolean openssl1Mode) throws Exception
	{
		System.out.println("Test Case: " + tc.name);
		
		X509Certificate[] toCheck = new X509Certificate[] {
				CertificateUtils.loadCertificate(new FileInputStream(
				"src/test/resources/glite-utiljava/" + tc.name + ".cert"),
				Encoding.PEM) };
		int expectedErrors = 0;
		boolean expectedResult = tc.valid;
		if (reverse)
			expectedResult = !expectedResult;
		if (!expectedResult)
			expectedErrors = Integer.MAX_VALUE;
		StoreUpdateListener l = new StoreUpdateListener()
		{
			@Override
			public void loadingNotification(String location, String type,
					Severity level, Exception cause)
			{
				if (level.equals(Severity.ERROR))
				{
					Assert.fail("Error reading a truststore: " + 
							location + " " + type + " " + cause);
				}
			}
		};
		List<StoreUpdateListener> listeners = Collections.singletonList(l);
		
		ValidatorParams params = new ValidatorParams(new RevocationParameters(revocation ? 
					CrlCheckingMode.REQUIRE : CrlCheckingMode.IF_VALID,
			new OCSPParametes(OCSPCheckingMode.IGNORE)), listeners);
		OpensslCertChainValidator validator = new OpensslCertChainValidator(
				"src/test/resources/glite-utiljava/grid-security/"+trustStore+"/",
				openssl1Mode,
				NamespaceCheckingMode.EUGRIDPMA, 
				-1, 
				params,
				true);
		
		ValidationResult result = validator.validate(toCheck);
		List<ValidationError> errors = result.getErrors();
		
		if (!result.isValid())
		{
			System.out.println("Result (short): " + result.toShortString());
			System.out.println("Result (full) : " + result);
		}
		
		if (expectedErrors == Integer.MAX_VALUE)
			Assert.assertTrue("Certificate validated successfully while should get error", errors.size() > 0);
		else
			Assert.assertEquals(expectedErrors, errors.size());
		validator.dispose();
	}

	
	
	private static class TestCase
	{
		private String name;
		private boolean valid;
		public TestCase(String name, boolean valid)
		{
			this.name = name;
			this.valid = valid;
		}
	}
	
	@Test
	public void test1()
	{
		String truststore = "certificates";
		boolean revocation = true;
		boolean openssl1Mode = false;
		
		for (TestCase tc: trustedTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: trustedRevokedTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: fakeCertsTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
	}

	@Test
	public void test1WithNewHash()
	{
		String truststore = "certificates-newhash-all";
		boolean revocation = true;
		boolean openssl1Mode = true;

		for (TestCase tc: trustedTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: trustedRevokedTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: fakeCertsTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
	}

	
	@Test
	public void test2()
	{
		String truststore = "certificates-withoutCrl";
		boolean revocation = false;
		boolean openssl1Mode = false;

		for (TestCase tc: trustedTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: trustedRevokedTestCases)
			gliteTest(true, tc, truststore, revocation, openssl1Mode);
		for (TestCase tc: fakeCertsTestCases)
			gliteTest(false, tc, truststore, revocation, openssl1Mode);
	}

	@Test
	public void test3()
	{
		String truststore = "certificates-withoutCrl";
		boolean revocation = true;
		boolean openssl1Mode = false;
		gliteTest(true, trustedTestCases[0], truststore, revocation, openssl1Mode);
		gliteTest(false, trustedRevokedTestCases[0], truststore, revocation, openssl1Mode);
	}

	@Test
	public void testSlash()
	{
		String truststore = "certificates";
		boolean revocation = false;
		boolean openssl1Mode = false;
		TestCase slash = new TestCase("slash-certs/slash_client_slash", true);
		gliteTest(false, slash, truststore, revocation, openssl1Mode);
	}
}
