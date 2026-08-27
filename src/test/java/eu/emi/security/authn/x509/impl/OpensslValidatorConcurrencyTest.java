/*
 * Copyright (c) 2026 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENSE.txt for licensing information.
 *
 * Parts of this file are based on code copyrighted as follows:
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 */
package eu.emi.security.authn.x509.impl;

import java.io.FileInputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.Assert;
import org.junit.Test;

import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

public class OpensslValidatorConcurrencyTest
{
	private static final String FIXTURES =
			"src/test/resources/fixtures/openssl-concurrency/";
	private static final String CLIENT =
			"src/test/resources/fixtures/shared/trusted-client.pem";

	@Test
	public void shouldValidateConcurrentlyWithOneSharedValidator() throws Exception
	{
		final OpensslCertChainValidator validator = new OpensslCertChainValidator(
				FIXTURES + "trust", 100000, new ValidatorParamsExt(), false);
		final X509Certificate[] chain;
		try (FileInputStream input = new FileInputStream(CLIENT))
		{
			chain = CertificateUtils.loadCertificateChain(input, Encoding.PEM);
		}

		ExecutorService executor = Executors.newFixedThreadPool(4);
		try
		{
			List<Callable<Void>> tasks = new ArrayList<Callable<Void>>();
			for (int thread = 0; thread < 4; thread++)
			{
				tasks.add(new Callable<Void>()
				{
					@Override
					public Void call()
					{
						for (int operation = 0; operation < 250; operation++)
						{
							ValidationResult result = validator.validate(chain);
							Assert.assertTrue(result.toString(), result.isValid());
						}
						return null;
					}
				});
			}

			for (Future<Void> future: executor.invokeAll(tasks))
				future.get();
		} finally
		{
			executor.shutdownNow();
			validator.dispose();
		}
	}
}
