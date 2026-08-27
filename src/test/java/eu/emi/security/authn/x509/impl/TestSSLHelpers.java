/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;

import org.junit.Assert;

import org.junit.Test;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.helpers.BinaryCertChainValidator;
import eu.emi.security.authn.x509.helpers.ssl.DisabledNameMismatchCallback;
import eu.emi.security.authn.x509.helpers.ssl.EnforcingNameMismatchCallback;

public class TestSSLHelpers
{
	@Test
	public void shouldFailOnHostnameMismatch() throws Exception
	{
		X509Credential c = new PEMCredential(new FileReader(CertificateUtilsTest.PFX + "pk-1.pem"), 
				new FileReader(CertificateUtilsTest.PFX + "cert-1.pem"),
				CertificateUtilsTest.KS_P);
		X509CertChainValidator v = new BinaryCertChainValidator(true);
		testClientServer(false, c, v, new EnforcingNameMismatchCallback());
	}
	
	/**
	@FunctionalTest(id="func:cli-srv", description="Client-Server Secure Communication " +
			"with mutual authentication. Establishes a TLS session and sends a byte over it. " +
			"The test is invoked two times: once with valid credentials (data should be sent) " +
			"and once with invalid (there should be a connection error)")
	*/
	@Test
	public void testCreation() throws Exception
	{
		System.out.println("Running func:cli-srv functional test");
		testCreation(true);
		testCreation(false);
	}

	private void testCreation(boolean mode) throws Exception
	{
		X509Credential c = new PEMCredential(new FileReader(CertificateUtilsTest.PFX + "pk-1.pem"), 
				new FileReader(CertificateUtilsTest.PFX + "cert-1.pem"),
				CertificateUtilsTest.KS_P);
		X509CertChainValidator v = new BinaryCertChainValidator(mode);
		testClientServer(mode, c, v, new DisabledNameMismatchCallback());
	}
	
	
	public void testClientServer(boolean shouldSucceed, X509Credential c, X509CertChainValidator v, 
			HostnameMismatchCallback2 hostnameMismatchCallback) throws Exception
	{
		SocketFactoryCreator2 socketFactoryCreator = new SocketFactoryCreator2(c, v, hostnameMismatchCallback);
		ExecutorService serverExecutor = Executors.newSingleThreadExecutor();
		try (ServerSocket ss = socketFactoryCreator.getServerSocketFactory().createServerSocket())
		{
			ss.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
			ss.setSoTimeout(1000);
			CountDownLatch serverAccepted = new CountDownLatch(1);
			AtomicReference<Socket> acceptedSocket = new AtomicReference<>();
			Future<Integer> received = serverExecutor.submit(() ->
			{
				try (Socket accepted = ss.accept())
				{
					acceptedSocket.set(accepted);
					serverAccepted.countDown();
					accepted.setSoTimeout(500);
					return accepted.getInputStream().read();
				}
			});

			try (Socket client = socketFactoryCreator.getSocketFactory().createSocket())
			{
				SocketAddress socketAddr = ss.getLocalSocketAddress();
				client.connect(socketAddr, 1000);
				Assert.assertTrue("SSL server did not accept the connection",
						serverAccepted.await(1, TimeUnit.SECONDS));
				client.setSoTimeout(1000);
				if (shouldSucceed)
				{
					((SSLSocket) client).startHandshake();
					OutputStream os = client.getOutputStream();
					byte value = 12;
					os.write(value);
					os.flush();
					Assert.assertEquals(value,
							received.get(3, TimeUnit.SECONDS).intValue());
				} else
				{
					Assert.assertThrows(SSLHandshakeException.class,
							() -> ((SSLSocket) client).startHandshake());
					client.close();
					acceptedSocket.get().close();
					try
					{
						received.get(3, TimeUnit.SECONDS);
						Assert.fail("Server accepted an invalid SSL channel");
					} catch (ExecutionException expected)
					{
						Assert.assertTrue(expected.getCause() instanceof IOException);
					}
				}
			} finally
			{
				received.cancel(true);
			}
		} finally
		{
			serverExecutor.shutdownNow();
			Assert.assertTrue("SSL server thread did not stop",
					serverExecutor.awaitTermination(3, TimeUnit.SECONDS));
		}
	}
}
