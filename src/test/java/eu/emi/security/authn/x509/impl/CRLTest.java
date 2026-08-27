/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.cert.CRL;
import java.security.cert.CertStoreSpi;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Timer;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;

import javax.security.auth.x500.X500Principal;

import static org.junit.Assert.*;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.rules.TemporaryFolder;

import com.sun.net.httpserver.HttpServer;

import eu.emi.security.authn.x509.RiskyIntegrationTests;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.StoreUpdateListener.Severity;
import eu.emi.security.authn.x509.helpers.ObserversHandler;
import eu.emi.security.authn.x509.helpers.crl.OpensslCRLStoreSpi;
import eu.emi.security.authn.x509.helpers.crl.PlainCRLStoreSpi;
import eu.emi.security.authn.x509.helpers.trust.OpensslTruststoreHelper;

public class CRLTest
{
	@Rule
	public TemporaryFolder temporary = new TemporaryFolder();

	static
	{
		//Required as we call low-level code directly (OpensslCRLStoreSpi)
		CertificateUtils.configureSecProvider();
	}
	
	private File initDir() throws IOException
	{
		return temporary.newFolder("diskCache");
	}
	
	@Test
	public void testUpdateCleanup() throws Exception
	{
		File dir = initDir();
		
		Timer t = new Timer(true);
		List<String> crls = new ArrayList<String>();
		String crlURL1 = dir.getPath() + "/*.in";
		crls.add(crlURL1);
		File target = new File(dir, "file.in");
		FileUtils.copyFile(new File("src/test/resources/test-pems/crls/relaxationsubca.crl"), 
				target);
		
		CRLParameters params = new CRLParameters(crls, 25,
				5000, dir.getPath());
		PlainCRLStoreSpi store = new PlainCRLStoreSpi(params, t, 
				new ObserversHandler());
		try
		{
			store.start();

			checkCRL("CN=the subca CA,OU=Relaxation,O=Utopia,L=Tropic,C=UG", store, 1);
			assertTrue(target.delete());
			awaitCRLCount("CN=the subca CA,OU=Relaxation,O=Utopia,L=Tropic,C=UG",
					store, 0, 2000);
		} finally
		{
			store.dispose();
		}
	}	
	
	
	@Test
	public void testNotificationsAndUpdate() throws Exception
	{
		File dir = initDir();
		HttpServer server = HttpServer.create(new InetSocketAddress(
				InetAddress.getLoopbackAddress(), 0), 0);
		server.createContext("/", exchange -> {
			exchange.sendResponseHeaders(404, -1);
			exchange.close();
		});
		server.start();

		Timer t = new Timer(true);
		List<String> crls = new ArrayList<String>();
		String serverUrl = "http://" + server.getAddress().getHostString() + ":" +
				server.getAddress().getPort();
		final String crlURL1 = serverUrl + "/non-existing/crl.pem";
		final String crlURL2 = serverUrl + "/non-existing2/crl2.pem";
		crls.add(crlURL1);
		crls.add(crlURL2);
		String base64URL = new String(Base64.encode(crlURL1.getBytes())) + "-crl.der";
		FileUtils.copyFile(new File("src/test/resources/test-pems/crls/relaxationsubca.crl"), 
				new File(dir, base64URL));
		
		CRLParameters params = new CRLParameters(crls, 50,
				100, dir.getPath());
		BlockingQueue<StoreNotification> notifications = new LinkedBlockingQueue<>();
		StoreUpdateListener listener = recordingListener(notifications);
		ObserversHandler observers = new ObserversHandler(Collections.singleton(listener));
		PlainCRLStoreSpi store = new PlainCRLStoreSpi(params, t, observers);
		try
		{
			store.start();
			assertCrlFailureNotifications(takeNotifications(notifications, 2, 1000,
					notification -> notification.level != Severity.NOTIFICATION),
					crlURL1, crlURL2);
			observers.removeObserver(listener);
			observers.addObserver(listener);
			assertCrlFailureNotifications(takeNotifications(notifications, 2, 1000,
					notification -> notification.level != Severity.NOTIFICATION),
					crlURL1, crlURL2);
			store.setUpdateInterval(-1);
			assertNull("Notification received after updates were disabled",
					notifications.poll(150, TimeUnit.MILLISECONDS));
		} finally
		{
			store.dispose();
			server.stop(0);
		}
	}
	
	@Test
	public void testTimeout() throws Exception
	{
		final ServerSocket serverSocket = new ServerSocket(0, 0,
				InetAddress.getByName("127.0.0.1"));
		final CountDownLatch releaseServer = new CountDownLatch(1);
		final AtomicReference<Throwable> serverFailure = new AtomicReference<>();
		Thread server = new Thread()
		{
			public void run()
			{
				try (Socket ignored = serverSocket.accept())
				{
					releaseServer.await(2, TimeUnit.SECONDS);
				} catch (Throwable e)
				{
					if (!serverSocket.isClosed())
						serverFailure.set(e);
				}
			}
		};
		server.setName("crl-timeout-test-server");
		server.start();
		
		File dir = initDir();
		
		Timer t = new Timer(true);
		List<String> crls = new ArrayList<String>();
		final String crlURL1 = "http://127.0.0.1:" + serverSocket.getLocalPort() +
				"/crl.pem";
		crls.add(crlURL1);
		CRLParameters params = new CRLParameters(crls, -1, 100, dir.getPath());
		BlockingQueue<StoreNotification> notifications = new LinkedBlockingQueue<>();
		StoreUpdateListener listener = recordingListener(notifications);
		long start = System.nanoTime();
		PlainCRLStoreSpi store = new PlainCRLStoreSpi(params, t, new ObserversHandler(
				Collections.singleton(listener)));
		try
		{
			store.start();

			StoreNotification notification = takeNotifications(notifications, 1, 1000).get(0);
			assertEquals(StoreUpdateListener.CRL, notification.type);
			assertEquals(Severity.ERROR, notification.level);
			assertEquals(crlURL1, notification.location);
			assertTrue(notification.cause instanceof SocketTimeoutException);
			long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
			assertTrue("Timeout took " + elapsedMillis + " ms", elapsedMillis < 500);
		} finally
		{
			store.dispose();
			releaseServer.countDown();
			serverSocket.close();
			server.join(3000);
		}
		assertFalse("Timeout server thread did not stop", server.isAlive());
		assertNull("Timeout server failed", serverFailure.get());
	}
	
	@Test
	public void testLoadPlain() throws Exception
	{
		File dir = initDir();
		byte[] remoteCrl = FileUtils.readFileToByteArray(new File(
				"src/test/resources/test-pems/crls/relaxationsubca.crl"));
		HttpServer server = HttpServer.create(new InetSocketAddress(
				InetAddress.getByName("127.0.0.1"), 0), 0);
		server.createContext("/crl.pem", exchange -> {
			exchange.sendResponseHeaders(200, remoteCrl.length);
			try (OutputStream output = exchange.getResponseBody())
			{
				output.write(remoteCrl);
			}
		});
		server.start();

		Timer t = new Timer(true);
		List<String> crls = new ArrayList<String>();
		String crlURL1 = "http://127.0.0.1:" + server.getAddress().getPort() +
				"/crl.pem";
		String crlURL2 = "src/test/resources/test-pems/crls/*.pem";
		crls.add(crlURL1);
		crls.add(crlURL2);
		String base64URL1 = new String(Base64.encode(crlURL1.getBytes())) + "-crl.der";

		CRLParameters params = new CRLParameters(crls, -1, 
				5000, dir.getPath());
		PlainCRLStoreSpi store = null;
		try
		{
			store = new PlainCRLStoreSpi(params, t, new ObserversHandler());
			store.start();

			checkCRL("CN=the subca CA,OU=Relaxation,O=Utopia,L=Tropic,C=UG", store, 1);
			String[] ls = dir.list();
			assertEquals(1, ls.length);
			assertEquals(base64URL1, ls[0]);

			checkCRL("CN=the trusted CA,OU=Relaxation,O=Utopia,L=Tropic,C=UG", store, 1);
			checkCRL("CN=missing CA,C=UG", store, 0);
			assertEquals(crls, store.getLocations());
		} finally
		{
			if (store != null)
				store.dispose();
			server.stop(0);
		}
	}

	@Test
	@Category(RiskyIntegrationTests.class)
	public void testMemoryFootprint() throws Exception
	{
		File dir = new File("target/test-tmp/crls/copiedCrls");
		FileUtils.deleteDirectory(dir);
		dir.mkdirs();

		int N = 100;
		File crl1 = new File("src/test/resources/test-pems/crls/relaxationsubca.crl");
		File crl2 = new File("src/test/resources/test-pems/crls/tropiccacrl.pem");
		for (int i=0; i<N; i++)
		{
			FileUtils.copyFile(crl1, new File(dir, "crl1_"+i+".pem"));
			FileUtils.copyFile(crl2, new File(dir, "crl2_"+i+".pem"));
		}
		
		Timer t = new Timer(true);
		List<String> crls = new ArrayList<String>();
		crls.add(dir.getPath()+"/*.pem");
		
		CRLParameters params = new CRLParameters(crls, -1, 
				5000, dir.getPath());
		
		int M = 150;
		PlainCRLStoreSpi[] stores = new PlainCRLStoreSpi[M];
		for (int i=0; i<M; i++)
		{
			stores[i] = new PlainCRLStoreSpi(params, t, new ObserversHandler());
			stores[i].start();
			if ((i %10) == 0)
			{
				Runtime r = Runtime.getRuntime();
				System.out.println("Loaded " + i + "\t: " + ((r.totalMemory()-r.freeMemory()))/1024 + "kb");
			}
		}
		
		for (int i=0; i<M; i++)
		{
			checkCRL("CN=the subca CA,OU=Relaxation,O=Utopia,L=Tropic,C=UG", stores[i], N);
		
			checkCRL("CN=the trusted CA,OU=Relaxation,O=Utopia,L=Tropic,C=UG", stores[i], N);
		
			assertEquals(crls, stores[i].getLocations());
		}
		
		for (int i=0; i<M; i++)
			stores[i].dispose();
	}

	
	
	@Test
	public void testLoadOpenssl() throws Exception
	{
		Timer t = new Timer(true);
		BlockingQueue<StoreNotification> notifications = new LinkedBlockingQueue<>();
		StoreUpdateListener listener = recordingListener(notifications);
		
		OpensslCRLStoreSpi store = new OpensslCRLStoreSpi(
				"src/test/resources/openssl-testcrldir", -1, t, 
				new ObserversHandler(Collections.singleton(listener)));

		
		checkCRL("CN=the trusted CA,OU=Relaxation,O=Utopia,L=Tropic,C=UG", store, 1);
		List<StoreNotification> received = new ArrayList<>();
		notifications.drainTo(received);
		for (StoreNotification notification: received)
			assertEquals(StoreUpdateListener.CRL, notification.type);
		assertEquals(1, countNotifications(received, Severity.ERROR));
		assertEquals(0, countNotifications(received, Severity.WARNING));
		
		store.dispose();
	}

	@Test
	public void checkPattern() throws Exception
	{
		assertNotNull(OpensslTruststoreHelper.getFileHash("5a1a2F89.r0", 
				"^([0-9a-fA-F]{8})\\.r[\\d]+$"));
	}
	
	private static void checkCRL(String caDN, CertStoreSpi store, int expected) throws Exception
	{
		X509CRLSelector selector = new X509CRLSelector();
		selector.addIssuer(new X500Principal(caDN));
		Collection<? extends CRL> matched = store.engineGetCRLs(selector);
		assertEquals(expected, matched.size());
		if (expected > 0)
		{
			X509CRL crl = (X509CRL) matched.iterator().next();
			assertTrue(X500NameUtils.equal(crl.getIssuerX500Principal(), caDN));
		}
	}

	private static void awaitCRLCount(String caDN, CertStoreSpi store, int expected,
			long timeoutMillis) throws Exception
	{
		long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
		int actual;
		do
		{
			X509CRLSelector selector = new X509CRLSelector();
			selector.addIssuer(new X500Principal(caDN));
			actual = store.engineGetCRLs(selector).size();
			if (actual == expected)
				return;
			Thread.sleep(10);
		} while (System.nanoTime() < deadline);
		assertEquals(expected, actual);
	}

	private static StoreUpdateListener recordingListener(
			BlockingQueue<StoreNotification> notifications)
	{
		return (location, type, level, cause) ->
				notifications.add(new StoreNotification(location, type, level, cause));
	}

	private static List<StoreNotification> takeNotifications(
			BlockingQueue<StoreNotification> notifications, int count, long timeoutMillis)
			throws InterruptedException
	{
		return takeNotifications(notifications, count, timeoutMillis, notification -> true);
	}

	private static List<StoreNotification> takeNotifications(
			BlockingQueue<StoreNotification> notifications, int count, long timeoutMillis,
			Predicate<StoreNotification> predicate) throws InterruptedException
	{
		long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
		List<StoreNotification> received = new ArrayList<>();
		while (received.size() < count)
		{
			long remaining = deadline - System.nanoTime();
			StoreNotification notification = remaining <= 0 ? null :
					notifications.poll(remaining, TimeUnit.NANOSECONDS);
			assertNotNull("Timed out waiting for store notification " +
					(received.size() + 1) + " of " + count, notification);
			if (predicate.test(notification))
				received.add(notification);
		}
		return received;
	}

	private static void assertCrlFailureNotifications(List<StoreNotification> notifications,
			String cachedLocation, String missingLocation)
	{
		assertEquals(2, notifications.size());
		StoreNotification warning = findNotification(notifications, Severity.WARNING);
		assertEquals(StoreUpdateListener.CRL, warning.type);
		assertEquals(cachedLocation, warning.location);
		assertTrue(warning.cause instanceof IOException);
		assertTrue(warning.cause.getMessage().contains("cached copy"));

		StoreNotification error = findNotification(notifications, Severity.ERROR);
		assertEquals(StoreUpdateListener.CRL, error.type);
		assertEquals(missingLocation, error.location);
		assertTrue(error.cause instanceof IOException);
	}

	private static StoreNotification findNotification(List<StoreNotification> notifications,
			Severity level)
	{
		for (StoreNotification notification: notifications)
			if (notification.level == level)
				return notification;
		fail("No " + level + " notification found");
		return null;
	}

	private static int countNotifications(List<StoreNotification> notifications, Severity level)
	{
		int count = 0;
		for (StoreNotification notification: notifications)
			if (notification.level == level)
				count++;
		return count;
	}

	private static class StoreNotification
	{
		private final String location;
		private final String type;
		private final Severity level;
		private final Exception cause;

		private StoreNotification(String location, String type, Severity level, Exception cause)
		{
			this.location = location;
			this.type = type;
			this.level = level;
			this.cause = cause;
		}
	}
}
