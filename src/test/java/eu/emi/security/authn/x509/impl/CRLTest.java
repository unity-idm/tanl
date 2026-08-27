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

import javax.security.auth.x500.X500Principal;

import static org.junit.Assert.*;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import com.sun.net.httpserver.HttpServer;

import eu.emi.security.authn.x509.RiskyIntegrationTests;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.helpers.ObserversHandler;
import eu.emi.security.authn.x509.helpers.crl.OpensslCRLStoreSpi;
import eu.emi.security.authn.x509.helpers.crl.PlainCRLStoreSpi;
import eu.emi.security.authn.x509.helpers.trust.OpensslTruststoreHelper;

public class CRLTest
{
	static
	{
		//Required as we call low-level code directly (OpensslCRLStoreSpi)
		CertificateUtils.configureSecProvider();
	}
	
	private int notificationOK;
	private int localPort;
	private int opensslWarn, opensslErr;
	
	
	private static File initDir() throws IOException
	{
		File dir = new File("target/test-tmp/crls/diskCache");
		FileUtils.deleteDirectory(dir);
		dir.mkdirs();
		return dir;
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
		
		CRLParameters params = new CRLParameters(crls, 250, 
				5000, dir.getPath());
		PlainCRLStoreSpi store = new PlainCRLStoreSpi(params, t, 
				new ObserversHandler());
		store.start();


		checkCRL("CN=the subca CA,OU=Relaxation,O=Utopia,L=Tropic,C=UG", store, 1);
		target.delete();
		Thread.sleep(500);
		checkCRL("CN=the subca CA,OU=Relaxation,O=Utopia,L=Tropic,C=UG", store, 0);
		
		store.dispose();
	}	
	
	
	@Test
	public void testNotificationsAndUpdate() throws Exception
	{
		File dir = initDir();
		
		Timer t = new Timer(true);
		List<String> crls = new ArrayList<String>();
		final String crlURL1 = "http://127.0.0.1/non-existing/crl.pem";
		final String crlURL2 = "http://127.0.0.1/non-existing2/crl2.pem";
		crls.add(crlURL1);
		crls.add(crlURL2);
		String base64URL = new String(Base64.encode(crlURL1.getBytes())) + "-crl.der";
		FileUtils.copyFile(new File("src/test/resources/test-pems/crls/relaxationsubca.crl"), 
				new File(dir, base64URL));
		
		CRLParameters params = new CRLParameters(crls, 500, 
				100, dir.getPath());
		notificationOK=0;
		StoreUpdateListener listener = new StoreUpdateListener()
		{
			public void loadingNotification(String crlLocation, String type, 
					Severity level,
					Exception cause)
			{
				assertEquals(type, StoreUpdateListener.CRL);
				if (level.equals(Severity.ERROR))
				{
					assertEquals(crlURL2, crlLocation);
					assertTrue(cause instanceof IOException);
					notificationOK++;
				} else if (level.equals(Severity.WARNING))
				{
					assertEquals(crlURL1, crlLocation);
					assertNotNull(cause);
					assertTrue(cause.toString(), cause instanceof IOException);
					assertTrue(cause.getMessage().contains("cached copy"));
					notificationOK++;
				}
			}
		};
		ObserversHandler observers = new ObserversHandler(Collections.singleton(listener));
		PlainCRLStoreSpi store = new PlainCRLStoreSpi(params, t, observers);
		store.start();

		assertEquals(2, notificationOK);
		observers.removeObserver(listener);
		observers.addObserver(listener);
		Thread.sleep(750);
		assertEquals(4, notificationOK);
		store.setUpdateInterval(-1);
		Thread.sleep(750);
		assertEquals(4, notificationOK);
		store.dispose();
	}
	
	@Test
	public void testTimeout() throws Exception
	{
		Thread server = new Thread()
		{
			public void run()
			{
				try
				{
					ServerSocket ss = new ServerSocket(0, 0,
							InetAddress.getByName("127.0.0.1"));
					localPort = ss.getLocalPort();
					Socket s = ss.accept();
					System.out.println("Got connection");
					Thread.sleep(5000);
					s.close();
					ss.close();
				} catch (Exception e)
				{
					fail(e.toString());
				}
			}
		};
		server.start();
		Thread.sleep(250);
		
		File dir = initDir();
		
		Timer t = new Timer(true);
		List<String> crls = new ArrayList<String>();
		final String crlURL1 = "http://127.0.0.1:"+ localPort + "/crl.pem";
		crls.add(crlURL1);
		CRLParameters params = new CRLParameters(crls, -1, 500, dir.getPath());
		notificationOK=0;
		StoreUpdateListener listener = new StoreUpdateListener()
		{
			public void loadingNotification(String crlLocation, String type, Severity level,
					Exception cause)
			{
				assertEquals(type, StoreUpdateListener.CRL);
				assertEquals(level, Severity.ERROR);
				assertEquals(crlURL1, crlLocation);
				assertTrue(cause instanceof SocketTimeoutException);
				System.out.println(crlLocation + " " + cause.toString());
				notificationOK++;
			}
		};
		long start = System.currentTimeMillis();
		PlainCRLStoreSpi store = new PlainCRLStoreSpi(params, t, new ObserversHandler(
				Collections.singleton(listener)));
		store.start();

		assertEquals(1, notificationOK);
		start = System.currentTimeMillis() - start;
		assertTrue(start < 500*3);
		store.dispose();
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
		opensslErr = 0;
		opensslWarn = 0;
		StoreUpdateListener listener = new StoreUpdateListener()
		{
			public void loadingNotification(String crlLocation, String type, Severity level,
					Exception cause)
			{
				assertEquals(type, StoreUpdateListener.CRL);
				if (level == Severity.ERROR)
					opensslErr++;
				else if (level == Severity.WARNING)
					opensslWarn++;
			}
		};
		
		OpensslCRLStoreSpi store = new OpensslCRLStoreSpi(
				"src/test/resources/openssl-testcrldir", -1, t, 
				new ObserversHandler(Collections.singleton(listener)));

		
		checkCRL("CN=the trusted CA,OU=Relaxation,O=Utopia,L=Tropic,C=UG", store, 1);
		assertEquals(1, opensslErr);
		assertEquals(0, opensslWarn);
		
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
}
