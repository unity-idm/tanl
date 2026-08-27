/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.impl;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.CertPath;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

import static org.junit.Assert.*;

import org.apache.commons.io.FileUtils;
import org.junit.Test;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.ValidationError;
import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.emi.security.authn.x509.StoreUpdateListener.Severity;
import eu.emi.security.authn.x509.ValidationErrorListener;
import eu.emi.security.authn.x509.ValidationResult;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;

/**
 * Testing of {@link InMemoryKeystoreCertChainValidator} and {@link KeystoreCertChainValidator}
 * is done here. The tests are in fact designed also to test all their parent classes
 * which provide a lot o shared functionality also for other validators.
 * 
 * @author K. Benedyczak
 */
public class TestKSValidators
{
	public static File initDir() throws IOException
	{
		File dir = new File("target/test-tmp/truststores");
		FileUtils.deleteDirectory(dir);
		dir.mkdirs();
		return dir;
	}

	/**
	 * Tests creation, basic validation
	 */
	@Test
	public void testKeystoreValidator() throws Exception
	{
		String path = "src/test/resources/truststores/truststore1.jks";
		KeystoreCertChainValidator validator1 = new KeystoreCertChainValidator(
				path, "the!njs".toCharArray(), "JKS", -1, 
				new ValidatorParamsExt(RevocationParametersExt.IGNORE));
		X509Certificate[] toValidate = CertificateUtils.loadCertificateChain(
				new FileInputStream("src/test/resources/validator-certs/trusted_client.cert"), 
				Encoding.PEM);
		
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		CertPath certPath = factory.generateCertPath(Arrays.asList(toValidate));
		
		ValidationResult res = validator1.validate(toValidate);
		assertTrue(res.isValid());
		
		ValidationResult res1 = validator1.validate(certPath);
		assertTrue(res1.isValid());
		
		assertEquals(validator1.getTruststorePath(), path);
		validator1.dispose();
	}

	/**
	 * Tests creation, basic validation
	 */
	@Test
	public void testInMemoryKeystoreValidator() throws Exception
	{
		String path = "src/test/resources/truststores/truststore1.jks";
		KeyStore normalKs = KeyStore.getInstance("JKS");
		normalKs.load(new FileInputStream(path), "the!njs".toCharArray());
		InMemoryKeystoreCertChainValidator validator1 = new InMemoryKeystoreCertChainValidator(
				normalKs, 
				new ValidatorParamsExt(RevocationParametersExt.IGNORE));
		X509Certificate[] toValidate = CertificateUtils.loadCertificateChain(
				new FileInputStream("src/test/resources/validator-certs/trusted_client.cert"), 
				Encoding.PEM);
		
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		CertPath certPath = factory.generateCertPath(Arrays.asList(toValidate));
		
		ValidationResult res = validator1.validate(toValidate);
		assertTrue(res.isValid());
		
		ValidationResult res1 = validator1.validate(certPath);
		assertTrue(res1.isValid());
		
		KeyStore emptyKs = KeyStore.getInstance("JKS");
		emptyKs.load(null);
		validator1.setTruststore(emptyKs);
		ValidationResult res2 = validator1.validate(toValidate);
		assertFalse(res2.isValid());
		assertEquals(validator1.getTruststore(), emptyKs);
		validator1.dispose();
	}

	
	/**
	 * Tests creation, basic validation
	 */
	@Test
	public void testValidationListener() throws Exception
	{
		AtomicInteger validationErrors = new AtomicInteger();
		KeyStore emptyKs = KeyStore.getInstance("JKS");
		emptyKs.load(null);
		InMemoryKeystoreCertChainValidator validator1 = new InMemoryKeystoreCertChainValidator(
				emptyKs, 
				new ValidatorParamsExt(RevocationParametersExt.IGNORE));
		X509Certificate[] toValidate = CertificateUtils.loadCertificateChain(
				new FileInputStream("src/test/resources/validator-certs/trusted_client.cert"), 
				Encoding.PEM);
		
		ValidationErrorListener l1 = new ValidationErrorListener()
		{
			public void onValidationError(ValidationError error)
			{
				validationErrors.incrementAndGet();
				System.out.println("L1: " + error);
			}
		};
		ValidationErrorListener l2 = new ValidationErrorListener()
		{
			public void onValidationError(ValidationError error)
			{
				validationErrors.incrementAndGet();
				System.out.println("L2: " + error);
			}
		};
		validator1.addValidationListener(l1);
		
		validationErrors.set(0);
		ValidationResult res = validator1.validate(toValidate);
		assertFalse(res.isValid());
		assertEquals(1, validationErrors.get());
		
		validator1.addValidationListener(l2);
		validationErrors.set(0);
		ValidationResult res1 = validator1.validate(toValidate);
		assertFalse(res1.getErrors().toString(), res1.isValid());
		assertEquals(2, validationErrors.get());
		
		validator1.removeValidationListener(l1);
		validationErrors.set(0);
		ValidationResult res2 = validator1.validate(toValidate);
		assertFalse(res2.isValid());
		assertEquals(1, validationErrors.get());
		
		validator1.dispose();
	}

	
	/**
	 * Tests update and notifications
	 */
	@Test
	public void testKeystoreValidatorUpdate() throws Exception
	{
		File dir = initDir();
		File ks = new File(dir, "work.jks");
		FileUtils.copyFile(new File("src/test/resources/truststores/empty.jks"), ks);
		
		KeystoreCertChainValidator validator1 = new KeystoreCertChainValidator(
				ks.getPath(), "the!njs".toCharArray(), "JKS", -1, new ValidatorParamsExt(
				RevocationParametersExt.IGNORE));
		X509Certificate[] toValidate = CertificateUtils.loadCertificateChain(
				new FileInputStream("src/test/resources/validator-certs/trusted_client.cert"), 
				Encoding.PEM);
		BlockingQueue<StoreNotification> notifications = new LinkedBlockingQueue<>();
		validator1.addUpdateListener(recordingListener(notifications));
		
		try
		{
			ValidationResult res = validator1.validate(toValidate);
			assertFalse(res.isValid());

			validator1.setTruststoreUpdateInterval(25);
			FileUtils.copyFile(new File("src/test/resources/truststores/truststore1.jks"), ks);
			StoreNotification loaded = takeNotification(notifications,
					notification -> notification.level == Severity.NOTIFICATION, 2000);
			assertEquals(StoreUpdateListener.CA_CERT, loaded.type);
			assertEquals(ks.getPath(), loaded.location);
			assertNull(loaded.cause);

			ValidationResult res2 = validator1.validate(toValidate);
			assertTrue(res2.isValid());

			notifications.clear();
			assertTrue(ks.delete());
			StoreNotification failure = takeNotification(notifications,
					notification -> notification.level == Severity.ERROR, 2000);
			assertEquals(StoreUpdateListener.CA_CERT, failure.type);
			assertEquals(ks.getPath(), failure.location);
			assertTrue(failure.cause instanceof FileNotFoundException);
		} finally
		{
			validator1.dispose();
		}
	}
	
	/**
	 * Tests update and notifications
	 */
	@Test
	public void testKeystoreValidatorCRL() throws Exception
	{
		String path = "src/test/resources/truststores/truststore1.jks";
		KeystoreCertChainValidator validator1 = new KeystoreCertChainValidator(
				path, "the!njs".toCharArray(), "JKS", -1,  
				new ValidatorParamsExt(
					new RevocationParametersExt(CrlCheckingMode.REQUIRE, new CRLParameters(),
							new OCSPParametes(OCSPCheckingMode.IGNORE))));
		X509Certificate[] toValidate1 = CertificateUtils.loadCertificateChain(
				new FileInputStream("src/test/resources/validator-certs/trusted_client.cert"), 
				Encoding.PEM);
		X509Certificate[] toValidate2 = CertificateUtils.loadCertificateChain(
				new FileInputStream("src/test/resources/validator-certs/trusted_client_rev.cert"), 
				Encoding.PEM);
		
		ValidationResult res = validator1.validate(toValidate1);
		assertFalse(res.isValid());
		ValidationResult res2 = validator1.validate(toValidate2);
		assertFalse(res2.isValid());
		
		File dir = initDir();
		validator1.setCrls(Collections.singletonList(dir.getPath() + "/*.crl"));
		BlockingQueue<StoreNotification> notifications = new LinkedBlockingQueue<>();
		validator1.addUpdateListener(recordingListener(notifications));
		
		res = validator1.validate(toValidate1);
		assertFalse(res.isValid());
		res2 = validator1.validate(toValidate2);
		assertFalse(res2.isValid());
		
		validator1.setCRLUpdateInterval(25);
		FileUtils.copyFile(new File("src/test/resources/truststores/maincacrl.pem"), new File(dir, "crl1.crl"));
		StoreNotification loaded = takeNotification(notifications,
				notification -> notification.level == Severity.NOTIFICATION, 2000);
		assertEquals(StoreUpdateListener.CRL, loaded.type);
		assertNull(loaded.cause);
		
		res = validator1.validate(toValidate1);
		assertTrue(res.isValid());
		res2 = validator1.validate(toValidate2);
		assertFalse(res2.isValid());

		
		
		validator1.dispose();
	}
	
	/**
	 * Tests self-signed certificate which is not in the truststore.
	 * This should fail.
	 */
	@Test
	public void testInvalidSelfSigned() throws Exception
	{
		String path = "src/test/resources/truststores/empty.jks";
		KeystoreCertChainValidator validator1 = new KeystoreCertChainValidator(path, 
			"the!njs".toCharArray(), "JKS", -1);
		X509Certificate[] toValidate = new KeystoreCredential("src/test/resources/selfsigned.jks",
			"the!client".toCharArray(), "the!client".toCharArray(), "mykey", "JKS").getCertificateChain();
		ValidationResult res = validator1.validate(toValidate);
		assertFalse(res.isValid());
	}

	/**
	 * Tests self-signed certificate which is one of trust anchors
	 * Note: this should succeed as issuer (==the checked cert) is trusted
	 */
	@Test
	public void testSelfSignedTA() throws Exception
	{
		String path = "src/test/resources/selfsigned.jks";
		KeystoreCertChainValidator validator1 = new KeystoreCertChainValidator(path, 
			"the!client".toCharArray(), "JKS", -1);
		X509Certificate[] toValidate = new KeystoreCredential(path,
			"the!client".toCharArray(), "the!client".toCharArray(), "mykey", "JKS").getCertificateChain();
		ValidationResult res = validator1.validate(toValidate);
		assertTrue(res.isValid());
	}

	/**
	 * Tests non-self signed certificate which is one of trust anchors
	 * Note: this should fail as *issuer is not trusted*
	 */
	@Test
	public void testNonSelfSignedTA() throws Exception
	{
		String path = "src/test/resources/nonselfsigned.jks";
		KeystoreCertChainValidator validator1 = new KeystoreCertChainValidator(path, 
			"the!client".toCharArray(), "JKS", -1);
		X509Certificate[] toValidate = new KeystoreCredential(path,
			"the!client".toCharArray(), "the!client".toCharArray(), "httpclient", "JKS").getCertificateChain();
		ValidationResult res = validator1.validate(toValidate);
		System.out.println(res);
		assertFalse(res.isValid());
	}
	
	/**
	 * Simple test using PKCS12 as truststore
	 */
	@Test
	public void testPkcs12Truststore() throws Exception
	{
		String path = "src/test/resources/truststore.p12";
		KeystoreCertChainValidator validator1 = new KeystoreCertChainValidator(path, 
			"the!njs".toCharArray(), "PKCS12", -1);
		assertEquals(1, validator1.getTrustedIssuers().length);
	}	

	private static StoreUpdateListener recordingListener(
			BlockingQueue<StoreNotification> notifications)
	{
		return (location, type, level, cause) ->
				notifications.add(new StoreNotification(location, type, level, cause));
	}

	private static StoreNotification takeNotification(
			BlockingQueue<StoreNotification> notifications,
			Predicate<StoreNotification> predicate, long timeoutMillis)
			throws InterruptedException
	{
		long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
		while (true)
		{
			long remaining = deadline - System.nanoTime();
			StoreNotification notification = remaining <= 0 ? null :
					notifications.poll(remaining, TimeUnit.NANOSECONDS);
			assertNotNull("Timed out waiting for a matching store notification", notification);
			if (predicate.test(notification))
				return notification;
		}
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
