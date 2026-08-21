/*
 * Copyright (c) 2026 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.io.File;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import eu.emi.security.authn.x509.OCSPParametes;

public class NativeOCSPResponderFailureCacheTest
{
	private static final URI RESPONDER = URI.create("http://ocsp.example.test/status");

	@Rule
	public TemporaryFolder temporary = new TemporaryFolder();

	private AtomicLong now;
	private NativeOCSPResponderFailureCache cache;

	@Before
	public void setUp()
	{
		now = new AtomicLong(1000L);
		cache = new NativeOCSPResponderFailureCache(
				new NativeOCSPResponderFailureCache.TimeSource()
				{
					@Override
					public long currentTimeMillis()
					{
						return now.get();
					}
				});
	}

	@Test
	public void shouldExpireAtConfiguredTtlInSeconds()
	{
		cache.put(RESPONDER, 2, null);

		now.set(2999L);
		assertThat(cache.contains(RESPONDER, 2, null), is(true));
		now.set(3000L);
		assertThat(cache.contains(RESPONDER, 2, null), is(false));
	}

	@Test
	public void shouldBoundZeroTtlWithTheDefaultCachePeriod()
	{
		cache.put(RESPONDER, 0, null);

		now.set(1000L + OCSPParametes.DEFAULT_CACHE * 1000L - 1);
		assertThat(cache.contains(RESPONDER, 0, null), is(true));
		now.incrementAndGet();
		assertThat(cache.contains(RESPONDER, 0, null), is(false));
	}

	@Test
	public void shouldDisableFailureCachingForNegativeTtl()
	{
		cache.put(RESPONDER, -1, null);

		assertThat(cache.contains(RESPONDER, -1, null), is(false));
		assertThat(cache.size(), is(0));
	}

	@Test
	public void shouldKeyFailuresByResponder()
	{
		URI other = URI.create("http://ocsp.example.test/other");
		cache.put(RESPONDER, 60, null);

		assertThat(cache.contains(RESPONDER, 60, null), is(true));
		assertThat(cache.contains(other, 60, null), is(false));
	}

	@Test
	public void shouldBoundEntriesAndEvictTheLeastRecentlyUsed()
	{
		for (int i=0; i<NativeOCSPResponderFailureCache.MAX_ENTRIES; i++)
			cache.put(URI.create("http://ocsp.example.test/" + i), 60, null);
		URI first = URI.create("http://ocsp.example.test/0");
		URI second = URI.create("http://ocsp.example.test/1");
		cache.contains(first, 60, null);
		cache.put(URI.create("http://ocsp.example.test/last"), 60, null);

		assertThat(cache.size(), is(NativeOCSPResponderFailureCache.MAX_ENTRIES));
		assertThat(cache.contains(second, 60, null), is(false));
		assertThat(cache.contains(first, 60, null), is(true));
	}

	@Test
	public void shouldPersistAndLoadOnlyFailureMetadata() throws Exception
	{
		File directory = new File(temporary.getRoot(), "new/cache");
		cache.put(RESPONDER, 60, directory);
		NativeOCSPResponderFailureCache reloaded = newCache();

		assertThat(reloaded.contains(RESPONDER, 60, directory), is(true));
		File[] files = directory.listFiles();
		assertThat(files.length, is(1));
		assertThat(files[0].getName().matches(
				"ocspfail-v1-[0-9a-f]{64}\\.cache"), is(true));
		assertThat(files[0].length(), is(16L));
	}

	@Test
	public void shouldDiscardCorruptPersistentEntry() throws Exception
	{
		File directory = temporary.newFolder("corrupt-cache");
		cache.put(RESPONDER, 60, directory);
		File cacheFile = directory.listFiles()[0];
		Files.write(cacheFile.toPath(), "corrupt".getBytes(StandardCharsets.US_ASCII),
				StandardOpenOption.TRUNCATE_EXISTING);

		assertThat(newCache().contains(RESPONDER, 60, directory), is(false));
		assertThat(cacheFile.exists(), is(false));
	}

	@Test
	public void shouldRemoveMemoryAndPersistentEntries() throws Exception
	{
		File directory = temporary.newFolder("remove-cache");
		cache.put(RESPONDER, 60, directory);

		cache.remove(RESPONDER, directory);

		assertThat(cache.contains(RESPONDER, 60, directory), is(false));
		assertThat(directory.listFiles().length, is(0));
	}

	private NativeOCSPResponderFailureCache newCache()
	{
		return new NativeOCSPResponderFailureCache(
				new NativeOCSPResponderFailureCache.TimeSource()
				{
					@Override
					public long currentTimeMillis()
					{
						return now.get();
					}
				});
	}
}
