/*
 * Copyright (c) 2026 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotSame;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class NativeOCSPResponseCacheTest
{
	private static final String DISK_KEY =
			"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

	@Rule
	public TemporaryFolder temporary = new TemporaryFolder();

	private AtomicLong now;
	private NativeOCSPResponseCache<String> cache;

	@Before
	public void setUp()
	{
		now = new AtomicLong(1000L);
		cache = new NativeOCSPResponseCache<String>(
				new NativeOCSPResponseCache.TimeSource()
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
		cache.put("response", new byte[] {1, 2, 3}, null, 2);

		now.set(2999L);
		assertArrayEquals(new byte[] {1, 2, 3}, cache.get("response", 2));
		now.set(3000L);
		assertThat(cache.get("response", 2), is(nullValue()));
	}

	@Test
	public void shouldExpireAtResponseLimitBeforeConfiguredTtl()
	{
		cache.put("response", new byte[] {1}, new Date(1500L), 60);

		now.set(1499L);
		assertArrayEquals(new byte[] {1}, cache.get("response", 60));
		now.set(1500L);
		assertThat(cache.get("response", 60), is(nullValue()));
	}

	@Test
	public void shouldTreatZeroTtlAsControlledOnlyByResponseValidity()
	{
		cache.put("response", new byte[] {1}, null, 0);
		now.set(Long.MAX_VALUE - 1);

		assertArrayEquals(new byte[] {1}, cache.get("response", 0));
	}

	@Test
	public void shouldDisableCachingForNegativeTtl()
	{
		cache.put("response", new byte[] {1}, null, -1);

		assertThat(cache.get("response", -1), is(nullValue()));
		assertThat(cache.size(), is(0));
	}

	@Test
	public void shouldCloneResponseBytesAtCacheBoundary()
	{
		byte[] original = {1, 2};
		cache.put("response", original, null, 60);
		original[0] = 9;

		byte[] first = cache.get("response", 60);
		byte[] second = cache.get("response", 60);
		assertArrayEquals(new byte[] {1, 2}, first);
		assertArrayEquals(new byte[] {1, 2}, second);
		assertNotSame(first, second);
	}

	@Test
	public void shouldBoundEntriesAndEvictTheLeastRecentlyUsed()
	{
		for (int i=0; i<NativeOCSPResponseCache.MAX_ENTRIES; i++)
			cache.put("response-" + i, new byte[] {(byte) i}, null, 60);
		cache.get("response-0", 60);
		cache.put("last", new byte[] {1}, null, 60);

		assertThat(cache.size(), is(NativeOCSPResponseCache.MAX_ENTRIES));
		assertThat(cache.get("response-1", 60), is(nullValue()));
		assertArrayEquals(new byte[] {0}, cache.get("response-0", 60));
	}

	@Test
	public void shouldPersistAndLoadAnEncodedResponse() throws Exception
	{
		File directory = temporary.newFolder("ocsp-cache");
		cache.put("memory-key", new byte[] {1, 2, 3}, new Date(9000L), 60,
				directory, DISK_KEY);
		NativeOCSPResponseCache<String> reloaded = newCache();

		assertArrayEquals(new byte[] {1, 2, 3}, reloaded.get("reloaded-key", 60,
				directory, DISK_KEY));
		File[] files = directory.listFiles();
		assertThat(files.length, is(1));
		assertThat(files[0].getName().matches(
				"ocspresp-v1-[0-9a-f]{64}\\.cache"), is(true));
	}

	@Test
	public void shouldDiscardCorruptPersistentEntry() throws Exception
	{
		File directory = temporary.newFolder("corrupt-cache");
		cache.put("memory-key", new byte[] {1, 2, 3}, null, 60,
				directory, DISK_KEY);
		File cacheFile = directory.listFiles()[0];
		Files.write(cacheFile.toPath(), "corrupt".getBytes(StandardCharsets.US_ASCII),
				StandardOpenOption.TRUNCATE_EXISTING);

		assertThat(newCache().get("reloaded-key", 60, directory, DISK_KEY),
				is(nullValue()));
		assertThat(cacheFile.exists(), is(false));
	}

	@Test
	public void shouldDiscardExpiredPersistentEntry() throws Exception
	{
		File directory = temporary.newFolder("expired-cache");
		cache.put("memory-key", new byte[] {1}, null, 2, directory, DISK_KEY);
		now.set(3000L);

		assertThat(newCache().get("reloaded-key", 2, directory, DISK_KEY),
				is(nullValue()));
		assertThat(directory.listFiles().length, is(0));
	}

	@Test
	public void shouldCreateConfiguredCacheDirectory() throws Exception
	{
		File directory = new File(temporary.getRoot(), "new/cache");

		cache.put("memory-key", new byte[] {1}, null, 60, directory, DISK_KEY);

		assertThat(directory.isDirectory(), is(true));
		assertThat(directory.listFiles().length, is(1));
	}

	private NativeOCSPResponseCache<String> newCache()
	{
		return new NativeOCSPResponseCache<String>(
				new NativeOCSPResponseCache.TimeSource()
				{
					@Override
					public long currentTimeMillis()
					{
						return now.get();
					}
				});
	}
}
