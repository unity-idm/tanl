/*
 * Copyright (c) 2026 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Bounded in-memory cache of encoded, natively validated OCSP responses.
 */
final class NativeOCSPResponseCache<K>
{
	static final int MAX_ENTRIES = 100;
	private static final int MAGIC = 0x434f4353;
	private static final int VERSION = 1;
	private static final int HEADER_SIZE = 28;
	private static final int MAX_RESPONSE_SIZE = 64 * 1024;
	private static final String FILE_PREFIX = "ocspresp-v1-";
	private static final String FILE_SUFFIX = ".cache";

	interface TimeSource
	{
		long currentTimeMillis();
	}

	private final Map<K, Entry> entries = new LinkedHashMap<K, Entry>(
			20, 0.75f, true)
	{
		private static final long serialVersionUID = 1L;

		@Override
		protected boolean removeEldestEntry(Map.Entry<K, Entry> eldest)
		{
			return size() > MAX_ENTRIES;
		}
	};
	private final TimeSource timeSource;

	NativeOCSPResponseCache()
	{
		this(new TimeSource()
		{
			@Override
			public long currentTimeMillis()
			{
				return System.currentTimeMillis();
			}
		});
	}

	NativeOCSPResponseCache(TimeSource timeSource)
	{
		if (timeSource == null)
			throw new IllegalArgumentException("Time source must not be null");
		this.timeSource = timeSource;
	}

	synchronized byte[] get(K key, int cacheTtlSeconds)
	{
		return get(key, cacheTtlSeconds, null, null);
	}

	synchronized byte[] get(K key, int cacheTtlSeconds,
			File diskDirectory, String diskKey)
	{
		if (cacheTtlSeconds < 0)
			return null;
		Entry entry = entries.get(key);
		if (entry == null)
		{
			entry = load(diskDirectory, diskKey);
			if (entry != null)
				entries.put(key, entry);
		}
		if (entry == null)
			return null;

		long expiresAt = configuredExpiry(entry.cachedAt, cacheTtlSeconds);
		if (entry.responseExpiry != null)
			expiresAt = Math.min(expiresAt, entry.responseExpiry.getTime());
		if (timeSource.currentTimeMillis() >= expiresAt)
		{
			entries.remove(key);
			delete(diskDirectory, diskKey);
			return null;
		}
		return entry.response.clone();
	}

	synchronized void put(K key, byte[] response, Date responseExpiry,
			int cacheTtlSeconds)
	{
		put(key, response, responseExpiry, cacheTtlSeconds, null, null);
	}

	synchronized void put(K key, byte[] response, Date responseExpiry,
			int cacheTtlSeconds, File diskDirectory, String diskKey)
	{
		if (cacheTtlSeconds < 0)
			return;
		if (key == null || response == null)
			throw new IllegalArgumentException("Cache key and response must not be null");
		Entry entry = new Entry(response.clone(), timeSource.currentTimeMillis(),
				responseExpiry == null ? null : new Date(responseExpiry.getTime()));
		entries.put(key, entry);
		store(diskDirectory, diskKey, entry);
	}

	synchronized void remove(K key)
	{
		remove(key, null, null);
	}

	synchronized void remove(K key, File diskDirectory, String diskKey)
	{
		entries.remove(key);
		delete(diskDirectory, diskKey);
	}

	synchronized int size()
	{
		return entries.size();
	}

	private long configuredExpiry(long cachedAt, int cacheTtlSeconds)
	{
		if (cacheTtlSeconds == 0)
			return Long.MAX_VALUE;
		long ttlMillis = cacheTtlSeconds * 1000L;
		if (Long.MAX_VALUE - cachedAt < ttlMillis)
			return Long.MAX_VALUE;
		return cachedAt + ttlMillis;
	}

	private Entry load(File diskDirectory, String diskKey)
	{
		Path file = cacheFile(diskDirectory, diskKey);
		if (file == null || !Files.isDirectory(diskDirectory.toPath(),
				LinkOption.NOFOLLOW_LINKS) ||
				!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS))
			return null;
		try
		{
			long size = Files.size(file);
			if (size < HEADER_SIZE || size > HEADER_SIZE + MAX_RESPONSE_SIZE)
				throw new IOException("Invalid OCSP cache entry size");
			DataInputStream input = new DataInputStream(new BufferedInputStream(
					Files.newInputStream(file, StandardOpenOption.READ,
							LinkOption.NOFOLLOW_LINKS)));
			try
			{
				if (input.readInt() != MAGIC || input.readInt() != VERSION)
					throw new IOException("Invalid OCSP cache entry header");
				long cachedAt = input.readLong();
				long expiryMillis = input.readLong();
				int responseLength = input.readInt();
				if (cachedAt < 0 || cachedAt > timeSource.currentTimeMillis() ||
						expiryMillis < -1 ||
						responseLength <= 0 || responseLength > MAX_RESPONSE_SIZE ||
						size != HEADER_SIZE + responseLength)
					throw new IOException("Invalid OCSP cache entry metadata");
				byte[] response = new byte[responseLength];
				input.readFully(response);
				Date expiry = expiryMillis < 0 ? null : new Date(expiryMillis);
				return new Entry(response, cachedAt, expiry);
			} finally
			{
				input.close();
			}
		} catch (IOException e)
		{
			delete(diskDirectory, diskKey);
			return null;
		} catch (RuntimeException e)
		{
			delete(diskDirectory, diskKey);
			return null;
		}
	}

	private void store(File diskDirectory, String diskKey, Entry entry)
	{
		Path file = cacheFile(diskDirectory, diskKey);
		if (file == null || entry.response.length > MAX_RESPONSE_SIZE)
			return;
		Path directory = diskDirectory.toPath();
		Path temporary = null;
		try
		{
			Files.createDirectories(directory);
			if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS))
				return;
			temporary = Files.createTempFile(directory, FILE_PREFIX, ".tmp");
			DataOutputStream output = new DataOutputStream(new BufferedOutputStream(
					Files.newOutputStream(temporary, StandardOpenOption.WRITE,
							StandardOpenOption.TRUNCATE_EXISTING)));
			try
			{
				output.writeInt(MAGIC);
				output.writeInt(VERSION);
				output.writeLong(entry.cachedAt);
				output.writeLong(entry.responseExpiry == null ? -1L :
						entry.responseExpiry.getTime());
				output.writeInt(entry.response.length);
				output.write(entry.response);
			} finally
			{
				output.close();
			}
			try
			{
				Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE,
						StandardCopyOption.REPLACE_EXISTING);
			} catch (AtomicMoveNotSupportedException e)
			{
				Files.move(temporary, file, StandardCopyOption.REPLACE_EXISTING);
			}
			temporary = null;
		} catch (IOException e)
		{
			// Persistence is an optimization. The validated in-memory entry
			// remains usable when the configured directory can not be written.
		} catch (RuntimeException e)
		{
			// Treat filesystem/provider runtime failures like an unavailable cache.
		} finally
		{
			if (temporary != null)
				try
				{
					Files.deleteIfExists(temporary);
				} catch (IOException e)
				{
					// Best effort cleanup of a cache-local temporary file.
				}
		}
	}

	private void delete(File diskDirectory, String diskKey)
	{
		Path file = cacheFile(diskDirectory, diskKey);
		if (file == null)
			return;
		try
		{
			Files.deleteIfExists(file);
		} catch (IOException e)
		{
			// A stale cache file can be ignored safely.
		} catch (RuntimeException e)
		{
			// A stale cache file can be ignored safely.
		}
	}

	private Path cacheFile(File diskDirectory, String diskKey)
	{
		if (diskDirectory == null || diskKey == null ||
				!diskKey.matches("[0-9a-f]{64}"))
			return null;
		return diskDirectory.toPath().resolve(FILE_PREFIX + diskKey + FILE_SUFFIX);
	}

	private static final class Entry
	{
		private final byte[] response;
		private final long cachedAt;
		private final Date responseExpiry;

		private Entry(byte[] response, long cachedAt, Date responseExpiry)
		{
			this.response = response;
			this.cachedAt = cachedAt;
			this.responseExpiry = responseExpiry;
		}
	}
}
