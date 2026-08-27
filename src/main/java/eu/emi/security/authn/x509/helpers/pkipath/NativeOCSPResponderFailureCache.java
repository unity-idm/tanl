/*
 * Copyright (c) 2026 Bixbit - Krzysztof Benedyczak. All rights reserved.
 * See LICENSE.txt for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;

import eu.emi.security.authn.x509.OCSPParametes;

/**
 * Bounded cache of OCSP responders which recently failed at the HTTP
 * transport boundary. Persistent entries contain timestamps only.
 */
final class NativeOCSPResponderFailureCache
{
	static final int MAX_ENTRIES = 100;
	private static final int MAGIC = 0x434f4643;
	private static final int VERSION = 1;
	private static final int ENTRY_SIZE = 16;
	private static final String FILE_PREFIX = "ocspfail-v1-";
	private static final String FILE_SUFFIX = ".cache";

	interface TimeSource
	{
		long currentTimeMillis();
	}

	private final Map<URI, Entry> entries = new LinkedHashMap<URI, Entry>(
			20, 0.75f, true)
	{
		private static final long serialVersionUID = 1L;

		@Override
		protected boolean removeEldestEntry(Map.Entry<URI,
				NativeOCSPResponderFailureCache.Entry> eldest)
		{
			return size() > MAX_ENTRIES;
		}
	};
	private final TimeSource timeSource;

	NativeOCSPResponderFailureCache()
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

	NativeOCSPResponderFailureCache(TimeSource timeSource)
	{
		if (timeSource == null)
			throw new IllegalArgumentException("Time source must not be null");
		this.timeSource = timeSource;
	}

	synchronized boolean contains(URI responder, int cacheTtlSeconds,
			File diskDirectory)
	{
		if (cacheTtlSeconds < 0)
			return false;
		Entry entry = entries.get(responder);
		if (entry == null)
		{
			entry = load(diskDirectory, responder);
			if (entry != null)
				entries.put(responder, entry);
		}
		if (entry == null)
			return false;
		if (timeSource.currentTimeMillis() >= expiry(entry.cachedAt,
				cacheTtlSeconds))
		{
			entries.remove(responder);
			delete(diskDirectory, responder);
			return false;
		}
		return true;
	}

	synchronized void put(URI responder, int cacheTtlSeconds,
			File diskDirectory)
	{
		if (cacheTtlSeconds < 0)
			return;
		if (responder == null)
			throw new IllegalArgumentException("Responder must not be null");
		Entry entry = new Entry(timeSource.currentTimeMillis());
		entries.put(responder, entry);
		store(diskDirectory, responder, entry);
	}

	synchronized void remove(URI responder, File diskDirectory)
	{
		entries.remove(responder);
		delete(diskDirectory, responder);
	}

	synchronized int size()
	{
		return entries.size();
	}

	private long expiry(long cachedAt, int cacheTtlSeconds)
	{
		long effectiveTtl = cacheTtlSeconds == 0 ?
				OCSPParametes.DEFAULT_CACHE : cacheTtlSeconds;
		long ttlMillis = effectiveTtl * 1000L;
		if (Long.MAX_VALUE - cachedAt < ttlMillis)
			return Long.MAX_VALUE;
		return cachedAt + ttlMillis;
	}

	private Entry load(File diskDirectory, URI responder)
	{
		Path file = cacheFile(diskDirectory, responder);
		if (file == null || !Files.isDirectory(diskDirectory.toPath(),
				LinkOption.NOFOLLOW_LINKS) ||
				!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS))
			return null;
		try
		{
			if (Files.size(file) != ENTRY_SIZE)
				throw new IOException("Invalid OCSP responder failure entry size");
			DataInputStream input = new DataInputStream(new BufferedInputStream(
					Files.newInputStream(file, StandardOpenOption.READ,
							LinkOption.NOFOLLOW_LINKS)));
			try
			{
				if (input.readInt() != MAGIC || input.readInt() != VERSION)
					throw new IOException(
							"Invalid OCSP responder failure entry header");
				long cachedAt = input.readLong();
				if (cachedAt < 0 || cachedAt > timeSource.currentTimeMillis())
					throw new IOException(
							"Invalid OCSP responder failure entry timestamp");
				return new Entry(cachedAt);
			} finally
			{
				input.close();
			}
		} catch (IOException e)
		{
			delete(diskDirectory, responder);
			return null;
		} catch (RuntimeException e)
		{
			delete(diskDirectory, responder);
			return null;
		}
	}

	private void store(File diskDirectory, URI responder, Entry entry)
	{
		Path file = cacheFile(diskDirectory, responder);
		if (file == null)
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
			// Persistence is an optimization; the memory entry remains usable.
		} catch (RuntimeException e)
		{
			// Treat filesystem/provider runtime failures as an unavailable cache.
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

	private void delete(File diskDirectory, URI responder)
	{
		Path file = cacheFile(diskDirectory, responder);
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

	private Path cacheFile(File diskDirectory, URI responder)
	{
		if (diskDirectory == null || responder == null)
			return null;
		return diskDirectory.toPath().resolve(FILE_PREFIX + diskKey(responder) +
				FILE_SUFFIX);
	}

	private String diskKey(URI responder)
	{
		try
		{
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] value = responder.toASCIIString().getBytes(StandardCharsets.UTF_8);
			digest.update((byte) (value.length >>> 24));
			digest.update((byte) (value.length >>> 16));
			digest.update((byte) (value.length >>> 8));
			digest.update((byte) value.length);
			byte[] encoded = digest.digest(value);
			char[] result = new char[encoded.length * 2];
			char[] digits = "0123456789abcdef".toCharArray();
			for (int i=0; i<encoded.length; i++)
			{
				int unsigned = encoded[i] & 0xff;
				result[i*2] = digits[unsigned >>> 4];
				result[i*2+1] = digits[unsigned & 0x0f];
			}
			return new String(result);
		} catch (NoSuchAlgorithmException e)
		{
			throw new IllegalStateException("SHA-256 digest is unavailable", e);
		}
	}

	private static final class Entry
	{
		private final long cachedAt;

		private Entry(long cachedAt)
		{
			this.cachedAt = cachedAt;
		}
	}
}
