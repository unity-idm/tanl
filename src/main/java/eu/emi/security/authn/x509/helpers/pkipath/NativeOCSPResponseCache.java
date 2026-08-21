/*
 * Copyright (c) 2026 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Bounded in-memory cache of encoded, natively validated OCSP responses.
 */
final class NativeOCSPResponseCache<K>
{
	static final int MAX_ENTRIES = 100;

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
		if (cacheTtlSeconds < 0)
			return null;
		Entry entry = entries.get(key);
		if (entry == null)
			return null;

		long expiresAt = configuredExpiry(entry.cachedAt, cacheTtlSeconds);
		if (entry.responseExpiry != null)
			expiresAt = Math.min(expiresAt, entry.responseExpiry.getTime());
		if (timeSource.currentTimeMillis() >= expiresAt)
		{
			entries.remove(key);
			return null;
		}
		return entry.response.clone();
	}

	synchronized void put(K key, byte[] response, Date responseExpiry,
			int cacheTtlSeconds)
	{
		if (cacheTtlSeconds < 0)
			return;
		if (key == null || response == null)
			throw new IllegalArgumentException("Cache key and response must not be null");
		entries.put(key, new Entry(response.clone(), timeSource.currentTimeMillis(),
				responseExpiry == null ? null : new Date(responseExpiry.getTime())));
	}

	synchronized void remove(K key)
	{
		entries.remove(key);
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
