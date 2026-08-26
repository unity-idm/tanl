/*
 * Copyright (c) 2012-2026 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.emi.security.authn.x509.helpers.pkipath;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.encoders.Base64;

import eu.emi.security.authn.x509.helpers.BinaryCertChainValidator;
import eu.emi.security.authn.x509.helpers.ssl.DisabledNameMismatchCallback;
import eu.emi.security.authn.x509.impl.SocketFactoryCreator2;

/**
 * Creates unsigned OCSP requests and performs bounded HTTP transport. Response
 * authentication and certificate-status decisions belong exclusively to the
 * native BC PKIX validator.
 */
final class NativeOCSPClient
{
	private static final Charset ASCII = Charset.forName("US-ASCII");
	private static final int MAX_RESPONSE_SIZE = 20480;
	private static final SecureRandom NONCE_RANDOM = new SecureRandom();

	static final class Response
	{
		private final OCSPResp response;
		private final Date maxCache;

		private Response(OCSPResp response, Date maxCache)
		{
			this.response = response;
			this.maxCache = maxCache;
		}

		OCSPResp getResponse()
		{
			return response;
		}

		Date getMaxCache()
		{
			return maxCache;
		}
	}

	static final class ResponseDecodingException extends IOException
	{
		private static final long serialVersionUID = 1L;

		private ResponseDecodingException(String message)
		{
			super(message);
		}

		private ResponseDecodingException(String message, Throwable cause)
		{
			super(message, cause);
		}
	}

	static final class HTTPException extends IOException
	{
		private static final long serialVersionUID = 1L;
		private final int statusCode;

		private HTTPException(int statusCode)
		{
			super("OCSP responder returned HTTP status " + statusCode);
			this.statusCode = statusCode;
		}

		int getStatusCode()
		{
			return statusCode;
		}
	}

	OCSPReq createRequest(X509Certificate certificate, X509Certificate issuer,
			boolean addNonce) throws OCSPException
	{
		OCSPReqBuilder builder = new OCSPReqBuilder();
		try
		{
			DigestCalculator digest = new BcDigestCalculatorProvider().get(
					CertificateID.HASH_SHA1);
			X509CertificateHolder issuerHolder =
					new JcaX509CertificateHolder(issuer);
			builder.addRequest(new CertificateID(digest, issuerHolder,
					certificate.getSerialNumber()));
		} catch (OperatorCreationException e)
		{
			throw new OCSPException("Problem creating OCSP request digester", e);
		} catch (CertificateEncodingException e)
		{
			throw new OCSPException("Issuer certificate is unsupported", e);
		}

		if (addNonce)
		{
			byte[] nonce = new byte[16];
			NONCE_RANDOM.nextBytes(nonce);
			builder.setRequestExtensions(new Extensions(new Extension(
					OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
					new DEROctetString(nonce))));
		}
		return builder.build();
	}

	Response send(URL responder, OCSPReq requestObject, int timeout)
			throws IOException
	{
		byte[] request = requestObject.getEncoded();
		HttpURLConnection connection;
		String getUrl = getHttpGetUrl(responder, request);
		if (getUrl == null)
			connection = doPost(responder, request, timeout);
		else
		{
			connection = (HttpURLConnection) URI.create(getUrl).toURL().openConnection();
			configureHttpConnection(connection, timeout);
		}

		byte[] response;
		Date maxCache;
		int statusCode = connection.getResponseCode();
		if (statusCode < 200 || statusCode >= 300)
		{
			connection.disconnect();
			throw new HTTPException(statusCode);
		}
		try (InputStream input = connection.getInputStream())
		{
			int contentLength = connection.getContentLength();
			if (contentLength == -1 || contentLength > MAX_RESPONSE_SIZE)
				contentLength = MAX_RESPONSE_SIZE;
			maxCache = getNextUpdateFromCacheHeader(
					connection.getHeaderField("cache-control"));
			response = new byte[contentLength];
			int total = 0;
			int count = 0;
			while (total < contentLength)
			{
				count = input.read(response, total, response.length-total);
				if (count < 0)
					break;
				total += count;
			}
			if (count >= 0 && input.read() >= 0)
				throw new ResponseDecodingException(
						"OCSP response size exceeded the upper limit of " +
						MAX_RESPONSE_SIZE);
			if (total != contentLength)
				response = Arrays.copyOf(response, total);
		}

		try
		{
			return new Response(new OCSPResp(response), maxCache);
		} catch (IOException e)
		{
			throw new ResponseDecodingException(
					"Can not decode the OCSP response", e);
		}
	}

	private void configureHttpConnection(HttpURLConnection connection, int timeout)
	{
		if (connection instanceof HttpsURLConnection)
		{
			HttpsURLConnection https = (HttpsURLConnection) connection;
			BinaryCertChainValidator trustAll = new BinaryCertChainValidator(true);
			SSLSocketFactory factory = new SocketFactoryCreator2(trustAll,
					new DisabledNameMismatchCallback()).getSocketFactory();
			https.setSSLSocketFactory(factory);
		}
		connection.setConnectTimeout(timeout);
		connection.setReadTimeout(timeout);
	}

	private String getHttpGetUrl(URL responder, byte[] request)
	{
		if (responder.toExternalForm().length()+request.length > 255)
			return null;
		String encoded = new String(Base64.encode(request), ASCII);
		try
		{
			encoded = URLEncoder.encode(encoded, ASCII.name());
		} catch (UnsupportedEncodingException e)
		{
			throw new IllegalStateException("US-ASCII encoding is unavailable", e);
		}
		String url = responder.toExternalForm();
		String result = url.endsWith("/") ? url+encoded : url+"/"+encoded;
		return result.length() > 255 ? null : result;
	}

	private HttpURLConnection doPost(URL responder, byte[] request, int timeout)
			throws IOException
	{
		HttpURLConnection connection =
				(HttpURLConnection) responder.openConnection();
		configureHttpConnection(connection, timeout);
		connection.setDoOutput(true);
		connection.setRequestMethod("POST");
		connection.setRequestProperty("Content-type", "application/ocsp-request");
		connection.setRequestProperty("Content-length",
				String.valueOf(request.length));
		try (OutputStream output = connection.getOutputStream())
		{
			output.write(request);
			output.flush();
		}
		return connection;
	}

	private Date getNextUpdateFromCacheHeader(String cacheControl)
	{
		if (cacheControl == null)
			return null;
		int start = cacheControl.indexOf("max-age=");
		if (start == -1)
			return null;
		start += 8;
		int end = cacheControl.indexOf(",", start);
		if (end == -1)
			end = cacheControl.length();
		try
		{
			int seconds = Integer.parseInt(
					cacheControl.substring(start, end).trim());
			return new Date(System.currentTimeMillis()+seconds*1000L);
		} catch (NumberFormatException e)
		{
			return null;
		}
	}
}
