/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package io.imunity.tanl.x509.helpers;

/**
 * Trivial implementation of {@link PasswordSupplier} which uses a password
 * provided to the constructor. 
 *
 * @author K. Benedyczak
 */
public class CharArrayPasswordFinder implements PasswordSupplier
{
	private transient char []password;
	
	public CharArrayPasswordFinder(char []password)
	{
		this.password = password;
	}

	@Override
	public char[] getPassword()
	{
		return password;
	}
}
