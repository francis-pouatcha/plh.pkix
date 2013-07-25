package org.adorsys.plh.pkix.core.utils.email;

import javax.mail.Authenticator;
import javax.mail.PasswordAuthentication;

public class PloohEmailAuthenticator extends Authenticator {

	private String userName;
	private String password;

	public PloohEmailAuthenticator(String userName, String password) {
		super();
		this.userName = userName;
		this.password = password;
	}

	@Override
	protected PasswordAuthentication getPasswordAuthentication() {
		return new PasswordAuthentication(userName, password);
	}
}
