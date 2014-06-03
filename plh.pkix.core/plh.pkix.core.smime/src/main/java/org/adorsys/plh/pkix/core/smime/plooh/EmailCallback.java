package org.adorsys.plh.pkix.core.smime.plooh;

import javax.security.auth.callback.NameCallback;

public class EmailCallback extends NameCallback {

	private static final long serialVersionUID = -9146570502337431654L;

	public EmailCallback(String prompt) {
		super(prompt);
	}
}
