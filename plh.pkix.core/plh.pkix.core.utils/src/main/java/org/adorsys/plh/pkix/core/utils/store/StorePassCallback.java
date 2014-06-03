package org.adorsys.plh.pkix.core.utils.store;

import javax.security.auth.callback.PasswordCallback;

public class StorePassCallback extends PasswordCallback {

	private static final long serialVersionUID = 9199402557601862250L;

	public StorePassCallback(String prompt, boolean echoOn) {
		super(prompt, echoOn);
	}

}
