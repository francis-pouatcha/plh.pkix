package org.adorsys.plh.pkix.core.utils.store;

import javax.security.auth.callback.PasswordCallback;

public class KeyPassCallback extends PasswordCallback {
	private static final long serialVersionUID = 1837109236753415995L;
	public KeyPassCallback(String prompt, boolean echoOn) {
		super(prompt, echoOn);
	}
}
