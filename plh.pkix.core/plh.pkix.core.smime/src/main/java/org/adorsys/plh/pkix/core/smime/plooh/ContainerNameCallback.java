package org.adorsys.plh.pkix.core.smime.plooh;

import javax.security.auth.callback.NameCallback;

public class ContainerNameCallback extends NameCallback {
	private static final long serialVersionUID = 4519106317997905423L;

	public ContainerNameCallback(String prompt) {
		super(prompt);
	}
}
