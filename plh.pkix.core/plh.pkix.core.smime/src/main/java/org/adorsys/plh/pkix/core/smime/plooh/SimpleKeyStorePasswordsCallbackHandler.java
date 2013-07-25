package org.adorsys.plh.pkix.core.smime.plooh;

public final class SimpleKeyStorePasswordsCallbackHandler implements
		KeyStorePasswordsCallbackHandler {
	
	private char[] keyPass;
	private char[] storePass;

	
	public SimpleKeyStorePasswordsCallbackHandler(char[] keyPass,
			char[] storePass) {
		this.keyPass = keyPass;
		this.storePass = storePass;
	}

	public SimpleKeyStorePasswordsCallbackHandler() {
		super();
	}

	public void setKeyPass(char[] keyPass) {
		this.keyPass = keyPass;
	}

	public void setStorePass(char[] storePass) {
		this.storePass = storePass;
	}

	@Override
	public char[] getKeyPass() {
		return this.keyPass;
	}

	@Override
	public char[] getStorePass() {
		return this.storePass;
	}

}
