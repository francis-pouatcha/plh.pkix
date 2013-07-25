package org.adorsys.plh.pkix.core.smime.plooh;

/**
 * A call back handler used to load a key from a key store.
 * 
 * @author fpo
 *
 */
public interface KeyStorePasswordsCallbackHandler {
	
	public char[] getKeyPass();
	
	public char[] getStorePass();

}
