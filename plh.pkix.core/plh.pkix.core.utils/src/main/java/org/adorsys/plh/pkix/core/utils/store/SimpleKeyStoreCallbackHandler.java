package org.adorsys.plh.pkix.core.utils.store;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

public class SimpleKeyStoreCallbackHandler implements CallbackHandler {
	
	private final char[] keyPass;
	private final char[] storePass;
	
	public SimpleKeyStoreCallbackHandler(char[] keyPass, char[] storePass) {
		super();
		this.keyPass = keyPass;
		this.storePass = storePass;
	}

	@Override
	public void handle(Callback[] callbacks) throws IOException,
			UnsupportedCallbackException {
		for (int i = 0; i < callbacks.length; i++) {
			Callback callback = callbacks[i];
			if(callback instanceof StorePassCallback){
				((StorePassCallback)callback).setPassword(storePass);
			} else if (callback instanceof KeyPassCallback){
				((KeyPassCallback)callback).setPassword(keyPass);
//			} else {
//				throw new UnsupportedCallbackException(callback);
			}
		}

	}
}
