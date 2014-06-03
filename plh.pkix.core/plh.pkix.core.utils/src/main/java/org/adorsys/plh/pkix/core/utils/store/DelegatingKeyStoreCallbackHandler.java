package org.adorsys.plh.pkix.core.utils.store;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * Delegate Callback to delete if value not set here.
 * 
 * @author francis
 */
public class DelegatingKeyStoreCallbackHandler implements CallbackHandler {

	private CallbackHandler delegate;
	private final char[] keyPass;
	private final char[] storePass;
	
	public DelegatingKeyStoreCallbackHandler(char[] keyPass, char[] storePass, CallbackHandler delegate) {
		this.keyPass = keyPass;
		this.storePass = storePass;
		this.delegate = delegate;
	}

	@Override
	public void handle(Callback[] callbacks) throws IOException,
			UnsupportedCallbackException {
		
		List<Callback> altCallbacks = new ArrayList<Callback>();
		
		for (int i = 0; i < callbacks.length; i++) {
			Callback callback = callbacks[i];
			if(callback instanceof StorePassCallback){
				if(storePass==null){
					altCallbacks.add(callback);
				} else {
					((StorePassCallback)callback).setPassword(storePass);
				}
			} else if (callback instanceof KeyPassCallback){
				if(keyPass==null){
					altCallbacks.add(callback);
				} else {
					((KeyPassCallback)callback).setPassword(keyPass);
				}
			} else {
				altCallbacks.add(callback);
			}
			
			if(!altCallbacks.isEmpty()){
				delegate.handle(altCallbacks.toArray(new Callback[altCallbacks.size()]));
			}
		}
	}
}
