package org.adorsys.plh.pkix.core.smime.plooh;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.adorsys.plh.pkix.core.utils.store.KeyPassCallback;
import org.adorsys.plh.pkix.core.utils.store.StorePassCallback;

public class FileContainerCallbackHandler implements CallbackHandler {

	private String email;
	private String containerName;
	
	private CallbackHandler keystoreCallbackHandler;
	
	public FileContainerCallbackHandler(String email, String containerName,
			CallbackHandler keystoreCallbackHandler) {
		this.email = email;
		this.containerName = containerName;
		assert keystoreCallbackHandler!=null:"parameter keystoreCallbackHandler can not be null";
		this.keystoreCallbackHandler = keystoreCallbackHandler;
		assert containerName!=null:"parameter containerName can not be null";
		this.containerName = containerName;
	}


	@Override
	public void handle(Callback[] callbacks) throws IOException,
			UnsupportedCallbackException {
		
		List<Callback> keyStoreCallbacks = new ArrayList<Callback>();
		
		for (int i = 0; i < callbacks.length; i++) {
			Callback callback = callbacks[i];
			if(callback instanceof StorePassCallback){
				keyStoreCallbacks.add(callback);
			} else if (callback instanceof KeyPassCallback){
				keyStoreCallbacks.add(callback);
			} else if (callback instanceof EmailCallback){
				((EmailCallback)callback).setName(email);
			} else if (callback instanceof ContainerNameCallback){
				((ContainerNameCallback)callback).setName(containerName);
			} else {
				throw new UnsupportedCallbackException(callback);
			}
		}
		if(!keyStoreCallbacks.isEmpty()){
			keystoreCallbackHandler.handle(keyStoreCallbacks.toArray(new Callback[keyStoreCallbacks.size()]));
		}
	}

}
