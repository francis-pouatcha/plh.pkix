package org.adorsys.plh.pkix.core.smime.plooh;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.adorsys.plh.pkix.core.smime.store.FileContainerImpl;
import org.adorsys.plh.pkix.core.utils.X500NameHelper;
import org.adorsys.plh.pkix.core.utils.jca.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.FilesContainer;
import org.adorsys.plh.pkix.core.utils.store.KeyPassCallback;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.adorsys.plh.pkix.core.utils.store.StorePassCallback;
import org.adorsys.plh.pkix.core.utils.store.UnprotectedFileWraper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.jboss.weld.exceptions.IllegalStateException;

/**
 * Provides factory methods for pki protected file containers.
 * 
 * @author fpo
 *
 */
public final class FileContainerFactory {
	public static final String CONTAINER_KEY_STORE_FILE_NAME="containerKeyStore";
	
	/**
	 * The KeyStore container can be unprotected (in case of a device) or protected (in the case of an account.
	 * We use the containerKeyPass and the containerStorePass to protect access to the KeyStore.
	 * 
	 * @param containerDataCallbackHandler
	 * @param containerType
	 * @param containerDir
	 * @param keyStorePasswordsCallbackHandler
	 * @return
	 */
	public static FilesContainer createFilesContainer(
			ContainerType containerType, 
			File containerDir, 
			FileWrapper containerDirWrapper, CallbackHandler callbackHandler)
	{
		FileWrapper keyStoreFileWraper = null;
		if(containerDirWrapper!=null){
			keyStoreFileWraper = containerDirWrapper.newChild(CONTAINER_KEY_STORE_FILE_NAME);
		} else {
			keyStoreFileWraper = new UnprotectedFileWraper(CONTAINER_KEY_STORE_FILE_NAME, containerDir);
		}
		
		KeyStoreWraper containerKeyStoreWraper = getContainerKeyStoreWraper(keyStoreFileWraper, callbackHandler);

		ContainerNameCallback nameCallback = new ContainerNameCallback("Enter container name: ");
		EmailCallback emailCallback = new EmailCallback("Enter container email: ");
		Callback[] callbacks = new Callback[]{nameCallback, emailCallback};
		try {
			callbackHandler.handle(callbacks);
		} catch (IOException | UnsupportedCallbackException e) {
			throw new IllegalStateException(e);
		}
		
		String fileContainerName = nameCallback.getName();
		String email = emailCallback.getName();
		X500Name containerX500Name = X500NameHelper.makeX500Name(fileContainerName,email,null, containerType.name());
		List<String> urls = new ArrayList<String>();
		urls.add(containerDir.toURI().toString());
		GeneralNames subjectAlternativeNames = X500NameHelper.makeSubjectAlternativeName(containerX500Name, Arrays.asList(email), urls);
		new KeyPairBuilder()
			.withEndEntityName(containerX500Name)
			.withSubjectAlternativeNames(subjectAlternativeNames)
			.withKeyStoreWraper(containerKeyStoreWraper)
			.build();
		
		return new FileContainerImpl(containerKeyStoreWraper, containerDir);
	}

	public static FilesContainer loadFilesContainer(File containerDir,
			FileWrapper containerDirWrapper, CallbackHandler callbackHandler){
		FileWrapper keyStoreFileWraper = null;
		if(containerDirWrapper!=null){
			keyStoreFileWraper = containerDirWrapper.newChild(CONTAINER_KEY_STORE_FILE_NAME);
		} else {
			keyStoreFileWraper = new UnprotectedFileWraper(CONTAINER_KEY_STORE_FILE_NAME, containerDir);
		}
		KeyStoreWraper containerKeyStoreWraper = getContainerKeyStoreWraper(keyStoreFileWraper, callbackHandler);
		return new FileContainerImpl(containerKeyStoreWraper, containerDir);
	}

	private static KeyStoreWraper getContainerKeyStoreWraper(FileWrapper keyStoreFileWraper, CallbackHandler callbackHandler){
		KeyPassCallback keyPassCallback = new KeyPassCallback("Enter key pass callback: ", false);
		StorePassCallback storePassCallback = new StorePassCallback("Enter store pass callback: ", false);
		Callback[] callbacks = new Callback[]{keyPassCallback, storePassCallback};
		try {
			callbackHandler.handle(callbacks);
		} catch (IOException | UnsupportedCallbackException e) {
			throw new IllegalStateException(e);
		}
		char[] storePass = storePassCallback.getPassword();
		char[] keyPass = keyPassCallback.getPassword();
		return new KeyStoreWraper(
				keyStoreFileWraper, 
				keyPass,
				storePass);
	}
}
