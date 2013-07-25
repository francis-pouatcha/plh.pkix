package org.adorsys.plh.pkix.core.smime.plooh;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.adorsys.plh.pkix.core.smime.store.FileContainerImpl;
import org.adorsys.plh.pkix.core.utils.X500NameHelper;
import org.adorsys.plh.pkix.core.utils.jca.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.FilesContainer;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.adorsys.plh.pkix.core.utils.store.UnprotectedFileWraper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralNames;

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
	 * @param fileContainerName
	 * @param containerType
	 * @param containerDir
	 * @param callbackHandler
	 * @return
	 */
	public static FilesContainer createFilesContainer(
			String fileContainerName, 
			ContainerType containerType, 
			File containerDir, 
			FileWrapper containerDirWrapper,
			KeyStorePasswordsCallbackHandler callbackHandler)
	{
		FileWrapper keyStoreFileWraper = null;
		if(containerDirWrapper!=null){
			keyStoreFileWraper = containerDirWrapper.newChild(CONTAINER_KEY_STORE_FILE_NAME);
		} else {
			keyStoreFileWraper = new UnprotectedFileWraper(CONTAINER_KEY_STORE_FILE_NAME, containerDir);
		}
		KeyStoreWraper containerKeyStoreWraper = getContainerKeyStoreWraper(keyStoreFileWraper, callbackHandler);
		
		X500Name containerX500Name = X500NameHelper.makeX500Name(fileContainerName,null,null, containerType.name());
		List<String> urls = new ArrayList<String>();
		urls.add(containerDir.toURI().toString());
		GeneralNames subjectAlternativeNames = X500NameHelper.makeSubjectAlternativeName(containerX500Name, null, urls);
		new KeyPairBuilder()
			.withEndEntityName(containerX500Name)
			.withSubjectAlternativeNames(subjectAlternativeNames)
			.withKeyStoreWraper(containerKeyStoreWraper)
			.build();
		
		return new FileContainerImpl(containerKeyStoreWraper, containerDir);
	}

	public static FilesContainer loadFilesContainer(File containerDir,
			FileWrapper containerDirWrapper, KeyStorePasswordsCallbackHandler callbackHandler){
		FileWrapper keyStoreFileWraper = null;
		if(containerDirWrapper!=null){
			keyStoreFileWraper = containerDirWrapper.newChild(CONTAINER_KEY_STORE_FILE_NAME);
		} else {
			keyStoreFileWraper = new UnprotectedFileWraper(CONTAINER_KEY_STORE_FILE_NAME, containerDir);
		}
		KeyStoreWraper containerKeyStoreWraper = getContainerKeyStoreWraper(keyStoreFileWraper, callbackHandler);
		return new FileContainerImpl(containerKeyStoreWraper, containerDir);
	}

	private static KeyStoreWraper getContainerKeyStoreWraper(FileWrapper keyStoreFileWraper, KeyStorePasswordsCallbackHandler callbackHandler){
		return new KeyStoreWraper(
				keyStoreFileWraper, 
				callbackHandler.getKeyPass(), 
				callbackHandler.getStorePass());
	}
}
