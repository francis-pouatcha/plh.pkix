package org.adorsys.plh.pkix.core.smime.contact;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.adorsys.plh.pkix.core.smime.store.FileContainerImpl;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.jca.KeyPairBuilder;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.adorsys.plh.pkix.core.utils.store.FilesContainer;
import org.adorsys.plh.pkix.core.utils.store.KeyStoreWraper;
import org.adorsys.plh.pkix.core.utils.store.UnprotectedFileContainer;
import org.bouncycastle.asn1.x500.X500Name;

public class AccountManagerFactory {
	
	public static final String CONTAINER_KEY_STORE_FILE_NAME="containerKeyStore";
	public static final String ACCOUNTS_FILE_NAME="accounts";

	public static FilesContainer createFilesContainer(File containerDir, char[] containerKeyPass, char[] containerStorePass){
		FilesContainer keyStoreContainer = new UnprotectedFileContainer(containerDir);

		KeyStoreWraper containerKeyStoreWraper = new KeyStoreWraper(keyStoreContainer
				.newFile(CONTAINER_KEY_STORE_FILE_NAME), containerKeyPass, containerStorePass);
		
		new KeyPairBuilder()
			.withEndEntityName(new X500Name("cn="+containerDir.getName()))
			.withKeyStoreWraper(containerKeyStoreWraper)
			.build();
		
		ContactManager containerContactManager = new ContactManagerImpl(containerKeyStoreWraper, null);
		
		return new FileContainerImpl(containerContactManager, containerDir);
	}
	
	public static FilesContainer loadFilesContainer(File containerDir, char[] containerKeyPass, char[] containerStorePass){
		FilesContainer keyStoreContainer = new UnprotectedFileContainer(containerDir);
		
		KeyStoreWraper containerKeyStoreWraper = new KeyStoreWraper(keyStoreContainer
				.newFile(CONTAINER_KEY_STORE_FILE_NAME), containerKeyPass, containerStorePass);
		
		ContactManager containerContactManager = new ContactManagerImpl(containerKeyStoreWraper, null);
		if(!containerContactManager.isAuthenticated()) return null;

		return new FileContainerImpl(containerContactManager, containerDir);
	}
	
	public static FilesContainer loadOrCreateFilesContainer(File containerDir, char[] containerKeyPass, char[] containerStorePass){
		if(containerDir.exists()){
			return loadFilesContainer(containerDir, containerKeyPass, containerStorePass);
		} else {
			return createFilesContainer(containerDir, containerKeyPass, containerStorePass);
		}
	}
	
	public static AccountManager createAccountManager(FilesContainer container, String accountDirName, String userName, 
			String  email, char[] accountKeyPass){
		
		FileWrapper accountsDir = container.newFile(ACCOUNTS_FILE_NAME);
		FileWrapper accountDir = accountsDir.newChild(accountDirName);
		
		return new AccountManager(new ActionContext(), accountDir, userName, email, accountKeyPass);
	}

	public static List<AccountManager> loadAccountManagers(FilesContainer container){
		FileWrapper accountsDir = container.newFile(ACCOUNTS_FILE_NAME);
		String[] accountNames = accountsDir.list();
		if(accountNames==null) return Collections.emptyList();
		List<AccountManager> result = new ArrayList<AccountManager>();
		for (String accountDirName : accountNames) {
			FileWrapper accountDir = accountsDir.newChild(accountDirName);
			result.add(new AccountManager(new ActionContext(), accountDir));
		}
		return result;
	}
}
