package org.adorsys.plh.pkix.core.test.cmp;

import java.io.File;
import java.util.List;
import java.util.Properties;

import org.adorsys.plh.pkix.core.cmp.CMPAccount;
import org.adorsys.plh.pkix.core.cmp.CMPMessenger;
import org.adorsys.plh.pkix.core.smime.plooh.FileContainerCallbackHandler;
import org.adorsys.plh.pkix.core.smime.plooh.SelectedFileNotADirectoryException;
import org.adorsys.plh.pkix.core.smime.plooh.UserAccount;
import org.adorsys.plh.pkix.core.smime.plooh.UserDevice;
import org.adorsys.plh.pkix.core.utils.store.SimpleKeyStoreCallbackHandler;
import org.bouncycastle.cert.X509CertificateHolder;

public class CMPClient {
	
	private final CMPAccount cmpAccount;;
	
	public CMPClient(CMPMessenger cmpMessenger, File workspaceDir, String containerName, char[] deviceKeyPass, char[] deviceStorePass, String email, char[] userKeyPass, char[] userStorePass) throws SelectedFileNotADirectoryException {
		
		SimpleKeyStoreCallbackHandler deviceCallBackHandler = 
				new SimpleKeyStoreCallbackHandler(deviceKeyPass, deviceStorePass);
		SimpleKeyStoreCallbackHandler userKeystoreCallBackHandler = 
				new SimpleKeyStoreCallbackHandler(userKeyPass, userStorePass);
		FileContainerCallbackHandler fileContainerCallbackHandler = new FileContainerCallbackHandler(email, containerName, userKeystoreCallBackHandler);
		UserAccount userAccount = loadOrCreateUserAccount(cmpMessenger, workspaceDir, containerName, deviceCallBackHandler, fileContainerCallbackHandler);
		cmpAccount = new CMPAccount(userAccount, cmpMessenger);
	}
	
	public CMPAccount getCmpAccount() {
		return cmpAccount;
	}

	public static UserAccount loadOrCreateUserAccount(CMPMessenger cmpMessenger, File workspaceDir, String containerName, SimpleKeyStoreCallbackHandler deviceCallBackHandler, FileContainerCallbackHandler fileContainerCallbackHandler) throws SelectedFileNotADirectoryException{
		File file = new File(workspaceDir, "accountDirs/"+containerName+"Account");
		UserAccount userAccount;
		if(file.exists()){
			userAccount = loadUserAccount(workspaceDir, containerName, deviceCallBackHandler, fileContainerCallbackHandler);
		} else {
			userAccount = newUserAccount(workspaceDir, containerName, deviceCallBackHandler, fileContainerCallbackHandler);
		}
		return userAccount;
	}
	private static UserAccount newUserAccount(File workspaceDir, String name, SimpleKeyStoreCallbackHandler deviceCallBackHandler, FileContainerCallbackHandler fileContainerCallbackHandler) throws SelectedFileNotADirectoryException{
		UserDevice device = loadUserDevice(workspaceDir, name, deviceCallBackHandler);
		return device.createUserAccount(new File(workspaceDir, "accountDirs/"+name+"Account"), fileContainerCallbackHandler);
		
	}
	
	private static UserAccount loadUserAccount(File workspaceDir, String name, SimpleKeyStoreCallbackHandler deviceCallBackHandler, FileContainerCallbackHandler fileContainerCallbackHandler) throws SelectedFileNotADirectoryException{
		UserDevice device = loadUserDevice(workspaceDir, name, deviceCallBackHandler);
		List<X509CertificateHolder> accounts = device.getAccounts();
		X509CertificateHolder accountCertificateHolder = accounts.iterator().next();
		return device.loadUserAccount(accountCertificateHolder, fileContainerCallbackHandler);
	}
	
	private static UserDevice loadUserDevice(File workspaceDir, String name, SimpleKeyStoreCallbackHandler deviceCallBackHandler) throws SelectedFileNotADirectoryException{
		// nadege
		Properties properties = new Properties();
		properties.put(UserDevice.PROPERTY_KEY_USER_HOME, new File(workspaceDir, name+"Device").getPath());
		return new UserDevice(deviceCallBackHandler, properties);
	}
}
