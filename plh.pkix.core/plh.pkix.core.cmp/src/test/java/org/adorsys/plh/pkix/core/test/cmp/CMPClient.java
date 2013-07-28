package org.adorsys.plh.pkix.core.test.cmp;

import java.io.File;
import java.util.List;
import java.util.Properties;

import org.adorsys.plh.pkix.core.cmp.CMPAccount;
import org.adorsys.plh.pkix.core.cmp.CMPMessenger;
import org.adorsys.plh.pkix.core.smime.plooh.SelectedFileNotADirectoryException;
import org.adorsys.plh.pkix.core.smime.plooh.SimpleKeyStorePasswordsCallbackHandler;
import org.adorsys.plh.pkix.core.smime.plooh.UserAccount;
import org.adorsys.plh.pkix.core.smime.plooh.UserDevice;
import org.bouncycastle.cert.X509CertificateHolder;

public class CMPClient {
	
	private final CMPAccount cmpAccount;;
	
	public CMPClient(CMPMessenger cmpMessenger, File workspaceDir, String containerName, char[] containerKeyPass, char[] containerStorePass) throws SelectedFileNotADirectoryException {
		
		SimpleKeyStorePasswordsCallbackHandler deviceCallBackHandler = 
				new SimpleKeyStorePasswordsCallbackHandler(containerKeyPass, containerStorePass);
		UserAccount userAccount = loadOrCreateUserAccount(cmpMessenger, workspaceDir, containerName, deviceCallBackHandler);
		cmpAccount = new CMPAccount(userAccount, cmpMessenger);
	}
	
	public CMPAccount getCmpAccount() {
		return cmpAccount;
	}

	public static UserAccount loadOrCreateUserAccount(CMPMessenger cmpMessenger, File workspaceDir, String containerName, SimpleKeyStorePasswordsCallbackHandler deviceCallBackHandler) throws SelectedFileNotADirectoryException{
		File file = new File(workspaceDir, "accountDirs/"+containerName+"Account");
		UserAccount userAccount;
		if(file.exists()){
			userAccount = loadUserAccount(workspaceDir, containerName, deviceCallBackHandler);
		} else {
			userAccount = newUserAccount(workspaceDir, containerName, deviceCallBackHandler);
		}
		return userAccount;
	}
	private static UserAccount newUserAccount(File workspaceDir, String name, SimpleKeyStorePasswordsCallbackHandler deviceCallBackHandler) throws SelectedFileNotADirectoryException{
		UserDevice device = loadUserDevice(workspaceDir, name, deviceCallBackHandler);
		return device.createUserAccount(new File(workspaceDir, "accountDirs/"+name+"Account"));
		
	}
	
	private static UserAccount loadUserAccount(File workspaceDir, String name, SimpleKeyStorePasswordsCallbackHandler deviceCallBackHandler) throws SelectedFileNotADirectoryException{
		UserDevice device = loadUserDevice(workspaceDir, name, deviceCallBackHandler);
		List<X509CertificateHolder> accounts = device.getAccounts();
		X509CertificateHolder accountCertificateHolder = accounts.iterator().next();
		return device.loadUserAccount(accountCertificateHolder);
	}
	
	private static UserDevice loadUserDevice(File workspaceDir, String name, SimpleKeyStorePasswordsCallbackHandler deviceCallBackHandler) throws SelectedFileNotADirectoryException{
		// nadege
		Properties properties = new Properties();
		properties.put(UserDevice.SYSTEM_PROPERTY_KEY_USER_HOME, new File(workspaceDir, name+"Device").getPath());
		properties.put(UserDevice.SYSTEM_PROPERTY_KEY_USER_NAME, name);
		return new UserDevice(deviceCallBackHandler, properties);
	}
}
