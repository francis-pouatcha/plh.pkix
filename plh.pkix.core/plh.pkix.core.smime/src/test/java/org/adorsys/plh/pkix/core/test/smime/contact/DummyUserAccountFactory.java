package org.adorsys.plh.pkix.core.test.smime.contact;

import java.io.File;
import java.util.List;
import java.util.Properties;

import org.adorsys.plh.pkix.core.smime.plooh.ContainerNameUtils;
import org.adorsys.plh.pkix.core.smime.plooh.FileContainerCallbackHandler;
import org.adorsys.plh.pkix.core.smime.plooh.SelectedFileNotADirectoryException;
import org.adorsys.plh.pkix.core.smime.plooh.UserAccount;
import org.adorsys.plh.pkix.core.smime.plooh.UserDevice;
import org.adorsys.plh.pkix.core.utils.store.SimpleKeyStoreCallbackHandler;
import org.bouncycastle.cert.X509CertificateHolder;

public class DummyUserAccountFactory {
	private final File testDir;

	public DummyUserAccountFactory(File testDir) {
		this.testDir = testDir;
	}

	public UserAccount newUserAccount(String userName, FileContainerCallbackHandler fileContainerCallbackHandler) throws SelectedFileNotADirectoryException{
		// nadege
		Properties properties = new Properties();
		properties.put(UserDevice.PROPERTY_KEY_USER_HOME, new File(testDir, userName+"Device").getPath());
		SimpleKeyStoreCallbackHandler deviceCallBackHandler = new SimpleKeyStoreCallbackHandler(
				(userName +"Device Key Pass").toCharArray(), 
				(userName+"Device Store Pass").toCharArray());
		UserDevice device = new UserDevice(deviceCallBackHandler, properties);
		return device.createUserAccount(new File(testDir, "accountDirs/"+userName+"Account"), fileContainerCallbackHandler);
		
	}
	
	public UserAccount loadUserAccount(String userName, FileContainerCallbackHandler fileContainerCallbackHandler) throws SelectedFileNotADirectoryException{
		// nadege
		Properties properties = new Properties();
		properties.put(UserDevice.PROPERTY_KEY_USER_HOME, new File(testDir, userName+"Device").getPath());
//		properties.put(UserDevice.SYSTEM_PROPERTY_KEY_USER_NAME, name);
		SimpleKeyStoreCallbackHandler deviceCallBackHandler = new SimpleKeyStoreCallbackHandler(
				(userName +"Device Key Pass").toCharArray(), 
				(userName+"Device Store Pass").toCharArray());
		UserDevice device = new UserDevice(deviceCallBackHandler, properties);

		List<X509CertificateHolder> accounts = device.getAccounts();

		X509CertificateHolder accountCertificateHolder = accounts.iterator().next();
		return device.loadUserAccount(accountCertificateHolder,fileContainerCallbackHandler);
		
	}

	public FileContainerCallbackHandler newFileContainerCallbackHandler(String userName, String email){
		SimpleKeyStoreCallbackHandler keystoreCallbackHandler = new SimpleKeyStoreCallbackHandler(
				(userName +"Container Key Pass").toCharArray(), 
				(userName+"Container Store Pass").toCharArray());
		return new FileContainerCallbackHandler(email, ContainerNameUtils.getContainerName(userName), keystoreCallbackHandler);
	}
}
