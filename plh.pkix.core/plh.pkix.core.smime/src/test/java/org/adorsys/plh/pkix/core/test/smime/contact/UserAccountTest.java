package org.adorsys.plh.pkix.core.test.smime.contact;

import java.io.File;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Properties;

import org.adorsys.plh.pkix.core.smime.plooh.SelectedDirNotEmptyException;
import org.adorsys.plh.pkix.core.smime.plooh.SelectedFileNotADirectoryException;
import org.adorsys.plh.pkix.core.smime.plooh.SimpleKeyStorePasswordsCallbackHandler;
import org.adorsys.plh.pkix.core.smime.plooh.UserAccount;
import org.adorsys.plh.pkix.core.smime.plooh.UserDevice;
import org.adorsys.plh.pkix.core.utils.exception.PlhCheckedException;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.AfterClass;
import org.junit.Test;

public class UserAccountTest {
	private static final File testDir = new File("target/"+UserAccountTest.class.getSimpleName());
	
	@AfterClass
	public static void cleanup(){
		FileUtils.deleteQuietly(testDir);
	}
	
	
	@Test
	public void test() throws CertificateException, KeyStoreException, PlhCheckedException, SelectedFileNotADirectoryException, SelectedDirNotEmptyException {
		newUserAccount("francis");
		loadUserAccount("francis");
	}
	
	private static UserAccount newUserAccount(String name) throws SelectedFileNotADirectoryException, SelectedDirNotEmptyException{
		// nadege
		Properties properties = new Properties();
		properties.put(UserDevice.SYSTEM_PROPERTY_KEY_USER_HOME, new File(testDir, name+"Device").getPath());
		properties.put(UserDevice.SYSTEM_PROPERTY_KEY_USER_NAME, name);
		SimpleKeyStorePasswordsCallbackHandler deviceCallBackHandler = new SimpleKeyStorePasswordsCallbackHandler(
				(name +"Container Key Pass").toCharArray(), 
				(name+"Container Store Pass").toCharArray());
		UserDevice device = new UserDevice(deviceCallBackHandler, properties);
		return device.createUserAccount(new File(testDir, "accountDirs/"+name+"Account"));
		
	}
	
	private static UserAccount loadUserAccount(String name) throws SelectedFileNotADirectoryException, SelectedDirNotEmptyException{
		// nadege
		Properties properties = new Properties();
		properties.put(UserDevice.SYSTEM_PROPERTY_KEY_USER_HOME, new File(testDir, name+"Device").getPath());
		properties.put(UserDevice.SYSTEM_PROPERTY_KEY_USER_NAME, name);
		SimpleKeyStorePasswordsCallbackHandler deviceCallBackHandler = new SimpleKeyStorePasswordsCallbackHandler(
				(name +"Container Key Pass").toCharArray(), 
				(name+"Container Store Pass").toCharArray());
		UserDevice device = new UserDevice(deviceCallBackHandler, properties);

		List<X509CertificateHolder> accounts = device.getAccounts();

		X509CertificateHolder accountCertificateHolder = accounts.iterator().next();
		return device.loadUserAccount(accountCertificateHolder);
		
	}
	
}
