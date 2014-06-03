package org.adorsys.plh.pkix.core.test.smime.contact;

import java.io.File;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Properties;

import javax.security.auth.callback.CallbackHandler;

import org.adorsys.plh.pkix.core.smime.plooh.ContainerNameUtils;
import org.adorsys.plh.pkix.core.smime.plooh.FileContainerCallbackHandler;
import org.adorsys.plh.pkix.core.smime.plooh.SelectedFileNotADirectoryException;
import org.adorsys.plh.pkix.core.smime.plooh.UserAccount;
import org.adorsys.plh.pkix.core.smime.plooh.UserDevice;
import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.exception.PlhCheckedException;
import org.adorsys.plh.pkix.core.utils.store.SimpleKeyStoreCallbackHandler;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Test;

public class ContactIndexTest {
	private static final File testDir = new File("target/"+ContactIndexTest.class.getSimpleName());
	
	@AfterClass
	public static void cleanup(){
		FileUtils.deleteQuietly(testDir);
	}
	
	
	@Test
	public void test() throws CertificateException, KeyStoreException, PlhCheckedException, SelectedFileNotADirectoryException {
		
		String emailSuffix = "@mail.com";
		// francis
		String francisName = "francis";
		FileContainerCallbackHandler francisFileContainerCallbackHandler = newFileContainerCallbackHandler(francisName, francisName+emailSuffix);
		UserAccount francisUserAccount = newUserAccount(francisName, francisFileContainerCallbackHandler);
		
		// nadege
		String nadegeName = "nadege";
		FileContainerCallbackHandler nadegeFileContainerCallbackHandler = newFileContainerCallbackHandler(nadegeName, nadegeName+emailSuffix);
		UserAccount nadegeUserAccount = newUserAccount(nadegeName, nadegeFileContainerCallbackHandler);

		// sandro
		String sandroName = "sandro";
		FileContainerCallbackHandler sandroFileContainerCallbackHandler = newFileContainerCallbackHandler(sandroName, sandroName+emailSuffix);
		UserAccount sandroUserAccount = newUserAccount(sandroName, sandroFileContainerCallbackHandler);

		PrivateKeyEntry nadegePrivateKeyEntry = nadegeUserAccount.getAnyMessagePrivateKeyEntry();
		PrivateKeyEntry sandroPrivateKeyEntry = sandroUserAccount.getAnyMessagePrivateKeyEntry();

		francisUserAccount.getTrustedContactManager().addCertEntry(V3CertificateUtils.getX509CertificateHolder(nadegePrivateKeyEntry.getCertificate()));
		francisUserAccount.getTrustedContactManager().addCertEntry(V3CertificateUtils.getX509CertificateHolder(sandroPrivateKeyEntry.getCertificate()));

		francisUserAccount = loadUserAccount(francisName, francisFileContainerCallbackHandler);

		ContactManager francisTrustedContactManager = francisUserAccount.getTrustedContactManager();
		List<KeyStoreAlias> keyStoreAliases = francisTrustedContactManager.keyStoreAliases();
		List<TrustedCertificateEntry> francisContacts = francisTrustedContactManager.findEntriesByAlias(TrustedCertificateEntry.class, keyStoreAliases);
		Assert.assertNotNull(francisContacts);
	}
	
	private static UserAccount newUserAccount(String name, CallbackHandler callbackHandler) throws SelectedFileNotADirectoryException{
		UserDevice device = loadUserDevice(name);
		return device.createUserAccount(new File(testDir, "accountDirs/"+name+"Account"), callbackHandler);
	}
	
	private static UserAccount loadUserAccount(String name, CallbackHandler callbackHandler) throws SelectedFileNotADirectoryException{
		UserDevice device = loadUserDevice(name);
		List<X509CertificateHolder> accounts = device.getAccounts();
		X509CertificateHolder accountCertificateHolder = accounts.iterator().next();
		return device.loadUserAccount(accountCertificateHolder, callbackHandler);
		
	}
	
	private static UserDevice loadUserDevice(String name) throws SelectedFileNotADirectoryException{
		SimpleKeyStoreCallbackHandler deviceCallBackHandler = new SimpleKeyStoreCallbackHandler(
				(name +"Device Key Pass").toCharArray(), 
				(name+"Device Store Pass").toCharArray());
		// nadege
		Properties properties = new Properties();
		properties.put(UserDevice.PROPERTY_KEY_USER_HOME, new File(testDir, name+"Device").getPath());
//		properties.put(UserDevice.PROPERTY_KEY_USER_NAME, name);
		
		return new UserDevice(deviceCallBackHandler, properties);
	}
	
	private FileContainerCallbackHandler newFileContainerCallbackHandler(String name, String email){
		SimpleKeyStoreCallbackHandler keystoreCallbackHandler = new SimpleKeyStoreCallbackHandler(
				(name +"Container Key Pass").toCharArray(), 
				(name+"Container Store Pass").toCharArray());
		return new FileContainerCallbackHandler(email, ContainerNameUtils.getContainerName(name), keystoreCallbackHandler);
		
	}
}
