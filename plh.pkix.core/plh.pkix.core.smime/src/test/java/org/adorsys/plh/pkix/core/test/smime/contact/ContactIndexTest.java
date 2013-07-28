package org.adorsys.plh.pkix.core.test.smime.contact;

import java.io.File;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Properties;

import org.adorsys.plh.pkix.core.smime.plooh.SelectedFileNotADirectoryException;
import org.adorsys.plh.pkix.core.smime.plooh.SimpleKeyStorePasswordsCallbackHandler;
import org.adorsys.plh.pkix.core.smime.plooh.UserAccount;
import org.adorsys.plh.pkix.core.smime.plooh.UserDevice;
import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.exception.PlhCheckedException;
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
		
		// francis
		UserAccount francisUserAccount = newUserAccount("francis");
		
		// nadege
		UserAccount nadegeUserAccount = newUserAccount("nadege");

		// sandro
		UserAccount sandroUserAccount = newUserAccount("sandro");

		PrivateKeyEntry nadegePrivateKeyEntry = nadegeUserAccount.getAnyMessagePrivateKeyEntry();
		PrivateKeyEntry sandroPrivateKeyEntry = sandroUserAccount.getAnyMessagePrivateKeyEntry();

		francisUserAccount.getTrustedContactManager().addCertEntry(V3CertificateUtils.getX509CertificateHolder(nadegePrivateKeyEntry.getCertificate()));
		francisUserAccount.getTrustedContactManager().addCertEntry(V3CertificateUtils.getX509CertificateHolder(sandroPrivateKeyEntry.getCertificate()));

		francisUserAccount = loadUserAccount("francis");

		ContactManager francisTrustedContactManager = francisUserAccount.getTrustedContactManager();
		List<KeyStoreAlias> keyStoreAliases = francisTrustedContactManager.keyStoreAliases();
		List<TrustedCertificateEntry> francisContacts = francisTrustedContactManager.findEntriesByAlias(TrustedCertificateEntry.class, keyStoreAliases);
		Assert.assertNotNull(francisContacts);
	}
	
	private static UserAccount newUserAccount(String name) throws SelectedFileNotADirectoryException{
		UserDevice device = loadUserDevice(name);
		return device.createUserAccount(new File(testDir, "accountDirs/"+name+"Account"));
		
	}
	
	private static UserAccount loadUserAccount(String name) throws SelectedFileNotADirectoryException{
		UserDevice device = loadUserDevice(name);
		List<X509CertificateHolder> accounts = device.getAccounts();
		X509CertificateHolder accountCertificateHolder = accounts.iterator().next();
		return device.loadUserAccount(accountCertificateHolder);
		
	}
	
	private static UserDevice loadUserDevice(String name) throws SelectedFileNotADirectoryException{
		// nadege
		Properties properties = new Properties();
		properties.put(UserDevice.SYSTEM_PROPERTY_KEY_USER_HOME, new File(testDir, name+"Device").getPath());
		properties.put(UserDevice.SYSTEM_PROPERTY_KEY_USER_NAME, name);
		SimpleKeyStorePasswordsCallbackHandler deviceCallBackHandler = new SimpleKeyStorePasswordsCallbackHandler(
				(name +"Container Key Pass").toCharArray(), 
				(name+"Container Store Pass").toCharArray());
		return new UserDevice(deviceCallBackHandler, properties);
	}
	
}
