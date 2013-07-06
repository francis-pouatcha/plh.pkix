package org.adorsys.plh.pkix.core.test.smime.contact;

import java.io.File;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Set;

import org.adorsys.plh.pkix.core.smime.contact.AccountManager;
import org.adorsys.plh.pkix.core.smime.contact.AccountManagerFactory;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.contact.ContactManager;
import org.adorsys.plh.pkix.core.utils.exception.PlhCheckedException;
import org.adorsys.plh.pkix.core.utils.store.FilesContainer;
import org.apache.commons.io.FileUtils;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Test;

public class ContactIndexTest {
	private static final File testDir = new File("target/ContactIndexTest");
	
	@AfterClass
	public static void cleanup(){
		FileUtils.deleteQuietly(testDir);
	}
	
	
	@Test
	public void test() throws CertificateException, KeyStoreException, PlhCheckedException {
		
		// 1. Generate key pair
		FilesContainer francisFilesContainer = AccountManagerFactory.createFilesContainer(new File(testDir, "francis"), "Francis Pouatcha Container Key Pass".toCharArray(), "Francis Pouatcha Container Store Pass".toCharArray());
		AccountManager francisContactManager = AccountManagerFactory.createAccountManager(francisFilesContainer, "francisAccount", "Francis Pouatcha", "fpo@biz.com", "francis key pass".toCharArray());
		
		FilesContainer nadegeFilesContainer = AccountManagerFactory.createFilesContainer(new File(testDir, "nadege"), "Nadege Pouatcha Container Key Pass".toCharArray(), "Nadege Pouatcha Container Store Pass".toCharArray());
		AccountManager nadegeContactManager = AccountManagerFactory.createAccountManager(nadegeFilesContainer, "nadegeAccount", "Nadege Pouatcha", "npa@biz.com", "nadege key pass".toCharArray());
		
		FilesContainer sandroFilesContainer = AccountManagerFactory.createFilesContainer(new File(testDir, "sandro"), "Sandro Sonntag Container Key Pass".toCharArray(), "Sandro Sonntag Container Store Pass".toCharArray());
		AccountManager sandroContactManager = AccountManagerFactory.createAccountManager(sandroFilesContainer, "sandroAccount", "Sandro Sonntag", "sso@biz.com", "sandro key pass".toCharArray());
		
		PrivateKeyEntry nadegePrivateKeyEntry = nadegeContactManager.getAccountContext().get(ContactManager.class).getMainMessagePrivateKeyEntry();
		PrivateKeyEntry sandroPrivateKeyEntry = sandroContactManager.getAccountContext().get(ContactManager.class).getMainMessagePrivateKeyEntry();
		francisContactManager.getAccountContext().get(ContactManager.class).addCertEntry(V3CertificateUtils.getX509CertificateHolder(nadegePrivateKeyEntry.getCertificate()));
		francisContactManager.getAccountContext().get(ContactManager.class).addCertEntry(V3CertificateUtils.getX509CertificateHolder(sandroPrivateKeyEntry.getCertificate()));

		francisFilesContainer = AccountManagerFactory.loadFilesContainer(new File(testDir, "francis"), "Francis Pouatcha Container Key Pass".toCharArray(), "Francis Pouatcha Container Store Pass".toCharArray());
		List<AccountManager> loadedAccountManagers = AccountManagerFactory.loadAccountManagers(francisFilesContainer);
		Assert.assertTrue(loadedAccountManagers.size()==1);
		AccountManager accountManager = loadedAccountManagers.get(0);

		boolean authenticated = accountManager.getContactManager().isAuthenticated();
		Assert.assertFalse(authenticated);
		accountManager.getContactManager().login("francis key pass".toCharArray());
		authenticated = accountManager.getContactManager().isAuthenticated();
		Assert.assertTrue(authenticated);
		
		Set<String> francisContacts = francisContactManager.getContactManager().listContacts();
		Assert.assertTrue(francisContacts.contains("npa@biz.com"));
		Assert.assertTrue(francisContacts.contains("sso@biz.com"));

	}
}
