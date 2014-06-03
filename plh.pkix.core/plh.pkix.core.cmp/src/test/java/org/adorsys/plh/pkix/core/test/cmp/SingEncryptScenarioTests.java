package org.adorsys.plh.pkix.core.test.cmp;

import java.io.File;
import java.io.IOException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import org.adorsys.plh.pkix.core.cmp.CMPAccount;
import org.adorsys.plh.pkix.core.cmp.InMemoryCMPMessenger;
import org.adorsys.plh.pkix.core.cmp.certrequest.endentity.CertificationRequestFieldHolder;
import org.adorsys.plh.pkix.core.cmp.initrequest.sender.InitializationRequestFieldHolder;
import org.adorsys.plh.pkix.core.smime.plooh.SelectedFileNotADirectoryException;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.KeyStoreAlias;
import org.adorsys.plh.pkix.core.utils.KeyStoreAlias.PurposeEnum;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class SingEncryptScenarioTests {

//	static final String srcFile1 = "src/test/resources/rfc4210.pdf";
//	static final String srcFile2 = "src/test/resources/rfc5652CMS.pdf";

	
	InMemoryCMPMessenger cmpMessenger = null;

	static File workspaceParentDir = new File("target/"+SingEncryptScenarioTests.class.getSimpleName());

	@BeforeClass
	@AfterClass
	public static void afterClass(){
		FileUtils.deleteQuietly(workspaceParentDir);
	}

	@Test
	public void testTimAndAlex2() throws IOException, SelectedFileNotADirectoryException {
		File workspaceDir = new File(workspaceParentDir, "testTimAndAlex2");;
		cmpMessenger = new LeakingCMPMessenger(workspaceDir);
		testTimAndAlexIntern(workspaceDir);
	}
	
	@Test
	public void testTimAndAlex() throws IOException, SelectedFileNotADirectoryException {
		File workspaceDir = new File(workspaceParentDir, "testTimAndAlex");;
		cmpMessenger = new InMemoryCMPMessenger();
		testTimAndAlexIntern(workspaceDir);
	}
	
	private void testTimAndAlexIntern(File workspaceDir) throws IOException, SelectedFileNotADirectoryException {
		BlockingQueue<String> endPointQueue = new ArrayBlockingQueue<String>(100);
		// collect registered endpoints into the given blocking queue.
		SmpleRegisterMessageEndpointListener eendPointListener = new SmpleRegisterMessageEndpointListener(endPointQueue);
		cmpMessenger.addRegisterMessageEndpointListener(eendPointListener);
		
		// collect registering client and will help wait for registration to finish.
		List<String> registeringClients = new ArrayList<String>(); 
		
		CMPClient certAuthClient = new CMPClient(cmpMessenger, workspaceDir, 
				"certAuth", "certAuthContainerKeyPass".toCharArray(), "certAuthContainerStorePass".toCharArray(),
				"certAuth@mail.com", "certAuthUserKeyPass".toCharArray(), "certAuthUserStorePass".toCharArray());
		CMPAccount certAuthAccount = certAuthClient.getCmpAccount();
		BlockingContactListener certAuthBlockingContactListener = new BlockingContactListener();
		certAuthAccount.getUserAccount().addContactListener(certAuthBlockingContactListener);
		X509CertificateHolder certAuthCertificate = certAuthAccount.getUserAccount().getAccountCertificateHolder();
		String certAuthPublicKeyHex = KeyIdUtils.createPublicKeyIdentifierAsString(certAuthCertificate);
		registeringClients.add(certAuthPublicKeyHex);
		certAuthAccount.registerAccount();

		CMPClient timClient = new CMPClient(cmpMessenger, workspaceDir, 
				"tims", "timsContainerKeyPass".toCharArray(), "timsContainerStorePass".toCharArray(),
				"tims@mail.com", "timsUserKeyPass".toCharArray(), "timsUserStorePass".toCharArray());
		CMPAccount timsAccount = timClient.getCmpAccount();
		BlockingContactListener timBlockingContactListener = new BlockingContactListener();
		timsAccount.getUserAccount().addContactListener(timBlockingContactListener);
		X509CertificateHolder timCertificate = timsAccount.getUserAccount().getAccountCertificateHolder();
		String timPublicKeyHex = KeyIdUtils.createPublicKeyIdentifierAsString(timCertificate);
		registeringClients.add(timPublicKeyHex);
		timsAccount.registerAccount();

		CMPClient alexClient = new CMPClient(cmpMessenger, workspaceDir, 
				"alexes", "alexesContainerKeyPass".toCharArray(), "alexesContainerStorePass".toCharArray(),
				"alexes@mail.com", "alexesUserKeyPass".toCharArray(), "alexesUserStorePass".toCharArray());
		CMPAccount alexesAccount = alexClient.getCmpAccount();
		BlockingContactListener alexesBlockingContactListener = new BlockingContactListener();
		alexesAccount.getUserAccount().addContactListener(alexesBlockingContactListener);
		X509CertificateHolder alexCertificate = alexesAccount.getUserAccount().getAccountCertificateHolder();
		String alexPublicKeyHex = KeyIdUtils.createPublicKeyIdentifierAsString(alexCertificate);
		registeringClients.add(alexPublicKeyHex);
		alexesAccount.registerAccount();
		
		// Main thread waits till all client are propertly registered.
		while(true){
			if(registeringClients.isEmpty()) break;
			try {
				String email = endPointQueue.take();
				registeringClients.remove(email);
			} catch (InterruptedException e) {
				// Noop
			}
		}

		InitializationRequestFieldHolder f = new InitializationRequestFieldHolder();
		f.setReceiverCertificate(certAuthCertificate);
		f.setSubjectPublicKeyInfo(certAuthCertificate.getSubjectPublicKeyInfo());
		timBlockingContactListener.expectContact(certAuthPublicKeyHex);
		// initialization request
		timsAccount.sendInitializationRequest(f);
		timBlockingContactListener.waitForContacts();
		List<TrustedCertificateEntry> timContacts = timsAccount.getUserAccount().findContactsByPublicKey(certAuthPublicKeyHex);
		Assert.assertNotNull(timContacts);
		Assert.assertEquals(1, timContacts.size());
		
		
		PrivateKeyEntry timMainMessagePrivateKey = timsAccount.getUserAccount().getAnyMessagePrivateKeyEntry();
		
		TrustedCertificateEntry certAuthMessagingCertificate = timContacts.get(0);
		X509CertificateHolder receiverCertificate = V3CertificateUtils.getX509CertificateHolder(certAuthMessagingCertificate.getTrustedCertificate());
		CertificationRequestFieldHolder crf = new CertificationRequestFieldHolder(timMainMessagePrivateKey);
		crf.setReceiverCertificate(receiverCertificate);
		crf.setCertAuthorityName(receiverCertificate.getIssuer());
		// We assume the messaging certificate of the cert auth is signed by a cert auth.
		AuthorityKeyIdentifier authorityKeyIdentifier = KeyIdUtils.readAuthorityKeyIdentifier(receiverCertificate);
		crf.setAuthorityKeyIdentifier(authorityKeyIdentifier);
		
		String authorityKeyIdentifierHex = KeyIdUtils.readAuthorityKeyIdentifierAsString(receiverCertificate);
		timBlockingContactListener.expectIssuedCertficate(authorityKeyIdentifierHex);
		timsAccount.sendCertificationRequest(crf);
		timBlockingContactListener.waitForIssuedCertificates();
		
		KeyStoreAlias certifiedPrivateKeyStoreAlias = new KeyStoreAlias(timPublicKeyHex, authorityKeyIdentifierHex, null, PurposeEnum.ME, PrivateKeyEntry.class);
		List<PrivateKeyEntry> timKeyEntries = timsAccount.getUserAccount().findPrivateKeys(certifiedPrivateKeyStoreAlias);
		Assert.assertNotNull(timKeyEntries);
		Assert.assertTrue(timKeyEntries.size()==1);
		
	}		

}
