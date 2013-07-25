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
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class SingEncryptScenarioTests {

	static final String srcFile1 = "src/test/resources/rfc4210.pdf";
	static final String srcFile2 = "src/test/resources/rfc5652CMS.pdf";

	
	InMemoryCMPMessenger cmpMessenger = null;

	static File workspaceParentDir = new File("target/"+SingEncryptScenarioTests.class.getSimpleName());

	@BeforeClass
	@AfterClass
	public static void afterClass(){
		FileUtils.deleteQuietly(workspaceParentDir);
	}

	@Test
	public void testTimAndAlex2() throws IOException {
		File workspaceDir = new File(workspaceParentDir, "testTimAndAlex2");;
		cmpMessenger = new LeakingCMPMessenger(workspaceDir);
		testTimAndAlexIntern(workspaceDir);
	}
	
	@Test
	public void testTimAndAlex() throws IOException {
		File workspaceDir = new File(workspaceParentDir, "testTimAndAlex");;
		cmpMessenger = new InMemoryCMPMessenger();
		testTimAndAlexIntern(workspaceDir);
	}
	
	private void testTimAndAlexIntern(File workspaceDir) throws IOException {
		BlockingQueue<String> endPointQueue = new ArrayBlockingQueue<String>(100);
		// collect registered endpoints into the given blocking queue.
		SmpleRegisterMessageEndpointListener eendPointListener = new SmpleRegisterMessageEndpointListener(endPointQueue);
		cmpMessenger.addRegisterMessageEndpointListener(eendPointListener);
		
		// collect registering client and will help wait for registration to finish.
		List<String> registeringClients = new ArrayList<String>(); 
		
		String certAUthEmail = "certauth@adorsys.com";
		registeringClients.add(certAUthEmail);
		CMPClient certAuthClient = new CMPClient(cmpMessenger, workspaceDir, 
				"certAuthComputer", "certAuthContainerKeyPass".toCharArray(), "certAuthContainerStorePass".toCharArray());
		CMPAccount certAuthAccount = certAuthClient.newAccount("Adorsys Certification Authority", certAUthEmail, "certAuthAccountPassword".toCharArray());
		BlockingContactListener certAuthBlockingContactListener = new BlockingContactListener();
		certAuthAccount.getPloohAccount().addContactListener(certAuthBlockingContactListener);
		certAuthAccount.registerAccount();

		String timEmail = "tim@adorsys.com";
		registeringClients.add(timEmail);
		CMPClient timClient = new CMPClient(cmpMessenger, workspaceDir, 
				"timsComputer", "timsContainerKeyPass".toCharArray(), "timsContainerStorePass".toCharArray());
		CMPAccount timsAccount = timClient.newAccount("Tim Tester", timEmail, "TimsAccountPassword".toCharArray());
		BlockingContactListener timBlockingContactListener = new BlockingContactListener();
		timsAccount.getPloohAccount().addContactListener(timBlockingContactListener);
		timsAccount.registerAccount();

		String alexEmail = "alex@adorsys.com";
		registeringClients.add(alexEmail);
		CMPClient alexClient = new CMPClient(cmpMessenger, workspaceDir, 
				"alexesComputer", "alexesContainerKeyPass".toCharArray(), "alexesContainerStorePass".toCharArray());
		CMPAccount alexesAccount = alexClient.newAccount("Alex Tester", alexEmail, "AlexesAccountPassword".toCharArray());
		BlockingContactListener alexesBlockingContactListener = new BlockingContactListener();
		alexesAccount.getPloohAccount().addContactListener(alexesBlockingContactListener);
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
		f.setReceiverEmail(certAUthEmail);
		GeneralName gn = new GeneralName(GeneralName.rfc822Name, certAUthEmail);
		GeneralNames subjectAltNames = new GeneralNames(gn);
		f.setSubjectAltNames(subjectAltNames);
		timBlockingContactListener.expectContact(certAUthEmail);
		// initialization request
		timsAccount.sendInitializationRequest(f);
		timBlockingContactListener.waitForContacts();
		List<TrustedCertificateEntry> timContacts = timsAccount.getPloohAccount().findContacts(certAUthEmail);
		Assert.assertNotNull(timContacts);
		if(timContacts.size()<2){
			timBlockingContactListener.expectContact(certAUthEmail);
			timBlockingContactListener.waitForContacts();
		}
		timContacts = timsAccount.getPloohAccount().findContacts(certAUthEmail);
		Assert.assertEquals(1, timContacts.size());
		
		
		PrivateKeyEntry timMainMessagePrivateKey = timsAccount.getPloohAccount().getMainMessagePrivateKey();
		CertificationRequestFieldHolder crf = new CertificationRequestFieldHolder(timMainMessagePrivateKey);
		
		TrustedCertificateEntry certAuthCaCertificate = timsAccount.getPloohAccount().findCaSigningCertificateByEmail(certAUthEmail);
		TrustedCertificateEntry certAuthMessagingCertificate = timsAccount.getPloohAccount().findMessagingCertificateByEmail(certAUthEmail);
	
		X509CertificateHolder certAuthorityCaCertHolder = V3CertificateUtils.getX509CertificateHolder(certAuthCaCertificate.getTrustedCertificate());
		crf.setCertAuthorityName(certAuthorityCaCertHolder.getSubject());
		X509CertificateHolder receiverCertificate = V3CertificateUtils.getX509CertificateHolder(certAuthMessagingCertificate.getTrustedCertificate());
		crf.setReceiverCertificate(receiverCertificate);
		crf.setReceiverEmail(certAUthEmail);
		timBlockingContactListener.expectIssuedCertficate(certAuthorityCaCertHolder.getSubject());
		timsAccount.sendCertificationRequest(crf);
		timBlockingContactListener.waitForIssuedCertificates();
		
		
		X509CertificateHolder timSampleCertificate = V3CertificateUtils.getX509CertificateHolder(timMainMessagePrivateKey.getCertificate());
		List<PrivateKeyEntry> timKeyEntries = timsAccount.getPloohAccount().findAllMessagePrivateKeyEntriesByPublicKey(timSampleCertificate);
		PrivateKeyEntry certifiedPrivateKeyEntry = null;
		for (PrivateKeyEntry privateKeyEntry : timKeyEntries) {
			X509CertificateHolder certHolder = V3CertificateUtils.getX509CertificateHolder(privateKeyEntry.getCertificate());
			X500Name issuer = certHolder.getIssuer();
			if(!issuer.equals(certAuthorityCaCertHolder.getSubject())) continue;
			if(V3CertificateUtils.isSigingCertificate(certHolder, certAuthorityCaCertHolder)){
				certifiedPrivateKeyEntry = privateKeyEntry; 
				break;
			}
		}
		Assert.assertNotNull(certifiedPrivateKeyEntry);
		
	}		

}
