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
import org.adorsys.plh.pkix.core.cmp.CMPandCMSClient;
import org.adorsys.plh.pkix.core.cmp.InMemoryCMPMessenger;
import org.adorsys.plh.pkix.core.cmp.certrequest.endentity.CertificationRequestFieldHolder;
import org.adorsys.plh.pkix.core.cmp.initrequest.sender.InitializationRequestFieldHolder;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.apache.commons.io.FileUtils;
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
	
	static File workspaceDir = new File("target/SingEncryptScenarioTests/testTimAndAlex");
	
	@BeforeClass
	@AfterClass
	public static void cleanUp(){
		FileUtils.deleteQuietly(workspaceDir);
	}
	
	@Test
	public void testTimAndAlex() throws IOException {
		
		InMemoryCMPMessenger cmpMessenger = new InMemoryCMPMessenger();
		BlockingQueue<String> endPointQueue = new ArrayBlockingQueue<String>(100);
		// collect registered endpoints into the given blocking queue.
		SmpleRegisterMessageEndpointListener eendPointListener = new SmpleRegisterMessageEndpointListener(endPointQueue);
		cmpMessenger.addRegisterMessageEndpointListener(eendPointListener);
		
		// collect registering client and will help wait for registration to finish.
		List<String> registeringClients = new ArrayList<String>(); 
		
		String certAUthEmail = "certauth@adorsys.com";
		registeringClients.add(certAUthEmail);
		CMPandCMSClient certAuthClient = new CMPandCMSClient(cmpMessenger, workspaceDir, 
				"certAuthComputer", "certAuthContainerKeyPass".toCharArray(), "certAuthContainerStorePass".toCharArray());
		CMPAccount certAuthAccount = certAuthClient.newAccount("Adorsys Certification Authority", certAUthEmail, "certAuthAccountPassword".toCharArray());
		BlockingContactListener certAuthBlockingContactListener = new BlockingContactListener();
		certAuthAccount.addContactListener(certAuthBlockingContactListener);
		certAuthAccount.registerAccount();

		String timEmail = "tim@adorsys.com";
		registeringClients.add(timEmail);
		CMPandCMSClient timClient = new CMPandCMSClient(cmpMessenger, workspaceDir, 
				"timsComputer", "timsContainerKeyPass".toCharArray(), "timsContainerStorePass".toCharArray());
		CMPAccount timsAccount = timClient.newAccount("Tim Tester", timEmail, "TimsAccountPassword".toCharArray());
		BlockingContactListener timBlockingContactListener = new BlockingContactListener();
		timsAccount.addContactListener(timBlockingContactListener);
		timsAccount.registerAccount();

		String alexEmail = "alex@adorsys.com";
		registeringClients.add(alexEmail);
		CMPandCMSClient alexClient = new CMPandCMSClient(cmpMessenger, workspaceDir, 
				"alexesComputer", "alexesContainerKeyPass".toCharArray(), "alexesContainerStorePass".toCharArray());
		CMPAccount alexesAccount = alexClient.newAccount("Alex Tester", alexEmail, "AlexesAccountPassword".toCharArray());
		BlockingContactListener alexesBlockingContactListener = new BlockingContactListener();
		alexesAccount.addContactListener(alexesBlockingContactListener);
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
		List<TrustedCertificateEntry> timContacts = timsAccount.findContacts(certAUthEmail);
		Assert.assertNotNull(timContacts);
		if(timContacts.size()<2){
			timBlockingContactListener.expectContact(certAUthEmail);
			timBlockingContactListener.waitForContacts();
		}
		timContacts = timsAccount.findContacts(certAUthEmail);
		Assert.assertEquals(2, timContacts.size());
		
		
		PrivateKeyEntry timMainMessagePrivateKey = timsAccount.getMainMessagePrivateKey();
		CertificationRequestFieldHolder crf = new CertificationRequestFieldHolder(timMainMessagePrivateKey);
		TrustedCertificateEntry certAuthCaCertificate = timsAccount.findCaSigningCertificateByEmail(certAUthEmail);
		TrustedCertificateEntry certAuthMessagingCertificate = timsAccount.findMessagingCertificateByEmail(certAUthEmail);
	
		X509CertificateHolder certAuthorityCertHolder = V3CertificateUtils.getX509CertificateHolder(certAuthCaCertificate.getTrustedCertificate());
		crf.setCertAuthorityName(certAuthorityCertHolder.getSubject());
		X509CertificateHolder receiverCertificate = V3CertificateUtils.getX509CertificateHolder(certAuthMessagingCertificate.getTrustedCertificate());
		crf.setReceiverCertificate(receiverCertificate);
		crf.setReceiverEmail(certAUthEmail);
		timBlockingContactListener.expectIssuedCertficate(certAUthEmail);
		timsAccount.sendCertificationRequest(crf);
		timBlockingContactListener.waitForIssuedCertificates();
		
		PrivateKeyEntry privateKeyByIssuer = timsAccount.findMessagePrivateKeyByIssuer(certAuthorityCertHolder);
		Assert.assertNotNull(privateKeyByIssuer);
		
	}		
	
//		String caCN="certAuth@plpkixhtest.biz";
//		CMPandCMSClient caClient = new CMPandCMSClient(clients);
//		caClient.register("certAuth", caCN);
//
//		String timCN = "tim@plpkixhtest.biz";
//		CMPandCMSClient timClient = new CMPandCMSClient(clients);
//		timClient.register("tim", timCN);
//		timClient.requestCertification(caCN);
//
//		String alexCN = "alex@plpkixhtest.biz";
//		CMPandCMSClient alexClient = new CMPandCMSClient(clients);
//		alexClient.register("alex", alexCN);
//		alexClient.requestCertification(caCN);
//		
//		// certificate exchange
//		alexClient.fetchCertificate(timCN, caCN);
//		timClient.fetchCertificate(alexCN, caCN);
//		
//		
//		File fileSentByTim = new File(srcFile1);
//		InputStream sentInputStream = new FileInputStream(srcFile1);
//		String fileSentByTimToAlexName = "target/"+fileSentByTim.getName()+".sentByTimToAlex.signed.encrypted";
//		File fileSentByTimToAlex = new File(fileSentByTimToAlexName);
//		OutputStream sentOutputStream = new FileOutputStream(fileSentByTimToAlex );
//		timClient.sendFile(caCN,sentInputStream, sentOutputStream, alexCN);
//		IOUtils.closeQuietly(sentInputStream);
//		IOUtils.closeQuietly(sentOutputStream);
//		
//		InputStream recievedInputStream = new FileInputStream(fileSentByTimToAlexName);
//		File fileRecievedByAlexFromTim = new File("target/"+fileSentByTim.getName()+".recievedByAlexFromTim.decrypted.verified");
//		OutputStream recivedOutputStream = new FileOutputStream(fileRecievedByAlexFromTim);
//		alexClient.receiveFile(recievedInputStream, recivedOutputStream);
//		IOUtils.closeQuietly(recievedInputStream);
//		IOUtils.closeQuietly(recivedOutputStream);
//	
//		boolean contentEquals = FileUtils.contentEquals(
//				new File(srcFile1), 
//				new File(fileRecievedByAlexFromTim.getAbsolutePath()));
//		Assert.assertTrue(contentEquals);
//	}
//
//
//	@Test
//	public void testTimAndTim() throws IOException {
//		ClientMap clients = new ClientMap();
//		String caCN="certAuth@plpkixhtest.biz";
//		CMPandCMSClient caClient = new CMPandCMSClient(clients);
//		caClient.register("certAuth", caCN);
//
//		String timCN = "tim@plpkixhtest.biz";
//		CMPandCMSClient timClient = new CMPandCMSClient(clients);
//		timClient.register("tim", timCN);
//		timClient.requestCertification(caCN);
//		
//		File fileSentByTim = new File(srcFile1);
//		InputStream sentInputStream = new FileInputStream(srcFile1);
//		String fileSentByTimToTimName = "target/"+fileSentByTim.getName()+".sentByTimToTim.signed.encrypted";
//		File fileSentByTimToTim = new File(fileSentByTimToTimName);
//		OutputStream sentOutputStream = new FileOutputStream(fileSentByTimToTim );
//		timClient.sendFile(caCN,sentInputStream, sentOutputStream, timCN);
//		IOUtils.closeQuietly(sentInputStream);
//		IOUtils.closeQuietly(sentOutputStream);
//		
//		InputStream recievedInputStream = new FileInputStream(fileSentByTimToTimName);
//		String fileRecievedByTimFromTimName = "target/"+fileSentByTim.getName()+".recievedByTimFromTim.decrypted.verified";
//		File  fileRecievedByTimFromTim = new File(fileRecievedByTimFromTimName);
//		OutputStream recivedOutputStream = new FileOutputStream(fileRecievedByTimFromTim);
//		timClient.receiveFile(recievedInputStream, recivedOutputStream);
//		IOUtils.closeQuietly(recievedInputStream);
//		IOUtils.closeQuietly(recivedOutputStream);
//	
//		boolean contentEquals = FileUtils.contentEquals(
//				new File(srcFile1), 
//				new File(fileRecievedByTimFromTim.getAbsolutePath()));
//		Assert.assertTrue(contentEquals);
//	}
}
