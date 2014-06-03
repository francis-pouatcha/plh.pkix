package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.io.File;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import javax.mail.Address;
import javax.mail.Message.RecipientType;
import javax.mail.MessagingException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.adorsys.plh.pkix.core.smime.engines.SMIMEBodyPartEncryptor;
import org.adorsys.plh.pkix.core.smime.plooh.FileContainerCallbackHandler;
import org.adorsys.plh.pkix.core.smime.plooh.SelectedFileNotADirectoryException;
import org.adorsys.plh.pkix.core.smime.plooh.UserAccount;
import org.adorsys.plh.pkix.core.smime.ports.SMIMEMessageEndpoint;
import org.adorsys.plh.pkix.core.test.smime.contact.DummyUserAccountFactory;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.X500NameHelper;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.mail.smime.SMIMEException;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class EmailAccountConfigTest {

	private static final File testDir = new File("target/"+EmailAccountConfigTest.class.getSimpleName());
	
	private static final String emailAccountsDirName = "emailAccountsData";
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		FileUtils.deleteQuietly(testDir);
	}
	@AfterClass
	public static void cleanup(){
		FileUtils.deleteQuietly(testDir);
	}

	private final SMIMEMessageEndpoint messageEndpoint = new SMIMEMessageEndpoint() {
		
		@Override
		public void receive(MimeMessage message) {
			// TODO Auto-generated method stub
			
		}
	};

	@Test
	public void test() throws SelectedFileNotADirectoryException, IOException, MessagingException, SMIMEException {
		
		String emailString = "francis.pouatcha@gmail.com";
		String userName = "francisgmail";
		DummyUserAccountFactory accountFactory = new DummyUserAccountFactory(testDir);
		FileContainerCallbackHandler fileContainerCallbackHandler =accountFactory. newFileContainerCallbackHandler(userName, emailString);
		UserAccount userAccount = accountFactory.newUserAccount(userName, fileContainerCallbackHandler);
		
		FileWrapper accountDir = userAccount.getAccountDir();
		FileWrapper emailAccountsDir = accountDir.newChild(emailAccountsDirName);
		String[] list = emailAccountsDir.list();
		Assert.assertTrue(list==null||list.length==0);
	
		DERIA5String accountId = new DERIA5String(UUID.randomUUID().toString());
		
		DERIA5String email = new DERIA5String(emailString);
		DERIA5String password = new DERIA5String("Ufczgcsavugn8!)");
		EmailAccountData emailAccountData = new EmailAccountData(accountId, email, password);
		FileWrapper emailAccountDir = emailAccountsDir.newChild(accountId.getString());
		EmailAccountConfig emailAccountConfig = new EmailAccountConfig(emailAccountDir, emailAccountData, userAccount, messageEndpoint);
		
		sendMessageToMySelf(emailAccountConfig);
		
	}
	
	public void sendMessageToMySelf(EmailAccountConfig emailAccountConfig) throws IOException, MessagingException, SMIMEException{
		UserAccount userAccount = emailAccountConfig.getUserAccount();
		MimeBodyPart document = new MimeBodyPart();
		document.setText("This is a sample message sent by francis for francis.");
		X509CertificateHolder accountCertificateHolder = userAccount.getAccountCertificateHolder();
		X509Certificate x509Certificate = V3CertificateUtils.getX509JavaCertificate(accountCertificateHolder);
		List<X509Certificate> recipientX509Certificates = Arrays.asList(x509Certificate);
		MimeBodyPart encryptedBodyPart = new SMIMEBodyPartEncryptor()
			.withMimeBodyPart(document)
			.withRecipientX509Certificates(recipientX509Certificates)
			.encrypt();
		MimeMultipart mimeMultipart = new MimeMultipart();
		mimeMultipart.addBodyPart(encryptedBodyPart);
		
		MimeMessage mimeMessage = emailAccountConfig.getIMapServer().createMimeMessage();
		List<String> subjectEmails = X500NameHelper.readSubjectEmails(accountCertificateHolder);
		String subjectEmail = subjectEmails.iterator().next();
		Address[] subjectEmailAddress = new Address[]{new InternetAddress(subjectEmail)};
		mimeMessage.addFrom(subjectEmailAddress);
		mimeMessage.addRecipients(RecipientType.TO, subjectEmailAddress);
		mimeMessage.setSubject("ploohTestMessage");
		
		// add recipients to certificates
		String publicKeyIdentifier = KeyIdUtils.createPublicKeyIdentifierAsString(accountCertificateHolder);
		mimeMessage.addHeader(PloohMessageHeaders.X_RECEIVER_PUB, publicKeyIdentifier);
		
		mimeMessage.setContent(mimeMultipart);
		mimeMessage.saveChanges();
		
		String messageId = UUID.randomUUID().toString();
		try {
			mimeMessage.addHeader(PloohMessageHeaders.X_MESSAGE_ID, messageId);
		} catch (MessagingException e) {
			throw new IllegalStateException(e);
		}
		emailAccountConfig.getIMapServer().getTransport().sendMessage(mimeMessage);
		
	}

}
