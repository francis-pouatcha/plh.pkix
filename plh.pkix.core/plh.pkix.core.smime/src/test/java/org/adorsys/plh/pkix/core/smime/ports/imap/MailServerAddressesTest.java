package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.io.File;
import java.io.IOException;
import java.util.UUID;

import javax.mail.internet.MimeMessage;
import javax.mail.internet.ParseException;

import org.adorsys.plh.pkix.core.smime.plooh.FileContainerCallbackHandler;
import org.adorsys.plh.pkix.core.smime.plooh.SelectedFileNotADirectoryException;
import org.adorsys.plh.pkix.core.smime.plooh.UserAccount;
import org.adorsys.plh.pkix.core.smime.ports.SMIMEMessageEndpoint;
import org.adorsys.plh.pkix.core.test.smime.contact.DummyUserAccountFactory;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.DERIA5String;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class MailServerAddressesTest {

	private static final File testDir = new File("target/"
			+ MailServerAddressesTest.class.getSimpleName());

	private static final String emailAccountsDirName = "emailAccountsData";
	private final SMIMEMessageEndpoint messageEndpoint = new SMIMEMessageEndpoint() {
		
		@Override
		public void receive(MimeMessage message) {
			// TODO Auto-generated method stub
			
		}
	};
	

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		FileUtils.deleteQuietly(testDir);
	}

	@AfterClass
	public static void cleanup() {
		FileUtils.deleteQuietly(testDir);
	}

	@Test
	public void test() throws IOException, SelectedFileNotADirectoryException,
			ParseException {
		String emailString = "francis.pouatcha@gmail.com";
		String userName = "abc";
		DummyUserAccountFactory accountFactory = new DummyUserAccountFactory(testDir);
		FileContainerCallbackHandler fileContainerCallbackHandler =accountFactory. newFileContainerCallbackHandler(userName, emailString);
		UserAccount userAccount = accountFactory.newUserAccount(userName, fileContainerCallbackHandler);

		FileWrapper accountDir = userAccount.getAccountDir();
		FileWrapper emailAccountsDir = accountDir
				.newChild(emailAccountsDirName);
		String[] list = emailAccountsDir.list();
		Assert.assertTrue(list == null || list.length == 0);

		DERIA5String accountId = new DERIA5String(UUID.randomUUID().toString());

		DERIA5String email = new DERIA5String(emailString);
		DERIA5String password = new DERIA5String(userName);
		EmailAccountData emailAccountData = new EmailAccountData(accountId,
				email, password);

		FileWrapper emailAccountDir = emailAccountsDir.newChild(accountId
				.getString());
		EmailAccountConfig emailAccountConfig = new EmailAccountConfig(emailAccountDir, emailAccountData, userAccount, messageEndpoint);

		MailServerAddresses.getInstance().preprocessMailAccount(
				emailAccountData);
		EmailAccountDAO emailAccountDAO = emailAccountConfig
				.getEmailAccountDAO();
		emailAccountData = emailAccountDAO
				.setEmailAccountData(emailAccountData).save().load()
				.getEmailAccountData();

		Assert.assertEquals("mail.gmail.com", emailAccountData.getSmtpHost()
				.getString());
		Assert.assertEquals("mail.gmail.com", emailAccountData.getHost()
				.getString());
	}
}
