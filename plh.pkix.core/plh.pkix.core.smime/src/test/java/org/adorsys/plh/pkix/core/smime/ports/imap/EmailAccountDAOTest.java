package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.io.File;
import java.io.IOException;
import java.util.UUID;

import javax.mail.internet.MimeMessage;

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

public class EmailAccountDAOTest {
	private static final File testDir = new File("target/"+EmailAccountDAOTest.class.getSimpleName());
	
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
	public void test() throws IOException, SelectedFileNotADirectoryException {
		
		String emailString = "abc@gmail.com";
		String userName = "abc";
		DummyUserAccountFactory accountFactory = new DummyUserAccountFactory(testDir);
		FileContainerCallbackHandler fileContainerCallbackHandler =accountFactory. newFileContainerCallbackHandler(userName, emailString);
		UserAccount userAccount = accountFactory.newUserAccount(userName, fileContainerCallbackHandler);
		
		FileWrapper accountDir = userAccount.getAccountDir();
		FileWrapper emailAccountsDir = accountDir.newChild(emailAccountsDirName);
		String[] list = emailAccountsDir.list();
		Assert.assertTrue(list==null||list.length==0);
	
		DERIA5String accountId = new DERIA5String(UUID.randomUUID().toString());
		
		DERIA5String email = new DERIA5String(emailString);
		DERIA5String password = new DERIA5String(userName);
		EmailAccountData emailAccountData = new EmailAccountData(accountId, email, password);
		emailAccountData.setHost("mail.gmail.com");
		emailAccountData.setPort(961l);
		FileWrapper emailAccountDir = emailAccountsDir.newChild(accountId.getString());
		EmailAccountConfig emailAccountConfig = new EmailAccountConfig(emailAccountDir, emailAccountData, userAccount, messageEndpoint);
		EmailAccountDAO emailAccountDAO = emailAccountConfig.getEmailAccountDAO();
		
		EmailAccountData emailAccountData2 = emailAccountDAO.getEmailAccountData();
		Assert.assertNotNull(emailAccountData2);
		Assert.assertEquals(emailAccountData.getDefaultEmail(), emailAccountData2.getDefaultEmail());
		Assert.assertEquals(emailAccountData2.getDefaultEmailAsString(), emailString);
		Assert.assertEquals(new Long(961), emailAccountData2.getPortAsLong());
	}
}
