package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.io.File;
import java.io.IOException;
import java.util.Date;
import java.util.UUID;

import javax.mail.internet.MimeMessage;

import org.adorsys.plh.pkix.core.smime.plooh.FileContainerCallbackHandler;
import org.adorsys.plh.pkix.core.smime.plooh.SelectedFileNotADirectoryException;
import org.adorsys.plh.pkix.core.smime.plooh.UserAccount;
import org.adorsys.plh.pkix.core.smime.ports.SMIMEMessageEndpoint;
import org.adorsys.plh.pkix.core.test.smime.contact.DummyUserAccountFactory;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class EmailSynchDAOTest {

	private static final File testDir = new File("target/"+EmailSynchDAOTest.class.getSimpleName());
	
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
	public static void cleanup(){
		FileUtils.deleteQuietly(testDir);
	}
	
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
		DERIA5String password = new DERIA5String("abc");
		EmailAccountData emailAccountData = new EmailAccountData(accountId, email, password);
		emailAccountData.setHost("mail.gmail.com");
		emailAccountData.setPort(961l);
		
		FileWrapper emailAccountDir = emailAccountsDir.newChild(accountId.getString());
		EmailAccountConfig emailAccountConfig = new EmailAccountConfig(emailAccountDir, emailAccountData, userAccount, messageEndpoint);
		
		EmailSynchDAO emailSynchDAO = emailAccountConfig.getEmailSynchDAO();
		EmailSynchData emailSynchData = emailSynchDAO.getEmailSynchData();
		emailSynchData.setLasSyncState(new DERIA5String("Success"));
		Date now = new Date();
		emailSynchData.setLastSynchDate(new DERGeneralizedTime(now));
		emailSynchData = emailSynchDAO.save().load().getEmailSynchData();
		Assert.assertEquals(emailSynchData.getLasSyncState(), new DERIA5String("Success"));
		Assert.assertEquals(new DERGeneralizedTime(now), emailSynchData.getLastSynchDate());
	}
	
	@Test
	public void testDate(){
		Date now = new Date();
		Date date2 = new Date(now.getTime());
		Assert.assertEquals(now, date2);
		DERGeneralizedTime derGeneralizedTime = new DERGeneralizedTime(now);
		ASN1Primitive asn1Primitive = derGeneralizedTime.toASN1Primitive();
		DERGeneralizedTime instance = DERGeneralizedTime.getInstance(asn1Primitive);
		Assert.assertEquals(new DERGeneralizedTime(now), instance);
	}
}
