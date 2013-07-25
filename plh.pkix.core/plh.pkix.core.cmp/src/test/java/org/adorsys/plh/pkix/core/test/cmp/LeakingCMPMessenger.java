package org.adorsys.plh.pkix.core.test.cmp;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.UUID;

import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.adorsys.plh.pkix.core.cmp.InMemoryCMPMessenger;
import org.adorsys.plh.pkix.core.cmp.handler.CMPDataGenerator;
import org.adorsys.plh.pkix.core.cmp.handler.CMPDataParser;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.cmp.PKIMessage;

public class LeakingCMPMessenger extends InMemoryCMPMessenger {
	File directory = null;
	
	
	public LeakingCMPMessenger(File workspaceDir) {
		super();
		directory = new File(workspaceDir, "leakingCmp");
	}


	@Override
	public void send(PKIMessage pkiMessage) {
        Properties props = System.getProperties();
		File f = new File(directory, UUID.randomUUID().toString());
		FileOutputStream fos = null;
		try {
			f.getParentFile().mkdirs();
			fos = new FileOutputStream(f);
	        MimeBodyPart mimeBodyPart = new CMPDataGenerator().generate(pkiMessage);
	        Session session = Session.getDefaultInstance(props, null);
	        MimeMessage mimeMessage = new MimeMessage(session);
	        MimeMultipart mimeMultipart = new MimeMultipart();
	        mimeMultipart.addBodyPart(mimeBodyPart);
			mimeMessage.setContent(mimeMultipart);
			mimeMessage.writeTo(fos);
		} catch (FileNotFoundException e) {
			String message = e.getMessage();
		} catch (IOException e) {
			String message = e.getMessage();
		} catch (MessagingException e) {
			String message = e.getMessage();
		} finally{
			IOUtils.closeQuietly(fos);
		}
		
		PKIMessage pkiMessage2 = null;
		FileInputStream fis = null;;
		try {
			fis = new FileInputStream(f);
			Session session = Session.getDefaultInstance(props, null);
			MimeMessage mimeMessage = new MimeMessage(session, fis);
			MimeMultipart mimeMultipart = (MimeMultipart) mimeMessage.getContent();
			BodyPart bodyPart = mimeMultipart.getBodyPart(0);
			pkiMessage2 = new CMPDataParser().parse(bodyPart);
		} catch (FileNotFoundException e) {
			String message = e.getMessage();
		} catch (MessagingException e) {
			String message = e.getMessage();
		} catch (IOException e) {
			String message = e.getMessage();
		} finally{
			IOUtils.closeQuietly(fis);
		}
        
		if(!pkiMessage.equals(pkiMessage2)){
			throw new IllegalStateException("Can not send message through a mail channel");
		}
		super.send(pkiMessage);
	}

}
