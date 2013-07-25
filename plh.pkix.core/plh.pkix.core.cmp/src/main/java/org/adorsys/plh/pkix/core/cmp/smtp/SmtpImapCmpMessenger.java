package org.adorsys.plh.pkix.core.cmp.smtp;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.adorsys.plh.pkix.core.cmp.CMPMessageEndpoint;
import org.adorsys.plh.pkix.core.cmp.CMPMessenger;
import org.adorsys.plh.pkix.core.cmp.handler.CMPDataGenerator;
import org.adorsys.plh.pkix.core.utils.X500NameHelper;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;

public class SmtpImapCmpMessenger {//implements CMPMessenger {
//	
//	Map<String, SMTPSender> smtpSenders = new HashMap<String, SMTPSender>();
//	
//	@Override
//	public void send(PKIMessage pkiMessage) {
//		PKIHeader header = pkiMessage.getHeader();
//		String recipientEmail = readEmail(header.getRecipient());
//		if(recipientEmail==null)			
//			throw new IllegalArgumentException("Expecting recipient to be from type rfc822Name or directoryName");
//		String senderEmail = readEmail(header.getSender());
//		if(senderEmail==null)			
//			throw new IllegalArgumentException("Expecting sender to be from type rfc822Name or directoryName");
//		
//		SMTPSender smtpSender = smtpSenders.get(senderEmail);
//		MimeMessage mimeMsessage = smtpSender.createMimeMessage();
//		MimeBodyPart mimeBodyPart = new CMPDataGenerator().generate(pkiMessage);
//		
//		try {
//	        MimeMultipart mimeMultipart = new MimeMultipart();
//	        mimeMultipart.addBodyPart(mimeBodyPart);
//	        mimeMsessage.setContent(mimeMultipart);
//	        mimeMsessage.setSender(address);
//	        smtpSender.sendMessage(mimeMsessage);
//			
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (MessagingException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//	}
//
//	@Override
//	public void registerMessageEndPoint(CMPMessageEndpoint endpoint,PKIMessage initRequest) {
//		// TODO Auto-generated method stub
//
//	}
//
//	private String readEmail(GeneralName entity){
//		if(entity.getTagNo()==GeneralName.rfc822Name){
//			DERIA5String emailString = DERIA5String.getInstance(entity.getName());
//			return emailString.getString();
//		} else if (entity.getTagNo()==GeneralName.directoryName){
//			X500Name recipientDN = X500Name.getInstance(entity.getName());
//			String emailFromDN = X500NameHelper.readEmailFromDN(recipientDN);
//			return emailFromDN;
//		}
//		return null;
//	}
}
