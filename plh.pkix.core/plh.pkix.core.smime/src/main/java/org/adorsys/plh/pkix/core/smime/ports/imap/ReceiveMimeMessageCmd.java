package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.io.IOException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.util.Date;

import javax.mail.FetchProfile;
import javax.mail.Flags.Flag;
import javax.mail.Folder;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import org.adorsys.plh.pkix.core.smime.plooh.UserAccount;
import org.adorsys.plh.pkix.core.smime.ports.SMIMEMessageEndpoint;
import org.adorsys.plh.pkix.core.utils.KeyIdUtils;
import org.adorsys.plh.pkix.core.utils.V3CertificateUtils;
import org.adorsys.plh.pkix.core.utils.action.ActionContext;
import org.adorsys.plh.pkix.core.utils.cmd.AbstractCommand;
import org.adorsys.plh.pkix.core.utils.cmd.Command;
import org.adorsys.plh.pkix.core.utils.cmd.MailServerAvailableCondition;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEEnvelopedParser;
import org.bouncycastle.mail.smime.SMIMESignedParser;

import com.sun.mail.imap.IMAPFolder;

public class ReceiveMimeMessageCmd extends AbstractCommand {

	public ReceiveMimeMessageCmd(ActionContext commandContext) {
		super(commandContext);
	}

	public ReceiveMimeMessageCmd(String handle, ActionContext parentContext,
			MimeMessage mimeMessage) {
		super(handle, parentContext, null, parentContext.get(MailServerAvailableCondition.class));
		if(getCondition()==null) 
			throw new IllegalStateException("Service of type " + MailServerAvailableCondition.class + " not available in the parent context.");
		commandContext.put(MimeMessageActionData.class, new MimeMessageActionData(mimeMessage));
	}

	
	/**
	 * This command processes at most 100 messages at a time.
	 */
	private int batchSize = 100;
	
	@Override
	public Command call() throws Exception {

		IMAPFolder imapFolder = commandContext.get(IMAPFolder.class);
		if(imapFolder==null) 
			throw new IllegalStateException("Service of type " + IMAPFolder.class + " not available in the context.");

        if(!imapFolder.isOpen())
        	imapFolder.open(Folder.READ_ONLY);
        
        long lastMessageUid = readLastMessageUid(imapFolder);
        
        int msgnum = findMessageWithLowerUid(lastMessageUid,imapFolder);
        
        int start = msgnum;
		int end = msgnum+batchSize;
		
		Message[] messages = imapFolder.getMessages(start, end);
		for (Message message : messages) {
			long currentMessageUid = imapFolder.getUID(message);
			if(currentMessageUid<=lastMessageUid) continue;
			
			boolean receivedMessage = receiveMessage(imapFolder, message);
			if(!receivedMessage) break;
		}
		return this;
	}

	public static final String PROCESSING = "PROCESSING";
	public static final String PROCESSED = "PROCESSED";
	private boolean receiveMessage(IMAPFolder imapFolder, Message message) throws MessagingException, IOException {
		EmailSynchDAO emailSynchDAO = commandContext.get(EmailSynchDAO.class);
        // Read the last stand of the synchronization from the local storage.
        // Extract the last message uid we processed.
        EmailSynchData emailSynchData = emailSynchDAO.getEmailSynchData();
		long currentUid = imapFolder.getUID(message);
		emailSynchData.setLastProcessedUid(new ASN1Integer(currentUid));
		emailSynchData.setLastSynchDate(new DERGeneralizedTime(new Date()));
		emailSynchData.setLastUidValidity(new ASN1Integer(imapFolder.getUIDValidity()));
		emailSynchData.setLasSyncState(new DERIA5String(PROCESSING));
		emailSynchDAO.save();
		try {
			shallProcess(message, imapFolder);
			emailSynchData.setLastSynchDate(new DERGeneralizedTime(new Date()));
			emailSynchData.setLasSyncState(new DERIA5String(PROCESSED));
			emailSynchDAO.save();
			return true;
		} catch(Exception ex){
			emailSynchData.setLastSynchDate(new DERGeneralizedTime(new Date()));
			String msg = ex.getClass().getSimpleName() + ":";
			String message2 = ex.getMessage();
			if(StringUtils.isNotBlank(message2)){
				msg += StringUtils.abbreviate(message2, 100);
			}
			emailSynchData.setLasSyncState(new DERIA5String(msg));
			emailSynchDAO.save();
			return false;
		}
	}

	/**
	 * read the envelope and check if the current user is a listed receiver of the message.
	 * 
	 * @param message
	 * @param imapFolder
	 * @throws MessagingException
	 */
	private void shallProcess(MimeMessage message, IMAPFolder imapFolder) throws MessagingException {
		FetchProfile fp = new FetchProfile();
		fp.add(FetchProfile.Item.CONTENT_INFO);
		Message[] msgs = new Message[]{message};
		imapFolder.fetch(msgs, fp);
		Message msg = msgs[0];
		
		// First check if this is an SMIME message
		// If not return.
		SMIMESignedParser
		
		UserAccount userAccount = commandContext.get(UserAccount.class);
		PrivateKeyEntry privateKeyEntry = userAccount.getAnyMessagePrivateKeyEntry();
		Certificate certificate = privateKeyEntry.getCertificate();
		X509CertificateHolder certificateHolder = V3CertificateUtils.getX509CertificateHolder(certificate);
		String keyIdentifierAsString = KeyIdUtils.readSubjectKeyIdentifierAsString(certificateHolder);
		String[] header = msg.getHeader(PloohMessageHeaders.X_RECEIVER_PUB);
		Message messageToProcess = null;
		for (String receiver_pub : header) {
			if(StringUtils.equalsIgnoreCase(receiver_pub, keyIdentifierAsString)) continue;
			messageToProcess = msg;
			break;
		}
		if(messageToProcess!=null)processReceiveMessage(messageToProcess,imapFolder);
	}

	private void processReceiveMessage(Message msg, IMAPFolder imapFolder) throws MessagingException {
		
		// Before Processing, message must be moved the plooh inbox folder to prevent parallel processing
		// by another agent of the same client.
		
		// We might thing about mutual exclusion of parallel agents, so that only one agent 
		// collect and process the messages. And then share the decision with their peers before making it 
		// vali locally.
		
		FetchProfile fp = new FetchProfile();
		fp.add(FetchProfile.Item.CONTENT_INFO);
		fp.add(FetchProfile.Item.ENVELOPE);
		fp.add(PloohMessageHeaders.X_RECEIVER_PUB);
		Message[] msgs = new MimeMessage[]{(MimeMessage) msg};
		imapFolder.fetch(msgs, fp);
		// Store in the local inbox folder for processing
		SMIMEMessageEndpoint endpoint = commandContext.get(SMIMEMessageEndpoint.class);
		endpoint.receive((MimeMessage) msg;
		
		// TODO create a mail delete command, to ensure deletion of this message later.
		
	}

	private long readLastMessageUid(IMAPFolder imapFolder) throws MessagingException{
		EmailSynchDAO emailSynchDAO = commandContext.get(EmailSynchDAO.class);
        // Read the last stand of the synchronization from the local storage.
        // Extract the last message uid we processed.
        EmailSynchData emailSynchData = emailSynchDAO.getEmailSynchData();
        ASN1Integer lastUidValidity = emailSynchData.getLastUidValidity();
        long lastMessageUid = -1;
        if(lastUidValidity!=null){
        	long uidValidity = lastUidValidity.getValue().longValue();
        	long currentUidValidity = imapFolder.getUIDValidity();
        	if(uidValidity==currentUidValidity){
        		ASN1Integer lastProcessedUid = emailSynchData.getLastProcessedUid();
        		if(lastProcessedUid!=null){
        			lastMessageUid = lastProcessedUid.getValue().longValue();
        		}
        	}
        }
        return lastMessageUid;
	}

	private int findMessageWithLowerUid(long lastMessageUid, IMAPFolder imapFolder) throws MessagingException 
	{
        int msgnum = 1;// first message
        if(lastMessageUid<=-1)return msgnum;
		
		int messageCount = imapFolder.getMessageCount();
		msgnum = messageCount-batchSize;
		while (msgnum>0) {
			Message message = imapFolder.getMessage(msgnum);
			long messageUid = imapFolder.getUID(message);
			if(messageUid<lastMessageUid){
				return msgnum;
			}
		}
		return msgnum;
	}
}
