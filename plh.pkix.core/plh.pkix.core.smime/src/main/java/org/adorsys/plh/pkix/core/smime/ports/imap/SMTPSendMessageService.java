package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.util.UUID;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import org.adorsys.plh.pkix.core.smime.ports.imap.IMapServer.TransportImpl;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.bouncycastle.asn1.DERIA5String;

/**
 * This class buffers all messages to be sent in a directory and send them out 
 * as the smtp server gets available.
 * 
 * @author francis
 *
 */
public class SMTPSendMessageService {

	/**
	 * The file in which account information are stored.
	 */
	private static final String MSG_OUT_DIR = "smtp_msg_out";
	/**
	 * We will will store file name of each sent message here and 
	 * delete is later.
	 * 
	 */
	private static final String MSG_SENT_DIR = "smtp_msg_sent";
	private static final String MSG_ERROR_DIR = "smtp_msg_err";

	private final EmailAccountConfig emailAccountConfig;

	private final FileWrapper msgOutDirectory;
	private final FileWrapper msgSentDirectory;
	private final FileWrapper msgErrorDirectory;
	
	private final SMPTSendBufferedMessageWorker sendBufferedMessageWorker;
	private final SMTPDeleteSentMessageWorker sendDeleteSentMessageWorker;
	
	public SMTPSendMessageService(EmailAccountConfig emailAccountConfig) {
		this.emailAccountConfig = emailAccountConfig;
		ScheduledExecutorService service = emailAccountConfig.getExecutionService();
		msgOutDirectory = emailAccountConfig.getEmailAccountDir().newChild(MSG_OUT_DIR);
		msgSentDirectory = emailAccountConfig.getEmailAccountDir().newChild(MSG_SENT_DIR);
		msgErrorDirectory = emailAccountConfig.getEmailAccountDir().newChild(MSG_ERROR_DIR);

		sendBufferedMessageWorker = new SMPTSendBufferedMessageWorker(emailAccountConfig, msgOutDirectory, msgSentDirectory, msgErrorDirectory);
		service.scheduleAtFixedRate(sendBufferedMessageWorker, 1, 5, TimeUnit.SECONDS);
		
		sendDeleteSentMessageWorker = new SMTPDeleteSentMessageWorker(msgSentDirectory, msgOutDirectory);
		service.scheduleAtFixedRate(sendDeleteSentMessageWorker, 5, 10, TimeUnit.SECONDS);
	}

	/**
	 * Store the mime message in a folder and handle it asynchronously to the mail server.
	 * 
	 * @param mimeMessage
	 * @throws MessagingException 
	 */
	public void sendMimeMessage(MimeMessage mimeMessage) {
		String messageId = UUID.randomUUID().toString();
		try {
			mimeMessage.addHeader(PloohMessageHeaders.X_MESSAGE_ID, messageId);
		} catch (MessagingException e) {
			throw new IllegalStateException(e);
		}
		
		IMapServer iMapServer = emailAccountConfig.getIMapServer();
		TransportImpl transport = iMapServer.getTransport();
		boolean sent = false;
		try {
			sent = transport.sendMessage(mimeMessage);
		} catch (MessagingException e) {
			MessageUtils.documentError(new DERIA5String(messageId), e, msgErrorDirectory);
		}

		if(!sent){
			FileWrapper emailAccountDir = emailAccountConfig.getEmailAccountDir();
			FileWrapper messageOutDir = emailAccountDir.newChild(MSG_OUT_DIR);
			FileWrapper messageFile = messageOutDir.newChild(messageId);
			// store message
			MessageUtils.writeMessageTo(mimeMessage, messageFile);
		} else {
			MessageUtils.documentSent(new DERIA5String(messageId), msgSentDirectory);
		}
	}
}
