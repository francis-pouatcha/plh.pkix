package org.adorsys.plh.pkix.core.smime.ports.imap;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;

import org.adorsys.plh.pkix.core.smime.ports.imap.IMapServer.TransportImpl;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.bouncycastle.asn1.DERIA5String;

/**
 * Read and send out all messages buffered while the transport
 * was not available.
 * @author francis
 *
 */
public class SMPTSendBufferedMessageWorker implements Runnable{

	private final EmailAccountConfig emailAccountConfig;

	private final FileWrapper msgOutDirectory;
	private final FileWrapper msgSentDirectory;
	private final FileWrapper msgErrorDirectory;
	
	public SMPTSendBufferedMessageWorker(EmailAccountConfig emailAccountConfig,
			FileWrapper msgOutDirectory, FileWrapper msgSentDirectory,
			FileWrapper msgErrorDirectory) {
		super();
		this.emailAccountConfig = emailAccountConfig;
		this.msgOutDirectory = msgOutDirectory;
		this.msgSentDirectory = msgSentDirectory;
		this.msgErrorDirectory = msgErrorDirectory;
	}


	@Override
	public void run() {
		IMapServer iMapServer = emailAccountConfig.getIMapServer();
		Session session = iMapServer.getSession();
		TransportImpl transport = iMapServer.getTransport();
		
		String[] list = msgOutDirectory.list();
		for (int i = 0; i < list.length; i++) {
			String messageId = list[i];
			FileWrapper messageFile = msgOutDirectory.newChild(messageId);
			MimeMessage message = MessageUtils.readMessageFrom(messageFile, session);
			boolean sent = false;
			try {
				sent = transport.sendMessage(message);
			} catch (MessagingException e) {
				MessageUtils.documentError(new DERIA5String(messageId), e, msgErrorDirectory);
			}
			if(sent){
				MessageUtils.documentSent(new DERIA5String(messageId), msgSentDirectory);
			} 
		}
	}
}
