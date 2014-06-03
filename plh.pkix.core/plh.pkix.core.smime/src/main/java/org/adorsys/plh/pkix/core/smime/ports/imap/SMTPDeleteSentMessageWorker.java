package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.io.IOException;
import java.text.ParseException;
import java.util.Date;

import org.adorsys.plh.pkix.core.utils.store.FileWrapper;
import org.apache.commons.lang3.time.DateUtils;

public class SMTPDeleteSentMessageWorker implements Runnable {

	private final FileWrapper msgSentDirectory;
	private final FileWrapper msgOutDirectory;

	private static final int gracePeriod = 20;
	
	public SMTPDeleteSentMessageWorker(FileWrapper msgSentDirectory,
			FileWrapper msgOutDirectory) {
		this.msgSentDirectory = msgSentDirectory;
		this.msgOutDirectory = msgOutDirectory;
	}

	@Override
	public void run() {
		String[] list = msgSentDirectory.list();
		for (String messageId : list) {
			try {
				SMTPSentMessageData sentMessage = MessageUtils.readSentMessage(messageId, msgSentDirectory);
				Date date = sentMessage.getSent().getDate();
				if(DateUtils.addSeconds(date, gracePeriod).before(new Date())){
					FileWrapper messageFile = msgOutDirectory.newChild(messageId);
					if(messageFile.exists()){
						messageFile.delete();
					}
					FileWrapper sentMessageFile = msgSentDirectory.newChild(messageId);
					if(sentMessageFile.exists()){
						sentMessageFile.delete();
					}
				}
				
			} catch (IOException e) {
				throw new IllegalStateException(e);
			} catch (ParseException e) {
				throw new IllegalStateException(e);
			}
		}
	}

}
