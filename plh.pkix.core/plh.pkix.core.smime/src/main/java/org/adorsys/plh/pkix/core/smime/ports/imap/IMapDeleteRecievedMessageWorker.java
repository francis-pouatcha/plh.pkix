package org.adorsys.plh.pkix.core.smime.ports.imap;

import javax.mail.FolderClosedException;
import javax.mail.MessagingException;
import javax.mail.StoreClosedException;

import org.adorsys.plh.pkix.core.smime.ports.imap.IMapServer.FolderImpl;

/**
 * Periodically expunges the inbox folder.
 * 
 * @author francis
 *
 */
public class IMapDeleteRecievedMessageWorker implements Runnable {
	
	private final FolderImpl inboxFolder;
	
	public IMapDeleteRecievedMessageWorker(
			EmailAccountConfig emailAccountConfig) {
		this.inboxFolder = emailAccountConfig.getInboxFolder();
	}

	@Override
	public void run() {
		try {
			inboxFolder.getFolder().expunge();
		} catch (MessagingException m) {
			boolean closedFodlerStore =
			m instanceof FolderClosedException || m instanceof StoreClosedException;
			if(!closedFodlerStore){
				throw new IllegalStateException(m);
			}
		}
	}

}
