package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.io.IOException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import javax.mail.MessagingException;

import org.adorsys.plh.pkix.core.smime.plooh.UserAccount;
import org.adorsys.plh.pkix.core.smime.ports.SMIMEMessageEndpoint;
import org.adorsys.plh.pkix.core.smime.ports.imap.IMapServer.FolderImpl;
import org.adorsys.plh.pkix.core.utils.store.FileWrapper;

public class EmailAccountConfig {
	
	private final FileWrapper emailAccountDir;
	
	private final EmailAccountDAO emailAccountDAO;
	private final EmailSynchDAO emailSynchDAO;
	private final IMapServer iMapServer;

	private final ScheduledExecutorService executorService;

	private final UserAccount userAccount;

	private final SMIMEMessageEndpoint messageEndpoint;

	public EmailAccountConfig(FileWrapper emailAccountDir, EmailAccountData emailAccountData,
			UserAccount userAccount, SMIMEMessageEndpoint messageEndpoint) throws IOException {
		
		this.userAccount = userAccount;
		this.messageEndpoint = messageEndpoint;
		this.executorService = Executors.newScheduledThreadPool(5);
		this.emailAccountDir = emailAccountDir;
		this.emailAccountDAO = new EmailAccountDAO(this, emailAccountData);
		this.emailSynchDAO = new EmailSynchDAO(this);
		this.iMapServer = new IMapServer(this);
		
	}

	public FileWrapper getEmailAccountDir() 
	{
		return emailAccountDir;
	}

	public EmailAccountDAO getEmailAccountDAO() {
		return emailAccountDAO;
	}
	
	

	public EmailSynchDAO getEmailSynchDAO() {
		return emailSynchDAO;
	}

	public IMapServer getIMapServer() {
		return iMapServer;
	}

	public ScheduledExecutorService getExecutionService() {
		return executorService;
	}

	public UserAccount getUserAccount() {
		return userAccount;
	}

	public SMIMEMessageEndpoint getSMIMEMessageEndpoint() {
		return messageEndpoint;
	}

	public FolderImpl getInboxFolder() {
		EmailAccountData emailAccountData = getEmailAccountDAO().getEmailAccountData();
		String inboxFolderName = emailAccountData.getInboxFolderAsString();
		try {
			return getIMapServer().getStore().getFolder(inboxFolderName);
		} catch (MessagingException e) {
			throw new IllegalArgumentException(e);
		}
	}
	public FolderImpl getPloohInFolder() {
		EmailAccountData emailAccountData = getEmailAccountDAO().getEmailAccountData();
		String inboxFolderName = emailAccountData.getPloohInFolderAsString();
		try {
			return getIMapServer().getStore().getFolder(inboxFolderName);
		} catch (MessagingException e) {
			throw new IllegalArgumentException(e);
		}
	}
	public FolderImpl getPloohArchiveFolder() {
		EmailAccountData emailAccountData = getEmailAccountDAO().getEmailAccountData();
		String inboxFolderName = emailAccountData.getPloohArchiveFolderAsString();
		try {
			return getIMapServer().getStore().getFolder(inboxFolderName);
		} catch (MessagingException e) {
			throw new IllegalArgumentException(e);
		}
	}

}
