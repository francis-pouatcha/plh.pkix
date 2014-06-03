package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

import javax.mail.Address;
import javax.mail.Authenticator;
import javax.mail.Folder;
import javax.mail.MessagingException;
import javax.mail.NoSuchProviderException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.event.ConnectionAdapter;
import javax.mail.internet.MimeMessage;

import org.adorsys.plh.pkix.core.utils.email.PloohEmailAuthenticator;
import org.adorsys.plh.pkix.core.utils.ssl.SimpleSSLSocketFactory;

import com.sun.mail.imap.IMAPFolder;
import com.sun.mail.imap.IMAPStore;

/**
 * This maps an imap server and it's inbox and storage folder.
 * 
 * @author fpo
 *
 */
public class IMapServer {

	private final Session session;
	
	private final StoreImpl store;
	private final TransportImpl transport;

	public IMapServer(EmailAccountConfig emailAccountConfig) {

		EmailAccountData emailAccountData = emailAccountConfig.getEmailAccountDAO().getEmailAccountData();
		
		Properties props = new Properties();

		String imapProtocol = "imaps";
		props.setProperty("mail.smtps.host", emailAccountData.getSmtpHostAsString());
		props.setProperty("mail.smtps.auth", "true");
		props.setProperty("mail.smtps.port", emailAccountData.getSmtpPortAsLong()+"");
		props.setProperty("mail.smtps.socketFactory.port", emailAccountData.getSmtpPortAsLong()+"");
		props.setProperty("mail.smtps.ssl.socketFactory.class", SimpleSSLSocketFactory.class.getName());
		props.setProperty("mail.smtps.socketFactory.class", SimpleSSLSocketFactory.class.getName());
		props.setProperty("mail.smtp.starttls.enable", "false");
		props.setProperty("mail.smtps.ssl.trust", "*");
		props.setProperty("mail.smtps.socketFactory.fallback", "true");
		Authenticator auth = new PloohEmailAuthenticator(emailAccountData.getUsernameAsString(), emailAccountData.getPasswordAsString());

		props.setProperty("mail.imap.socketFactory.class","javax.net.ssl.SSLSocketFactory");
		props.setProperty("mail.imap.socketFactory.fallback", "false");

		props.setProperty("mail.store.protocol", imapProtocol);
		session = Session.getInstance(props, auth);
		
		store = new StoreImpl(session);
		transport = new TransportImpl(session);
		

	}

	public Session getSession() {
		return session;
	}
	public StoreImpl getStore(){
		return store;
	}
	public TransportImpl getTransport(){
		return transport;
	}

	public MimeMessage createMimeMessage() {
		return new MimeMessage(session);
	}
	
	static class StoreImpl extends ConnectionAdapter {

		private IMAPStore store;
		private Map<String, FolderImpl> folders = new HashMap<String, IMapServer.FolderImpl>();

		StoreImpl(Session session){
			try {
				store = (IMAPStore) session.getStore();
				store.addConnectionListener(this);
			} catch (NoSuchProviderException e) {
				throw new IllegalStateException(e);
			}
		}
		
		FolderImpl getFolder(String folderName) throws MessagingException{
			FolderImpl folder = folders.get(folderName);
			if(folder==null){
				synchronized (this) {
					folder = new FolderImpl(folderName, store);
					folders.put(folderName, folder);
				}
			}
			return folder;
		}
	}
	
	static class FolderImpl extends ConnectionAdapter {
		private IMAPFolder folder;
		private MessagingException folderUsableException;
		
		boolean folderChecked;
		public FolderImpl(String folderName, IMAPStore store) throws MessagingException {
			this.folder = (IMAPFolder) store.getFolder(folderName);
		}
		
		public IMAPFolder getFolder() throws MessagingException {
			checkExists();
			return folder;
		}
		
		private void checkExists() throws MessagingException {
			if(folderChecked) return;
			
			if(!folder.exists()){
				folder.create(Folder.HOLDS_MESSAGES);
			}
		}

		public IMAPFolder open() throws MessagingException {
			checkExists();
			try {
				folder.open(Folder.READ_WRITE);
			} catch( IllegalStateException e){
				// noop.
			} catch (MessagingException e) {// Folder not usable.
				folderUsableException = e;
				throw e;
			}
			return folder;
		}
		
		public boolean usable(){
			return folderUsableException==null;
		}
		
		public MessagingException getUsageException(){
			return folderUsableException;
		}
		public void closeFolder() throws MessagingException {
			folder.close(false);
		}
	}
	
	static class TransportImpl extends ConnectionAdapter {
		private Transport transport;
		boolean available = false;
		public TransportImpl(Session session){
			try {
				transport = session.getTransport("smtps");
			} catch (NoSuchProviderException e) {
				throw new IllegalStateException(e);
			}
		}

		public boolean sendMessage(MimeMessage message) throws MessagingException {
			Address[] recipients = message.getAllRecipients();
			if (recipients==null || recipients.length==0)return true;
			
			String[] receiverHeader = message.getHeader(PloohMessageHeaders.X_RECEIVER_PUB);
			if(receiverHeader==null || receiverHeader.length!=recipients.length)
				throw new org.jboss.weld.exceptions.IllegalStateException("Message transport requires same number of recipient public key as receivers.");

			String messageIdHeader = MessageUtils.getHeader(message, PloohMessageHeaders.X_MESSAGE_ID);
			if(messageIdHeader==null){
				message.addHeader(PloohMessageHeaders.X_MESSAGE_ID, UUID.randomUUID().toString());
			}
			
			if(!transport.isConnected()){
				synchronized (this) {
					try {
						transport.connect();
					} catch (MessagingException e) {
						available=false;
					}
				}
			}
			if(available){
				message.saveChanges(); // don't forget this
				transport.sendMessage(message, message.getAllRecipients());
				return true;
			}
			return false;
		}
	}
}
