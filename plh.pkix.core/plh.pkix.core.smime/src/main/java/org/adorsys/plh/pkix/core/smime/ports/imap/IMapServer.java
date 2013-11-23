package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.util.Properties;

import javax.mail.AuthenticationFailedException;
import javax.mail.Authenticator;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.MimeMessage;

import org.adorsys.plh.pkix.core.utils.email.PloohEmailAuthenticator;
import org.adorsys.plh.pkix.core.utils.ssl.SimpleSSLSocketFactory;
import org.apache.commons.lang3.StringUtils;

import com.sun.mail.imap.IMAPFolder;
import com.sun.mail.imap.IMAPStore;

/**
 * This maps an imap server and it's inbox and storage folder.
 * 
 * @author fpo
 *
 */
public class IMapServer {

	private final String username;
	private final String password;

	private final String host;
	private final int port;

	private IMAPStore server;
	private IMAPFolder inboxFolder;
	private IMAPFolder storageFolder;
	private Session session;
	boolean supportsIdle = true;
	
	public IMapServer(String username, String password, String host, int port) {
		super();
		this.username = username;
		this.password = password;
		this.host = host;
		this.port = port;
	}

	public void initConnection(String inboxFolderName, String storageFoderName) {

		Properties props = new Properties();

		String imapProtocol = "imaps";
		props.setProperty("mail.smtps.host", host);
		props.setProperty("mail.smtps.auth", "true");
		props.setProperty("mail.smtps.port", port+"");
		props.setProperty("mail.smtps.socketFactory.port", port+"");
		props.setProperty("mail.smtps.ssl.socketFactory.class", SimpleSSLSocketFactory.class.getName());
		props.setProperty("mail.smtps.socketFactory.class", SimpleSSLSocketFactory.class.getName());
		props.setProperty("mail.smtp.starttls.enable", "false");
		props.setProperty("mail.smtps.ssl.trust", "*");
		props.setProperty("mail.smtps.socketFactory.fallback", "true");
		Authenticator auth = new PloohEmailAuthenticator(username, password);

		props.setProperty("mail.imap.socketFactory.class","javax.net.ssl.SSLSocketFactory");
		props.setProperty("mail.imap.socketFactory.fallback", "false");

		props.setProperty("mail.store.protocol", imapProtocol);
		session = Session.getDefaultInstance(props, null);
		session.setDebug(true);
		try {
			server = (IMAPStore) session.getStore(imapProtocol);
			connect(inboxFolderName, storageFoderName);
		} catch (MessagingException ex) {
			throw new IllegalStateException(ex);
		}

	

		session = Session.getInstance(props, auth);
	
	}

	private void connect(String inboxFolderName, String storageFoderName) {
		try {
			server.connect(host, port, username, password);
			inboxFolder = (IMAPFolder) server.getFolder(inboxFolderName);
			if(StringUtils.isNotBlank(storageFoderName)){
				storageFolder = (IMAPFolder) server.getFolder(storageFoderName);
			}
		} catch (AuthenticationFailedException ex) {
			throw new IllegalStateException(ex);
		} catch (MessagingException ex) {
			throw new IllegalStateException(ex);
		}
	}

	public void disconnect() {
		try {
			server.close();
		} catch (MessagingException e) {
			e.printStackTrace();
		}
	}

	public Session getSession() {
		return session;
	}

	public IMAPFolder getInboxFolder() {
		return inboxFolder;
	}

	public IMAPFolder getStorageFolder() {
		return storageFolder;
	}

	public MimeMessage createMimeMessage() {
		return new MimeMessage(session);
	}

	public void sendMessage(MimeMessage message) throws MessagingException {
		Transport tr = session.getTransport("smtps");
		tr.connect();
		message.saveChanges(); // don't forget this
		if (message.getAllRecipients()==null)return;
		tr.sendMessage(message, message.getAllRecipients());
		tr.close();
	}
	
}
