package org.adorsys.plh.pkix.core.smime.ports.imap;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.mail.AuthenticationFailedException;
import javax.mail.MessagingException;
import javax.mail.NoSuchProviderException;
import javax.mail.Session;
import javax.mail.Store;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.ParseException;
import javax.net.ssl.SSLHandshakeException;

import org.adorsys.plh.pkix.core.utils.email.MailAddress;
import org.adorsys.plh.pkix.core.utils.ssl.SimpleSSLSocketFactory;
import org.apache.commons.lang3.StringUtils;

public class MailServerAddresses {
	
	private static final Map<String, MailServerAddress> MAILSERVERADDRESSES_MAP = new HashMap<String, MailServerAddress>();
	
	private static final MailServerAddresses instance  = new MailServerAddresses();
	
	public static final MailServerAddresses getInstance(){
		return instance;
	}
	
	private MailServerAddresses(){
		new MailServerAddress()
			.setDomain("adorsys.de")
			.setImapAddress("mail.adorsys.de")
			.setSmtpAddress("mail.adorsys.de")
			.putIn(MAILSERVERADDRESSES_MAP);
		
		new MailServerAddress()
			.setDomain("adorsys.com")
			.setImapAddress("mail.adorsys.com")
			.setSmtpAddress("mail.adorsys.com")
			.putIn(MAILSERVERADDRESSES_MAP);
		
		new MailServerAddress()
			.setDomain("afrotools.com")
			.setImapAddress("imap.afrotools.com")
			.setSmtpAddress("smtp.afrotools.com")
			.putIn(MAILSERVERADDRESSES_MAP);

		new MailServerAddress()
			.setDomain("bellsouth.net")
			.setImapAddress("mail.bellsouth.net")
			.setSmtpAddress("smtp.bellsouth.net")
			.putIn(MAILSERVERADDRESSES_MAP);

		new MailServerAddress()
			.setDomain("currysimple.com")
			.setImapAddress("imap.currysimple.com")
			.setSmtpAddress("smtp.currysimple.com")
			.putIn(MAILSERVERADDRESSES_MAP);

		new MailServerAddress()
		.setDomain("gaccsouth.com")
		.setImapAddress("mail.gaccsouth.com")
		.setSmtpAddress("smtp.gaccsouth.com")
		.putIn(MAILSERVERADDRESSES_MAP);

		new MailServerAddress()
			.setDomain("germanhealthplans.com")
			.setImapAddress("imap.germanhealthplans.com")
			.setSmtpAddress("smtp.germanhealthplans.com")
			.putIn(MAILSERVERADDRESSES_MAP);
		
		new MailServerAddress()
			.setDomain("gmx.de")
			.setImapAddress("imap.gmx.de")
			.setSmtpAddress("mail.gmx.de")
			.putIn(MAILSERVERADDRESSES_MAP);

		new MailServerAddress()
			.setDomain("gmx.com")
			.setImapAddress("imap.gmx.com")
			.setSmtpAddress("mail.gmx.com")
			.putIn(MAILSERVERADDRESSES_MAP);

		new MailServerAddress()
			.setDomain("gmail.com")
			.setImapAddress("mail.gmail.com")
			.setSmtpAddress("mail.gmail.com")
			.putIn(MAILSERVERADDRESSES_MAP);

		new MailServerAddress()
			.setDomain("googlemail.com")
			.setImapAddress("imap.googlemail.com")
			.setSmtpAddress("smtp.googlemail.com")
			.putIn(MAILSERVERADDRESSES_MAP);

		new MailServerAddress()
			.setDomain("hotmail.com")
			.setImapAddress("mail.hotmail.com")
			.setSmtpAddress("smtp.hotmail.com")
			.putIn(MAILSERVERADDRESSES_MAP);

		new MailServerAddress()
			.setDomain("msn.com")
			.setImapAddress("mail.msn.com")
			.setSmtpAddress("smtp.msn.com")
			.putIn(MAILSERVERADDRESSES_MAP);

		new MailServerAddress()
			.setDomain("simpaq.com")
			.setImapAddress("imap.simpaq.com")
			.setSmtpAddress("smtp.simpaq.com")
			.putIn(MAILSERVERADDRESSES_MAP);

		new MailServerAddress()
			.setDomain("web.de")
			.setImapAddress("imap.web.de")
			.setSmtpAddress("smtp.web.de")
			.putIn(MAILSERVERADDRESSES_MAP);

		new MailServerAddress()
			.setDomain("yahoo.com")
			.setImapAddress("imap.yahoo.com")
			.setSmtpAddress("smtp.yahoo.com")
			.putIn(MAILSERVERADDRESSES_MAP);

		new MailServerAddress()
			.setDomain("yahoo.fr")
			.setImapAddress("imap.yahoo.fr")
			.setSmtpAddress("smtp.yahoo.fr")
			.putIn(MAILSERVERADDRESSES_MAP);
	}
	
	public void preprocessMailAccount(final EmailAccountData emailAccount)
			throws ParseException {
		String email = emailAccount.getDefaultEmailAsString();
		if (email == null)
			return;
		InternetAddress internetAddress = new InternetAddress(email);
		MailAddress mailAddress = new MailAddress(internetAddress);
		
		@SuppressWarnings("deprecation")
		String host = mailAddress.getHost();
		
		host = host.toLowerCase();
		MailServerAddress mailServerAddress = MAILSERVERADDRESSES_MAP.get(host);
		
		String imapHostTest = "imap." + host;
		String smtpHostTest = "smtp." + host;
		String mailHostTest = "mail." + host;

		String imapHost = emailAccount.getHostAsString();
		
		if (StringUtils.isBlank(imapHost)) {
			if (mailServerAddress != null) {
				emailAccount.setHost(mailServerAddress.getImapAddress());
				emailAccount.setPort(new Long(mailServerAddress.getImapsPort()));
			} else {
				// Validate host before setting
				if (testImapHost(imapHostTest)) {
					emailAccount.setHost(imapHostTest);
				} else if (testImapHost(mailHostTest)) {
					emailAccount.setHost(mailHostTest);
				} else {
					emailAccount.setAdvanced(true);
					throw new ParseException("Unable to check email host.");
				}
			}
		}
		
		String smtpHost = emailAccount.getSmtpHostAsString();
		if (StringUtils.isBlank(smtpHost)) {
			if (mailServerAddress != null) {
				emailAccount.setSmtpHost(mailServerAddress.getSmtpAddress());
				emailAccount.setSmtpPort(new Long(mailServerAddress.getSmtpsPort()));
			} else {
				// Validate host before setting
				if (testSmtpHost(smtpHostTest)) {
					emailAccount.setSmtpHost(smtpHostTest);
				} else if (testSmtpHost(mailHostTest)) {
					emailAccount.setSmtpHost(mailHostTest);
				} else {
					emailAccount.setAdvanced(true);
					throw new ParseException("Unable to check email host.");
				}
			}
		}
	}

	private static boolean testImapHost(String imapHostTest) {
		try {
			InetAddress.getByName(imapHostTest).isReachable(2000);
		} catch (UnknownHostException e) {
			return false;
		} catch (IOException e) {
			return checkImapHost(imapHostTest, -1);
		}
		return true;
	}

	private static boolean testSmtpHost(String host) {
		try {
			InetAddress.getByName(host).isReachable(2000);
		} catch (UnknownHostException e) {
			return false;
		} catch (IOException e) {
			return checkSmtpHost(host, -1);
		}
		return true;
	}
	
	public static boolean checkImapHost(String host, int port) {
		Properties properties = new Properties();
		addSSLMailProperties(properties);
		Session instance = Session.getInstance(properties);
		Store store = null;

		try {
			store = instance.getStore("imaps");
		} catch (NoSuchProviderException e) {
			throw new IllegalStateException(
					"IMAP_PROTOCOL_NOT_AVAILABLE_SOPS_7019");
		}
		try {
			store.connect(host, 993, "mario.bastler.x24", "mario1590");
		} catch (AuthenticationFailedException au) {
			return true;
		} catch (MessagingException e) {
			Throwable cause = e.getCause();
			if (cause != null && cause instanceof UnknownHostException) {
				return false;
			}
			if (cause != null && cause instanceof SSLHandshakeException) {
				return true;
			}
		}
		return true;
	}

	
	public static boolean checkSmtpHost(String host, int port) {
		Properties properties = new Properties();
		properties.put("mail.smtp.host", host);
		properties.put("mail.smtp.port", port);
		addSSLMailProperties(properties);
		Session session = Session.getDefaultInstance(properties, null);
		try {
			session.getTransport().connect("mario.bastler.x24", "mario1590");
		} catch (NoSuchProviderException e) {
			return false;
		} catch (MessagingException e) {
			Throwable cause = e.getCause();
			if (cause != null && cause instanceof UnknownHostException) {
				return false;
			}
			if (cause != null && cause instanceof SSLHandshakeException) {
				return true;
			}
		} finally {
			try {
				session.getTransport().close();
			} catch (NoSuchProviderException e) {

			} catch (MessagingException e) {

			}
		}
		return false;

	}	
	
	public static void addSSLMailProperties(final Properties properties) {
		// set this session up to use SSL for IMAP connections
		properties.setProperty("mail.smtp.socketFactory.class",
				SimpleSSLSocketFactory.class.getName());
		properties.setProperty("mail.imaps.socketFactory.class",
				SimpleSSLSocketFactory.class.getName());
		properties.setProperty("mail.pop3s.socketFactory.class",
				SimpleSSLSocketFactory.class.getName());
		// don't fallback to normal IMAP connections on failure.
		properties.setProperty("mail.smtp.socketFactory.fallback", "false");
		properties.setProperty("mail.imaps.socketFactory.fallback", "false");
		properties.setProperty("mail.pop3s.socketFactory.fallback", "false");
	}

	public static boolean checkImapHost(EmailAccountData emailAccount) throws MessagingException {
		Properties properties = new Properties();
		addSSLMailProperties(properties);
		Session instance = Session.getInstance(properties);
		Store store = null;

		try {
			store = instance.getStore("imaps");
			emailAccount.setProtocol("imaps");
		} catch (NoSuchProviderException e) {
			throw new IllegalStateException("IMAP_PROTOCOL_NOT_AVAILABLE_SOPS_7019");
		}
		try {
			store.connect(emailAccount.getHostAsString(), 993, "mario.bastler.x24", "mario1590");
		} catch (AuthenticationFailedException au) {
			emailAccount.setPort(993l);
			return true;
		}
		return true;
	}	
	

	public static boolean checkSmtpHost(EmailAccountData emailAccount) throws MessagingException {
		Properties properties = new Properties();
		properties.put("mail.smtp.host", emailAccount.getSmtpHost());
		addSSLMailProperties(properties);
		Session session = Session.getDefaultInstance(properties, null);
		try {
			session.getTransport("smtp").connect("mario.bastler.x24", "mario1590");
		} catch (NoSuchProviderException e) {
			throw new IllegalStateException("SMTP_PROTOCOL_NOT_AVAILABLE_SOPS_7019");
		} finally {
			try {
				session.getTransport().close();
			} catch (NoSuchProviderException e) {

			} catch (MessagingException e) {

			}
		}
		return true;
	}	
													
}
