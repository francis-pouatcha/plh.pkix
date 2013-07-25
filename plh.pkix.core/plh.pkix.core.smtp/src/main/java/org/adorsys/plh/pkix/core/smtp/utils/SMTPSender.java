package org.adorsys.plh.pkix.core.smtp.utils;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Properties;
import java.util.UUID;

import javax.mail.Authenticator;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.adorsys.plh.pkix.core.utils.email.PloohEmailAuthenticator;
import org.adorsys.plh.pkix.core.utils.ssl.SimpleSSLSocketFactory;
import org.bouncycastle.asn1.x500.X500Name;

public class SMTPSender {

	private Session session;
	
	private PloohSMTPSecrets ploohSMTPSecrets;

	private SMTPSender(String server, String username, String passwort,
			String port, PloohSMTPSecrets ploohSMTPSecrets) {

		this.ploohSMTPSecrets = ploohSMTPSecrets;
		Properties props = new Properties();
		props.setProperty("mail.smtps.host", server);
		props.put("mail.smtps.auth", "true");
		props.put("mail.smtps.port", port);
		props.put("mail.smtps.socketFactory.port", port);
		props.put("mail.smtps.ssl.socketFactory.class",
				SimpleSSLSocketFactory.class.getName());
		props.put("mail.smtps.socketFactory.class",
				SimpleSSLSocketFactory.class.getName());
		props.put("mail.smtp.starttls.enable", "false");
		props.setProperty("mail.smtps.ssl.trust", "*");

		props.put("mail.smtps.socketFactory.fallback", "true");
		Authenticator auth = new PloohEmailAuthenticator(username, passwort);
		session = Session.getInstance(props, auth);
	}

	public void sendMessage(MimeMessage message) throws MessagingException {
		Transport tr = session.getTransport("smtps");
		tr.connect();
		message.saveChanges(); // don't forget this
		if (message.getAllRecipients()==null)return;
		tr.sendMessage(message, message.getAllRecipients());
		tr.close();
	}

	public MimeMessage createMimeMessage() {
		return new MimeMessage(session);
	}

	public static SMTPSender newSender(PloohSMTPSecrets ploohSMTPSecrets) {
		String server = ploohSMTPSecrets.getSmtpsHost();
		String username = ploohSMTPSecrets.getSmtpsUserName(); 
		String password = ploohSMTPSecrets.getSmtpsPassword(); 
		String port = ploohSMTPSecrets.getSmtpsPort(); 
		return new SMTPSender(server, username, password, port, ploohSMTPSecrets);
	}

	public static SMTPSender newSender(String server, String username, String password, PloohSMTPSecrets ploohSMTPSecrets) {
		String port = ploohSMTPSecrets.getSmtpsPort(); 
		return new SMTPSender(server, username, password, port, ploohSMTPSecrets);
	}
	
	public void setMessageId(final MimeMessage mimeMessage) throws MessagingException {
		String string = UUID.randomUUID().toString();
		String server = ploohSMTPSecrets.getSmtpsHost(); 
		mimeMessage.setHeader("Message-ID", "<" + string + ".plooh@" + server + ">");
	}
	
	public static MimeMessage signMessage(
			PrivateKey senderPrivateKey,
			X509Certificate senderCertificate,X500Name sender,
			X509Certificate issuerCertificate, X500Name issuer,			
			MimeBodyPart mbp, MimeMessage msg) {
		MimeMessage signMail;
		try {
//			SMIMESignEncryptUtils signEncryptUtils = new SMIMESignEncryptUtils();
//			signMail = signEncryptUtils.signMail(
//					senderPrivateKey, senderCertificate, sender, 
//					issuerCertificate, issuer, mbp, msg);
//		} catch (CertificateEncodingException e) {
//			throw new IllegalStateException("CERTIFICATE_EXCEPTION",e);
//		} catch (NoSuchAlgorithmException e) {
//			throw new IllegalStateException("NO_SUCH_ALGORITHM",e);
//		} catch (NoSuchProviderException e) {
//			throw new IllegalStateException("BOUNCY_CASTLE_PROVIDER_NOT_FOUND",e);
//		} catch (CertStoreException e) {
//			throw new IllegalStateException("KEY_STORE_EXCEPTION",e);
//		} catch (InvalidAlgorithmParameterException e) {
//			throw new IllegalStateException("INVAID_ALGORITHM",e);
//		} catch (SMIMEException e) {
//			throw new IllegalStateException("SMIME_EXCEPTION",e);
//		} catch (MessagingException e) {
//			throw new IllegalStateException("MESSAGING_EXCEPTION",e);
//		} catch (IOException e) {
//			throw new IllegalStateException("ERROR_READING_KEY",e);
//		} catch (OperatorCreationException e) {
//			throw new IllegalStateException(e);
		} finally {
			
		}
		return null;
	}
	
	public MimeMessage signAndSendMessage(
			PrivateKey senderPrivateKey,
			X509Certificate senderCertificate,X500Name sender,
			X509Certificate issuerCertificate, X500Name issuer,			
			MimeBodyPart mbp, MimeMessage msg)throws MessagingException{
		MimeMessage signMessage = signMessage(senderPrivateKey, senderCertificate, sender, issuerCertificate, issuer, mbp, msg);
		sendMessage(signMessage);
		return signMessage;
	}

	public static MimeMessage signMultipartMessage(
			PrivateKey senderPrivateKey,
			X509Certificate senderCertificate,X500Name sender,
			X509Certificate issuerCertificate, X500Name issuer,			
			MimeMultipart mpart, MimeMessage msg) {
		MimeMessage signMail;
		try {
//			SMIMESignEncryptUtils signEncryptUtils = new SMIMESignEncryptUtils();
//			signMail = signEncryptUtils.signMail(
//					senderPrivateKey, senderCertificate, sender, 
//					issuerCertificate, issuer, mpart, msg);
//		} catch (CertificateEncodingException e) {
//			throw new IllegalStateException("CERTIFICATE_EXCEPTION",e);
//		} catch (NoSuchAlgorithmException e) {
//			throw new IllegalStateException("NO_SUCH_ALGORITHM",e);
//		} catch (NoSuchProviderException e) {
//			throw new IllegalStateException("BOUNCY_CASTLE_PROVIDER_NOT_FOUND",e);
//		} catch (CertStoreException e) {
//			throw new IllegalStateException("KEY_STORE_EXCEPTION",e);
//		} catch (InvalidAlgorithmParameterException e) {
//			throw new IllegalStateException("INVAID_ALGORITHM",e);
//		} catch (SMIMEException e) {
//			throw new IllegalStateException("SMIME_EXCEPTION",e);
//		} catch (MessagingException e) {
//			throw new IllegalStateException("MESSAGING_EXCEPTION",e);
//		} catch (IOException e) {
//			throw new IllegalStateException("ERROR_READING_KEY",e);
//		} catch (OperatorCreationException e) {
//			throw new IllegalStateException(e);
		} finally {
			
		}
		return null;
	}
	
	public MimeMessage signAndSendMultipartMessage(
			PrivateKey senderPrivateKey,
			X509Certificate senderCertificate,X500Name sender,
			X509Certificate issuerCertificate, X500Name issuer,			
			MimeMultipart mpart, MimeMessage msg) throws MessagingException {
		MimeMessage signMail = signMultipartMessage(senderPrivateKey, senderCertificate, sender, issuerCertificate, issuer, mpart, msg);
		sendMessage(signMail);
		return signMail;
	}

}
